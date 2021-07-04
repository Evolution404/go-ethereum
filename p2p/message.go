// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package p2p

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
)

// Msg defines the structure of a p2p message.
//
// Note that a Msg can only be sent once since the Payload reader is
// consumed during sending. It is not possible to create a Msg and
// send it any number of times. If you want to reuse an encoded
// structure, encode the payload into a byte array and create a
// separate Msg with a bytes.Reader as Payload for each send.
// p2p网络中传递的消息对象
// 每个Msg对象只能发送一次,因为发送一次中后内部的Payload是io.Reader类型已经被读取完了
type Msg struct {
	Code       uint64
	Size       uint32 // Size of the raw payload
	Payload    io.Reader
	// 消息接收到的时间
	// 在Peer.readLoop函数中设置
	ReceivedAt time.Time

	meterCap  Cap    // Protocol name and version for egress metering
	meterCode uint64 // Message within protocol for egress metering
	meterSize uint32 // Compressed message size for ingress metering
}

// Decode parses the RLP content of a message into
// the given value, which must be a pointer.
//
// For the decoding rules, please see package rlp.
// 将Msg.Payload里保存的rlp编码解码成输入的类型
func (msg Msg) Decode(val interface{}) error {
	s := rlp.NewStream(msg.Payload, uint64(msg.Size))
	if err := s.Decode(val); err != nil {
		return newPeerError(errInvalidMsg, "(code %x) (size %d) %v", msg.Code, msg.Size, err)
	}
	return nil
}

func (msg Msg) String() string {
	return fmt.Sprintf("msg #%v (%v bytes)", msg.Code, msg.Size)
}

// Discard reads any remaining payload data into a black hole.
// 清空Msg.Payload中保存的数据
func (msg Msg) Discard() error {
	_, err := io.Copy(ioutil.Discard, msg.Payload)
	return err
}

// 获得消息接收的时间
func (msg Msg) Time() time.Time {
	return msg.ReceivedAt
}

// 读取消息,ReadMsg
type MsgReader interface {
	ReadMsg() (Msg, error)
}

// 写入消息,WriteMsg
type MsgWriter interface {
	// WriteMsg sends a message. It will block until the message's
	// Payload has been consumed by the other end.
	//
	// Note that messages can be sent only once because their
	// payload reader is drained.
	WriteMsg(Msg) error
}

// MsgReadWriter provides reading and writing of encoded messages.
// Implementations should ensure that ReadMsg and WriteMsg can be
// called simultaneously from multiple goroutines.
// 对消息可读可写 ReadMsg,WriteMsg
type MsgReadWriter interface {
	MsgReader
	MsgWriter
}

// Send writes an RLP-encoded message with the given code.
// data should encode as an RLP list.
// 将消息msgcode和data通过w发送出去
func Send(w MsgWriter, msgcode uint64, data interface{}) error {
	size, r, err := rlp.EncodeToReader(data)
	if err != nil {
		return err
	}
	return w.WriteMsg(Msg{Code: msgcode, Size: uint32(size), Payload: r})
}

// SendItems writes an RLP with the given code and data elements.
// For a call such as:
//
//    SendItems(w, code, e1, e2, e3)
//
// the message payload will be an RLP list containing the items:
//
//    [e1, e2, e3]
//
// 发送好几个数据,例如调用SendItems(w, code, e1, e2, e3)
// 会将e1,e2,e3编码成一个数组[e1,e2,e3]
func SendItems(w MsgWriter, msgcode uint64, elems ...interface{}) error {
	return Send(w, msgcode, elems)
}

// eofSignal wraps a reader with eof signaling. the eof channel is
// closed when the wrapped reader returns an error or when count bytes
// have been read.
// 内部封装了一个管道eof,当io.Reader读取结束或者发生错误时会向eof发送空对象
type eofSignal struct {
	wrapped io.Reader
	count   uint32 // number of bytes left
	eof     chan<- struct{}
}

// note: when using eofSignal to detect whether a message payload
// has been read, Read might not be called for zero sized messages.
// 相比普通的io.Reader增加了向eof管道通知的功能
func (r *eofSignal) Read(buf []byte) (int, error) {
	if r.count == 0 {
		if r.eof != nil {
			r.eof <- struct{}{}
			r.eof = nil
		}
		return 0, io.EOF
	}

	max := len(buf)
	if int(r.count) < len(buf) {
		max = int(r.count)
	}
	n, err := r.wrapped.Read(buf[:max])
	r.count -= uint32(n)
	if (err != nil || r.count == 0) && r.eof != nil {
		r.eof <- struct{}{} // tell Peer that msg has been consumed
		r.eof = nil
	}
	return n, err
}

// MsgPipe creates a message pipe. Reads on one end are matched
// with writes on the other. The pipe is full-duplex, both ends
// implement MsgReadWriter.
// 创建一对MsgPipeRW对象,他们实现了MsgReadWriter接口
func MsgPipe() (*MsgPipeRW, *MsgPipeRW) {
	var (
		c1, c2  = make(chan Msg), make(chan Msg)
		closing = make(chan struct{})
		// 共用同一个closed,一旦关闭两个对象同时关闭
		closed  = new(int32)
		rw1     = &MsgPipeRW{c1, c2, closing, closed}
		rw2     = &MsgPipeRW{c2, c1, closing, closed}
	)
	return rw1, rw2
}

// ErrPipeClosed is returned from pipe operations after the
// pipe has been closed.
var ErrPipeClosed = errors.New("p2p: read or write on closed message pipe")

// MsgPipeRW is an endpoint of a MsgReadWriter pipe.
// 实现了MsgReadWriter接口
type MsgPipeRW struct {
	w       chan<- Msg
	r       <-chan Msg
	closing chan struct{}
	closed  *int32
}

// WriteMsg sends a message on the pipe.
// It blocks until the receiver has consumed the message payload.
func (p *MsgPipeRW) WriteMsg(msg Msg) error {
	if atomic.LoadInt32(p.closed) == 0 {
		consumed := make(chan struct{}, 1)
		msg.Payload = &eofSignal{msg.Payload, msg.Size, consumed}
		select {
		case p.w <- msg:
			if msg.Size > 0 {
				// wait for payload read or discard
				select {
				case <-consumed:
				case <-p.closing:
				}
			}
			return nil
		case <-p.closing:
		}
	}
	return ErrPipeClosed
}

// ReadMsg returns a message sent on the other end of the pipe.
func (p *MsgPipeRW) ReadMsg() (Msg, error) {
	if atomic.LoadInt32(p.closed) == 0 {
		select {
		case msg := <-p.r:
			return msg, nil
		case <-p.closing:
		}
	}
	return Msg{}, ErrPipeClosed
}

// Close unblocks any pending ReadMsg and WriteMsg calls on both ends
// of the pipe. They will return ErrPipeClosed. Close also
// interrupts any reads from a message payload.
// Close函数的目的是关闭closing管道
// 使用额外变量closed来标记是否关闭过
func (p *MsgPipeRW) Close() error {
	// 加一之后不等于一,说明其他地方执行过了不再重复关闭
	if atomic.AddInt32(p.closed, 1) != 1 {
		// someone else is already closing
		atomic.StoreInt32(p.closed, 1) // avoid overflow
		return nil
	}
	// 关闭closing管道,用来通知已经关闭
	close(p.closing)
	return nil
}

// ExpectMsg reads a message from r and verifies that its
// code and encoded RLP content match the provided values.
// If content is nil, the payload is discarded and not verified.
// 从r中读取一条消息判断是否与输入的code和content匹配
func ExpectMsg(r MsgReader, code uint64, content interface{}) error {
	msg, err := r.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Code != code {
		return fmt.Errorf("message code mismatch: got %d, expected %d", msg.Code, code)
	}
	if content == nil {
		return msg.Discard()
	}
	contentEnc, err := rlp.EncodeToBytes(content)
	if err != nil {
		panic("content encode error: " + err.Error())
	}
	if int(msg.Size) != len(contentEnc) {
		return fmt.Errorf("message size mismatch: got %d, want %d", msg.Size, len(contentEnc))
	}
	actualContent, err := ioutil.ReadAll(msg.Payload)
	if err != nil {
		return err
	}
	// 判断读取到的数据与输入的数据的rlp编码是否一致
	if !bytes.Equal(actualContent, contentEnc) {
		return fmt.Errorf("message payload mismatch:\ngot:  %x\nwant: %x", actualContent, contentEnc)
	}
	return nil
}

// msgEventer wraps a MsgReadWriter and sends events whenever a message is sent
// or received
// 内部封装了一个MsgReadWriter对象,每次接收或者发送消息都将向外部触发事件
// 使用内部的MsgReadWriter来接收发送消息
type msgEventer struct {
	MsgReadWriter

	feed          *event.Feed
	peerID        enode.ID
	Protocol      string
	localAddress  string
	remoteAddress string
}

// newMsgEventer returns a msgEventer which sends message events to the given
// feed
func newMsgEventer(rw MsgReadWriter, feed *event.Feed, peerID enode.ID, proto, remote, local string) *msgEventer {
	return &msgEventer{
		MsgReadWriter: rw,
		feed:          feed,
		peerID:        peerID,
		Protocol:      proto,
		remoteAddress: remote,
		localAddress:  local,
	}
}

// ReadMsg reads a message from the underlying MsgReadWriter and emits a
// "message received" event
// 调用MsgReadWriter.ReadMsg,然后额外调用feed.Send触发事件
func (ev *msgEventer) ReadMsg() (Msg, error) {
	msg, err := ev.MsgReadWriter.ReadMsg()
	if err != nil {
		return msg, err
	}
	ev.feed.Send(&PeerEvent{
		Type:          PeerEventTypeMsgRecv,
		Peer:          ev.peerID,
		Protocol:      ev.Protocol,
		MsgCode:       &msg.Code,
		MsgSize:       &msg.Size,
		LocalAddress:  ev.localAddress,
		RemoteAddress: ev.remoteAddress,
	})
	return msg, nil
}

// WriteMsg writes a message to the underlying MsgReadWriter and emits a
// "message sent" event
// 调用MsgReadWriter.WriteMsg,然后额外调用feed.Send触发事件
func (ev *msgEventer) WriteMsg(msg Msg) error {
	err := ev.MsgReadWriter.WriteMsg(msg)
	if err != nil {
		return err
	}
	ev.feed.Send(&PeerEvent{
		Type:          PeerEventTypeMsgSend,
		Peer:          ev.peerID,
		Protocol:      ev.Protocol,
		MsgCode:       &msg.Code,
		MsgSize:       &msg.Size,
		LocalAddress:  ev.localAddress,
		RemoteAddress: ev.remoteAddress,
	})
	return nil
}

// Close closes the underlying MsgReadWriter if it implements the io.Closer
// interface
func (ev *msgEventer) Close() error {
	// 如果内部的MsgReadWriter有Close函数话就调用
	if v, ok := ev.MsgReadWriter.(io.Closer); ok {
		return v.Close()
	}
	return nil
}
