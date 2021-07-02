// Copyright 2015 The go-ethereum Authors
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

// Package rlpx implements the RLPx transport protocol.
package rlpx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	mrand "math/rand"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/golang/snappy"
	"golang.org/x/crypto/sha3"
)

// Conn is an RLPx network connection. It wraps a low-level network connection. The
// underlying connection should not be used for other activity when it is wrapped by Conn.
//
// Before sending messages, a handshake must be performed by calling the Handshake method.
// This type is not generally safe for concurrent use, but reading and writing of messages
// may happen concurrently after the handshake.
// Conn代表了基于RLPx协议的网络连接
// 内部封装了net.Conn对象实现真正的传输层通信
type Conn struct {
	// diaDest代表远程节点的公钥
	dialDest  *ecdsa.PublicKey
	conn      net.Conn
	handshake *handshakeState
	snappy    bool
}

// cipher.Stream有XORKeyStream(dst,src)对整个src加密写入dst
// cipher.Block.Encrypt(dst,src)对src的第一个块长度进行加密写入到dst
type handshakeState struct {
	// 用于加密发送的消息的aes ctr模式的流
	enc cipher.Stream
	// 用于解密接收的消息的aes ctr模式的流
	dec cipher.Stream

	macCipher cipher.Block
	// 本地向外发送消息使用的MAC
	egressMAC hash.Hash
	// 接收外部消息使用的MAC
	ingressMAC hash.Hash
}

// NewConn wraps the given network connection. If dialDest is non-nil, the connection
// behaves as the initiator during the handshake.
// dialDest不为nil说明本地是握手的发起方
// dialDest是nil说明本地是握手的接收方
func NewConn(conn net.Conn, dialDest *ecdsa.PublicKey) *Conn {
	return &Conn{
		dialDest: dialDest,
		conn:     conn,
	}
}

// SetSnappy enables or disables snappy compression of messages. This is usually called
// after the devp2p Hello message exchange when the negotiated version indicates that
// compression is available on both ends of the connection.
func (c *Conn) SetSnappy(snappy bool) {
	c.snappy = snappy
}

// SetReadDeadline sets the deadline for all future read operations.
// 超过指定时间后不能再Read
func (c *Conn) SetReadDeadline(time time.Time) error {
	return c.conn.SetReadDeadline(time)
}

// SetWriteDeadline sets the deadline for all future write operations.
// 超过指定时间后不能再Write
func (c *Conn) SetWriteDeadline(time time.Time) error {
	return c.conn.SetWriteDeadline(time)
}

// SetDeadline sets the deadline for all future read and write operations.
// 超过指定时间后不能再Read和Write
func (c *Conn) SetDeadline(time time.Time) error {
	return c.conn.SetDeadline(time)
}

// Read reads a message from the connection.
// 通过网络读取一个消息,获取code和消息内的数据
// 从链路中读取一个帧,返回code和真实的数据,以及通过链路传输的数据的长度
func (c *Conn) Read() (code uint64, data []byte, wireSize int, err error) {
	if c.handshake == nil {
		panic("can't ReadMsg before handshake")
	}

	frame, err := c.handshake.readFrame(c.conn)
	if err != nil {
		return 0, nil, 0, err
	}
	// 帧数据是code和data两个部分
	code, data, err = rlp.SplitUint64(frame)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("invalid message code: %v", err)
	}
	// 代表通过网络传输的数据
	wireSize = len(data)

	// If snappy is enabled, verify and decompress message.
	// 如果启用了压缩,就将获取的数据进行解压
	if c.snappy {
		var actualSize int
		actualSize, err = snappy.DecodedLen(data)
		if err != nil {
			return code, nil, 0, err
		}
		if actualSize > maxUint24 {
			return code, nil, 0, errPlainMessageTooLarge
		}
		data, err = snappy.Decode(nil, data)
	}
	return code, data, wireSize, err
}

// 读取一个帧内的数据
func (h *handshakeState) readFrame(conn io.Reader) ([]byte, error) {
	// read the header
	// 读取头部信息, header-data和header-mac各16字节
	headbuf := make([]byte, 32)
	if _, err := io.ReadFull(conn, headbuf); err != nil {
		return nil, err
	}

	// verify header mac
	// 通过headbuf的前16字节计算出来后16字节的MAC,然后校验MAC是否与读取到的匹配
	shouldMAC := updateMAC(h.ingressMAC, h.macCipher, headbuf[:16])
	if !hmac.Equal(shouldMAC, headbuf[16:]) {
		return nil, errors.New("bad header MAC")
	}
	// 对header-data解密
	h.dec.XORKeyStream(headbuf[:16], headbuf[:16]) // first half is now decrypted
	// 或者帧内数据长度
	fsize := readInt24(headbuf)
	// ignore protocol type for now

	// read the frame content
	// rsize代表帧内数据填充为16的整数倍后的长度
	var rsize = fsize // frame size rounded up to 16 byte boundary
	if padding := fsize % 16; padding > 0 {
		rsize += 16 - padding
	}
	// 读取frame-data
	framebuf := make([]byte, rsize)
	if _, err := io.ReadFull(conn, framebuf); err != nil {
		return nil, err
	}

	// read and validate frame MAC. we can re-use headbuf for that.
	h.ingressMAC.Write(framebuf)
	fmacseed := h.ingressMAC.Sum(nil)
	// 将收到的frame-mac保存到headbuf前16字节
	if _, err := io.ReadFull(conn, headbuf[:16]); err != nil {
		return nil, err
	}
	// 本地计算出来的MAC叫shouldMAC
	shouldMAC = updateMAC(h.ingressMAC, h.macCipher, fmacseed)
	// 判断是否匹配
	if !hmac.Equal(shouldMAC, headbuf[:16]) {
		return nil, errors.New("bad frame MAC")
	}

	// decrypt frame content
	// 解密帧内数据
	h.dec.XORKeyStream(framebuf, framebuf)
	// 返回的数据去掉后面的填充
	return framebuf[:fsize], nil
}

// Write writes a message to the connection.
//
// Write returns the written size of the message data. This may be less than or equal to
// len(data) depending on whether snappy compression is enabled.
// 通过网络发送一个消息,指定code和数据
// 返回进行网络传输的数据长度,不使用压缩时就等于data的长度,压缩的话可能小于data的长度
func (c *Conn) Write(code uint64, data []byte) (uint32, error) {
	if c.handshake == nil {
		panic("can't WriteMsg before handshake")
	}
	if len(data) > maxUint24 {
		return 0, errPlainMessageTooLarge
	}
	// 对数据进行压缩
	if c.snappy {
		data = snappy.Encode(nil, data)
	}

	wireSize := uint32(len(data))
	err := c.handshake.writeFrame(c.conn, code, data)
	return wireSize, err
}

// 将输入的数据封装成帧写入到conn中
// 帧分为四个部分,这四个部分长度都是16字节的整数倍,对于header和frame-data都是不足16字节进行补零
// frame = header-ciphertext(16字节) || header-mac(16字节) || frame-data-ciphertext || frame-mac(16字节)
// header = frame-size(3字节) || header-data(现在使用zeroHeader,填充了3字节) || header-padding
func (h *handshakeState) writeFrame(conn io.Writer, code uint64, data []byte) error {
	ptype, _ := rlp.EncodeToBytes(code)

	// write header
	// headbuf的结构,总长度32字节
	// 前16字节: fsize(3字节) || zeroHeader(3字节) || 10字节的全零
	// 后16字节: MAC
	headbuf := make([]byte, 32)
	// frame-size代表帧中真正的数据的长度,就是参数中的code和data的总长度
	fsize := len(ptype) + len(data)
	if fsize > maxUint24 {
		return errPlainMessageTooLarge
	}
	putInt24(uint32(fsize), headbuf)
	copy(headbuf[3:], zeroHeader)
	h.enc.XORKeyStream(headbuf[:16], headbuf[:16]) // first half is now encrypted

	// write header MAC
	copy(headbuf[16:], updateMAC(h.egressMAC, h.macCipher, headbuf[:16]))
	// 将前32字节传输出去,就是header-ciphertext和header-mac这两个部分
	if _, err := conn.Write(headbuf); err != nil {
		return err
	}
	// 接下来处理frame-data和frame-mac

	// write encrypted frame, updating the egress MAC hash with
	// the data written to conn.
	// 将frame-data加密并传输出去
	tee := cipher.StreamWriter{S: h.enc, W: io.MultiWriter(conn, h.egressMAC)}
	if _, err := tee.Write(ptype); err != nil {
		return err
	}
	if _, err := tee.Write(data); err != nil {
		return err
	}
	// 将已经写入的frame-data补零到16字节的整数倍
	if padding := fsize % 16; padding > 0 {
		if _, err := tee.Write(zero16[:16-padding]); err != nil {
			return err
		}
	}

	// write frame MAC. egress MAC hash is up to date because
	// frame content was written to it as well.
	// 计算frame-mac并通过网络传输
	fmacseed := h.egressMAC.Sum(nil)
	mac := updateMAC(h.egressMAC, h.macCipher, fmacseed)
	_, err := conn.Write(mac)
	return err
}

// 将b的前三个字节放到uint32后24位
func readInt24(b []byte) uint32 {
	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}

// 输入时要保证b长度大于等于3,将utin32后24位写入到b[0],b[1],b[2]中
func putInt24(v uint32, b []byte) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

// updateMAC reseeds the given hash with encrypted seed.
// it returns the first 16 bytes of the hash sum after seeding.
// 用于生成MAC,包括header-mac和frame-mac
func updateMAC(mac hash.Hash, block cipher.Block, seed []byte) []byte {
	aesbuf := make([]byte, aes.BlockSize)
	block.Encrypt(aesbuf, mac.Sum(nil))
	for i := range aesbuf {
		aesbuf[i] ^= seed[i]
	}
	mac.Write(aesbuf)
	return mac.Sum(nil)[:16]
}

// Handshake performs the handshake. This must be called before any data is written
// or read from the connection.
// 执行两个节点间的握手,调用NewConn后就应该执行Handshake
// 在执行Handshake之前不能进行任何数据传输
func (c *Conn) Handshake(prv *ecdsa.PrivateKey) (*ecdsa.PublicKey, error) {
	var (
		sec Secrets
		err error
	)
	if c.dialDest != nil {
		sec, err = initiatorEncHandshake(c.conn, prv, c.dialDest)
	} else {
		sec, err = receiverEncHandshake(c.conn, prv)
	}
	if err != nil {
		return nil, err
	}
	// 设置c.handshake
	c.InitWithSecrets(sec)
	return sec.remote, err
}

// InitWithSecrets injects connection secrets as if a handshake had
// been performed. This cannot be called after the handshake.
// 用于模拟握手完成,不执行真正的握手过程,直接需要握手过程共享的秘密保存到Conn中
// 就是用Secrets对象生成handshakeState对象
func (c *Conn) InitWithSecrets(sec Secrets) {
	if c.handshake != nil {
		panic("can't handshake twice")
	}
	macc, err := aes.NewCipher(sec.MAC)
	if err != nil {
		panic("invalid MAC secret: " + err.Error())
	}
	encc, err := aes.NewCipher(sec.AES)
	if err != nil {
		panic("invalid AES secret: " + err.Error())
	}
	// we use an all-zeroes IV for AES because the key used
	// for encryption is ephemeral.
	// 使用的IV是16字节的全零数组,因为每次通信的密钥都不同所以IV可以一样
	iv := make([]byte, encc.BlockSize())
	c.handshake = &handshakeState{
		enc:        cipher.NewCTR(encc, iv),
		dec:        cipher.NewCTR(encc, iv),
		macCipher:  macc,
		egressMAC:  sec.EgressMAC,
		ingressMAC: sec.IngressMAC,
	}
}

// Close closes the underlying network connection.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// Constants for the handshake.
const (
	// frame-size使用了3个字节保存,所以帧长度最多24位
	maxUint24 = int(^uint32(0) >> 8)

	sskLen = 16                     // ecies.MaxSharedKeyLength(pubKey) / 2
	sigLen = crypto.SignatureLength // elliptic S256
	pubLen = 64                     // 512 bit pubkey in uncompressed representation without format byte
	shaLen = 32                     // hash length (for nonce etc)

	authMsgLen  = sigLen + shaLen + pubLen + shaLen + 1
	authRespLen = pubLen + shaLen + 1

	// eciesOverhead代表明文通过ecies.Encrypt加密后长度增加了多少
	eciesOverhead = 65 /* pubkey */ + 16 /* IV */ + 32 /* MAC */

	encAuthMsgLen  = authMsgLen + eciesOverhead  // size of encrypted pre-EIP-8 initiator handshake
	encAuthRespLen = authRespLen + eciesOverhead // size of encrypted pre-EIP-8 handshake reply
)

var (
	// this is used in place of actual frame header data.
	// TODO: replace this when Msg contains the protocol type code.
	zeroHeader = []byte{0xC2, 0x80, 0x80}
	// sixteen zero bytes
	zero16 = make([]byte, 16)

	// errPlainMessageTooLarge is returned if a decompressed message length exceeds
	// the allowed 24 bits (i.e. length >= 16MB).
	errPlainMessageTooLarge = errors.New("message length >= 16MB")
)

// Secrets represents the connection secrets which are negotiated during the handshake.
type Secrets struct {
	// AES和MAC长度都是32字节,作为AES-256算法的密钥
	AES, MAC              []byte
	EgressMAC, IngressMAC hash.Hash
	remote                *ecdsa.PublicKey
}

// encHandshake contains the state of the encryption handshake.
// 代表握手过程的状态
type encHandshake struct {
	// 标记本地是连接的发起方还是接收方
	initiator bool
	// remote代表远程节点的公钥
	//   发送方通过Conn.diaDest在initiatorEncHandshake设置remote
	//   接收方在receiverEncHandshake根据收到的authMsg解析出来remote
	remote *ecies.PublicKey // remote-pubk
	// initNonce: 发起方在makeAuthMsg中生成,接收方在handleAuthMsg中解析出来
	// respNonce: 发起方在handleAuthResp中解析出来,接收方在makeAuthResp中生成
	initNonce, respNonce []byte // nonce
	// 握手过程中双方都成一对随机的公私钥
	// 本地保存自己随机生成的私钥,通过握手能得到远程节点随机生成的公钥
	randomPrivKey   *ecies.PrivateKey // ecdhe-random
	remoteRandomPub *ecies.PublicKey  // ecdhe-random-pubk
}

// RLPx v4 handshake auth (defined in EIP-8).
// 握手过程中总共发送两条消息,分别是发起方发送authMsg和接收方接收后回复authResp
// 发起方调用initiatorEncHandshake处理握手
//   内部调用了makeAuthMsg发送消息,然后调用handleAuthResp处理接收方的回复
// 接收方调用receiverEncHandshake处理握手
//   内部调用了handleAuthMsg处理发起方的消息,然后调用makeAuthResp回复发起方

type authMsgV4 struct {
	gotPlain bool // whether read packet had plain format.

	// 双方的静态公私钥可以推导出共享秘密token
	// 使用发送方生成的随机私钥对 Nonce与token 的异或结果进行签名
	// 接收方有Nonce和token可以推导出发送方的随机公钥
	Signature [sigLen]byte
	// 发送方的静态公钥
	InitiatorPubkey [pubLen]byte
	// 发送authMsg生成的随机数
	Nonce [shaLen]byte
	// 当前一定是4
	Version uint

	// Ignore additional fields (forward-compatibility)
	Rest []rlp.RawValue `rlp:"tail"`
}

// RLPx v4 handshake response (defined in EIP-8).
type authRespV4 struct {
	// 接收方生成的随机公钥
	RandomPubkey [pubLen]byte
	// 接收方生成的随机Nonce
	Nonce        [shaLen]byte
	// 当前一定是4
	Version      uint

	// Ignore additional fields (forward-compatibility)
	Rest []rlp.RawValue `rlp:"tail"`
}

// receiverEncHandshake negotiates a session token on conn.
// it should be called on the listening side of the connection.
//
// prv is the local client's private key.
func receiverEncHandshake(conn io.ReadWriter, prv *ecdsa.PrivateKey) (s Secrets, err error) {
	// 从网络字节流中解析出来authMsg对象,authPacket代表authMsg的rlp编码
	authMsg := new(authMsgV4)
	authPacket, err := readHandshakeMsg(authMsg, encAuthMsgLen, prv, conn)
	if err != nil {
		return s, err
	}
	// 处理接收到的authMsg
	h := new(encHandshake)
	if err := h.handleAuthMsg(authMsg, prv); err != nil {
		return s, err
	}

	// 接收方收到authMsg后开始发送authResp
	authRespMsg, err := h.makeAuthResp()
	if err != nil {
		return s, err
	}
	var authRespPacket []byte
	if authMsg.gotPlain {
		authRespPacket, err = authRespMsg.sealPlain(h)
	} else {
		// 将构造的authResp对象编码成字节流,使用接收方的静态公钥进行加密
		authRespPacket, err = sealEIP8(authRespMsg, h)
	}
	if err != nil {
		return s, err
	}
	// 将数据发送给发送方
	if _, err = conn.Write(authRespPacket); err != nil {
		return s, err
	}
	// 接收方已经能构造出来接下来通信使用的Secrets对象了
	return h.secrets(authPacket, authRespPacket)
}

// 接收方处理发送方发送的authMsg包
// 接收方通过authMsg包可以得知发送方的静态公钥,随机私钥,随机Nonce
func (h *encHandshake) handleAuthMsg(msg *authMsgV4, prv *ecdsa.PrivateKey) error {
	// Import the remote identity.
	rpub, err := importPublicKey(msg.InitiatorPubkey[:])
	if err != nil {
		return err
	}
	h.initNonce = msg.Nonce[:]
	h.remote = rpub

	// Generate random keypair for ECDH.
	// If a private key is already set, use it instead of generating one (for testing).
	// 生成接收方的随机私钥
	if h.randomPrivKey == nil {
		h.randomPrivKey, err = ecies.GenerateKey(rand.Reader, crypto.S256(), nil)
		if err != nil {
			return err
		}
	}

	// Check the signature.
	// 校验authMsg里的签名是否正确
	// 首先生成共享秘密token
	token, err := h.staticSharedSecret(prv)
	if err != nil {
		return err
	}
	// token与nonce异或
	signedMsg := xor(token, h.initNonce)
	// 使用signedMsg和签名恢复出来发送方生成的随机公钥
	remoteRandomPub, err := crypto.Ecrecover(signedMsg, msg.Signature[:])
	if err != nil {
		return err
	}
	h.remoteRandomPub, _ = importPublicKey(remoteRandomPub)
	return nil
}

// secrets is called after the handshake is completed.
// It extracts the connection secrets from the handshake values.
// 利用握手过程中发送的两个数据包构建租出Secrets对象
func (h *encHandshake) secrets(auth, authResp []byte) (Secrets, error) {
	ecdheSecret, err := h.randomPrivKey.GenerateShared(h.remoteRandomPub, sskLen, sskLen)
	if err != nil {
		return Secrets{}, err
	}

	// derive base secrets from ephemeral key agreement
	sharedSecret := crypto.Keccak256(ecdheSecret, crypto.Keccak256(h.respNonce, h.initNonce))
	aesSecret := crypto.Keccak256(ecdheSecret, sharedSecret)
	s := Secrets{
		remote: h.remote.ExportECDSA(),
		AES:    aesSecret,
		MAC:    crypto.Keccak256(ecdheSecret, aesSecret),
	}

	// setup sha3 instances for the MACs
	mac1 := sha3.NewLegacyKeccak256()
	mac1.Write(xor(s.MAC, h.respNonce))
	mac1.Write(auth)
	mac2 := sha3.NewLegacyKeccak256()
	mac2.Write(xor(s.MAC, h.initNonce))
	mac2.Write(authResp)
	// 发送方和接收方的egress和ingress正好相反
	if h.initiator {
		s.EgressMAC, s.IngressMAC = mac1, mac2
	} else {
		s.EgressMAC, s.IngressMAC = mac2, mac1
	}

	return s, nil
}

// staticSharedSecret returns the static shared secret, the result
// of key agreement between the local and remote static node key.
func (h *encHandshake) staticSharedSecret(prv *ecdsa.PrivateKey) ([]byte, error) {
	return ecies.ImportECDSA(prv).GenerateShared(h.remote, sskLen, sskLen)
}

// initiatorEncHandshake negotiates a session token on conn.
// it should be called on the dialing side of the connection.
//
// prv is the local client's private key.
// 连接发起方处理握手,发起方握手过程分两步
// 首先构造authMsg发送给对方,然后接收对方的authRespMsg
// 通过中这两个数据包调用secrets构造Secrets对象
func initiatorEncHandshake(conn io.ReadWriter, prv *ecdsa.PrivateKey, remote *ecdsa.PublicKey) (s Secrets, err error) {
	h := &encHandshake{initiator: true, remote: ecies.ImportECDSAPublic(remote)}
	// 构造authMsg对象
	authMsg, err := h.makeAuthMsg(prv)
	if err != nil {
		return s, err
	}
	// 对authMsg对象进行编码
	authPacket, err := sealEIP8(authMsg, h)
	if err != nil {
		return s, err
	}

	// 将数据发送出去
	if _, err = conn.Write(authPacket); err != nil {
		return s, err
	}

	authRespMsg := new(authRespV4)
	authRespPacket, err := readHandshakeMsg(authRespMsg, encAuthRespLen, prv, conn)
	if err != nil {
		return s, err
	}
	if err := h.handleAuthResp(authRespMsg); err != nil {
		return s, err
	}
	return h.secrets(authPacket, authRespPacket)
}

// makeAuthMsg creates the initiator handshake message.
// 创建消息发起方的握手信息
// 发起方生成了initNonce
func (h *encHandshake) makeAuthMsg(prv *ecdsa.PrivateKey) (*authMsgV4, error) {
	// Generate random initiator nonce.
	// 生成随机的initNonce
	h.initNonce = make([]byte, shaLen)
	_, err := rand.Read(h.initNonce)
	if err != nil {
		return nil, err
	}
	// Generate random keypair to for ECDH.
	// 生成临时随机私钥
	h.randomPrivKey, err = ecies.GenerateKey(rand.Reader, crypto.S256(), nil)
	if err != nil {
		return nil, err
	}

	// Sign known message: static-shared-secret ^ nonce
	// 利用本地的静态私钥和对方的静态公钥计算双方共享的秘密token
	token, err := h.staticSharedSecret(prv)
	if err != nil {
		return nil, err
	}
	// 将共享秘密token与生成的随机数异或,得到signed
	signed := xor(token, h.initNonce)
	// 使用本地的随机私钥对signed签名
	signature, err := crypto.Sign(signed, h.randomPrivKey.ExportECDSA())
	if err != nil {
		return nil, err
	}

	// 构造authMsg
	msg := new(authMsgV4)
	copy(msg.Signature[:], signature)
	copy(msg.InitiatorPubkey[:], crypto.FromECDSAPub(&prv.PublicKey)[1:])
	copy(msg.Nonce[:], h.initNonce)
	msg.Version = 4
	return msg, nil
}

func (h *encHandshake) handleAuthResp(msg *authRespV4) (err error) {
	h.respNonce = msg.Nonce[:]
	h.remoteRandomPub, err = importPublicKey(msg.RandomPubkey[:])
	return err
}

// 构造authRespV4对象
// 生成随机的Nonce,利用handleAuthMsg生成的随机私钥导出公钥保存的msg中
func (h *encHandshake) makeAuthResp() (msg *authRespV4, err error) {
	// Generate random nonce.
	h.respNonce = make([]byte, shaLen)
	if _, err = rand.Read(h.respNonce); err != nil {
		return nil, err
	}

	msg = new(authRespV4)
	copy(msg.Nonce[:], h.respNonce)
	copy(msg.RandomPubkey[:], exportPubkey(&h.randomPrivKey.PublicKey))
	msg.Version = 4
	return msg, nil
}

func (msg *authMsgV4) decodePlain(input []byte) {
	n := copy(msg.Signature[:], input)
	n += shaLen // skip sha3(initiator-ephemeral-pubk)
	n += copy(msg.InitiatorPubkey[:], input[n:])
	copy(msg.Nonce[:], input[n:])
	msg.Version = 4
	msg.gotPlain = true
}

func (msg *authRespV4) sealPlain(hs *encHandshake) ([]byte, error) {
	buf := make([]byte, authRespLen)
	n := copy(buf, msg.RandomPubkey[:])
	copy(buf[n:], msg.Nonce[:])
	return ecies.Encrypt(rand.Reader, hs.remote, buf, nil, nil)
}

func (msg *authRespV4) decodePlain(input []byte) {
	n := copy(msg.RandomPubkey[:], input)
	copy(msg.Nonce[:], input[n:])
	msg.Version = 4
}

var padSpace = make([]byte, 300)

// 将authMsgV4或者authRespV4对象编码成字节流
// 首先将msg进行rlp编码,然后使用远程节点的静态公钥进行加密
// 最后的字节流为 prefix || ciphertext
// prefix是后面密文的长度,密文长度比原始的rlp编码长了113字节
func sealEIP8(msg interface{}, h *encHandshake) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := rlp.Encode(buf, msg); err != nil {
		return nil, err
	}
	// pad with random amount of data. the amount needs to be at least 100 bytes to make
	// the message distinguishable from pre-EIP-8 handshakes.
	// pad的长度必须大于100字节,才能与eip-8之前的握手包进行区分
	// pad的长度是[100,300)的随机数
	pad := padSpace[:mrand.Intn(len(padSpace)-100)+100]
	buf.Write(pad)
	prefix := make([]byte, 2)
	binary.BigEndian.PutUint16(prefix, uint16(buf.Len()+eciesOverhead))

	enc, err := ecies.Encrypt(rand.Reader, h.remote, buf.Bytes(), nil, prefix)
	return append(prefix, enc...), err
}

type plainDecoder interface {
	decodePlain([]byte)
}

// 从r中读取一个握手过程中的消息,对读取到的数据进行解密,返回消息的rlp编码,rlp解码的对象保存在参数msg中
// 调用的地方有两处:
//   1. 发起方发送authMsg后,用于接收authResp
//   2. 接收方接收authMsg的时候
// prv是用来解密数据包的本地私钥,因为远程发送过来的时候加密使用的是本地公钥
func readHandshakeMsg(msg plainDecoder, plainSize int, prv *ecdsa.PrivateKey, r io.Reader) ([]byte, error) {
	buf := make([]byte, plainSize)
	// 读取数据到buf中
	if _, err := io.ReadFull(r, buf); err != nil {
		return buf, err
	}
	// Attempt decoding pre-EIP-8 "plain" format.
	key := ecies.ImportECDSA(prv)
	if dec, err := key.Decrypt(buf, nil, nil); err == nil {
		msg.decodePlain(dec)
		return buf, nil
	}
	// Could be EIP-8 format, try that.
	// 前两字节是后面密文的长度
	prefix := buf[:2]
	size := binary.BigEndian.Uint16(prefix)
	if size < uint16(plainSize) {
		return buf, fmt.Errorf("size underflow, need at least %d bytes", plainSize)
	}
	buf = append(buf, make([]byte, size-uint16(plainSize)+2)...)
	if _, err := io.ReadFull(r, buf[plainSize:]); err != nil {
		return buf, err
	}
	dec, err := key.Decrypt(buf[2:], nil, prefix)
	if err != nil {
		return buf, err
	}
	// Can't use rlp.DecodeBytes here because it rejects
	// trailing data (forward-compatibility).
	s := rlp.NewStream(bytes.NewReader(dec), 0)
	return buf, s.Decode(msg)
}

// importPublicKey unmarshals 512 bit public keys.
// 通过字节数组恢复出来公钥
func importPublicKey(pubKey []byte) (*ecies.PublicKey, error) {
	var pubKey65 []byte
	switch len(pubKey) {
	case 64:
		// add 'uncompressed key' flag
		pubKey65 = append([]byte{0x04}, pubKey...)
	case 65:
		pubKey65 = pubKey
	default:
		return nil, fmt.Errorf("invalid public key length %v (expect 64/65)", len(pubKey))
	}
	// TODO: fewer pointless conversions
	pub, err := crypto.UnmarshalPubkey(pubKey65)
	if err != nil {
		return nil, err
	}
	return ecies.ImportECDSAPublic(pub), nil
}

// 编码公钥到字节数组
func exportPubkey(pub *ecies.PublicKey) []byte {
	if pub == nil {
		panic("nil pubkey")
	}
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)[1:]
}

// 计算one与other异或的结果,返回结果的长度是one的长度
func xor(one, other []byte) (xor []byte) {
	xor = make([]byte, len(one))
	for i := 0; i < len(one); i++ {
		xor[i] = one[i] ^ other[i]
	}
	return xor
}
