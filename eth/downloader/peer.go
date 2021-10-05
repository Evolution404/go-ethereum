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

// Contains the active peer-set of the downloader, maintaining both failures
// as well as reputation metrics to prioritize the block retrievals.

package downloader

import (
	"errors"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/msgrate"
)

const (
	maxLackingHashes = 4096 // Maximum number of entries allowed on the list or lacking items
)

var (
	errAlreadyFetching   = errors.New("already fetching blocks from peer")
	errAlreadyRegistered = errors.New("peer is already registered")
	errNotRegistered     = errors.New("peer is not registered")
)

// peerConnection represents an active peer from which hashes and blocks are retrieved.
// 两个节点间的连接对象,每个与远程节点的连接都用一个peerConnection来表示
type peerConnection struct {
	id string // Unique identifier of the peer

	// 以下值为1的时候代表操作正在进行中,为0的时候代表空闲状态
	headerIdle  int32 // Current header activity state of the peer (idle = 0, active = 1)
	blockIdle   int32 // Current block activity state of the peer (idle = 0, active = 1)
	receiptIdle int32 // Current receipt activity state of the peer (idle = 0, active = 1)
	stateIdle   int32 // Current node data activity state of the peer (idle = 0, active = 1)

	headerStarted  time.Time // Time instance when the last header fetch was started
	blockStarted   time.Time // Time instance when the last block (body) fetch was started
	receiptStarted time.Time // Time instance when the last receipt fetch was started
	stateStarted   time.Time // Time instance when the last node data fetch was started

	rates   *msgrate.Tracker         // Tracker to hone in on the number of items retrievable per second
	lacking map[common.Hash]struct{} // Set of hashes not to request (didn't have previously)

	peer Peer

	// eth协议的版本
	version uint       // Eth protocol version number to switch strategies
	log     log.Logger // Contextual logger to add extra infos to peer logs
	lock    sync.RWMutex
}

// LightPeer encapsulates the methods required to synchronise with a remote light peer.
// 远程节点是light类型
type LightPeer interface {
	Head() (common.Hash, *big.Int)
	RequestHeadersByHash(common.Hash, int, int, bool) error
	RequestHeadersByNumber(uint64, int, int, bool) error
}

// Peer encapsulates the methods required to synchronise with a remote full peer.
// 远程节点是full类型
type Peer interface {
	LightPeer
	RequestBodies([]common.Hash) error
	RequestReceipts([]common.Hash) error
	RequestNodeData([]common.Hash) error
}

// lightPeerWrapper wraps a LightPeer struct, stubbing out the Peer-only methods.
// 实现了Peer接口,但是只有LightPeer的函数有意义,其他的会panic
// 可以包装一个LightPeer对象成为Peer对象
// 由于Downloader.RegisterPeer只接收Peer对象,所以在外部可以包装LightPeer对象成为lightPeerWrapper
type lightPeerWrapper struct {
	peer LightPeer
}

// 调用内部的LightPeer对应的函数
func (w *lightPeerWrapper) Head() (common.Hash, *big.Int) { return w.peer.Head() }
func (w *lightPeerWrapper) RequestHeadersByHash(h common.Hash, amount int, skip int, reverse bool) error {
	return w.peer.RequestHeadersByHash(h, amount, skip, reverse)
}
func (w *lightPeerWrapper) RequestHeadersByNumber(i uint64, amount int, skip int, reverse bool) error {
	return w.peer.RequestHeadersByNumber(i, amount, skip, reverse)
}

// Peer对象才有的函数直接报错
func (w *lightPeerWrapper) RequestBodies([]common.Hash) error {
	panic("RequestBodies not supported in light client mode sync")
}
func (w *lightPeerWrapper) RequestReceipts([]common.Hash) error {
	panic("RequestReceipts not supported in light client mode sync")
}
func (w *lightPeerWrapper) RequestNodeData([]common.Hash) error {
	panic("RequestNodeData not supported in light client mode sync")
}

// newPeerConnection creates a new downloader peer.
// 指定连接id,版本,远程节点对象和日志对象 创建一个连接对象
func newPeerConnection(id string, version uint, peer Peer, logger log.Logger) *peerConnection {
	return &peerConnection{
		id:      id,
		lacking: make(map[common.Hash]struct{}),
		peer:    peer,
		version: version,
		log:     logger,
	}
}

// Reset clears the internal state of a peer entity.
// 把Idle系列和Throughput系列都置0
func (p *peerConnection) Reset() {
	p.lock.Lock()
	defer p.lock.Unlock()

	atomic.StoreInt32(&p.headerIdle, 0)
	atomic.StoreInt32(&p.blockIdle, 0)
	atomic.StoreInt32(&p.receiptIdle, 0)
	atomic.StoreInt32(&p.stateIdle, 0)

	p.lacking = make(map[common.Hash]struct{})
}

// FetchHeaders sends a header retrieval request to the remote peer.
// 从远程节点获取区块头
// from:开始的区块,count:要拉取的区块头个数
func (p *peerConnection) FetchHeaders(from uint64, count int) error {
	// Short circuit if the peer is already fetching
	// 当headerIdle为0的时候将它设置为1
	// 当headerIdle为0的时候交换成功返回true,然后取非不进入if,执行下面的操作
	if !atomic.CompareAndSwapInt32(&p.headerIdle, 0, 1) {
		return errAlreadyFetching
	}
	p.headerStarted = time.Now()

	// Issue the header retrieval request (absolute upwards without gaps)
	go p.peer.RequestHeadersByNumber(from, count, 0, false)

	return nil
}

// FetchBodies sends a block body retrieval request to the remote peer.
// 请求一批区块体
func (p *peerConnection) FetchBodies(request *fetchRequest) error {
	// Short circuit if the peer is already fetching
	if !atomic.CompareAndSwapInt32(&p.blockIdle, 0, 1) {
		return errAlreadyFetching
	}
	p.blockStarted = time.Now()

	// 解析出来要请求的所有区块的哈希,一次性查询这一批区块体
	go func() {
		// Convert the header set to a retrievable slice
		hashes := make([]common.Hash, 0, len(request.Headers))
		for _, header := range request.Headers {
			hashes = append(hashes, header.Hash())
		}
		p.peer.RequestBodies(hashes)
	}()

	return nil
}

// FetchReceipts sends a receipt retrieval request to the remote peer.
// 获取一批区块的receipt
func (p *peerConnection) FetchReceipts(request *fetchRequest) error {
	// Short circuit if the peer is already fetching
	if !atomic.CompareAndSwapInt32(&p.receiptIdle, 0, 1) {
		return errAlreadyFetching
	}
	p.receiptStarted = time.Now()

	go func() {
		// Convert the header set to a retrievable slice
		hashes := make([]common.Hash, 0, len(request.Headers))
		for _, header := range request.Headers {
			hashes = append(hashes, header.Hash())
		}
		p.peer.RequestReceipts(hashes)
	}()

	return nil
}

// FetchNodeData sends a node state data retrieval request to the remote peer.
// 获取一系列NodeData
func (p *peerConnection) FetchNodeData(hashes []common.Hash) error {
	// Short circuit if the peer is already fetching
	if !atomic.CompareAndSwapInt32(&p.stateIdle, 0, 1) {
		return errAlreadyFetching
	}
	p.stateStarted = time.Now()

	go p.peer.RequestNodeData(hashes)

	return nil
}

// SetHeadersIdle sets the peer to idle, allowing it to execute new header retrieval
// requests. Its estimated header retrieval throughput is updated with that measured
// just now.
func (p *peerConnection) SetHeadersIdle(delivered int, deliveryTime time.Time) {
	p.rates.Update(eth.BlockHeadersMsg, deliveryTime.Sub(p.headerStarted), delivered)
	atomic.StoreInt32(&p.headerIdle, 0)
}

// SetBodiesIdle sets the peer to idle, allowing it to execute block body retrieval
// requests. Its estimated body retrieval throughput is updated with that measured
// just now.
func (p *peerConnection) SetBodiesIdle(delivered int, deliveryTime time.Time) {
	p.rates.Update(eth.BlockBodiesMsg, deliveryTime.Sub(p.blockStarted), delivered)
	atomic.StoreInt32(&p.blockIdle, 0)
}

// SetReceiptsIdle sets the peer to idle, allowing it to execute new receipt
// retrieval requests. Its estimated receipt retrieval throughput is updated
// with that measured just now.
func (p *peerConnection) SetReceiptsIdle(delivered int, deliveryTime time.Time) {
	p.rates.Update(eth.ReceiptsMsg, deliveryTime.Sub(p.receiptStarted), delivered)
	atomic.StoreInt32(&p.receiptIdle, 0)
}

// SetNodeDataIdle sets the peer to idle, allowing it to execute new state trie
// data retrieval requests. Its estimated state retrieval throughput is updated
// with that measured just now.
func (p *peerConnection) SetNodeDataIdle(delivered int, deliveryTime time.Time) {
	p.rates.Update(eth.NodeDataMsg, deliveryTime.Sub(p.stateStarted), delivered)
	atomic.StoreInt32(&p.stateIdle, 0)
}

// HeaderCapacity retrieves the peers header download allowance based on its
// previously discovered throughput.
// 输入给定的RTT时间,计算应该获取多少条区块头数据
func (p *peerConnection) HeaderCapacity(targetRTT time.Duration) int {
	cap := p.rates.Capacity(eth.BlockHeadersMsg, targetRTT)
	if cap > MaxHeaderFetch {
		cap = MaxHeaderFetch
	}
	return cap
}

// BlockCapacity retrieves the peers block download allowance based on its
// previously discovered throughput.
// 给定RTT时间能够获取多少区块
func (p *peerConnection) BlockCapacity(targetRTT time.Duration) int {
	cap := p.rates.Capacity(eth.BlockBodiesMsg, targetRTT)
	if cap > MaxBlockFetch {
		cap = MaxBlockFetch
	}
	return cap
}

// ReceiptCapacity retrieves the peers receipt download allowance based on its
// previously discovered throughput.
// 给定RTT时间能够获取多少条收据
func (p *peerConnection) ReceiptCapacity(targetRTT time.Duration) int {
	cap := p.rates.Capacity(eth.ReceiptsMsg, targetRTT)
	if cap > MaxReceiptFetch {
		cap = MaxReceiptFetch
	}
	return cap
}

// NodeDataCapacity retrieves the peers state download allowance based on its
// previously discovered throughput.
// 给定RTT时间内能够获取多少条Node Data
func (p *peerConnection) NodeDataCapacity(targetRTT time.Duration) int {
	cap := p.rates.Capacity(eth.NodeDataMsg, targetRTT)
	if cap > MaxStateFetch {
		cap = MaxStateFetch
	}
	return cap
}

// MarkLacking appends a new entity to the set of items (blocks, receipts, states)
// that a peer is known not to have (i.e. have been requested before). If the
// set reaches its maximum allowed capacity, items are randomly dropped off.
// 让p.lacking[hash]=struct{}{}
// 如果保存的p.lacking超过上限,就从中随机删除直到小于上限
func (p *peerConnection) MarkLacking(hash common.Hash) {
	p.lock.Lock()
	defer p.lock.Unlock()

	for len(p.lacking) >= maxLackingHashes {
		for drop := range p.lacking {
			delete(p.lacking, drop)
			break
		}
	}
	// 清空指定的peer
	p.lacking[hash] = struct{}{}
}

// Lacks retrieves whether the hash of a blockchain item is on the peers lacking
// list (i.e. whether we know that the peer does not have it).
// 判断给定hash是不是存在于p.lacking
func (p *peerConnection) Lacks(hash common.Hash) bool {
	p.lock.RLock()
	defer p.lock.RUnlock()

	_, ok := p.lacking[hash]
	return ok
}

// peerSet represents the collection of active peer participating in the chain
// download procedure.
type peerSet struct {
	peers map[string]*peerConnection
	rates *msgrate.Trackers // Set of rate trackers to give the sync a common beat

	// 向多个订阅者发布信息
	newPeerFeed  event.Feed
	peerDropFeed event.Feed

	lock sync.RWMutex
}

// newPeerSet creates a new peer set top track the active download sources.
// 创建新的peerSet
func newPeerSet() *peerSet {
	return &peerSet{
		peers: make(map[string]*peerConnection),
		rates: msgrate.NewTrackers(log.New("proto", "eth")),
	}
}

// SubscribeNewPeers subscribes to peer arrival events.
// 让newPeerFeed增加一个订阅
func (ps *peerSet) SubscribeNewPeers(ch chan<- *peerConnection) event.Subscription {
	return ps.newPeerFeed.Subscribe(ch)
}

// SubscribePeerDrops subscribes to peer departure events.
// 让peerDropFeed增加增加一个订阅
func (ps *peerSet) SubscribePeerDrops(ch chan<- *peerConnection) event.Subscription {
	return ps.peerDropFeed.Subscribe(ch)
}

// Reset iterates over the current peer set, and resets each of the known peers
// to prepare for a next batch of block retrieval.
// 让每个peer调用Reset
func (ps *peerSet) Reset() {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	for _, peer := range ps.peers {
		peer.Reset()
	}
}

// Register injects a new peer into the working set, or returns an error if the
// peer is already known.
//
// The method also sets the starting throughput values of the new peer to the
// average of all existing peers, to give it a realistic chance of being used
// for data retrievals.
// 向peerSet中添加一个peerConnection, 同一个peer重复调用会报错
// 就是将新的peerConnection加入到ps.peers中,并向newPeerFeed发送通知
func (ps *peerSet) Register(p *peerConnection) error {
	// Register the new peer with some meaningful defaults
	ps.lock.Lock()
	// 已经存在的peer再调用Register会报错
	if _, ok := ps.peers[p.id]; ok {
		ps.lock.Unlock()
		return errAlreadyRegistered
	}
	p.rates = msgrate.NewTracker(ps.rates.MeanCapacities(), ps.rates.MedianRoundTrip())
	if err := ps.rates.Track(p.id, p.rates); err != nil {
		return err
	}
	ps.peers[p.id] = p
	ps.lock.Unlock()

	// 向newPeerFeed发送通知
	ps.newPeerFeed.Send(p)
	return nil
}

// Unregister removes a remote peer from the active set, disabling any further
// actions to/from that particular entity.
// 根据peerConnection.id来删除, 不存在的peer调用也会报错
// 删除成功后向peerDropFeed发送通知
func (ps *peerSet) Unregister(id string) error {
	ps.lock.Lock()
	p, ok := ps.peers[id]
	if !ok {
		ps.lock.Unlock()
		return errNotRegistered
	}
	// 直接删除即可
	delete(ps.peers, id)
	ps.rates.Untrack(id)
	ps.lock.Unlock()

	// 向peerDropFeed发送通知
	ps.peerDropFeed.Send(p)
	return nil
}

// Peer retrieves the registered peer with the given id.
// 根据id从peerSet中获取peerConnection
func (ps *peerSet) Peer(id string) *peerConnection {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return ps.peers[id]
}

// Len returns if the current number of peers in the set.
// 获取peerSet的长度
func (ps *peerSet) Len() int {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return len(ps.peers)
}

// AllPeers retrieves a flat list of all the peers within the set.
// 获取peerSet中的所有peerConnection对象
// 保存在peerSet中是以键值对的形式,转化成数组形式返回
func (ps *peerSet) AllPeers() []*peerConnection {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	list := make([]*peerConnection, 0, len(ps.peers))
	for _, p := range ps.peers {
		list = append(list, p)
	}
	return list
}

// HeaderIdlePeers retrieves a flat list of all the currently header-idle peers
// within the active peer set, ordered by their reputation.
// 获取header空闲的节点,按照headerThroughput降序排列
// 第二个返回值是满足协议版本的peer的个数
func (ps *peerSet) HeaderIdlePeers() ([]*peerConnection, int) {
	// 判断给定的peerConnection是不是空闲状态
	// headerIdle为0说明处于空闲状态
	idle := func(p *peerConnection) bool {
		return atomic.LoadInt32(&p.headerIdle) == 0
	}
	throughput := func(p *peerConnection) int {
		return p.rates.Capacity(eth.BlockHeadersMsg, time.Second)
	}
	return ps.idlePeers(eth.ETH66, eth.ETH66, idle, throughput)
}

// BodyIdlePeers retrieves a flat list of all the currently body-idle peers within
// the active peer set, ordered by their reputation.
// 获取block空闲的节点,按照blockThroughput降序排列
func (ps *peerSet) BodyIdlePeers() ([]*peerConnection, int) {
	idle := func(p *peerConnection) bool {
		return atomic.LoadInt32(&p.blockIdle) == 0
	}
	throughput := func(p *peerConnection) int {
		return p.rates.Capacity(eth.BlockBodiesMsg, time.Second)
	}
	return ps.idlePeers(eth.ETH66, eth.ETH66, idle, throughput)
}

// ReceiptIdlePeers retrieves a flat list of all the currently receipt-idle peers
// within the active peer set, ordered by their reputation.
// 获取receipt空闲的节点,按照receiptThroughput降序排列
func (ps *peerSet) ReceiptIdlePeers() ([]*peerConnection, int) {
	idle := func(p *peerConnection) bool {
		return atomic.LoadInt32(&p.receiptIdle) == 0
	}
	throughput := func(p *peerConnection) int {
		return p.rates.Capacity(eth.ReceiptsMsg, time.Second)
	}
	return ps.idlePeers(eth.ETH66, eth.ETH66, idle, throughput)
}

// NodeDataIdlePeers retrieves a flat list of all the currently node-data-idle
// peers within the active peer set, ordered by their reputation.
// 获取stateIdle为0的节点,按照stateThroughput降序排列
func (ps *peerSet) NodeDataIdlePeers() ([]*peerConnection, int) {
	idle := func(p *peerConnection) bool {
		return atomic.LoadInt32(&p.stateIdle) == 0
	}
	throughput := func(p *peerConnection) int {
		return p.rates.Capacity(eth.NodeDataMsg, time.Second)
	}
	return ps.idlePeers(eth.ETH66, eth.ETH66, idle, throughput)
}

// idlePeers retrieves a flat list of all currently idle peers satisfying the
// protocol version constraints, using the provided function to check idleness.
// The resulting set of peers are sorted by their capacity.
// 获取peerSet中所有满足版本要求并且空闲的peer,并且按照throughput降序排列
func (ps *peerSet) idlePeers(minProtocol, maxProtocol uint, idleCheck func(*peerConnection) bool, capacity func(*peerConnection) int) ([]*peerConnection, int) {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	var (
		total = 0
		idle  = make([]*peerConnection, 0, len(ps.peers))
		tps   = make([]int, 0, len(ps.peers))
	)
	for _, p := range ps.peers {
		if p.version >= minProtocol && p.version <= maxProtocol {
			if idleCheck(p) {
				idle = append(idle, p)
				tps = append(tps, capacity(p))
			}
			total++
		}
	}

	// And sort them
	sortPeers := &peerCapacitySort{idle, tps}
	// 按照throughput降序排列
	sort.Sort(sortPeers)
	return sortPeers.p, total
}

// peerCapacitySort implements sort.Interface.
// It sorts peer connections by capacity (descending).
type peerCapacitySort struct {
	p  []*peerConnection
	tp []int
}

func (ps *peerCapacitySort) Len() int {
	return len(ps.p)
}

// 这里tp[i]>tp[j]才返回true
// 说明是要进行根据tp的值降序排列
func (ps *peerCapacitySort) Less(i, j int) bool {
	return ps.tp[i] > ps.tp[j]
}

func (ps *peerCapacitySort) Swap(i, j int) {
	ps.p[i], ps.p[j] = ps.p[j], ps.p[i]
	ps.tp[i], ps.tp[j] = ps.tp[j], ps.tp[i]
}
