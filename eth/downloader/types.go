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

package downloader

import (
	"fmt"

	"github.com/ethereum/go-ethereum/core/types"
)

// peerDropFn is a callback type for dropping a peer detected as malicious.
// 检测到恶意节点后的回调函数
type peerDropFn func(id string)

// dataPack is a data message returned by a peer for some query.
// 节点返回的查询结果接口
// 有headerPack,bodyPack,receiptPack,statePack
type dataPack interface {
	PeerId() string
	Items() int
	Stats() string
}

// headerPack is a batch of block headers returned by a peer.
// 保存查询到的区块头列表
type headerPack struct {
	peerID  string
	headers []*types.Header
}

func (p *headerPack) PeerId() string { return p.peerID }
func (p *headerPack) Items() int     { return len(p.headers) }
func (p *headerPack) Stats() string  { return fmt.Sprintf("%d", len(p.headers)) }

// bodyPack is a batch of block bodies returned by a peer.
// 保存了每个区块对应的交易列表和叔块列表
type bodyPack struct {
	peerID       string
	transactions [][]*types.Transaction
	uncles       [][]*types.Header
}

func (p *bodyPack) PeerId() string { return p.peerID }
// 返回交易或者叔块较少的
func (p *bodyPack) Items() int {
	if len(p.transactions) <= len(p.uncles) {
		return len(p.transactions)
	}
	return len(p.uncles)
}
// x:x,交易数和叔块数
func (p *bodyPack) Stats() string { return fmt.Sprintf("%d:%d", len(p.transactions), len(p.uncles)) }

// receiptPack is a batch of receipts returned by a peer.
// 每个区块代表的收据
type receiptPack struct {
	peerID   string
	receipts [][]*types.Receipt
}

func (p *receiptPack) PeerId() string { return p.peerID }
func (p *receiptPack) Items() int     { return len(p.receipts) }
func (p *receiptPack) Stats() string  { return fmt.Sprintf("%d", len(p.receipts)) }

// statePack is a batch of states returned by a peer.
type statePack struct {
	peerID string
	states [][]byte
}

func (p *statePack) PeerId() string { return p.peerID }
func (p *statePack) Items() int     { return len(p.states) }
func (p *statePack) Stats() string  { return fmt.Sprintf("%d", len(p.states)) }
