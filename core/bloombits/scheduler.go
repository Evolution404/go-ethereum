// Copyright 2017 The go-ethereum Authors
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

package bloombits

import (
	"sync"
)

// request represents a bloom retrieval task to prioritize and pull from the local
// database or remotely from the network.
// 描述针对一个区块段的布隆过滤器的查询信息
type request struct {
	// 要查询的区块段号，用于定位是哪个布隆过滤器
	section uint64 // Section index to retrieve the a bit-vector from
	// 要查询的布隆过滤器的比特位
	bit     uint   // Bit index within the section to retrieve the vector of
}

// response represents the state of a requested bit-vector through a scheduler.
// 描述请求的响应，请求对象与响应对象一一对应
type response struct {
	// 代表查询的结果，是一个长度4096位的位集
	// 将结果保存下来，重复的请求直接返回
	cached []byte        // Cached bits to dedup multiple requests
	// 响应到达关闭done管道，通知外部数据到达
	done   chan struct{} // Channel to allow waiting for completion
}

// scheduler handles the scheduling of bloom-filter retrieval operations for
// entire section-batches belonging to a single bloom bit. Beside scheduling the
// retrieval operations, this struct also deduplicates the requests and caches
// the results to minimize network/database overhead even in complex filtering
// scenarios.
// 一个scheduler对象用于调度针对布隆过滤器的某一个比特位的所有查询
type scheduler struct {
	// 当前scheduler对象负责处理的布隆过滤器的比特位
	bit       uint                 // Index of the bit in the bloom filter this scheduler is responsible for
	// 区块段号=>响应，保存各个区块段的查询的结果
	responses map[uint64]*response // Currently pending retrieval requests or already cached responses
	// 用于保护responses变量的锁
	lock      sync.Mutex           // Lock protecting the responses from concurrent access
}

// newScheduler creates a new bloom-filter retrieval scheduler for a specific
// bit index.
// 创建调度器对象，需要传入这个调度器对象需要负责的布隆过滤器比特位
func newScheduler(idx uint) *scheduler {
	return &scheduler{
		bit:       idx,
		responses: make(map[uint64]*response),
	}
}

// run creates a retrieval pipeline, receiving section indexes from sections and
// returning the results in the same order through the done channel. Concurrent
// runs of the same scheduler are allowed, leading to retrieval task deduplication.
// 调度器的启动函数
// 从sections管道接收各个要被查询的区块段号，然后将查询到的位集发送到done管道
func (s *scheduler) run(sections chan uint64, dist chan *request, done chan []byte, quit chan struct{}, wg *sync.WaitGroup) {
	// Create a forwarder channel between requests and responses of the same size as
	// the distribution channel (since that will block the pipeline anyway).
	pend := make(chan uint64, cap(dist))

	// Start the pipeline schedulers to forward between user -> distributor -> user
	wg.Add(2)
	go s.scheduleRequests(sections, dist, pend, quit, wg)
	go s.scheduleDeliveries(pend, done, quit, wg)
}

// reset cleans up any leftovers from previous runs. This is required before a
// restart to ensure the no previously requested but never delivered state will
// cause a lockup.
func (s *scheduler) reset() {
	s.lock.Lock()
	defer s.lock.Unlock()

	for section, res := range s.responses {
		if res.cached == nil {
			delete(s.responses, section)
		}
	}
}

// scheduleRequests reads section retrieval requests from the input channel,
// deduplicates the stream and pushes unique retrieval tasks into the distribution
// channel for a database or network layer to honour.
// 从reqs管道接收请求,对请求去重后发送到dist中
// 发送到dist和pend管道中的数据一一对应
func (s *scheduler) scheduleRequests(reqs chan uint64, dist chan *request, pend chan uint64, quit chan struct{}, wg *sync.WaitGroup) {
	// Clean up the goroutine and pipeline when done
	defer wg.Done()
	defer close(pend)

	// Keep reading and scheduling section requests
	for {
		select {
		case <-quit:
			return

		// 监听reqs的输入
		case section, ok := <-reqs:
			// New section retrieval requested
			// 请求管道已经关闭,直接结束函数
			if !ok {
				return
			}
			// Deduplicate retrieval requests
			// 用于标识是否是新的请求
			unique := false

			s.lock.Lock()
			if s.responses[section] == nil {
				s.responses[section] = &response{
					done: make(chan struct{}),
				}
				unique = true
			}
			s.lock.Unlock()

			// Schedule the section for retrieval and notify the deliverer to expect this section
			// 向dist和pend管道发送数据
			if unique {
				select {
				case <-quit:
					return
				case dist <- &request{bit: s.bit, section: section}:
				}
			}
			select {
			case <-quit:
				return
			case pend <- section:
			}
		}
	}
}

// scheduleDeliveries reads section acceptance notifications and waits for them
// to be delivered, pushing them into the output data buffer.
// pend管道代表查询任务,等待查询任务结束向done管道发送查询结果
func (s *scheduler) scheduleDeliveries(pend chan uint64, done chan []byte, quit chan struct{}, wg *sync.WaitGroup) {
	// Clean up the goroutine and pipeline when done
	defer wg.Done()
	defer close(done)

	// Keep reading notifications and scheduling deliveries
	for {
		select {
		case <-quit:
			return

		// 监听pend管道,每收到一项代表有一个查询请求已经发出
		case idx, ok := <-pend:
			// New section retrieval pending
			if !ok {
				return
			}
			// Wait until the request is honoured
			s.lock.Lock()
			res := s.responses[idx]
			s.lock.Unlock()
			// 等待查询完成
			select {
			case <-quit:
				return
			case <-res.done:
			}
			// Deliver the result
			// 将查询数据发送到done管道
			select {
			case <-quit:
				return
			case done <- res.cached:
			}
		}
	}
}

// deliver is called by the request distributor when a reply to a request arrives.
// sections[i]对应data[i]
// 交付sections里面各个部分的数据
func (s *scheduler) deliver(sections []uint64, data [][]byte) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for i, section := range sections {
		if res := s.responses[section]; res != nil && res.cached == nil { // Avoid non-requests and double deliveries
			// 将数据保存下来
			res.cached = data[i]
			// 通知scheduleDeliveries数据已经到达
			close(res.done)
		}
	}
}
