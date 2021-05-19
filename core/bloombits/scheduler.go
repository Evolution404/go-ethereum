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
// 代表了一次查询请求
type request struct {
	// 第几个section
	section uint64 // Section index to retrieve the a bit-vector from
	// section中的第几个比特
	bit     uint   // Bit index within the section to retrieve the vector of
}

// response represents the state of a requested bit-vector through a scheduler.
// request与response一一对应
type response struct {
	// 缓存查询结果,最长4096位(512字节)保存每个块指定比特位的结果
	cached []byte        // Cached bits to dedup multiple requests
	done   chan struct{} // Channel to allow waiting for completion
}

// scheduler handles the scheduling of bloom-filter retrieval operations for
// entire section-batches belonging to a single bloom bit. Beside scheduling the
// retrieval operations, this struct also deduplicates the requests and caches
// the results to minimize network/database overhead even in complex filtering
// scenarios.
// 将所有查询同一个比特位的section集合起来
type scheduler struct {
	bit       uint                 // Index of the bit in the bloom filter this scheduler is responsible for
	// 要查询的section=>response
	responses map[uint64]*response // Currently pending retrieval requests or already cached responses
	lock      sync.Mutex           // Lock protecting the responses from concurrent access
}

// newScheduler creates a new bloom-filter retrieval scheduler for a specific
// bit index.
// 指定比特位的scheduler
func newScheduler(idx uint) *scheduler {
	return &scheduler{
		bit:       idx,
		responses: make(map[uint64]*response),
	}
}

// run creates a retrieval pipeline, receiving section indexes from sections and
// returning the results in the same order through the done channel. Concurrent
// runs of the same scheduler are allowed, leading to retrieval task deduplication.
// sections管道向内输入要查询的section
// done与输入的section一一对应,将查询结果输出到done中
// dist代表真正的查询操作,重复的section只会向dist发送一次
func (s *scheduler) run(sections chan uint64, dist chan *request, done chan []byte, quit chan struct{}, wg *sync.WaitGroup) {
	// Create a forwarder channel between requests and responses of the same size as
	// the distribution channel (since that will block the pipeline anyway).
	pend := make(chan uint64, cap(dist))

	// Start the pipeline schedulers to forward between user -> distributor -> user
	// 增加等待两个协程
	// 以下两个方法内部都将调用wg.Done()
	wg.Add(2)
	go s.scheduleRequests(sections, dist, pend, quit, wg)
	go s.scheduleDeliveries(pend, done, quit, wg)
}

// reset cleans up any leftovers from previous runs. This is required before a
// restart to ensure the no previously requested but never delivered state will
// cause a lockup.
// 清空所有没有缓存的response
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
// 安排一次请求,并进行去重
// reqs: 外部向这里发送要查询的section
// dist: 该函数向dist发送request对象,重复的request对象不会被发送
// pend: 与reqs一一对应,每次从reqs收到section都会发送到pend中
func (s *scheduler) scheduleRequests(reqs chan uint64, dist chan *request, pend chan uint64, quit chan struct{}, wg *sync.WaitGroup) {
	// Clean up the goroutine and pipeline when done
	defer wg.Done()
	defer close(pend)

	// Keep reading and scheduling section requests
	for {
		select {
		case <-quit:
			return

		case section, ok := <-reqs:
			// New section retrieval requested
			if !ok {
				return
			}
			// Deduplicate retrieval requests
			// 是否与之前的查询重复
			unique := false

			s.lock.Lock()
			// 是nil的话说明之前没有查询过这个section
			if s.responses[section] == nil {
				// 第一次查询,在scheduler里面初始化一个response
				s.responses[section] = &response{
					done: make(chan struct{}),
				}
				unique = true
			}
			s.lock.Unlock()

			// Schedule the section for retrieval and notify the deliverer to expect this section
			// 向dist发送request,应该是在接收dist的地方进行真正的查询操作
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
// 从pend接收,并将查询结果发送到done中
func (s *scheduler) scheduleDeliveries(pend chan uint64, done chan []byte, quit chan struct{}, wg *sync.WaitGroup) {
	// Clean up the goroutine and pipeline when done
	defer wg.Done()
	defer close(done)

	// Keep reading notifications and scheduling deliveries
	for {
		select {
		case <-quit:
			return

		case idx, ok := <-pend:
			// New section retrieval pending
			if !ok {
				return
			}
			// Wait until the request is honoured
			s.lock.Lock()
			res := s.responses[idx]
			s.lock.Unlock()

			// res.done阻塞结束说明这次请求完成
			select {
			case <-quit:
				return
			case <-res.done:
			}
			// Deliver the result
			// 读取完成将结果写入done管道
			select {
			case <-quit:
				return
			case done <- res.cached:
			}
		}
	}
}

// deliver is called by the request distributor when a reply to a request arrives.
// 用于与上一个函数配合
// 当查询操作完成后,调用这个函数修改scheduler中的responses来通知scheduleDeliveries
func (s *scheduler) deliver(sections []uint64, data [][]byte) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for i, section := range sections {
		if res := s.responses[section]; res != nil && res.cached == nil { // Avoid non-requests and double deliveries
			res.cached = data[i]
			close(res.done)
		}
	}
}
