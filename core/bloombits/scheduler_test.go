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
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Tests that the scheduler can deduplicate and forward retrieval requests to
// underlying fetchers and serve responses back, irrelevant of the concurrency
// of the requesting clients or serving data fetchers.
func TestSchedulerSingleClientSingleFetcher(t *testing.T) { testScheduler(t, 1, 1, 5000) }
func TestSchedulerSingleClientMultiFetcher(t *testing.T)  { testScheduler(t, 1, 10, 5000) }
func TestSchedulerMultiClientSingleFetcher(t *testing.T)  { testScheduler(t, 10, 1, 5000) }
func TestSchedulerMultiClientMultiFetcher(t *testing.T)   { testScheduler(t, 10, 10, 5000) }

func testScheduler(t *testing.T, clients int, fetchers int, requests int) {
	t.Parallel()
	// 所有测试的调度器都负责0比特位
	f := newScheduler(0)

	// Create a batch of handler goroutines that respond to bloom bit requests and
	// deliver them to the scheduler.
	var fetchPend sync.WaitGroup
	fetchPend.Add(fetchers)
	defer fetchPend.Wait()

	fetch := make(chan *request, 16)
	defer close(fetch)

	var delivered uint32
	for i := 0; i < fetchers; i++ {
		go func() {
			defer fetchPend.Done()

			for req := range fetch {
				time.Sleep(time.Duration(rand.Intn(int(100 * time.Microsecond))))
				atomic.AddUint32(&delivered, 1)

				f.deliver([]uint64{
					req.section + uint64(requests), // Non-requested data (ensure it doesn't go out of bounds)
					req.section,                    // Requested data
					req.section,                    // Duplicated data (ensure it doesn't double close anything)
				}, [][]byte{
					{},
					new(big.Int).SetUint64(req.section).Bytes(),
					new(big.Int).SetUint64(req.section).Bytes(),
				})
			}
		}()
	}
	// Start a batch of goroutines to concurrently run scheduling tasks
	quit := make(chan struct{})

	var pend sync.WaitGroup
	pend.Add(clients)

	for i := 0; i < clients; i++ {
		go func() {
			defer pend.Done()

			in := make(chan uint64, 16)
			out := make(chan []byte, 16)

			f.run(in, fetch, out, quit, &pend)

			go func() {
				for j := 0; j < requests; j++ {
					in <- uint64(j)
				}
				close(in)
			}()
			b := new(big.Int)
			for j := 0; j < requests; j++ {
				bits := <-out
				if want := b.SetUint64(uint64(j)).Bytes(); !bytes.Equal(bits, want) {
					t.Errorf("vector %d: delivered content mismatch: have %x, want %x", j, bits, want)
				}
			}
		}()
	}
	pend.Wait()

	if have := atomic.LoadUint32(&delivered); int(have) != requests {
		t.Errorf("request count mismatch: have %v, want %v", have, requests)
	}
}

func TestMyScheduler(t *testing.T) {
	// 负责0比特位的调度器
	s := newScheduler(0)

	// 客户端和服务器所需要的管道
	sections := make(chan uint64)
	dist := make(chan *request)
	done := make(chan []byte)

	var wg sync.WaitGroup

	// 启动客户端
	go func() {
		var i uint64
		// 发送9次请求,并接收查询结果
		for i = 1; i < 10; i++ {
			// 9次不同的请求
			// sections <- i
			// 9次相同的请求
			sections <- 10
			fmt.Println(<-done)
		}
		// 结束关闭sections管道
		close(sections)
	}()
	// 启动服务端，每接收一个请求就提交一次结果，结果就是请求的区块段号
	go func() {
		for req := range dist {
			fmt.Println("server search")
			s.deliver([]uint64{req.section}, [][]byte{new(big.Int).SetUint64(req.section).Bytes()})
		}
	}()
	s.run(sections, dist, done, nil, &wg)
	wg.Wait()
}
