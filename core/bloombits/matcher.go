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
	"context"
	"errors"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common/bitutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// bloomIndexes represents the bit indexes inside the bloom filter that belong
// to some key.
// 三个整数代表要查询布隆过滤器的比特位
type bloomIndexes [3]uint

// calcBloomIndexes returns the bloom filter bit indexes belonging to the given key.
func calcBloomIndexes(b []byte) bloomIndexes {
	b = crypto.Keccak256(b)

	var idxs bloomIndexes
	for i := 0; i < len(idxs); i++ {
		// (uint(b[2*i])<<8)&2047 最大1792
		// uint(b[2*i+1]) 最大255
		// 所以相加最大2047,正好在[0-2047]比特位之间
		// 比特位置就是 b[0]的后三位和b[1]的八位拼在一起
		idxs[i] = (uint(b[2*i])<<8)&2047 + uint(b[2*i+1])
	}
	return idxs
}

// partialMatches with a non-nil vector represents a section in which some sub-
// matchers have already found potential matches. Subsequent sub-matchers will
// binary AND their matches with this vector. If vector is nil, it represents a
// section to be processed by the first sub-matcher.
// 保存某个section流水线的中间状态
// 如果bitset所有位都是0,这个流水线就可以立刻结束
type partialMatches struct {
	section uint64
	// 长度4096位(512字节)
	// 第n位比特位为1:代表经过当前的几个filter过滤后这个section的第n个块都成功通过
	bitset  []byte
}

// Retrieval represents a request for retrieval task assignments for a given
// bit with the given number of fetch elements, or a response for such a request.
// It can also have the actual results set to be used as a delivery data struct.
//
// The contest and error fields are used by the light client to terminate matching
// early if an error is encountered on some path of the pipeline.
// 代表一次布隆过滤器检索工作
type Retrieval struct {
	Bit      uint
	Sections []uint64
	Bitsets  [][]byte

	Context context.Context
	Error   error
}

// Matcher is a pipelined system of schedulers and logic matchers which perform
// binary AND/OR operations on the bit-streams, creating a stream of potential
// blocks to inspect for data content.
type Matcher struct {
	sectionSize uint64 // Size of the data batches to filter on

	// 保存了三数字类型的filters
	filters    [][]bloomIndexes    // Filter the system is matching for
	// 要查询的比特位=>schedulers
	schedulers map[uint]*scheduler // Retrieval schedulers for loading bloom bits

	retrievers chan chan uint       // Retriever processes waiting for bit allocations
	counters   chan chan uint       // Retriever processes waiting for task count reports
	retrievals chan chan *Retrieval // Retriever processes waiting for task allocations
	deliveries chan *Retrieval      // Retriever processes waiting for task response deliveries

	running uint32 // Atomic flag whether a session is live or not
}

// NewMatcher creates a new pipeline for retrieving bloom bit streams and doing
// address and topic filtering on them. Setting a filter component to `nil` is
// allowed and will result in that filter rule being skipped (OR 0x11...1).
// 设地址为ax,topic为tx, filters[i]称为filter
// filters的格式为 [ [a1,a2,a3], [t11,t12], [t21,t22,t23]]
// 只有filters[0]保存了地址列表,后面都是topic列表
// 满足filters的条件是每个filter中的值都至少被找到一个
// 输入filters生成一个Matcher
//   1. 将原始filters转换成三数字类型的filters
//   2. filters可以得到需要查询的比特位,每个比特位生成一个scheduler
func NewMatcher(sectionSize uint64, filters [][][]byte) *Matcher {
	// Create the matcher instance
	m := &Matcher{
		sectionSize: sectionSize,
		schedulers:  make(map[uint]*scheduler),
		retrievers:  make(chan chan uint),
		counters:    make(chan chan uint),
		retrievals:  make(chan chan *Retrieval),
		deliveries:  make(chan *Retrieval),
	}
	// Calculate the bloom bit indexes for the groups we're interested in
	m.filters = nil

	for _, filter := range filters {
		// Gather the bit indexes of the filter rule, special casing the nil filter
		if len(filter) == 0 {
			continue
		}
		// filter内保存的是地址或哈希的列表
		// 首先要将他们转换成三个数字代表的布隆过滤器位置
		// bloomBits与filter一一对应
		bloomBits := make([]bloomIndexes, len(filter))
		for i, clause := range filter {
			if clause == nil {
				bloomBits = nil
				break
			}
			bloomBits[i] = calcBloomIndexes(clause)
		}
		// Accumulate the filter rules if no nil rule was within
		// 加入到Matcher.filters里面
		if bloomBits != nil {
			m.filters = append(m.filters, bloomBits)
		}
	}
	// For every bit, create a scheduler to load/download the bit vectors
	// 每个比特位生成一个scheduler
	//     filter
	for _, bloomIndexLists := range m.filters {
		//     三数字
		for _, bloomIndexList := range bloomIndexLists {
			//     单个数字
			for _, bloomIndex := range bloomIndexList {
				m.addScheduler(bloomIndex)
			}
		}
	}
	return m
}

// addScheduler adds a bit stream retrieval scheduler for the given bit index if
// it has not existed before. If the bit is already selected for filtering, the
// existing scheduler can be used.
// idx是布隆过滤器的比特位
// 创建新的查询idx位置的scheduler
func (m *Matcher) addScheduler(idx uint) {
	if _, ok := m.schedulers[idx]; ok {
		return
	}
	m.schedulers[idx] = newScheduler(idx)
}

// Start starts the matching process and returns a stream of bloom matches in
// a given range of blocks. If there are no more matches in the range, the result
// channel is closed.
// 查询begin到end块, 查询到的块号写入到results中
func (m *Matcher) Start(ctx context.Context, begin, end uint64, results chan uint64) (*MatcherSession, error) {
	// Make sure we're not creating concurrent sessions
	// 存入新的值并且读取原来的值
	if atomic.SwapUint32(&m.running, 1) == 1 {
		return nil, errors.New("matcher already running")
	}
	defer atomic.StoreUint32(&m.running, 0)

	// Initiate a new matching round
	session := &MatcherSession{
		matcher: m,
		quit:    make(chan struct{}),
		ctx:     ctx,
	}
	for _, scheduler := range m.schedulers {
		scheduler.reset()
	}
	// results管道有多少容量,就给查询管道开多少容量
	// sink管道接收流水线的最终结果
	sink := m.run(begin, end, cap(results), session)

	// Read the output from the result sink and deliver to the user
	// 等待下面的协程执行完毕
	session.pend.Add(1)
	go func() {
		defer session.pend.Done()
		defer close(results)

		for {
			select {
			case <-session.quit:
				return

			// sink管道内得到流水线的最终结果
			case res, ok := <-sink:
				// New match result found
				if !ok {
					return
				}
				// Calculate the first and last blocks of the section
				// 从section号转换为具体的区块开始结束位置
				sectionStart := res.section * m.sectionSize

				first := sectionStart
				if begin > first {
					first = begin
				}
				last := sectionStart + m.sectionSize - 1
				if end < last {
					last = end
				}
				// Iterate over all the blocks in the section and return the matching ones
				for i := first; i <= last; i++ {
					// Skip the entire byte if no matches are found inside (and we're processing an entire byte!)
					next := res.bitset[(i-sectionStart)/8]
					// 字节为0代表8个位都是0,直接跳过当前字节,简单的优化
					if next == 0 {
						if i%8 == 0 {
							i += 7
						}
						continue
					}
					// Some bit it set, do the actual submatching
					// 判断第i位是不是1
					if bit := 7 - i%8; next&(1<<bit) != 0 {
						select {
						case <-session.quit:
							return
						// 第i位是1,发送块号到results中
						case results <- i:
						}
					}
				}
			}
		}
	}()
	return session, nil
}

// run creates a daisy-chain of sub-matchers, one for the address set and one
// for each topic set, each sub-matcher receiving a section only if the previous
// ones have all found a potential match in one of the blocks of the section,
// then binary AND-ing its own matches and forwarding the result to the next one.
//
// The method starts feeding the section indexes into the first sub-matcher on a
// new goroutine and returns a sink channel receiving the results.
// buffer代表查询管道的缓存
func (m *Matcher) run(begin, end uint64, buffer int, session *MatcherSession) chan *partialMatches {
	// Create the source channel and feed section indexes into
	source := make(chan *partialMatches, buffer)

	session.pend.Add(1)
	go func() {
		defer session.pend.Done()
		defer close(source)

		// 每个section一条流水线,每次经过一个filter都会对partialMatches进行修改
		for i := begin / m.sectionSize; i <= end/m.sectionSize; i++ {
			select {
			case <-session.quit:
				return
				// bitset初始化为全1,代表初始时候section内的4096个块都都是1
			case source <- &partialMatches{i, bytes.Repeat([]byte{0xff}, int(m.sectionSize/8))}:
			}
		}
	}()
	// Assemble the daisy-chained filtering pipeline
	next := source
	dist := make(chan *request, buffer)

	for _, bloom := range m.filters {
		// 每次处理一个filter
		next = m.subMatch(next, dist, bloom, session)
	}
	// Start the request distribution
	session.pend.Add(1)
	go m.distributor(dist, session)

	return next
}

// subMatch creates a sub-matcher that filters for a set of addresses or topics, binary OR-s those matches, then
// binary AND-s the result to the daisy-chain input (source) and forwards it to the daisy-chain output.
// The matches of each address/topic are calculated by fetching the given sections of the three bloom bit indexes belonging to
// that address/topic, and binary AND-ing those vectors together.
// bloom代表一个filter,一个subMatch对应一个filter
// subMatch让所有流水线,通过这个filter
func (m *Matcher) subMatch(source chan *partialMatches, dist chan *request, bloom []bloomIndexes, session *MatcherSession) chan *partialMatches {
	// Start the concurrent schedulers for each bit required by the bloom filter
	// sectionSources输入要查询的section
	// sectionSources[i][j]用来发送: filter中第i个条件第j个比特要查询的section
	sectionSources := make([][3]chan uint64, len(bloom))
	// sectionSinks接收查询结果
	// sectionSinks[i][j]用来接收: filter中第i个条件第j个比特的查询结果
	sectionSinks := make([][3]chan []byte, len(bloom))
	for i, bits := range bloom {
		for j, bit := range bits {
			sectionSources[i][j] = make(chan uint64, cap(source))
			sectionSinks[i][j] = make(chan []byte, cap(source))

			m.schedulers[bit].run(sectionSources[i][j], dist, sectionSinks[i][j], session.quit, &session.pend)
		}
	}

	// 每从source中接收一个partialMatches,就再写入process中
	process := make(chan *partialMatches, cap(source)) // entries from source are forwarded here after fetches have been initiated
	// 从process读取后最终再写入results,写入这个管道里的流水线进入下一个filter
	results := make(chan *partialMatches, cap(source))

	// 下面有两个协程
	session.pend.Add(2)
	go func() {
		// Tear down the goroutine and terminate all source channels
		defer session.pend.Done()
		defer close(process)

		defer func() {
			for _, bloomSources := range sectionSources {
				for _, bitSource := range bloomSources {
					close(bitSource)
				}
			}
		}()
		// Read sections from the source channel and multiplex into all bit-schedulers
		for {
			select {
			case <-session.quit:
				return

			// 遍历流水线
			case subres, ok := <-source:
				// New subresult from previous link
				if !ok {
					return
				}
				// Multiplex the section index to all bit-schedulers
				// 收到要section后,发送section位置进行查询
				for _, bloomSources := range sectionSources {
					for _, bitSource := range bloomSources {
						select {
						case <-session.quit:
							return
						// 写入section后会驱动schedulers.run运行
						case bitSource <- subres.section:
						}
					}
				}
				// Notify the processor that this section will become available
				// source管道里面被读取过了,重新写入process管道进行接下来的处理
				select {
				case <-session.quit:
					return
				case process <- subres:
				}
			}
		}
	}()

	go func() {
		// Tear down the goroutine and terminate the final sink channel
		defer session.pend.Done()
		defer close(results)

		// Read the source notifications and collect the delivered results
		for {
			select {
			case <-session.quit:
				return

			// 从process管道接收流水线中间状态
			case subres, ok := <-process:
				// Notified of a section being retrieved
				if !ok {
					return
				}
				// Gather all the sub-results and merge them together
				var orVector []byte
				// 将每个条件进行的查询结果进行或运算
				for _, bloomSinks := range sectionSinks {
					var andVector []byte
					// 内部的for循环将每个条件查询的三个比特位进行与运算
					for _, bitSink := range bloomSinks {
						var data []byte
						select {
						case <-session.quit:
							return
						case data = <-bitSink:
						}
						// 每查到一个比特位进行一次与,因为三个比特位都为1才代表在这个块中
						if andVector == nil {
							andVector = make([]byte, int(m.sectionSize/8))
							copy(andVector, data)
						} else {
							bitutil.ANDBytes(andVector, andVector, data)
						}
					}
					// 对每个条件的结果进行或,这些条件只要满足一个即可
					if orVector == nil {
						orVector = andVector
					} else {
						bitutil.ORBytes(orVector, orVector, andVector)
					}
				}
				// 当前filter没有条件,默认所有块都不通过
				if orVector == nil {
					orVector = make([]byte, int(m.sectionSize/8))
				}
				// 中间状态和当前filter的结果进行与运算,流水线进入下一个filter
				if subres.bitset != nil {
					bitutil.ANDBytes(orVector, orVector, subres.bitset)
				}
				// 只有有非零位的流水线才有继续进行的必要
				if bitutil.TestBytes(orVector) {
					select {
					case <-session.quit:
						return
					case results <- &partialMatches{subres.section, orVector}:
					}
				}
			}
		}
	}()
	return results
}

// distributor receives requests from the schedulers and queues them into a set
// of pending requests, which are assigned to retrievers wanting to fulfil them.
func (m *Matcher) distributor(dist chan *request, session *MatcherSession) {
	defer session.pend.Done()

	var (
		// requests: 比特位=>要查询的section列表,根据section的大小排序
		requests   = make(map[uint][]uint64) // Per-bit list of section requests, ordered by section number
		// 从dist中接收完成,还没有派发给retriever的请求
		unallocs   = make(map[uint]struct{}) // Bits with pending requests but not allocated to any retriever
		retrievers chan chan uint            // Waiting retrievers (toggled to nil if unallocs is empty)
		// 被分配查询比特位任务的个数,一个section查询一个比特位代表一个任务
		// 为了维护allocs最终为0,allocateRetrieval与deliverSections调用是一一对应
		allocs     int                       // Number of active allocations to handle graceful shutdown requests
		shutdown   = session.quit            // Shutdown request channel, will gracefully wait for pending requests
	)

	// assign is a helper method fo try to assign a pending bit an actively
	// listening servicer, or schedule it up for later when one arrives.
	assign := func(bit uint) {
		// 如果有空闲的retrievers直接分配当前比特位任务
		select {
		case fetcher := <-m.retrievers:
			allocs++
			fetcher <- bit
		// 没有空闲的retriever,加入unallocs中,让下面的事件监听处理
		default:
			// No retrievers active, start listening for new ones
			retrievers = m.retrievers
			unallocs[bit] = struct{}{}
		}
	}

	// 1. req:= <-dist
	//   所有请求首先从dist中读取,写入requests中
	//   所有任务在requests中根据查询的比特位不同,分为若干个比特位任务
	// 2. fetcher := <-retrievers
	//   每个retriever将会被分配一个比特位任务,向所有需要查询这个比特位的section进行查询操作
	//   调用allocateRetrieval就会从requests中派发一个比特位的任务
	// 3. fetcher := <-m.retrievals
	//   retriever只得到了被派发的比特位,通过这个管道可以获取指定长度的section列表进行查询
	for {
		select {
		case <-shutdown:
			// Shutdown requested. No more retrievers can be allocated,
			// but we still need to wait until all pending requests have returned.
			shutdown = nil
			if allocs == 0 {
				return
			}

		case req := <-dist:
			// New retrieval request arrived to be distributed to some fetcher process
			// 向requests[req.bit]数组按照升序插入req.section
			queue := requests[req.bit]
			index := sort.Search(len(queue), func(i int) bool { return queue[i] >= req.section })
			requests[req.bit] = append(queue[:index], append([]uint64{req.section}, queue[index:]...)...)

			// If it's a new bit and we have waiting fetchers, allocate to them
			// 第一次遇到这个比特位调用assign
			if len(queue) == 0 {
				assign(req.bit)
			}

		case fetcher := <-retrievers:
			// New retriever arrived, find the lowest section-ed bit to assign
			// 派发一个比特位,选取的是第一个任务section最小的那个比特位
			bit, best := uint(0), uint64(math.MaxUint64)
			for idx := range unallocs {
				if requests[idx][0] < best {
					bit, best = idx, requests[idx][0]
				}
			}
			// Stop tracking this bit (and alloc notifications if no more work is available)
			delete(unallocs, bit)
			if len(unallocs) == 0 {
				// 设置为nil之后,这个retrievers分支就相当于被禁用
				retrievers = nil
			}
			allocs++
			fetcher <- bit

		// pendingSections先向counters管道发送fetcher,然后立刻向fetcher发送要查询的比特位
		case fetcher := <-m.counters:
			// New task count request arrives, return number of items
			// 得到指定比特位的请求个数,重新发送到fetcher
			fetcher <- uint(len(requests[<-fetcher]))

		case fetcher := <-m.retrievals:
			// New fetcher waiting for tasks to retrieve, assign
			// 接收从allocateSections发送来的Retrieval对象
			task := <-fetcher
			// 要查询的长度大于当前剩余的长度,直接返回当前列表
			if want := len(task.Sections); want >= len(requests[task.Bit]) {
				task.Sections = requests[task.Bit]
				// 当前比特位的请求都已经被查询了,直接清空
				delete(requests, task.Bit)
			} else {
				// 从requests中取前want个
				task.Sections = append(task.Sections[:0], requests[task.Bit][:want]...)
				// 去掉requests中被取回的
				requests[task.Bit] = append(requests[task.Bit][:0], requests[task.Bit][want:]...)
			}
			// 将查询结果返回
			fetcher <- task

			// If anything was left unallocated, try to assign to someone else
			if len(requests[task.Bit]) > 0 {
				assign(task.Bit)
			}

		// deliveries管道通过deliverSections函数写入了最终的查询结果
		case result := <-m.deliveries:
			// New retrieval task response from fetcher, split out missing sections and
			// deliver complete ones
			var (
				sections = make([]uint64, 0, len(result.Sections))
				bitsets  = make([][]byte, 0, len(result.Bitsets))
				missing  = make([]uint64, 0, len(result.Sections))
			)
			for i, bitset := range result.Bitsets {
				if len(bitset) == 0 {
					missing = append(missing, result.Sections[i])
					// 查询结果长度是0的不放到最终结果中
					continue
				}
				sections = append(sections, result.Sections[i])
				bitsets = append(bitsets, bitset)
			}
			// 这个比特位任务顺利完成
			m.schedulers[result.Bit].deliver(sections, bitsets)
			allocs--

			// Reschedule missing sections and allocate bit if newly available
			if len(missing) > 0 {
				queue := requests[result.Bit]
				// 把没有查到结果的section号重新加入到requests中
				for _, section := range missing {
					index := sort.Search(len(queue), func(i int) bool { return queue[i] >= section })
					// 在index位置向queue插入section
					queue = append(queue[:index], append([]uint64{section}, queue[index:]...)...)
				}
				requests[result.Bit] = queue

				// 长度相等说明之前的retriever已经读取了所有requests
				// 需要重新安排一个retriever
				if len(queue) == len(missing) {
					assign(result.Bit)
				}
			}

			// End the session when all pending deliveries have arrived.
			if shutdown == nil && allocs == 0 {
				return
			}
		}
	}
}

// MatcherSession is returned by a started matcher to be used as a terminator
// for the actively running matching operation.
// 调用Matcher.Start后返回MatcherSession对象
// 可以使用MatcherSession.Close方法来终止查询过程
type MatcherSession struct {
	matcher *Matcher

	// sync.Once类型能保证closer.Do(f)内的函数f只被执行一次
	// closer和quit共同实现Close函数
	closer sync.Once     // Sync object to ensure we only ever close once
	quit   chan struct{} // Quit channel to request pipeline termination

	ctx context.Context // Context used by the light client to abort filtering
	err atomic.Value    // Global error to track retrieval failures deep in the chain

	pend sync.WaitGroup
}

// Close stops the matching process and waits for all subprocesses to terminate
// before returning. The timeout may be used for graceful shutdown, allowing the
// currently running retrievals to complete before this time.
// 关闭quit管道,并等待所有子线程完成工作正常结束
func (s *MatcherSession) Close() {
	s.closer.Do(func() {
		// Signal termination and wait for all goroutines to tear down
		close(s.quit)
		s.pend.Wait()
	})
}

// Error returns any failure encountered during the matching session.
func (s *MatcherSession) Error() error {
	if err := s.err.Load(); err != nil {
		return err.(error)
	}
	return nil
}

// 先调用allocateRetrieval
// 再调用allocateSections
// 中间过程会调用pendingSections来查询还剩余多少section

// allocateRetrieval assigns a bloom bit index to a client process that can either
// immediately request and fetch the section contents assigned to this bit or wait
// a little while for more sections to be requested.
func (s *MatcherSession) allocateRetrieval() (uint, bool) {
	fetcher := make(chan uint)

	select {
	case <-s.quit:
		return 0, false
		// 向retrievers写入fetcher
	case s.matcher.retrievers <- fetcher:
		bit, ok := <-fetcher
		return bit, ok
	}
}

// pendingSections returns the number of pending section retrievals belonging to
// the given bloom bit index.
// 查询给定的比特位有多少请求
func (s *MatcherSession) pendingSections(bit uint) int {
	fetcher := make(chan uint)

	select {
	case <-s.quit:
		return 0
	case s.matcher.counters <- fetcher:
		fetcher <- bit
		// distributor函数里的接收方读取比特位后再写入fetcher结果
		return int(<-fetcher)
	}
}

// allocateSections assigns all or part of an already allocated bit-task queue
// to the requesting process.
// bit=>查询的比特位 count=>执行查询的section个数
// 返回查询这个比特位的section列表
func (s *MatcherSession) allocateSections(bit uint, count int) []uint64 {
	fetcher := make(chan *Retrieval)

	select {
	case <-s.quit:
		return nil
	case s.matcher.retrievals <- fetcher:
		task := &Retrieval{
			Bit:      bit,
			Sections: make([]uint64, count),
		}
		fetcher <- task
		return (<-fetcher).Sections
	}
}

// deliverSections delivers a batch of section bit-vectors for a specific bloom
// bit index to be injected into the processing pipeline.
// 完成了一个完整的比特位任务后调用
func (s *MatcherSession) deliverSections(bit uint, sections []uint64, bitsets [][]byte) {
	s.matcher.deliveries <- &Retrieval{Bit: bit, Sections: sections, Bitsets: bitsets}
}

// Multiplex polls the matcher session for retrieval tasks and multiplexes it into
// the requested retrieval queue to be serviced together with other sessions.
//
// This method will block for the lifetime of the session. Even after termination
// of the session, any request in-flight need to be responded to! Empty responses
// are fine though in that case.
// 向外部暴露的接口
func (s *MatcherSession) Multiplex(batch int, wait time.Duration, mux chan chan *Retrieval) {
	for {
		// allocateRetrieval与deliverSections调用是一一对应
		// Allocate a new bloom bit index to retrieve data for, stopping when done
		bit, ok := s.allocateRetrieval()
		if !ok {
			return
		}
		// Bit allocated, throttle a bit if we're below our batch limit
		// 如果比特位任务包括的section没有达到batch个,稍微等待一会可能会增加查询任务
		if s.pendingSections(bit) < batch {
			select {
			case <-s.quit:
				// Session terminating, we can't meaningfully service, abort
				s.allocateSections(bit, 0)
				s.deliverSections(bit, []uint64{}, [][]byte{})
				return

			case <-time.After(wait):
				// Throttling up, fetch whatever's available
			}
		}
		// Allocate as much as we can handle and request servicing
		sections := s.allocateSections(bit, batch)
		request := make(chan *Retrieval)

		select {
		case <-s.quit:
			// Session terminating, we can't meaningfully service, abort
			s.deliverSections(bit, sections, make([][]byte, len(sections)))
			return

		// 可以写入request说明已经有结果被查询到了
		case mux <- request:
			// Retrieval accepted, something must arrive before we're aborting
			request <- &Retrieval{Bit: bit, Sections: sections, Context: s.ctx}
			// 获取比特位任务的最终结果
			result := <-request
			if result.Error != nil {
				s.err.Store(result.Error)
				s.Close()
			}
			s.deliverSections(result.Bit, result.Sections, result.Bitsets)
		}
	}
}
