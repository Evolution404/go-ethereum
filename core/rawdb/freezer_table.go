// Copyright 2019 The go-ethereum Authors
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

package rawdb

// 每个freezertable对应了一个索引文件和数个数据文件
// 索引文件以ridx或者cidx结尾
//   索引文件每六个字节保存了一个数据项,每个数据项filenum记录该项数据存储在哪个数据文件,offset记录在数据文件的结束位置
//   索引文件最开始六个字节不对应数据项,offset字段保存了这个表删除了多少之前的数据
//   例如第一个条目的索引存储在索引文件的7-12字节,offset记录了第一项在数据文件的结束位置
// 数据文件以rdat或者cdat结尾

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/golang/snappy"
)

var (
	// errClosed is returned if an operation attempts to read from or write to the
	// freezer table after it has already been closed.
	errClosed = errors.New("closed")

	// errOutOfBounds is returned if the item requested is not contained within the
	// freezer table.
	errOutOfBounds = errors.New("out of bounds")

	// errNotSupported is returned if the database doesn't support the required operation.
	errNotSupported = errors.New("this operation is not supported")
)

// indexEntry contains the number/id of the file that the data resides in, aswell as the
// offset within the file to the end of the data
// In serialized form, the filenum is stored as uint16.
// 表示数据位置的对象
//   jfilenum记录保存在哪个数据文件
//   joffset记录保存在数据文件的哪个位置
// 对于保存在索引文件的第一个indexEntry有特殊意义
// filenum没有意义,offset记录了这个表已经删除的多少记录
type indexEntry struct {
	filenum uint32 // stored as uint16 ( 2 bytes)
	offset  uint32 // stored as uint32 ( 4 bytes)
}

// indexEntry对象转化成字节数组后的大小
const indexEntrySize = 6

// unmarshallBinary deserializes binary b into the rawIndex entry.
// 输入的字节数组前六字节会被解析
// 前两个字节保存着filenum
// 三到六字节保存了offset
func (i *indexEntry) unmarshalBinary(b []byte) error {
	i.filenum = uint32(binary.BigEndian.Uint16(b[:2]))
	i.offset = binary.BigEndian.Uint32(b[2:6])
	return nil
}

// marshallBinary serializes the rawIndex entry into binary.
// 将indexEntry对象编码成长度为六的字节数组
func (i *indexEntry) marshallBinary() []byte {
	b := make([]byte, indexEntrySize)
	binary.BigEndian.PutUint16(b[:2], uint16(i.filenum))
	binary.BigEndian.PutUint32(b[2:6], i.offset)
	return b
}

// freezerTable represents a single chained data table within the freezer (e.g. blocks).
// It consists of a data file (snappy encoded arbitrary data blobs) and an indexEntry
// file (uncompressed 64 bit indices into the data file).
type freezerTable struct {
	// WARNING: The `items` field is accessed atomically. On 32 bit platforms, only
	// 64-bit aligned fields can be atomic. The struct is guaranteed to be so aligned,
	// so take advantage of that (https://golang.org/pkg/sync/atomic/#pkg-note-BUG).
	// 在这个表内保存了多少条数据,items的访问需要是原子的
	items uint64 // Number of items stored in the table (including items removed from tail)

	// 标记表是否压缩
	noCompression bool   // if true, disables snappy compression. Note: does not work retroactively
	// 代表一个dat数据文件大小的最大值
	// newTable函数中使用的值是2*1000*1000*1000
	maxFileSize   uint32 // Max file size for data-files
	// 表的名称
	name          string
	// 表的存储路径
	path          string

	// 当前数据文件的文件描述符
	head   *os.File            // File descriptor for the data head of the table
	// 记录所有打开的索引文件,便于根据索引文件号获取文件对象
	files  map[uint32]*os.File // open files
	// 当前的数据文件的编号,当前在写的所以是head
	headId uint32              // number of the currently active head file
	// 初始数据文件的编号,最开始写的定义为tail
	tailId uint32              // number of the earliest file
	// 这个表对应的索引文件
	index  *os.File            // File descriptor for the indexEntry file of the table

	// In the case that old items are deleted (from the tail), we use itemOffset
	// to count how many historic items have gone missing.
	// 记录当前冻结数据表中丢失了多少条数据
	itemOffset uint32 // Offset (number of discarded items)

	// 记录当前数据文件的大小
	headBytes  uint32        // Number of bytes written to the head file
	readMeter  metrics.Meter // Meter for measuring the effective amount of data read
	writeMeter metrics.Meter // Meter for measuring the effective amount of data written
	sizeGauge  metrics.Gauge // Gauge for tracking the combined size of all freezer tables

	logger log.Logger   // Logger with database path and table name ambedded
	lock   sync.RWMutex // Mutex protecting the data file descriptors
}

// NewFreezerTable opens the given path as a freezer table.
func NewFreezerTable(path, name string, disableSnappy bool) (*freezerTable, error) {
	return newTable(path, name, metrics.NilMeter{}, metrics.NilMeter{}, metrics.NilGauge{}, disableSnappy)
}

// newTable opens a freezer table with default settings - 2G files
func newTable(path string, name string, readMeter metrics.Meter, writeMeter metrics.Meter, sizeGauge metrics.Gauge, disableSnappy bool) (*freezerTable, error) {
	// 每个dat文件的最大值是20亿字节
	return newCustomTable(path, name, readMeter, writeMeter, sizeGauge, 2*1000*1000*1000, disableSnappy)
}

// 以下三个函数定义了三种不同的打开文件的模式
// openFreezerFileForAppend -> 直接打开文件并指向文件末尾
// openFreezerFileForReadOnly -> 以只读模式打开文件
// openFreezerFileTruncated -> 确保打开的文件是空文件,原来有内容会清空

// openFreezerFileForAppend opens a freezer table file and seeks to the end
// 打开指定的文件,并让文件指针指向文件末尾
func openFreezerFileForAppend(filename string) (*os.File, error) {
	// Open the file without the O_APPEND flag
	// because it has differing behaviour during Truncate operations
	// on different OS's
	// os.O_RDWR代表读写,os.O_CREATE如果文件不存在就创建
	// 已经存在的文件不会进行修改,只是打开
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	// Seek to end for append
	if _, err = file.Seek(0, io.SeekEnd); err != nil {
		return nil, err
	}
	return file, nil
}

// openFreezerFileForReadOnly opens a freezer table file for read only access
// 以只读模式打开文件
func openFreezerFileForReadOnly(filename string) (*os.File, error) {
	return os.OpenFile(filename, os.O_RDONLY, 0644)
}

// openFreezerFileTruncated opens a freezer table making sure it is truncated
// 保证打开一个空文件,如果原来文件有内容会清空
func openFreezerFileTruncated(filename string) (*os.File, error) {
	return os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
}

// truncateFreezerFile resizes a freezer table file and seeks to the end
// 修改文件的大小为指定大小,并将文件指针指向修改后大小的末尾
func truncateFreezerFile(file *os.File, size int64) error {
	// 修改文件的大小为指定的size
	if err := file.Truncate(size); err != nil {
		return err
	}
	// Seek to end for append
	// 然后将文件指针指向最后
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	return nil
}

// newCustomTable opens a freezer table, creating the data and index files if they are
// non existent. Both files are truncated to the shortest common length to ensure
// they don't go out of sync.
func newCustomTable(path string, name string, readMeter metrics.Meter, writeMeter metrics.Meter, sizeGauge metrics.Gauge, maxFilesize uint32, noCompression bool) (*freezerTable, error) {
	// Ensure the containing directory exists and open the indexEntry file
	// 创建路径
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, err
	}
	// 索引文件的文件名
	var idxName string
	if noCompression {
		// Raw idx
		// 不压缩就是Raw idx
		idxName = fmt.Sprintf("%s.ridx", name)
	} else {
		// Compressed idx
		// 压缩就是Compressed idx
		idxName = fmt.Sprintf("%s.cidx", name)
	}
	// 打开索引文件，并指向索引文件的末尾位置
	offsets, err := openFreezerFileForAppend(filepath.Join(path, idxName))
	if err != nil {
		return nil, err
	}
	// Create the table and repair any past inconsistency
	tab := &freezerTable{
		index:         offsets,
		files:         make(map[uint32]*os.File),
		readMeter:     readMeter,
		writeMeter:    writeMeter,
		sizeGauge:     sizeGauge,
		name:          name,
		path:          path,
		// 日志默认显示database和table字段
		logger:        log.New("database", path, "table", name),
		noCompression: noCompression,
		maxFileSize:   maxFilesize,
	}
	if err := tab.repair(); err != nil {
		tab.Close()
		return nil, err
	}
	// Initialize the starting size counter
	// 在创建表对象的时候计算一下之前的文件大小,在sizeGauge中记录一下
	size, err := tab.sizeNolock()
	if err != nil {
		tab.Close()
		return nil, err
	}
	tab.sizeGauge.Inc(int64(size))

	return tab, nil
}

// repair cross checks the head and the index file and truncates them to
// be in sync with each other after a potential crash / data loss.
// 维护索引文件和数据文件的相关关系,修复可能出现的错误
// 1. 索引文件的大小必须是6字节的整数倍,如果不是6的整数倍就去掉多余的部分
// 当前已经有索引文件,根据索引文件设置head,headId,headBytes,tailId
func (t *freezerTable) repair() error {
	// Create a temporary offset buffer to init files with and read indexEntry into
	buffer := make([]byte, indexEntrySize)

	// If we've just created the files, initialize the index with the 0 indexEntry
	stat, err := t.index.Stat()
	if err != nil {
		return err
	}
	// 文件大小是0,说明文件是刚被创建
	// 向空文件写入6个字节的0
	if stat.Size() == 0 {
		if _, err := t.index.Write(buffer); err != nil {
			return err
		}
	}
	// Ensure the index is a multiple of indexEntrySize bytes
	// 确保索引文件的大小一定是6的倍数
	if overflow := stat.Size() % indexEntrySize; overflow != 0 {
		truncateFreezerFile(t.index, stat.Size()-overflow) // New file can't trigger this path
	}
	// Retrieve the file sizes and prepare for truncation
	if stat, err = t.index.Stat(); err != nil {
		return err
	}
	// offsetsSize用来记录索引文件的大小,初始化大小是经过6的倍数校验后的结果
	offsetsSize := stat.Size()

	// Open the head file
	var (
		// 索引文件的最开始6字节
		firstIndex  indexEntry
		// 索引文件的最末尾6字节
		lastIndex   indexEntry
		// 当前正在操作的数据文件的大小
		contentSize int64
		// 索引文件记录的最后一个数据项的结束位置
		contentExp  int64
	)
	// Read index zero, determine what file is the earliest
	// and what item offset to use
	// 读取最开始六个字节
	t.index.ReadAt(buffer, 0)
	firstIndex.unmarshalBinary(buffer)

	t.tailId = firstIndex.filenum
	// 第一个索引记录的偏移量就是这个表整体的偏移量
	t.itemOffset = firstIndex.offset

	// 读取最后六个字节,获得最后一条数据所在的数据文件和在数据文件中的位置
	t.index.ReadAt(buffer, offsetsSize-indexEntrySize)
	lastIndex.unmarshalBinary(buffer)
	// 打开当前所操作的数据文件
	t.head, err = t.openFile(lastIndex.filenum, openFreezerFileForAppend)
	if err != nil {
		return err
	}
	// 记录数据文件的文件信息
	if stat, err = t.head.Stat(); err != nil {
		return err
	}
	// 当前操作的数据文件的实际大小
	contentSize = stat.Size()

	// Keep truncating both files until they come in sync
	// 索引文件记录的数据文件的大小
	contentExp = int64(lastIndex.offset)

	// 校对索引文件记录的数据文件大小是否和实际的数据文件大小一致
	// 有可能会出现如下的两种错误情况
	// 索引记录的少于数据文件
	//   清除数据文件的大于索引的部分
	// 索引记录的大于数据文件
	//   向前搜索索引直到有记录在数据文件内部的,之后的索引都被丢弃
	for contentExp != contentSize {
		// Truncate the head file to the last offset pointer
		// 当索引记录的比数据文件小,那么就丢弃数据文件多余的部分
		if contentExp < contentSize {
			t.logger.Warn("Truncating dangling head", "indexed", common.StorageSize(contentExp), "stored", common.StorageSize(contentSize))
			if err := truncateFreezerFile(t.head, contentExp); err != nil {
				return err
			}
			contentSize = contentExp
		}
		// Truncate the index to point within the head file
		// 索引记录的比文件本身大,不断向前搜索之前的索引,直到索引位置小于等于文件的大小
		if contentExp > contentSize {
			t.logger.Warn("Truncating dangling indexes", "indexed", common.StorageSize(contentExp), "stored", common.StorageSize(contentSize))
			// 将索引文件末尾6字节去掉，然后读取新的末尾6字节代表的数据项信息
			if err := truncateFreezerFile(t.index, offsetsSize-indexEntrySize); err != nil {
				return err
			}
			// 维护索引文件的大小，前面缩小了6字节
			offsetsSize -= indexEntrySize
			// 读取去掉旧末尾项后新的末尾项,新末尾项用newLastIndex表示
			t.index.ReadAt(buffer, offsetsSize-indexEntrySize)
			// 定义新末尾项
			var newLastIndex indexEntry
			newLastIndex.unmarshalBinary(buffer)
			// We might have slipped back into an earlier head-file here
			// 搜索的索引已经不是当前文件了,说明当前这个文件整个需要丢弃
			if newLastIndex.filenum != lastIndex.filenum {
				// Release earlier opened file
				t.releaseFile(lastIndex.filenum)
				if t.head, err = t.openFile(newLastIndex.filenum, openFreezerFileForAppend); err != nil {
					return err
				}
				if stat, err = t.head.Stat(); err != nil {
					// TODO, anything more we can do here?
					// A data file has gone missing...
					return err
				}
				contentSize = stat.Size()
			}
			lastIndex = newLastIndex
			contentExp = int64(lastIndex.offset)
		}
	}
	// Ensure all reparation changes have been written to disk
	if err := t.index.Sync(); err != nil {
		return err
	}
	if err := t.head.Sync(); err != nil {
		return err
	}
	// Update the item and byte counters and return
	// 计算当前表中有多少条数据
	// 总条数=丢失的数据条数+保存的数据条数
	// 保存的数据条数=索引文件大小/6-1  减1是因为最开始6字节用于记录丢失数据
	t.items = uint64(t.itemOffset) + uint64(offsetsSize/indexEntrySize-1) // last indexEntry points to the end of the data file
	t.headBytes = uint32(contentSize)
	t.headId = lastIndex.filenum

	// Close opened files and preopen all files
	if err := t.preopen(); err != nil {
		return err
	}
	t.logger.Debug("Chain freezer table opened", "items", t.items, "size", common.StorageSize(t.headBytes))
	return nil
}

// preopen opens all files that the freezer will need. This method should be called from an init-context,
// since it assumes that it doesn't have to bother with locking
// The rationale for doing preopen is to not have to do it from within Retrieve, thus not needing to ever
// obtain a write-lock within Retrieve.
// 打开所有数据文件
// 历史数据文件以只读模式打开
// 当前数据文件以读写模式打开,并且文件指针指向文件末尾
func (t *freezerTable) preopen() (err error) {
	// The repair might have already opened (some) files
	t.releaseFilesAfter(0, false)
	// Open all except head in RDONLY
	// 以只读的方式打开这个表下的除了当前操作的其他所有数据文件
	for i := t.tailId; i < t.headId; i++ {
		if _, err = t.openFile(i, openFreezerFileForReadOnly); err != nil {
			return err
		}
	}
	// Open head in read/write
	// 以读写方式打开当前的数据文件
	t.head, err = t.openFile(t.headId, openFreezerFileForAppend)
	return err
}

// truncate discards any recent data above the provided threshold number.
// 如果表内保存的项大于items,清除多余的部分
func (t *freezerTable) truncate(items uint64) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	// If our item count is correct, don't do anything
	existing := atomic.LoadUint64(&t.items)
	// 当前的个数没有限制的大,直接返回
	if existing <= items {
		return nil
	}
	// We need to truncate, save the old size for metrics tracking
	oldSize, err := t.sizeNolock()
	if err != nil {
		return err
	}
	// Something's out of sync, truncate the table's offset index
	log := t.logger.Debug
	// 只清除一个不需要打印出来
	if existing > items+1 {
		log = t.logger.Warn // Only loud warn if we delete multiple items
	}
	log("Truncating freezer table", "items", existing, "limit", items)
	// 清除索引文件多余的部分, items+1是因为索引文件第一个indexEntry保存了之前清除的个数
	if err := truncateFreezerFile(t.index, int64(items+1)*indexEntrySize); err != nil {
		return err
	}
	// Calculate the new expected size of the data file and truncate it
	// 读取清理过后的最后一个索引,数据文件的处理包括两个部分
	//   清理末尾索引指向文件多余部分
	//   删除末尾索引之后的数据文件
	buffer := make([]byte, indexEntrySize)
	if _, err := t.index.ReadAt(buffer, int64(items*indexEntrySize)); err != nil {
		return err
	}
	var expected indexEntry
	expected.unmarshalBinary(buffer)

	// We might need to truncate back to older files
	// 末尾索引和当前操作的不是一个文件,删除多余的文件
	if expected.filenum != t.headId {
		// If already open for reading, force-reopen for writing
		t.releaseFile(expected.filenum)
		newHead, err := t.openFile(expected.filenum, openFreezerFileForAppend)
		if err != nil {
			return err
		}
		// Release any files _after the current head -- both the previous head
		// and any files which may have been opened for reading
		// 删除多余的文件
		t.releaseFilesAfter(expected.filenum, true)
		// Set back the historic head
		t.head = newHead
		atomic.StoreUint32(&t.headId, expected.filenum)
	}
	// 清除当前文件多余的部分
	if err := truncateFreezerFile(t.head, int64(expected.offset)); err != nil {
		return err
	}
	// All data files truncated, set internal counters and return
	atomic.StoreUint64(&t.items, items)
	atomic.StoreUint32(&t.headBytes, expected.offset)

	// Retrieve the new size and update the total size counter
	newSize, err := t.sizeNolock()
	if err != nil {
		return err
	}
	t.sizeGauge.Dec(int64(oldSize - newSize))

	return nil
}

// Close closes all opened files.
// 关闭所有打开的文件
func (t *freezerTable) Close() error {
	t.lock.Lock()
	defer t.lock.Unlock()

	var errs []error
	if err := t.index.Close(); err != nil {
		errs = append(errs, err)
	}
	t.index = nil

	for _, f := range t.files {
		if err := f.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	t.head = nil

	if errs != nil {
		return fmt.Errorf("%v", errs)
	}
	return nil
}

// openFile assumes that the write-lock is held by the caller
// 打开数据文件,num代表文件序号
// 数据文件命名规则是  表名.序号.rdat 或者 表名.序号.cdat
// 如果t.files里面已经保存了这个文件就直接返回
func (t *freezerTable) openFile(num uint32, opener func(string) (*os.File, error)) (f *os.File, err error) {
	var exist bool
	// 先判断map里面是否已经保存了这个文件
	if f, exist = t.files[num]; !exist {
		var name string
		// 不压缩的文件后缀是 rdat
		if t.noCompression {
			name = fmt.Sprintf("%s.%04d.rdat", t.name, num)
			// 压缩的文件的后缀是 cdat
		} else {
			name = fmt.Sprintf("%s.%04d.cdat", t.name, num)
		}
		f, err = opener(filepath.Join(t.path, name))
		if err != nil {
			return nil, err
		}
		t.files[num] = f
	}
	return f, err
}

// releaseFile closes a file, and removes it from the open file cache.
// Assumes that the caller holds the write lock
// 释放文件就是从t.files里面删除这个键值对,并且关闭文件指针
func (t *freezerTable) releaseFile(num uint32) {
	if f, exist := t.files[num]; exist {
		delete(t.files, num)
		f.Close()
	}
}

// releaseFilesAfter closes all open files with a higher number, and optionally also deletes the files
// 释放所有大于等于num的数据文件，remove为true代表会删除对应的数据文件
func (t *freezerTable) releaseFilesAfter(num uint32, remove bool) {
	for fnum, f := range t.files {
		if fnum > num {
			// 从map中删除文件描述符，然后关闭文件
			delete(t.files, fnum)
			f.Close()
			// 判断是否要删除文件
			if remove {
				os.Remove(f.Name())
			}
		}
	}
}

// Append injects a binary blob at the end of the freezer table. The item number
// is a precautionary parameter to ensure data correctness, but the table will
// reject already existing data.
//
// Note, this method will *not* flush any data to disk so be sure to explicitly
// fsync before irreversibly deleting data from the database.
// 向表内追加一项数据,调用后不会写入硬盘,确保最终调用Sync
func (t *freezerTable) Append(item uint64, blob []byte) error {
	// Encode the blob before the lock portion
	// 如果是压缩表,对原始数据进行压缩
	if !t.noCompression {
		blob = snappy.Encode(nil, blob)
	}
	// Read lock prevents competition with truncate
	// 先尝试只使用读锁
	retry, err := t.append(item, blob, false)
	if err != nil {
		return err
	}
	// 读锁不行,需要写锁
	if retry {
		// Read lock was insufficient, retry with a writelock
		_, err = t.append(item, blob, true)
	}
	return err
}

// append injects a binary blob at the end of the freezer table.
// Normally, inserts do not require holding the write-lock, so it should be invoked with 'wlock' set to
// false.
// However, if the data will grown the current file out of bounds, then this
// method will return 'true, nil', indicating that the caller should retry, this time
// with 'wlock' set to true.
// wlock决定是否使用写锁
func (t *freezerTable) append(item uint64, encodedBlob []byte, wlock bool) (bool, error) {
	if wlock {
		t.lock.Lock()
		defer t.lock.Unlock()
	} else {
		t.lock.RLock()
		defer t.lock.RUnlock()
	}
	// Ensure the table is still accessible
	if t.index == nil || t.head == nil {
		return false, errClosed
	}
	// Ensure only the next item can be written, nothing else
	// 校验用户输入的数据序号和实际存储的是否一致，不一致返回错误
	if atomic.LoadUint64(&t.items) != item {
		return false, fmt.Errorf("appending unexpected item: want %d, have %d", t.items, item)
	}
	// 代表存储到磁盘上的数据的真实长度，不压缩就是数据长度，压缩就是压缩后的长度
	bLen := uint32(len(encodedBlob))
	// 当前数据文件大小 + 新数据大小 > 单个数据文件最大值
	// 这种情况需要新建数据文件
	if t.headBytes+bLen < bLen ||
	t.headBytes+bLen > t.maxFileSize {
		// Writing would overflow, so we need to open a new data file.
		// If we don't already hold the writelock, abort and let the caller
		// invoke this method a second time.
		// 确保拿到了修改head的锁
		if !wlock {
			return true, nil
		}
		// 新数据文件的序号就是原来的序号加一
		nextID := atomic.LoadUint32(&t.headId) + 1
		// We open the next file in truncated mode -- if this file already
		// exists, we need to start over from scratch on it
		// 打开新的数据文件,如果原来存在这个文件会被清空
		newHead, err := t.openFile(nextID, openFreezerFileTruncated)
		if err != nil {
			return false, err
		}
		// Close old file, and reopen in RDONLY mode
		// 关闭原来的数据文件，然后以只读模式重新打开
		t.releaseFile(t.headId)
		t.openFile(t.headId, openFreezerFileForReadOnly)

		// Swap out the current head
		// 更新相关的数据，文件描述符、数据文件大小、数据文件序号
		t.head = newHead
		atomic.StoreUint32(&t.headBytes, 0)
		atomic.StoreUint32(&t.headId, nextID)
	}
	// 执行添加一条数据时真正的磁盘操作
	// 1. 数据写入数据文件
	// 2. 索引文件添加一项

	// 向数据文件写入新增的数据
	if _, err := t.head.Write(encodedBlob); err != nil {
		return false, err
	}
	newOffset := atomic.AddUint32(&t.headBytes, bLen)
	idx := indexEntry{
		filenum: atomic.LoadUint32(&t.headId),
		offset:  newOffset,
	}
	// Write indexEntry
	// 向索引文件写入索引项
	t.index.Write(idx.marshallBinary())

	t.writeMeter.Mark(int64(bLen + indexEntrySize))
	t.sizeGauge.Inc(int64(bLen + indexEntrySize))

	// 数据条数+1
	atomic.AddUint64(&t.items, 1)
	return false, nil
}

// getBounds returns the indexes for the item
// returns start, end, filenumber and error
// 读取指定条目保存的位置
// 返回 开始位置,结束位置,文件名
func (t *freezerTable) getBounds(item uint64) (uint32, uint32, uint32, error) {
	buffer := make([]byte, indexEntrySize)
	var startIdx, endIdx indexEntry
	// Read second index
	if _, err := t.index.ReadAt(buffer, int64((item+1)*indexEntrySize)); err != nil {
		return 0, 0, 0, err
	}
	endIdx.unmarshalBinary(buffer)
	// Read first index (unless it's the very first item)
	if item != 0 {
		if _, err := t.index.ReadAt(buffer, int64(item*indexEntrySize)); err != nil {
			return 0, 0, 0, err
		}
		startIdx.unmarshalBinary(buffer)
		// 第0条数据的开始位置一定是0
	} else {
		// Special case if we're reading the first item in the freezer. We assume that
		// the first item always start from zero(regarding the deletion, we
		// only support deletion by files, so that the assumption is held).
		// This means we can use the first item metadata to carry information about
		// the 'global' offset, for the deletion-case
		return 0, endIdx.offset, endIdx.filenum, nil
	}
	// 跨文件了,一定都保存在第二个文件里面
	if startIdx.filenum != endIdx.filenum {
		// If a piece of data 'crosses' a data-file,
		// it's actually in one piece on the second data-file.
		// We return a zero-indexEntry for the second file as start
		return 0, endIdx.offset, endIdx.filenum, nil
	}
	return startIdx.offset, endIdx.offset, endIdx.filenum, nil
}

// Retrieve looks up the data offset of an item with the given number and retrieves
// the raw binary blob from the data file.
// 从文件中取回指定条目
func (t *freezerTable) Retrieve(item uint64) ([]byte, error) {
	blob, err := t.retrieve(item)
	if err != nil {
		return nil, err
	}
	// 处理一下压缩
	if t.noCompression {
		return blob, nil
	}
	return snappy.Decode(nil, blob)
}

// retrieve looks up the data offset of an item with the given number and retrieves
// the raw binary blob from the data file. OBS! This method does not decode
// compressed data.
// 真正取回文件内容
func (t *freezerTable) retrieve(item uint64) ([]byte, error) {
	t.lock.RLock()
	defer t.lock.RUnlock()
	// Ensure the table and the item is accessible
	if t.index == nil || t.head == nil {
		return nil, errClosed
	}
	if atomic.LoadUint64(&t.items) <= item {
		return nil, errOutOfBounds
	}
	// Ensure the item was not deleted from the tail either
	if uint64(t.itemOffset) > item {
		return nil, errOutOfBounds
	}
	// 找到数据文件的位置
	startOffset, endOffset, filenum, err := t.getBounds(item - uint64(t.itemOffset))
	if err != nil {
		return nil, err
	}
	dataFile, exist := t.files[filenum]
	if !exist {
		return nil, fmt.Errorf("missing data file %d", filenum)
	}
	// Retrieve the data itself, decompress and return
	blob := make([]byte, endOffset-startOffset)
	// 从数据文件中读
	if _, err := dataFile.ReadAt(blob, int64(startOffset)); err != nil {
		return nil, err
	}
	t.readMeter.Mark(int64(len(blob) + 2*indexEntrySize))
	// 返回二进制数据
	return blob, nil
}

// has returns an indicator whether the specified number data
// exists in the freezer table.
// 输入下标小于长度就有
func (t *freezerTable) has(number uint64) bool {
	return atomic.LoadUint64(&t.items) > number
}

// size returns the total data size in the freezer table.
// 索引文件和数据文件总大小
func (t *freezerTable) size() (uint64, error) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.sizeNolock()
}

// sizeNolock returns the total data size in the freezer table without obtaining
// the mutex first.
// 返回当前表占用空间的大小
// 计算索引文件和所有数据文件的大小求和
func (t *freezerTable) sizeNolock() (uint64, error) {
	stat, err := t.index.Stat()
	if err != nil {
		return 0, err
	}
	// 计算一个表的大小需要计算数据文件和索引文件大小的和
	//       之前的所有数据文件                                当前的数据文件        索引文件
	total := uint64(t.maxFileSize)*uint64(t.headId-t.tailId) + uint64(t.headBytes) + uint64(stat.Size())
	return total, nil
}

// Sync pushes any pending data from memory out to disk. This is an expensive
// operation, so use it with care.
func (t *freezerTable) Sync() error {
	if err := t.index.Sync(); err != nil {
		return err
	}
	return t.head.Sync()
}

// DumpIndex is a debug print utility function, mainly for testing. It can also
// be used to analyse a live freezer table index.
func (t *freezerTable) DumpIndex(start, stop int64) {
	buf := make([]byte, indexEntrySize)

	fmt.Printf("| number | fileno | offset |\n")
	fmt.Printf("|--------|--------|--------|\n")

	for i := uint64(start); ; i++ {
		if _, err := t.index.ReadAt(buf, int64(i*indexEntrySize)); err != nil {
			break
		}
		var entry indexEntry
		entry.unmarshalBinary(buf)
		fmt.Printf("|  %03d   |  %03d   |  %03d   | \n", i, entry.filenum, entry.offset)
		if stop > 0 && i >= uint64(stop) {
			break
		}
	}
	fmt.Printf("|--------------------------|\n")
}
