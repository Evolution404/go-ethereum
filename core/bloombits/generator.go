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
	"errors"

	"github.com/ethereum/go-ethereum/core/types"
)

var (
	// errSectionOutOfBounds is returned if the user tried to add more bloom filters
	// to the batch than available space, or if tries to retrieve above the capacity.
	errSectionOutOfBounds = errors.New("section out of bounds")

	// errBloomBitOutOfBounds is returned if the user tried to retrieve specified
	// bit bloom above the capacity.
	errBloomBitOutOfBounds = errors.New("bloom bit out of bounds")
)

// Generator takes a number of bloom filters and generates the rotated bloom bits
// to be used for batched filtering.
type Generator struct {
	// 保存了sections个布隆过滤器
	// blooms[x]保存了这sections个布隆过滤器的第x位的值
	blooms   [types.BloomBitLength][]byte // Rotated blooms for per-bit matching
	sections uint                         // Number of sections to batch together
	// 保存的section的个数,必须保证nextSec<=sections
	nextSec  uint                         // Next section to set when adding a bloom
}

// NewGenerator creates a rotated bloom generator that can iteratively fill a
// batched bloom filter's bits.
// 生成一个Generator,并为他初始化保存布隆过滤器的空间
func NewGenerator(sections uint) (*Generator, error) {
	if sections%8 != 0 {
		return nil, errors.New("section count not multiple of 8")
	}
	b := &Generator{sections: sections}
	for i := 0; i < types.BloomBitLength; i++ {
		// sections个布隆过滤器总共需要 2048*sections bit
		// 这里除以8,正好保存所有布隆过滤器
		b.blooms[i] = make([]byte, sections/8)
	}
	return b, nil
}

// AddBloom takes a single bloom filter and sets the corresponding bit column
// in memory accordingly.
// 往Generator里面增加保存一个布隆过滤器,总共需要修改2048个位
// 分别就是 blooms[0]的第index位,blooms[1]的第index位,...,blooms[2047]的第index位
func (b *Generator) AddBloom(index uint, bloom types.Bloom) error {
	// Make sure we're not adding more bloom filters than our capacity
	if b.nextSec >= b.sections {
		return errSectionOutOfBounds
	}
	if b.nextSec != index {
		return errors.New("bloom filter with unexpected index")
	}
	// Rotate the bloom and insert into our collection
	// 放置的字节位置
	byteIndex := b.nextSec / 8
	// 放置在字节哪个比特
	bitIndex := byte(7 - b.nextSec%8)
	// 遍历要设置的bloom, 一次扫描一个字节
	for byt := 0; byt < types.BloomByteLength; byt++ {
		bloomByte := bloom[types.BloomByteLength-1-byt]
		// 0的话没必要改了
		if bloomByte == 0 {
			continue
		}
		base := 8 * byt
		// 设置8个比特位
		b.blooms[base+7][byteIndex] |= ((bloomByte >> 7) & 1) << bitIndex
		b.blooms[base+6][byteIndex] |= ((bloomByte >> 6) & 1) << bitIndex
		b.blooms[base+5][byteIndex] |= ((bloomByte >> 5) & 1) << bitIndex
		b.blooms[base+4][byteIndex] |= ((bloomByte >> 4) & 1) << bitIndex
		b.blooms[base+3][byteIndex] |= ((bloomByte >> 3) & 1) << bitIndex
		b.blooms[base+2][byteIndex] |= ((bloomByte >> 2) & 1) << bitIndex
		b.blooms[base+1][byteIndex] |= ((bloomByte >> 1) & 1) << bitIndex
		b.blooms[base][byteIndex] |= (bloomByte & 1) << bitIndex
	}
	b.nextSec++
	return nil
}

// Bitset returns the bit vector belonging to the given bit index after all
// blooms have been added.
// 查询所有布隆过滤器第idx位的结果
// 返回结果第i位就代表第i个布隆过滤器第idx位的结果
func (b *Generator) Bitset(idx uint) ([]byte, error) {
	if b.nextSec != b.sections {
		return nil, errors.New("bloom not fully generated yet")
	}
	if idx >= types.BloomBitLength {
		return nil, errBloomBitOutOfBounds
	}
	return b.blooms[idx], nil
}
