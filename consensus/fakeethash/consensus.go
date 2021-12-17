package fakeethash

import (
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/crypto/sha3"
)

type Config struct {
	Hashrate float64
}

type FakeEthash struct {
	config Config
}

func New(config Config) *FakeEthash {
	return &FakeEthash{
		config: config,
	}
}

func (fe *FakeEthash) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

func (fe *FakeEthash) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return nil
}

func (fe *FakeEthash) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort, results := make(chan struct{}), make(chan error, len(headers))
	for i := 0; i < len(headers); i++ {
		results <- nil
	}
	return abort, results
}

func (fe *FakeEthash) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	return nil
}

func (fe *FakeEthash) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Difficulty = fe.CalcDifficulty(chain, header.Time, parent)
	return nil
}

func (fe *FakeEthash) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header) {
	// Accumulate any block and uncle rewards and commit the final state root
	accumulateRewards(chain.Config(), state, header, uncles)
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
}

func (fe *FakeEthash) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// Finalize block
	fe.Finalize(chain, header, state, txs, uncles)

	// Header seems complete, assemble into a block and return
	return types.NewBlock(header, txs, uncles, receipts, trie.NewStackTrie(nil)), nil
}

func (fe *FakeEthash) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	milliseconds := block.Difficulty().Int64() * 1000 / int64(fe.Hashrate())
	timer := time.NewTimer(time.Millisecond * time.Duration(milliseconds))
	fmt.Printf("wait %d ms\n", milliseconds)
	go func() {
		select {
		case <-stop:
		case <-timer.C:
			header := block.Header()
			header.Nonce, header.MixDigest = types.BlockNonce{}, common.Hash{}
			select {
			case results <- block.WithSeal(header):
			default:
				fmt.Println("Sealing result is not read by miner", "mode", "fake", "sealhash", fe.SealHash(block.Header()))
			}
		}
	}()
	return nil
}

func (fe *FakeEthash) SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()

	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	rlp.Encode(hasher, enc)
	hasher.Sum(hash[:0])
	return hash
}

func (fe *FakeEthash) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return ethash.CalcDifficulty(chain.Config(), time, parent)
}

func (fe *FakeEthash) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{}
}

func (fe *FakeEthash) Hashrate() float64 {
	return fe.config.Hashrate
}

var (
	big8  = big.NewInt(8)
	big32 = big.NewInt(32)
)

func accumulateRewards(config *params.ChainConfig, state *state.StateDB, header *types.Header, uncles []*types.Header) {
	// Select the correct block reward based on chain progression
	blockReward := ethash.FrontierBlockReward
	if config.IsByzantium(header.Number) {
		blockReward = ethash.ByzantiumBlockReward
	}
	if config.IsConstantinople(header.Number) {
		blockReward = ethash.ConstantinopleBlockReward
	}
	// Accumulate the rewards for the miner and any included uncles
	reward := new(big.Int).Set(blockReward)
	r := new(big.Int)
	for _, uncle := range uncles {
		r.Add(uncle.Number, big8)
		r.Sub(r, header.Number)
		r.Mul(r, blockReward)
		r.Div(r, big8)
		state.AddBalance(uncle.Coinbase, r)

		r.Div(blockReward, big32)
		reward.Add(reward, r)
	}
	state.AddBalance(header.Coinbase, reward)
}

func (fe *FakeEthash) Close() error {
	return nil
}
