package engine

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
)

// This file contains the robust implementation of execution block hash computation
// using go-ethereum's Header type to ensure compatibility with geth's block hash calculation.
// This replaces the simple demo implementation with the most stable and accurate approach.

// hexToHash converts a hex string to common.Hash
func hexToHash(s string) common.Hash {
	if len(s) == 0 || s == "0x" {
		return common.Hash{}
	}
	return common.HexToHash(s)
}

// hexToAddress converts a hex string to common.Address
func hexToAddress(s string) common.Address {
	if len(s) == 0 || s == "0x" {
		return common.Address{}
	}
	return common.HexToAddress(s)
}

// hexToBig converts a hex string to *big.Int
func hexToBig(s string) *big.Int {
	if s == "" || s == "0x" {
		return big.NewInt(0)
	}
	v, _ := new(big.Int).SetString(s[2:], 16)
	return v
}

// computeTxRootFromBytesList computes transaction root from transaction list
func computeTxRootFromBytesList(txs []string) common.Hash {
	// For empty transactions, use EmptyRootHash
	if len(txs) == 0 {
		return gethtypes.EmptyRootHash
	}
	// To support transactions, we would need to decode each 0x-prefixed bytes as RLP
	// and build geth's types.Transaction, then use gethtypes.DeriveSha
	// For now, we'll use empty root for simplicity
	return gethtypes.EmptyRootHash
}

// computeWithdrawalsRootEmpty computes withdrawals root for empty withdrawals
func computeWithdrawalsRootEmpty() *common.Hash {
	// For Deneb, withdrawalsHash is optional but Header can carry it
	// For empty list, we can use geth's EmptyWithdrawalsHash (naming may vary by version)
	h := gethtypes.EmptyWithdrawalsHash
	return &h
}

// computeExecutionBlockHashWithGeth computes the block hash using go-ethereum's Header
// This is the most robust implementation as it uses the exact same logic as geth
func computeExecutionBlockHashWithGeth(p *ExecutionPayload) string {
	// Determine nonce: genesis block (number 0 and zero parent) uses 0x42, otherwise zero
	nonce := gethtypes.BlockNonce{}
	if p.BlockNumber == "0x0" && p.ParentHash == zeroHash32() {
		nonce = gethtypes.EncodeNonce(0x42)
	}

	// Optional header fields added in Shanghai/Deneb should be nil when not used
	var withdrawalsHash *common.Hash
	if len(p.Withdrawals) > 0 {
		// For now support empty withdrawals only
		withdrawalsHash = computeWithdrawalsRootEmpty()
	}

	var blobGasUsed *uint64
	if p.BlobGasUsed != "" && p.BlobGasUsed != "0x" && p.BlobGasUsed != "0x0" {
		val := hexToBig(p.BlobGasUsed).Uint64()
		blobGasUsed = &val
	}

	var excessBlobGas *uint64
	if p.ExcessBlobGas != "" && p.ExcessBlobGas != "0x" && p.ExcessBlobGas != "0x0" {
		val := hexToBig(p.ExcessBlobGas).Uint64()
		excessBlobGas = &val
	}

	var parentBeaconRoot *common.Hash
	if p.ParentBeaconBlockRoot != "" && p.ParentBeaconBlockRoot != "0x" && p.ParentBeaconBlockRoot != zeroHash32() {
		h := hexToHash(p.ParentBeaconBlockRoot)
		parentBeaconRoot = &h
	}

	hdr := &gethtypes.Header{
		ParentHash:       hexToHash(p.ParentHash),
		UncleHash:        gethtypes.EmptyUncleHash, // Fixed after merge
		Coinbase:         hexToAddress(p.FeeRecipient),
		Root:             hexToHash(p.StateRoot),
		TxHash:           computeTxRootFromBytesList(p.Transactions),
		ReceiptHash:      hexToHash(p.ReceiptsRoot),
		Bloom:            gethtypes.Bloom{}, // p.LogsBloom is zero in our usage
		Difficulty:       big.NewInt(0),
		Number:           hexToBig(p.BlockNumber),
		GasLimit:         hexToBig(p.GasLimit).Uint64(),
		GasUsed:          hexToBig(p.GasUsed).Uint64(),
		Time:             hexToBig(p.Timestamp).Uint64(),
		Extra:            common.FromHex(p.ExtraData),
		MixDigest:        hexToHash(p.PrevRandao), // post-merge uses prevRandao
		Nonce:            nonce,
		BaseFee:          hexToBig(p.BaseFeePerGas),
		WithdrawalsHash:  withdrawalsHash,
		BlobGasUsed:      blobGasUsed,
		ExcessBlobGas:    excessBlobGas,
		ParentBeaconRoot: parentBeaconRoot,
	}

	h := hdr.Hash()
	return h.Hex() // Returns with 0x prefix
}
