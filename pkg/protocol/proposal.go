package protocol

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	VersionV1      = uint64(1)
	EngineAPIV2    = uint64(2)
	MaxEnvelopeLen = 128 * 1024
)

var EnvelopePrefix = []byte{'E', 'T', 'H', 'B', 'F', 'T', 0x00, 0x01}

// ExecutionMetadataV1 is the deterministic, transaction-free portion of an
// Engine API V2 execution payload. The proposal entries after the envelope are
// the payload transactions in their exact execution order.
type ExecutionMetadataV1 struct {
	ProtocolVersion  uint64
	EngineAPIVersion uint64
	ChainID          *big.Int
	ConsensusHeight  uint64
	PreviousAppHash  []byte

	ParentHash   common.Hash
	FeeRecipient common.Address
	StateRoot    common.Hash
	ReceiptsRoot common.Hash
	LogsBloom    []byte
	PrevRandao   common.Hash
	BlockNumber  uint64
	GasLimit     uint64
	GasUsed      uint64
	Timestamp    uint64
	ExtraData    []byte
	BaseFee      *big.Int
	BlockHash    common.Hash
	Withdrawals  []*types.Withdrawal
}

func NewExecutionMetadataV1(chainID *big.Int, height int64, previousAppHash []byte, payload *engine.ExecutableData) (*ExecutionMetadataV1, error) {
	if chainID == nil || chainID.Sign() <= 0 {
		return nil, fmt.Errorf("invalid chain ID")
	}
	if height <= 0 {
		return nil, fmt.Errorf("invalid consensus height %d", height)
	}
	if payload == nil {
		return nil, fmt.Errorf("nil execution payload")
	}
	if payload.BaseFeePerGas == nil {
		return nil, fmt.Errorf("execution payload has nil base fee")
	}
	if payload.BlobGasUsed != nil || payload.ExcessBlobGas != nil {
		return nil, fmt.Errorf("blob payloads are not supported by protocol v1")
	}
	return &ExecutionMetadataV1{
		ProtocolVersion:  VersionV1,
		EngineAPIVersion: EngineAPIV2,
		ChainID:          new(big.Int).Set(chainID),
		ConsensusHeight:  uint64(height),
		PreviousAppHash:  append([]byte(nil), previousAppHash...),
		ParentHash:       payload.ParentHash,
		FeeRecipient:     payload.FeeRecipient,
		StateRoot:        payload.StateRoot,
		ReceiptsRoot:     payload.ReceiptsRoot,
		LogsBloom:        append([]byte(nil), payload.LogsBloom...),
		PrevRandao:       payload.Random,
		BlockNumber:      payload.Number,
		GasLimit:         payload.GasLimit,
		GasUsed:          payload.GasUsed,
		Timestamp:        payload.Timestamp,
		ExtraData:        append([]byte(nil), payload.ExtraData...),
		BaseFee:          new(big.Int).Set(payload.BaseFeePerGas),
		BlockHash:        payload.BlockHash,
		Withdrawals:      cloneWithdrawals(payload.Withdrawals),
	}, nil
}

func (m *ExecutionMetadataV1) Payload(transactions [][]byte) engine.ExecutableData {
	return engine.ExecutableData{
		ParentHash:    m.ParentHash,
		FeeRecipient:  m.FeeRecipient,
		StateRoot:     m.StateRoot,
		ReceiptsRoot:  m.ReceiptsRoot,
		LogsBloom:     append([]byte(nil), m.LogsBloom...),
		Random:        m.PrevRandao,
		Number:        m.BlockNumber,
		GasLimit:      m.GasLimit,
		GasUsed:       m.GasUsed,
		Timestamp:     m.Timestamp,
		ExtraData:     append([]byte(nil), m.ExtraData...),
		BaseFeePerGas: new(big.Int).Set(m.BaseFee),
		BlockHash:     m.BlockHash,
		Transactions:  cloneTransactions(transactions),
		Withdrawals:   cloneWithdrawals(m.Withdrawals),
	}
}

func (m *ExecutionMetadataV1) ValidateBasic() error {
	if m == nil {
		return fmt.Errorf("nil execution metadata")
	}
	if m.ProtocolVersion != VersionV1 {
		return fmt.Errorf("unsupported protocol version %d", m.ProtocolVersion)
	}
	if m.EngineAPIVersion != EngineAPIV2 {
		return fmt.Errorf("unsupported Engine API version %d", m.EngineAPIVersion)
	}
	if m.ChainID == nil || m.ChainID.Sign() <= 0 || m.ChainID.BitLen() > 256 {
		return fmt.Errorf("invalid chain ID")
	}
	if m.ConsensusHeight == 0 {
		return fmt.Errorf("invalid consensus height")
	}
	if len(m.PreviousAppHash) != 0 && len(m.PreviousAppHash) != common.HashLength {
		return fmt.Errorf("previous app hash must be empty or 32 bytes")
	}
	if len(m.LogsBloom) != types.BloomByteLength {
		return fmt.Errorf("invalid logs bloom length %d", len(m.LogsBloom))
	}
	if len(m.ExtraData) > 32 {
		return fmt.Errorf("invalid extra data length %d", len(m.ExtraData))
	}
	if m.BaseFee == nil || m.BaseFee.Sign() < 0 || m.BaseFee.BitLen() > 256 {
		return fmt.Errorf("invalid base fee")
	}
	if m.BlockHash == (common.Hash{}) {
		return fmt.Errorf("zero execution block hash")
	}
	if m.Withdrawals == nil {
		return fmt.Errorf("withdrawals must be an explicit list")
	}
	return nil
}

func EncodeEnvelope(metadata *ExecutionMetadataV1) ([]byte, error) {
	if err := metadata.ValidateBasic(); err != nil {
		return nil, err
	}
	body, err := rlp.EncodeToBytes(metadata)
	if err != nil {
		return nil, fmt.Errorf("encode execution metadata: %w", err)
	}
	if len(body)+len(EnvelopePrefix) > MaxEnvelopeLen {
		return nil, fmt.Errorf("execution envelope exceeds %d bytes", MaxEnvelopeLen)
	}
	out := make([]byte, 0, len(EnvelopePrefix)+len(body))
	out = append(out, EnvelopePrefix...)
	out = append(out, body...)
	return out, nil
}

func DecodeEnvelope(raw []byte) (*ExecutionMetadataV1, error) {
	if !IsEnvelope(raw) {
		return nil, fmt.Errorf("missing EthBFT execution envelope prefix")
	}
	if len(raw) > MaxEnvelopeLen {
		return nil, fmt.Errorf("execution envelope exceeds %d bytes", MaxEnvelopeLen)
	}
	body := raw[len(EnvelopePrefix):]
	var metadata ExecutionMetadataV1
	if err := rlp.DecodeBytes(body, &metadata); err != nil {
		return nil, fmt.Errorf("decode execution metadata: %w", err)
	}
	if err := metadata.ValidateBasic(); err != nil {
		return nil, err
	}
	canonical, err := rlp.EncodeToBytes(&metadata)
	if err != nil {
		return nil, fmt.Errorf("re-encode execution metadata: %w", err)
	}
	if !bytes.Equal(canonical, body) {
		return nil, fmt.Errorf("non-canonical execution metadata encoding")
	}
	return &metadata, nil
}

func IsEnvelope(raw []byte) bool {
	return len(raw) >= len(EnvelopePrefix) && bytes.Equal(raw[:len(EnvelopePrefix)], EnvelopePrefix)
}

func cloneTransactions(transactions [][]byte) [][]byte {
	out := make([][]byte, len(transactions))
	for i := range transactions {
		out[i] = append([]byte(nil), transactions[i]...)
	}
	return out
}

func cloneWithdrawals(withdrawals []*types.Withdrawal) []*types.Withdrawal {
	if withdrawals == nil {
		return nil
	}
	out := make([]*types.Withdrawal, len(withdrawals))
	for i, withdrawal := range withdrawals {
		if withdrawal != nil {
			copy := *withdrawal
			out[i] = &copy
		}
	}
	return out
}
