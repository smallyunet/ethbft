package engine

import (
	"fmt"
	"strings"
)

// NOTE: Canonical SSZ integration scaffold.
// We prepare canonical Deneb block structures suitable for an external SSZ library
// (e.g. prysmaticlabs/go-ssz). For now, we keep fallback to existing marshal
// until full encode/decode wiring is completed.

// CanonicalExecutionPayloadDeneb mirrors Deneb ExecutionPayload with concrete byte fields.
// List limits (comments) align with spec; struct tags for go-ssz will be added when library imported.
type CanonicalExecutionPayloadDeneb struct {
	ParentHash    [32]byte  `ssz-size:"32"`
	FeeRecipient  [20]byte  `ssz-size:"20"`
	StateRoot     [32]byte  `ssz-size:"32"`
	ReceiptsRoot  [32]byte  `ssz-size:"32"`
	LogsBloom     [256]byte `ssz-size:"256"`
	PrevRandao    [32]byte  `ssz-size:"32"`
	BlockNumber   uint64
	GasLimit      uint64
	GasUsed       uint64
	Timestamp     uint64
	ExtraData     []byte   `ssz-max:"32"`
	BaseFeePerGas [32]byte `ssz-size:"32"`
	BlockHash     [32]byte `ssz-size:"32"`
	Transactions  [][]byte `ssz-max:"1048576" ssz-size:"?"`
	Withdrawals   [][]byte `ssz-max:"16" ssz-size:"?"`
	BlobGasUsed   uint64
	ExcessBlobGas uint64
}

// CanonicalBeaconBlockBodyDeneb holds only execution payload (other lists currently empty in demo).
type CanonicalBeaconBlockBodyDeneb struct {
	ExecutionPayload *CanonicalExecutionPayloadDeneb
}

// CanonicalBeaconBlockDeneb (unsigned).
type CanonicalBeaconBlockDeneb struct {
	Slot          uint64
	ProposerIndex uint64
	ParentRoot    [32]byte `ssz-size:"32"`
	StateRoot     [32]byte `ssz-size:"32"`
	Body          *CanonicalBeaconBlockBodyDeneb
}

// CanonicalSignedBeaconBlockDeneb wraps message + signature.
type CanonicalSignedBeaconBlockDeneb struct {
	Message   *CanonicalBeaconBlockDeneb
	Signature [96]byte
}

// toCanonicalExecutionPayload converts internal ExecutionPayload (hex strings) to canonical form.
func toCanonicalExecutionPayload(p *ExecutionPayload) *CanonicalExecutionPayloadDeneb {
	if p == nil {
		return nil
	}
	var c CanonicalExecutionPayloadDeneb
	copy(c.ParentHash[:], hexToBytes32(p.ParentHash))
	// FeeRecipient (20 bytes) -> placed in first 20 bytes of 20-length array
	fr := hexToBytes20(p.FeeRecipient)
	copy(c.FeeRecipient[:], fr)
	copy(c.StateRoot[:], hexToBytes32(p.StateRoot))
	copy(c.ReceiptsRoot[:], hexToBytes32(p.ReceiptsRoot))
	// Logs bloom 256
	lb := hexToBytes256(p.LogsBloom)
	copy(c.LogsBloom[:], lb)
	copy(c.PrevRandao[:], hexToBytes32(p.PrevRandao))
	// Parse numeric fields
	c.BlockNumber = parseUint64Hex(p.BlockNumber)
	c.GasLimit = parseUint64Hex(p.GasLimit)
	c.GasUsed = parseUint64Hex(p.GasUsed)
	c.Timestamp = parseUint64Hex(p.Timestamp)
	c.ExtraData = hexToBytesDynamic(p.ExtraData, 32)
	// base_fee_per_gas treated as uint256 -> keep zero / parse low bytes
	copy(c.BaseFeePerGas[:], hexToBytes32(p.BaseFeePerGas))
	copy(c.BlockHash[:], hexToBytes32(p.BlockHash))
	// Transactions (each hex string to raw bytes)
	for _, tx := range p.Transactions {
		c.Transactions = append(c.Transactions, hexToBytesDynamic(tx, 1<<24))
	}
	// Withdrawals omitted (empty) in demo
	c.BlobGasUsed = parseUint64Hex(p.BlobGasUsed)
	c.ExcessBlobGas = parseUint64Hex(p.ExcessBlobGas)
	return &c
}

// Helper: parse hex uint64 like "0x1a".
func parseUint64Hex(h string) uint64 {
	var v uint64
	if h == "" {
		return 0
	}
	_, _ = fmt.Sscanf(h, "%#x", &v)
	return v
}

// hexToBytesDynamic converts hex (0x...) to raw bytes with a max limit; truncates if over.
func hexToBytesDynamic(h string, limit int) []byte {
	if h == "" || h == "0x" {
		return []byte{}
	}
	core := strings.TrimPrefix(h, "0x")
	if len(core)%2 == 1 {
		core = "0" + core
	}
	if len(core) > limit*2 {
		core = core[:limit*2]
	}
	out := make([]byte, len(core)/2)
	for i := 0; i < len(out); i++ {
		hi := fromHexNibble(core[2*i])
		lo := fromHexNibble(core[2*i+1])
		if hi < 0 || lo < 0 {
			return []byte{}
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out
}

// buildCanonicalSignedBlock builds canonical block + signed wrapper from internal block.
func buildCanonicalSignedBlock(sb *SignedBeaconBlock) *CanonicalSignedBeaconBlockDeneb {
	if sb == nil || sb.Message == nil || sb.Message.Body == nil || sb.Message.Body.ExecutionPayload == nil {
		return nil
	}
	var parent, state [32]byte
	copy(parent[:], hexToBytes32(sb.Message.ParentRoot))
	copy(state[:], hexToBytes32(sb.Message.StateRoot))
	c := &CanonicalSignedBeaconBlockDeneb{
		Message: &CanonicalBeaconBlockDeneb{
			Slot:          sb.Message.Slot,
			ProposerIndex: sb.Message.ProposerIndex,
			ParentRoot:    parent,
			StateRoot:     state,
			Body:          &CanonicalBeaconBlockBodyDeneb{ExecutionPayload: toCanonicalExecutionPayload(sb.Message.Body.ExecutionPayload)},
		},
		Signature: sb.Signature,
	}
	return c
}

// serializeCanonicalSSZ tries external SSZ marshal (when integrated), otherwise falls back.
func serializeCanonicalSSZ(sb *SignedBeaconBlock) (root string, sszBytes []byte, err error) {
	// Fallback: use existing root + custom deterministic bytes until external library added.
	c := buildCanonicalSignedBlock(sb)
	if c == nil {
		return "", nil, fmt.Errorf("nil block for canonical serialization")
	}
	root = computeSignedBeaconBlockRoot(sb)
	sszBytes = marshalSignedBeaconBlockSSZ(sb)
	return root, sszBytes, nil
}

// decodeCanonicalSSZ decodes persisted SSZ bytes back into internal SignedBeaconBlock
func decodeCanonicalSSZ(b []byte) (*SignedBeaconBlock, error) {
	return unmarshalSignedBeaconBlockSSZ(b)
}
