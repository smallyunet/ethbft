package protocol

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func testMetadata(t *testing.T) *ExecutionMetadataV1 {
	t.Helper()
	payload := &engine.ExecutableData{
		ParentHash:    common.HexToHash("0x01"),
		FeeRecipient:  common.HexToAddress("0x02"),
		StateRoot:     common.HexToHash("0x03"),
		ReceiptsRoot:  common.HexToHash("0x04"),
		LogsBloom:     make([]byte, types.BloomByteLength),
		Random:        common.HexToHash("0x05"),
		Number:        1,
		GasLimit:      30_000_000,
		Timestamp:     1_800_000_000,
		ExtraData:     []byte("ethbft"),
		BaseFeePerGas: big.NewInt(1),
		BlockHash:     common.HexToHash("0x06"),
		Withdrawals:   []*types.Withdrawal{},
	}
	metadata, err := NewExecutionMetadataV1(big.NewInt(1337), 1, nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	return metadata
}

func TestEnvelopeRoundTrip(t *testing.T) {
	metadata := testMetadata(t)
	raw, err := EncodeEnvelope(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if !IsEnvelope(raw) {
		t.Fatal("encoded metadata is not recognized as an envelope")
	}
	decoded, err := DecodeEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.BlockHash != metadata.BlockHash || decoded.ChainID.Cmp(metadata.ChainID) != 0 || decoded.ConsensusHeight != metadata.ConsensusHeight {
		t.Fatalf("decoded metadata mismatch: %+v", decoded)
	}
}

func TestEnvelopeRejectsWrongPrefixAndTrailingBytes(t *testing.T) {
	metadata := testMetadata(t)
	raw, err := EncodeEnvelope(metadata)
	if err != nil {
		t.Fatal(err)
	}
	wrongPrefix := append([]byte(nil), raw...)
	wrongPrefix[0] ^= 1
	if _, err := DecodeEnvelope(wrongPrefix); err == nil {
		t.Fatal("expected wrong prefix to fail")
	}
	withTrailing := append(append([]byte(nil), raw...), 0)
	if _, err := DecodeEnvelope(withTrailing); err == nil {
		t.Fatal("expected trailing bytes to fail")
	}
}

func TestMetadataRejectsBlobPayload(t *testing.T) {
	metadata := testMetadata(t)
	blobGas := uint64(1)
	payload := metadata.Payload(nil)
	payload.BlobGasUsed = &blobGas
	if _, err := NewExecutionMetadataV1(big.NewInt(1337), 1, nil, &payload); err == nil {
		t.Fatal("expected blob payload to be rejected")
	}
}
