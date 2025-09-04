package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	ssz "github.com/karalabe/ssz"
)

// Ethereum execution payload SSZ limits for Deneb
const (
	MAX_TRANSACTIONS_PER_PAYLOAD = 1048576 // 2^20
	MAX_WITHDRAWALS_PER_PAYLOAD  = 16      // 2^4
)

// Beacon block body SSZ limits for Deneb
const (
	MAX_PROPOSER_SLASHINGS         = 16   // 2^4
	MAX_ATTESTER_SLASHINGS         = 2    // 2^1
	MAX_ATTESTATIONS               = 128  // 2^7
	MAX_DEPOSITS                   = 16   // 2^4
	MAX_VOLUNTARY_EXITS            = 16   // 2^4
	MAX_BLS_TO_EXECUTION_CHANGES   = 16   // 2^4
	MAX_BLOB_COMMITMENTS_PER_BLOCK = 4096 // 2^12
)

func zeroHash32() string {
	return "0x" + strings.Repeat("0", 64)
}

func zeroSig96() string {
	return "0x" + strings.Repeat("0", 192)
}

func zeroHexBytes(n int) string {
	return "0x" + strings.Repeat("0", n*2)
}

func zeroBloom256() string {
	return "0x" + strings.Repeat("0", 512) // 256 bytes = 512 hex characters
}

func normalizeRoot(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	h = strings.TrimPrefix(h, "0x")
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			h = h[:i]
			break
		}
	}
	if len(h) < 64 {
		h = strings.Repeat("0", 64-len(h)) + h
	}
	if len(h) > 64 {
		h = h[:64]
	}
	return "0x" + h
}

// beaconHeaderFields holds minimal fields to compute a pseudo SSZ root for BeaconBlockHeader.
type beaconHeaderFields struct {
	Slot       int64
	ParentRoot string
	StateRoot  string
	BodyRoot   string
}

// ---------------- Provisional SSZ block types (Deneb minimal) ---------------- //

// BeaconBlockBody represents the 12 Deneb body fields (simplified: all empty except execution_payload)
type BeaconBlockBody struct {
	RandaoReveal           [96]byte // stored as 96 raw bytes (all zero)
	Eth1DepositRoot        [32]byte
	Eth1DepositCount       uint64
	Eth1BlockHash          [32]byte
	Graffiti               [32]byte
	ProposerSlashings      [][]byte
	AttesterSlashings      [][]byte
	Attestations           [][]byte
	Deposits               [][]byte
	VoluntaryExits         [][]byte
	SyncCommitteeBits      [64]byte // 512 bits
	SyncCommitteeSignature [96]byte
	ExecutionPayload       *ExecutionPayload
	BLSToExecutionChanges  [][]byte
	BlobKZGCommitments     [][]byte
}

// BeaconBlock (unsigned)
type BeaconBlock struct {
	Slot          uint64
	ProposerIndex uint64
	ParentRoot    string
	StateRoot     string
	Body          *BeaconBlockBody
}

// SignedBeaconBlock (signature always zero for mock)
type SignedBeaconBlock struct {
	Message   *BeaconBlock
	Signature [96]byte
}

// Real SSZ container wrappers (hash-only) leveraging github.com/karalabe/ssz
type SignedBeaconBlockContainer struct {
	Message   *BeaconBlockContainer
	Signature [96]byte
}

type BeaconBlockContainer struct {
	Slot          uint64
	ProposerIndex uint64
	ParentRoot    [32]byte
	StateRoot     [32]byte
	Body          *BeaconBlockBodyContainer
}

type BeaconBlockBodyContainer struct {
	Payload *ExecutionPayload
}

func (b *BeaconBlockBodyContainer) SizeSSZ(s *ssz.Sizer) uint32 { return 0 }
func (b *BeaconBlockBodyContainer) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		// Build individual 12 field roots with proper SSZ List computation
		var roots [12][32]byte

		// 0 randao_reveal (96 bytes -> merkle root of 3 zero chunks)
		r := merkleizeChunks([][]byte{zero32(), zero32(), zero32()})
		copy(roots[0][:], r)

		// 1 eth1_data (fixed non-zero test values to differ from randao)
		eth1DepositRoot := hexToBytes32("0x0101010101010101010101010101010101010101010101010101010101010101")
		eth1DepositCount := hashUint64(1)
		eth1BlockHash := hexToBytes32("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
		e1 := merkleizeChunks([][]byte{eth1DepositRoot, eth1DepositCount, eth1BlockHash})
		copy(roots[1][:], e1)

		// 2 graffiti (32 bytes all zero)
		copy(roots[2][:], zero32())

		// 3 proposer_slashings: List[ProposerSlashing, MAX_PROPOSER_SLASHINGS]
		proposerSlashingsRoot := computeListRootWithLimit(nil, 0, MAX_PROPOSER_SLASHINGS)
		copy(roots[3][:], proposerSlashingsRoot)

		// 4 attester_slashings: List[AttesterSlashing, MAX_ATTESTER_SLASHINGS]
		attesterSlashingsRoot := computeListRootWithLimit(nil, 0, MAX_ATTESTER_SLASHINGS)
		copy(roots[4][:], attesterSlashingsRoot)

		// 5 attestations: List[Attestation, MAX_ATTESTATIONS]
		attestationsRoot := computeListRootWithLimit(nil, 0, MAX_ATTESTATIONS)
		copy(roots[5][:], attestationsRoot)

		// 6 deposits: List[Deposit, MAX_DEPOSITS]
		depositsRoot := computeListRootWithLimit(nil, 0, MAX_DEPOSITS)
		copy(roots[6][:], depositsRoot)

		// 7 voluntary_exits: List[SignedVoluntaryExit, MAX_VOLUNTARY_EXITS]
		voluntaryExitsRoot := computeListRootWithLimit(nil, 0, MAX_VOLUNTARY_EXITS)
		copy(roots[7][:], voluntaryExitsRoot)

		// 8 sync_aggregate: Use SSZ library to compute proper container root
		syncAgg := &SyncAggregate{
			SyncCommitteeBits:      make([]byte, 64), // 512 bits = 64 bytes, all zeros
			SyncCommitteeSignature: &BLSSignature{},  // 96 bytes, all zeros
		}
		syncAggRoot := ssz.HashSequential(syncAgg)
		copy(roots[8][:], syncAggRoot[:])

		// 9 execution_payload
		execRoot := computeExecutionPayloadRootSpec(b.Payload)
		copy(roots[9][:], execRoot)

		// 10 bls_to_execution_changes: List[SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES]
		blsToExecChangesRoot := computeListRootWithLimit(nil, 0, MAX_BLS_TO_EXECUTION_CHANGES)
		copy(roots[10][:], blsToExecChangesRoot)

		// 11 blob_kzg_commitments: List[KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK]
		blobKZGCommitmentsRoot := computeListRootWithLimit(nil, 0, MAX_BLOB_COMMITMENTS_PER_BLOCK)
		copy(roots[11][:], blobKZGCommitmentsRoot)

		for i := 0; i < 12; i++ {
			ssz.HashStaticBytes(has, &roots[i])
		}
	})
}

func (b *BeaconBlockContainer) SizeSSZ(s *ssz.Sizer) uint32 { return 0 }
func (b *BeaconBlockContainer) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		// body hash first
		bodyRoot := ssz.HashSequential(b.Body)
		var chunks [5][32]byte
		for i := 0; i < 8; i++ {
			chunks[0][i] = byte(b.Slot >> (8 * i))
		}
		for i := 0; i < 8; i++ {
			chunks[1][i] = byte(b.ProposerIndex >> (8 * i))
		}
		ssz.HashStaticBytes(has, &chunks[0])
		ssz.HashStaticBytes(has, &chunks[1])
		ssz.HashStaticBytes(has, (*[32]byte)(&b.ParentRoot))
		ssz.HashStaticBytes(has, (*[32]byte)(&b.StateRoot))
		ssz.HashStaticBytes(has, (*[32]byte)(&bodyRoot))
	})
}

func (s *SignedBeaconBlockContainer) SizeSSZ(sz *ssz.Sizer) uint32 { return 0 }
func (s *SignedBeaconBlockContainer) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		msgRoot := ssz.HashSequential(s.Message)
		// hash message root as single chunk then signature as three 32-byte chunks (all zero)
		ssz.HashStaticBytes(has, (*[32]byte)(&msgRoot))
		// signature 96 bytes => 3 zero chunks
		var z [32]byte
		ssz.HashStaticBytes(has, &z)
		ssz.HashStaticBytes(has, &z)
		ssz.HashStaticBytes(has, &z)
	})
}

// marshalSignedBeaconBlockSSZ - provisional deterministic binary (NOT production SSZ!)
func marshalSignedBeaconBlockSSZ(sb *SignedBeaconBlock) []byte {
	// Layout: slot(8) proposer(8) parent(32) state(32) body_root(32) exec_payload_fields roots (17*32) signature(96)
	// Compute body_root via existing function for consistency.
	bodyRootHex := computeBeaconBodyRootSpec(sb.Message.Body.ExecutionPayload)
	bodyRootBytes := hexToBytes32(bodyRootHex)
	buf := bytes.NewBuffer(nil)
	le := func(v uint64) {
		for i := 0; i < 8; i++ {
			buf.WriteByte(byte(v >> (8 * i)))
		}
	}
	le(sb.Message.Slot)
	le(sb.Message.ProposerIndex)
	buf.Write(hexToBytes32(sb.Message.ParentRoot))
	buf.Write(hexToBytes32(sb.Message.StateRoot))
	buf.Write(bodyRootBytes)
	// Execution payload raw roots (reuse computeExecutionPayloadRootSpec diagnostic list by recomputing field roots)
	execRootBytes := computeExecutionPayloadRootSpec(sb.Message.Body.ExecutionPayload)
	buf.Write(execRootBytes) // single 32-byte root of payload (placeholder for full field serialization)
	// Signature (96 bytes)
	buf.Write(make([]byte, 96))
	return buf.Bytes()
}

// unmarshalSignedBeaconBlockSSZ - ONLY for self-check and JSON conversion (never "reconstruct" from latest)
func unmarshalSignedBeaconBlockSSZ(b []byte) (*SignedBeaconBlock, error) {
	if len(b) < 8+8+32+32+32+32+96 {
		return nil, fmt.Errorf("invalid block bytes length=%d", len(b))
	}
	rd := bytes.NewReader(b)
	readU64 := func() uint64 {
		var v uint64
		for i := 0; i < 8; i++ {
			bt, _ := rd.ReadByte()
			v |= uint64(bt) << (8 * uint(i))
		}
		return v
	}
	slot := readU64()
	proposer := readU64()
	readBytes := func(n int) []byte { buf := make([]byte, n); rd.Read(buf); return buf }
	parent := "0x" + bytesToHex(readBytes(32))
	state := "0x" + bytesToHex(readBytes(32))
	bodyRoot := readBytes(32) // currently unused for reconstruction validation
	_ = bodyRoot
	_ = readBytes(32) // exec payload root placeholder
	sig := readBytes(96)
	var sigArr [96]byte
	copy(sigArr[:], sig)
	blk := &BeaconBlock{Slot: slot, ProposerIndex: proposer, ParentRoot: parent, StateRoot: state, Body: &BeaconBlockBody{ExecutionPayload: &ExecutionPayload{ // deterministic genesis payload
		ParentHash:            zeroHash32(),
		FeeRecipient:          zeroHexBytes(20),
		StateRoot:             state,
		ReceiptsRoot:          "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
		LogsBloom:             zeroBloom256(),
		PrevRandao:            zeroHash32(),
		BlockNumber:           "0x0",
		GasLimit:              "0x1388",
		GasUsed:               "0x0",
		Timestamp:             "0x0",
		ExtraData:             "0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa",
		BaseFeePerGas:         "0x0",
		BlockHash:             "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
		Transactions:          []string{},
		Withdrawals:           []string{},
		BlobGasUsed:           "0x0",
		ExcessBlobGas:         "0x0",
		ParentBeaconBlockRoot: zeroHash32(),
	}}}
	return &SignedBeaconBlock{Message: blk, Signature: sigArr}, nil
}

// computeSignedBeaconBlockRoot reuses existing header root (block root same formula slot..bodyRoot)
func computeSignedBeaconBlockRoot(sb *SignedBeaconBlock) string {
	// Build container structs
	var parent, state [32]byte
	copy(parent[:], hexToBytes32(sb.Message.ParentRoot))
	copy(state[:], hexToBytes32(sb.Message.StateRoot))
	cont := &SignedBeaconBlockContainer{Message: &BeaconBlockContainer{Slot: sb.Message.Slot, ProposerIndex: sb.Message.ProposerIndex, ParentRoot: parent, StateRoot: state, Body: &BeaconBlockBodyContainer{Payload: sb.Message.Body.ExecutionPayload}}, Signature: sb.Signature}
	root := ssz.HashSequential(cont)
	return "0x" + bytesToHex(root[:])
}

// logBlockFieldRoots logs key fields & per-field roots for a reconstructed block
func logBlockFieldRoots(sb *SignedBeaconBlock, root string) {
	bodyRoot := computeBeaconBodyRootSpec(sb.Message.Body.ExecutionPayload)
	fmt.Printf("BLOCK_LOG slot=%d parent=%s state=%s body_root=%s block_root=%s\n", sb.Message.Slot, sb.Message.ParentRoot, sb.Message.StateRoot, bodyRoot, root)
	// Body per-field roots already printed inside computeBeaconBodyRootSpec; also execution payload per-field inside computeExecutionPayloadRootSpec
}

// bytesToHex returns lowercase hex without 0x.
func bytesToHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[2*i] = hexdigits[v>>4]
		out[2*i+1] = hexdigits[v&0xf]
	}
	return string(out)
}

// sha256Sum returns the SHA256 hash of the input
func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// Simple SSZ-style merkleization (simplified version)
func merkleizeSHA256(chunks [][]byte) []byte {
	if len(chunks) == 0 {
		return make([]byte, 32)
	}
	if len(chunks) == 1 {
		return chunks[0]
	}

	// Pad to next power of 2
	n := 1
	for n < len(chunks) {
		n *= 2
	}

	// Pad with zero chunks
	padded := make([][]byte, n)
	copy(padded, chunks)
	for i := len(chunks); i < n; i++ {
		padded[i] = make([]byte, 32)
	}

	// Merkleize
	layer := padded
	for len(layer) > 1 {
		nextLayer := make([][]byte, len(layer)/2)
		for i := 0; i < len(layer); i += 2 {
			combined := make([]byte, 64)
			copy(combined, layer[i])
			copy(combined[32:], layer[i+1])
			nextLayer[i/2] = sha256Sum(combined)
		}
		layer = nextLayer
	}

	return layer[0]
}

// computeBeaconBodyRootWithStateRoot - updated to use complete ExecutionPayload for SSZ computation
func computeBeaconBodyRootWithStateRoot(payload *ExecutionPayload) string {
	fmt.Printf("SSZ_CALC: computeBeaconBodyRootWithStateRoot called (spec)\n")
	return computeBeaconBodyRootSpec(payload)
}

// computeBeaconBodyRootWithRealPayload - using complete execution payload for SSZ computation
func computeBeaconBodyRootWithRealPayload(payload *ExecutionPayload) string {
	fmt.Printf("SSZ_CALC: computeBeaconBodyRootWithRealPayload called (spec)\n")
	return computeBeaconBodyRootSpec(payload)
}

// Helper functions for hex parsing
func hexToBytes20(hex string) []byte {
	out := make([]byte, 20)
	if hex == "" {
		return out
	}
	core := strings.TrimPrefix(hex, "0x")
	for i := 0; i < 20 && i*2+1 < len(core); i++ {
		hi := fromHexNibble(core[2*i])
		lo := fromHexNibble(core[2*i+1])
		if hi >= 0 && lo >= 0 {
			out[i] = byte(hi<<4 | lo)
		}
	}
	return out
}

func hexToBytes256(hex string) []byte {
	out := make([]byte, 256)
	if hex == "" {
		return out
	}
	core := strings.TrimPrefix(hex, "0x")
	for i := 0; i < 256 && i*2+1 < len(core); i++ {
		hi := fromHexNibble(core[2*i])
		lo := fromHexNibble(core[2*i+1])
		if hi >= 0 && lo >= 0 {
			out[i] = byte(hi<<4 | lo)
		}
	}
	return out
}

func hexToUint64(hex string) uint64 {
	hex = strings.TrimPrefix(hex, "0x")
	if hex == "" {
		return 0
	}
	val := uint64(0)
	for i := 0; i < len(hex) && i < 16; i++ {
		digit := fromHexNibble(hex[i])
		if digit >= 0 {
			val = val*16 + uint64(digit)
		}
	}
	return val
}

func hexToUint256Bytes(hex string) []byte {
	out := make([]byte, 32)
	hex = strings.TrimPrefix(hex, "0x")
	if hex == "" {
		return out
	}
	// Parse as big-endian uint256 (most significant byte first)
	for i := 0; i < len(hex) && i < 64; i += 2 {
		bytePos := 31 - (len(hex)-2-i)/2 // Position from right (little-endian)
		if i+1 < len(hex) {
			hi := fromHexNibble(hex[i])
			lo := fromHexNibble(hex[i+1])
			if hi >= 0 && lo >= 0 {
				out[bytePos] = byte(hi<<4 | lo)
			}
		}
	}
	return out
}

// BeaconBlockBodyWithRealPayload represents a Deneb beacon block body with complete execution payload
type BeaconBlockBodyWithRealPayload struct {
	ExecutionPayload *ExecutionPayload
}

func (b *BeaconBlockBodyWithRealPayload) SizeSSZ(sizer *ssz.Sizer) uint32 { return 0 }

func (b *BeaconBlockBodyWithRealPayload) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		// Deneb BeaconBlockBody has exactly 12 fields as per Ethereum specification:
		// 0. randao_reveal: BLSSignature (96 bytes)
		// 1. eth1_data: Eth1Data
		// 2. graffiti: Bytes32
		// 3. proposer_slashings: List[ProposerSlashing, MAX_PROPOSER_SLASHINGS]
		// 4. attester_slashings: List[AttesterSlashing, MAX_ATTESTER_SLASHINGS]
		// 5. attestations: List[Attestation, MAX_ATTESTATIONS]
		// 6. deposits: List[Deposit, MAX_DEPOSITS]
		// 7. voluntary_exits: List[SignedVoluntaryExit, MAX_VOLUNTARY_EXITS]
		// 8. sync_aggregate: SyncAggregate
		// 9. execution_payload: ExecutionPayload (Deneb)
		// 10. bls_to_execution_changes: List[SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES]
		// 11. blob_kzg_commitments: List[KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK]

		var bodyChunks [12][32]byte

		// 0. randao_reveal (BLSSignature - 96 bytes = 3 chunks merged into one root)
		bodyChunks[0] = [32]byte{} // all zeros for now

		// 1. eth1_data (Eth1Data with 3 fields: deposit_root, deposit_count, block_hash)
		bodyChunks[1] = [32]byte{} // all zeros for now

		// 2. graffiti (Bytes32)
		bodyChunks[2] = [32]byte{} // all zeros

		// 3-7. Empty lists (5 fields)
		emptyListRoot := [32]byte{} // Empty list SSZ root is zero hash
		for i := 3; i <= 7; i++ {
			bodyChunks[i] = emptyListRoot
		}

		// 8. sync_aggregate (SyncAggregate)
		bodyChunks[8] = [32]byte{} // all zeros for now

		// 9. execution_payload (ExecutionPayload with REAL Deneb fields)
		execPayload := b.ExecutionPayload
		execPayloadRoot := computeDenebExecutionPayloadRoot(execPayload)
		copy(bodyChunks[9][:], execPayloadRoot)

		// 10. bls_to_execution_changes (empty list)
		bodyChunks[10] = emptyListRoot

		// 11. blob_kzg_commitments (empty list)
		bodyChunks[11] = emptyListRoot

		// Hash all 12 chunks into the SSZ hasher
		for _, chunk := range bodyChunks {
			ssz.HashStaticBytes(has, &chunk)
		}
	})
}

// computeDenebExecutionPayloadRoot computes the SSZ root for Deneb ExecutionPayload
func computeDenebExecutionPayloadRoot(payload *ExecutionPayload) []byte {
	// Deneb ExecutionPayload has exactly 17 fields as per specification:
	// 0. parent_hash: Hash32
	// 1. fee_recipient: ExecutionAddress (20 bytes)
	// 2. state_root: Bytes32
	// 3. receipts_root: Bytes32
	// 4. logs_bloom: ByteVector[BYTES_PER_LOGS_BLOOM] (256 bytes = 8 chunks)
	// 5. prev_randao: Bytes32
	// 6. block_number: uint64
	// 7. gas_limit: uint64
	// 8. gas_used: uint64
	// 9. timestamp: uint64
	// 10. extra_data: ByteList[MAX_EXTRA_DATA_BYTES]
	// 11. base_fee_per_gas: uint256
	// 12. block_hash: Hash32
	// 13. transactions: List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD]
	// 14. withdrawals: List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD]
	// 15. blob_gas_used: uint64 (NEW in Deneb)
	// 16. excess_blob_gas: uint64 (NEW in Deneb)

	var chunks [][32]byte

	// 0. parent_hash
	parentHash := [32]byte{}
	if payload.ParentHash != "" {
		copy(parentHash[:], hexToBytes32(payload.ParentHash))
	}
	chunks = append(chunks, parentHash)

	// 1. fee_recipient (20 bytes, left-padded to 32)
	feeRecipient := [32]byte{}
	if payload.FeeRecipient != "" {
		feeBytes := hexToBytes20(payload.FeeRecipient)
		copy(feeRecipient[:20], feeBytes)
	}
	chunks = append(chunks, feeRecipient)

	// 2. state_root (MOST IMPORTANT - this is the real execution state)
	stateRoot := [32]byte{}
	if payload.StateRoot != "" {
		copy(stateRoot[:], hexToBytes32(payload.StateRoot))
	}
	chunks = append(chunks, stateRoot)

	// 3. receipts_root
	receiptsRoot := [32]byte{}
	if payload.ReceiptsRoot != "" {
		copy(receiptsRoot[:], hexToBytes32(payload.ReceiptsRoot))
	} else {
		// Use empty receipts root (standard value for empty receipt list)
		emptyReceiptsRoot := hexToBytes32("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
		copy(receiptsRoot[:], emptyReceiptsRoot)
	}
	chunks = append(chunks, receiptsRoot)

	// 4. logs_bloom (256 bytes = 8 chunks)
	if payload.LogsBloom != "" && len(payload.LogsBloom) > 2 {
		bloomBytes := hexToBytes256(payload.LogsBloom)
		for i := 0; i < 8; i++ {
			var chunk [32]byte
			copy(chunk[:], bloomBytes[i*32:(i+1)*32])
			chunks = append(chunks, chunk)
		}
	} else {
		// Add 8 zero chunks for empty logs bloom
		for i := 0; i < 8; i++ {
			chunks = append(chunks, [32]byte{})
		}
	}

	// 5. prev_randao
	prevRandao := [32]byte{}
	if payload.PrevRandao != "" {
		copy(prevRandao[:], hexToBytes32(payload.PrevRandao))
	}
	chunks = append(chunks, prevRandao)

	// 6. block_number (uint64, little-endian in 32 bytes)
	blockNumber := [32]byte{}
	if payload.BlockNumber != "" {
		num := hexToUint64(payload.BlockNumber)
		for i := 0; i < 8; i++ {
			blockNumber[i] = byte(num >> (8 * i))
		}
	}
	chunks = append(chunks, blockNumber)

	// 7. gas_limit (uint64, little-endian in 32 bytes)
	gasLimit := [32]byte{}
	if payload.GasLimit != "" {
		limit := hexToUint64(payload.GasLimit)
		for i := 0; i < 8; i++ {
			gasLimit[i] = byte(limit >> (8 * i))
		}
	}
	chunks = append(chunks, gasLimit)

	// 8. gas_used (uint64, little-endian in 32 bytes)
	gasUsed := [32]byte{}
	if payload.GasUsed != "" {
		used := hexToUint64(payload.GasUsed)
		for i := 0; i < 8; i++ {
			gasUsed[i] = byte(used >> (8 * i))
		}
	}
	chunks = append(chunks, gasUsed)

	// 9. timestamp (uint64, little-endian in 32 bytes)
	timestamp := [32]byte{}
	if payload.Timestamp != "" {
		ts := hexToUint64(payload.Timestamp)
		for i := 0; i < 8; i++ {
			timestamp[i] = byte(ts >> (8 * i))
		}
	}
	chunks = append(chunks, timestamp)

	// 10. extra_data (ByteList - hash with length mixing)
	extraData := [32]byte{} // Empty list root for now
	chunks = append(chunks, extraData)

	// 11. base_fee_per_gas (uint256, little-endian in 32 bytes)
	baseFee := [32]byte{}
	if payload.BaseFeePerGas != "" {
		copy(baseFee[:], hexToUint256Bytes(payload.BaseFeePerGas))
	}
	chunks = append(chunks, baseFee)

	// 12. block_hash
	blockHash := [32]byte{}
	if payload.BlockHash != "" {
		copy(blockHash[:], hexToBytes32(payload.BlockHash))
	}
	chunks = append(chunks, blockHash)

	// 13. transactions (List - empty list root)
	transactions := [32]byte{} // Empty list root
	chunks = append(chunks, transactions)

	// 14. withdrawals (List - empty list root)
	withdrawals := [32]byte{} // Empty list root
	chunks = append(chunks, withdrawals)

	// 15. blob_gas_used (uint64, NEW in Deneb)
	blobGasUsed := [32]byte{}
	chunks = append(chunks, blobGasUsed)

	// 16. excess_blob_gas (uint64, NEW in Deneb)
	excessBlobGas := [32]byte{}
	chunks = append(chunks, excessBlobGas)

	// Convert to [][]byte for merkleization
	chunkBytes := make([][]byte, len(chunks))
	for i, chunk := range chunks {
		chunkBytes[i] = chunk[:]
	}

	return merkleizeSHA256(chunkBytes)
}

// ===== Spec-compliant SSZ helpers for body root (lists, vectors, mix_in_length) =====

// zero32 returns a 32-byte zero slice
func zero32() []byte { return make([]byte, 32) }

// mixInLength(root, length) per SSZ specification (Phase 0): hash(root || length_le_64)
// mixInLength(root, length) per SSZ: sha256( root || length_le_64 ) where input is 32+8=40 bytes (NOT padded to 64)
func mixInLength(root []byte, length uint64) []byte {
	buf := make([]byte, 40)
	copy(buf[:32], root)
	for i := 0; i < 8; i++ {
		buf[32+i] = byte(length >> (8 * i))
	}
	return sha256Sum(buf)
}

// merkleizeChunks pads chunks to next power of two and merkleizes (no length mix-in)
func merkleizeChunks(chunks [][]byte) []byte {
	if len(chunks) == 0 {
		return zero32()
	}
	// Ensure each chunk is 32 bytes
	for _, c := range chunks {
		if len(c) != 32 {
			panic("chunk not 32 bytes")
		}
	}
	n := 1
	for n < len(chunks) {
		n <<= 1
	}
	padded := make([][]byte, n)
	copy(padded, chunks)
	for i := len(chunks); i < n; i++ {
		padded[i] = zero32()
	}
	layer := padded
	for len(layer) > 1 {
		next := make([][]byte, len(layer)/2)
		for i := 0; i < len(layer); i += 2 {
			combined := append(layer[i], layer[i+1]...)
			h := sha256Sum(combined)
			next[i/2] = h
		}
		layer = next
	}
	return layer[0]
}

// packBytesVector packs a fixed-size byte vector into 32-byte chunks
func packBytesVector(b []byte) [][]byte {
	if len(b)%32 != 0 {
		// pad last chunk to 32
		padLen := 32 - (len(b) % 32)
		b = append(b, make([]byte, padLen)...)
	}
	chunks := make([][]byte, len(b)/32)
	for i := 0; i < len(chunks); i++ {
		chunk := make([]byte, 32)
		copy(chunk, b[i*32:(i+1)*32])
		chunks[i] = chunk
	}
	return chunks
}

// hashFixedComposite takes field roots (already 32 bytes each) and merkleizes them
func hashFixedComposite(fieldRoots [][]byte) []byte {
	return merkleizeChunks(fieldRoots)
}

// emptyListRoot returns SSZ hash_tree_root([]) = mixInLength(zero32, 0)
func emptyListRoot() []byte { return mixInLength(zero32(), 0) }

// hashUint64 little-endian padded to 32 bytes
func hashUint64(v uint64) []byte {
	b := make([]byte, 32)
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
	return b
}

// hexToBytes32Slice returns 32 bytes (copies existing helper hexToBytes32 returning [32]byte presumably)
// We'll re-use hexToBytes32(h) which returns [32]byte

// computeByteListRoot computes SSZ root of a ByteList
func computeByteListRoot(hexData string) []byte {
	if hexData == "" || hexData == "0x" {
		return mixInLength(zero32(), 0)
	}
	core := strings.TrimPrefix(hexData, "0x")
	b, err := hex.DecodeString(core)
	if err != nil {
		return mixInLength(zero32(), 0)
	}
	chunks := packBytesVector(b)
	mer := merkleizeChunks(chunks)
	return mixInLength(mer, uint64(len(b)))
}

func computeTransactionByteListRoot(txHex string) []byte { return computeByteListRoot(txHex) }

// computeListRootWithLimit computes SSZ List[T, N] root properly considering the limit N
// For empty lists, this ensures different roots for different list types due to different tree heights
func computeListRootWithLimit(elementRoots [][]byte, length uint64, limit uint64) []byte {
	if len(elementRoots) == 0 {
		// For empty list: mixInLength(merkleize([], limit), 0)
		// merkleize([]) with limit creates zero-filled tree to appropriate height for the limit
		emptyMerkleRoot := merkleizeToLimit([][]byte{}, limit)
		return mixInLength(emptyMerkleRoot, 0)
	}
	mer := merkleizeChunks(elementRoots)
	return mixInLength(mer, length)
}

// merkleizeToLimit creates a merkle tree for the given chunks, padding with zeros to the tree height needed for the limit
func merkleizeToLimit(chunks [][]byte, limit uint64) []byte {
	if limit == 0 {
		return zero32()
	}

	// Find the tree height needed for this limit
	// Tree height = ceil(log2(limit))
	height := 0
	temp := limit - 1
	for temp > 0 {
		height++
		temp >>= 1
	}

	// Pad chunks to the required number for this height
	requiredLeaves := uint64(1) << height
	paddedChunks := make([][]byte, requiredLeaves)

	// Copy existing chunks
	for i := 0; i < len(chunks) && i < int(requiredLeaves); i++ {
		paddedChunks[i] = chunks[i]
	}

	// Pad with zero chunks
	for i := len(chunks); i < int(requiredLeaves); i++ {
		paddedChunks[i] = zero32()
	}

	return merkleizeChunks(paddedChunks)
}

func computeListRoot(elementRoots [][]byte, length uint64) []byte {
	if len(elementRoots) == 0 {
		return mixInLength(zero32(), 0)
	}
	mer := merkleizeChunks(elementRoots)
	return mixInLength(mer, length)
}

// computeExecutionPayloadRootSpec builds an execution payload root using Deneb 17 fields with proper distinct list roots.
func computeExecutionPayloadRootSpec(p *ExecutionPayload) []byte {
	// Normalize hex inputs
	parent := hexToBytes32(p.ParentHash)
	state := hexToBytes32(p.StateRoot)
	receipts := hexToBytes32(p.ReceiptsRoot)
	prevRandao := hexToBytes32(p.PrevRandao)
	blockHash := hexToBytes32(p.BlockHash)
	// NOTE: parent_beacon_block_root is Cancun (post-Deneb); excluded for Deneb body root.

	// Logs bloom (256 bytes). Expect hex string of length 0x + 512 hex chars. If empty produce 256 zero bytes
	logsBloomBytes := make([]byte, 256)
	// simple parse (skip correctness if malformed)
	if len(p.LogsBloom) > 2 {
		hb := p.LogsBloom[2:]
		if len(hb) >= 512 {
			for i := 0; i < 256 && i*2+1 < len(hb); i++ {
				var v byte
				fmt.Sscanf(hb[i*2:i*2+2], "%02x", &v)
				logsBloomBytes[i] = v
			}
		}
	}
	logsBloomChunks := packBytesVector(logsBloomBytes) // 256 bytes -> 8 * 32-byte chunks
	logsBloomRoot := merkleizeChunks(logsBloomChunks)

	// fee_recipient (20 bytes) inside 32 byte chunk
	feeRecipient := make([]byte, 32)
	if len(p.FeeRecipient) > 2 {
		hb := p.FeeRecipient[2:]
		// expect 40 hex chars
		tmp := make([]byte, 20)
		for i := 0; i < 20 && i*2+1 < len(hb); i++ {
			var v byte
			fmt.Sscanf(hb[i*2:i*2+2], "%02x", &v)
			tmp[i] = v
		}
		copy(feeRecipient[:20], tmp)
	}

	// extra_data (ByteList) root
	extraDataRoot := computeByteListRoot(p.ExtraData)

	// uint64 parsing helpers
	parseUint := func(hexStr string) uint64 {
		if hexStr == "" {
			return 0
		}
		v := uint64(0)
		fmt.Sscanf(hexStr, "%#x", &v)
		return v
	}

	blockNumber := parseUint(p.BlockNumber)
	gasLimit := parseUint(p.GasLimit)
	gasUsed := parseUint(p.GasUsed)
	timestamp := parseUint(p.Timestamp)
	blobGasUsed := parseUint(p.BlobGasUsed)
	excessBlobGas := parseUint(p.ExcessBlobGas)

	// base_fee_per_gas uint256 (we treat as 32 bytes). Assume hex fits into 32 bytes.
	baseFee := make([]byte, 32)
	if len(p.BaseFeePerGas) > 2 {
		// parse minimal low 8 bytes little-endian (simplified)
	}

	// transactions list (List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD])
	var txRoots [][]byte
	for _, tx := range p.Transactions {
		txRoots = append(txRoots, computeTransactionByteListRoot(tx))
	}
	transactionsRoot := computeListRootWithLimit(txRoots, uint64(len(txRoots)), MAX_TRANSACTIONS_PER_PAYLOAD)

	// withdrawals list (List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD]) - currently empty
	withdrawalsRoot := computeListRootWithLimit(nil, 0, MAX_WITHDRAWALS_PER_PAYLOAD)

	fieldRoots := [][]byte{
		parent[:],                 // 0 parent_hash
		feeRecipient,              // 1 fee_recipient (padded)
		state[:],                  // 2 state_root
		receipts[:],               // 3 receipts_root
		logsBloomRoot,             // 4 logs_bloom
		prevRandao[:],             // 5 prev_randao
		hashUint64(blockNumber),   // 6 block_number
		hashUint64(gasLimit),      // 7 gas_limit
		hashUint64(gasUsed),       // 8 gas_used
		hashUint64(timestamp),     // 9 timestamp
		extraDataRoot,             // 10 extra_data
		baseFee,                   // 11 base_fee_per_gas (uint256) zero
		blockHash[:],              // 12 block_hash
		transactionsRoot,          // 13 transactions
		withdrawalsRoot,           // 14 withdrawals
		hashUint64(blobGasUsed),   // 15 blob_gas_used
		hashUint64(excessBlobGas), // 16 excess_blob_gas
	}

	// Debug: log per-field roots (execution payload) once per call
	if true {
		labels := []string{"parent_hash", "fee_recipient", "state_root", "receipts_root", "logs_bloom", "prev_randao", "block_number", "gas_limit", "gas_used", "timestamp", "extra_data", "base_fee_per_gas", "block_hash", "transactions", "withdrawals", "blob_gas_used", "excess_blob_gas", "parent_beacon_block_root"}
		for i, r := range fieldRoots {
			fmt.Printf("EXEC_FIELD_ROOT[%d] %s=0x%s\n", i, labels[i], bytesToHex(r))
		}
	}

	// Merkleize 17 roots (pad to next power-of-two).
	execRoot := merkleizeChunks(fieldRoots)
	return execRoot
}

// computeBeaconBodyRootSpec builds the body root for Deneb using zero/default and provided payload.
func computeBeaconBodyRootSpec(payload *ExecutionPayload) string {
	// 0 randao_reveal (BLSSignature 96 bytes -> 3 chunks all zero)
	randaoChunks := [][]byte{zero32(), zero32(), zero32()}
	randaoRoot := merkleizeChunks(randaoChunks)

	// For visibility, log signature component root (should be deterministic)
	if true {
		fmt.Printf("RANDAO_REVEAL_ROOT=0x%s\n", bytesToHex(randaoRoot))
	}

	// 1 eth1_data (deposit_root, deposit_count, block_hash) all zero
	// Use non-zero fixed test values so that eth1_data root != randao root
	eth1DepositRoot := hexToBytes32("0x0101010101010101010101010101010101010101010101010101010101010101")
	eth1DepositCount := hashUint64(1) // little-endian 0x01
	eth1BlockHash := hexToBytes32("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
	eth1Root := merkleizeChunks([][]byte{eth1DepositRoot, eth1DepositCount, eth1BlockHash})
	if true {
		fmt.Printf("ETH1_DATA_ROOT=0x%s deposit_root=0x%s deposit_count=%d block_hash=0x%s\n", bytesToHex(eth1Root), bytesToHex(eth1DepositRoot), 1, bytesToHex(eth1BlockHash))
	}

	// 2 graffiti zero bytes32
	graffitiRoot := zero32()

	// 3-7 empty lists
	emptyListRootVal := mixInLength(zero32(), 0)
	proposerSlashingsRoot := emptyListRootVal
	attesterSlashingsRoot := emptyListRootVal
	attestationsRoot := emptyListRootVal
	depositsRoot := emptyListRootVal
	voluntaryExitsRoot := emptyListRootVal

	// 8 sync_aggregate (bits + signature)
	// bits: 512 bits (64 bytes) -> 2 chunks zeros -> rootBits
	bitsChunks := packBytesVector(make([]byte, 64))
	bitsRoot := merkleizeChunks(bitsChunks)
	sigRoot := merkleizeChunks([][]byte{zero32(), zero32(), zero32()})
	syncAggregateRoot := merkleizeChunks([][]byte{bitsRoot, sigRoot})

	// 9 execution_payload root spec
	execRoot := computeExecutionPayloadRootSpec(payload)

	// 10 bls_to_execution_changes empty list
	blsToExecChangesRoot := emptyListRootVal

	// 11 blob_kzg_commitments empty list
	blobKZGCommitmentsRoot := emptyListRootVal

	bodyFieldRoots := [][]byte{
		randaoRoot,
		eth1Root,
		graffitiRoot,
		proposerSlashingsRoot,
		attesterSlashingsRoot,
		attestationsRoot,
		depositsRoot,
		voluntaryExitsRoot,
		syncAggregateRoot,
		execRoot,
		blsToExecChangesRoot,
		blobKZGCommitmentsRoot,
	}

	if true { // debug body field roots
		bodyLabels := []string{"randao_reveal", "eth1_data", "graffiti", "proposer_slashings", "attester_slashings", "attestations", "deposits", "voluntary_exits", "sync_aggregate", "execution_payload", "bls_to_execution_changes", "blob_kzg_commitments"}
		for i, r := range bodyFieldRoots {
			fmt.Printf("BODY_FIELD_ROOT[%d] %s=0x%s\n", i, bodyLabels[i], bytesToHex(r))
		}
	}

	bodyRoot := merkleizeChunks(bodyFieldRoots)
	return "0x" + bytesToHex(bodyRoot)
}

// BeaconBlockBodyDeneb represents a Deneb beacon block body for SSZ computation
type BeaconBlockBodyDeneb struct {
	StateRoot   string
	BlockNumber uint64
	Timestamp   uint64
}

func (b *BeaconBlockBodyDeneb) SizeSSZ(sizer *ssz.Sizer) uint32 { return 0 }

func (b *BeaconBlockBodyDeneb) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		z32 := make([]byte, 32)

		// Helper function to convert uint64 to 32-byte little-endian
		uint64ToBytes32 := func(v uint64) []byte {
			b := make([]byte, 32)
			for i := 0; i < 8; i++ {
				b[i] = byte(v >> (8 * i))
			}
			return b
		}

		// Helper function to convert hex string to 32 bytes
		hexToBytes32 := func(hex string) []byte {
			core := strings.TrimPrefix(normalizeRoot(hex), "0x")
			out := make([]byte, 32)
			for i := 0; i < 32 && i*2+1 < len(core); i++ {
				hi := fromHexNibble(core[2*i])
				lo := fromHexNibble(core[2*i+1])
				if hi >= 0 && lo >= 0 {
					out[i] = byte(hi<<4 | lo)
				}
			}
			return out
		}

		// Helper function for empty list root (for SSZ lists)
		emptyListRoot := func() []byte {
			preimage := make([]byte, 64) // 32 zero root + 32-byte length (all zeros)
			h := sha256.Sum256(preimage)
			return h[:]
		}

		// BLS signature root (96 bytes = 3 chunks of 32 bytes)
		blsSignatureRoot := func() []byte {
			chunks := [][]byte{z32, z32, z32}
			return merkleizeSHA256(chunks)
		}()

		// Sync aggregate root
		syncAggregateRoot := func() []byte {
			bitsRoot := merkleizeSHA256([][]byte{z32, z32}) // 64 bytes for sync committee bits
			return merkleizeSHA256([][]byte{bitsRoot, blsSignatureRoot})
		}()

		// ETH1 data root
		eth1DataRoot := func() []byte {
			depositRoot := z32
			depositCount := uint64ToBytes32(0)
			blockHash := z32
			// Pad to power of 2 (4 elements)
			leaves := [][]byte{depositRoot, depositCount, blockHash, z32}
			return merkleizeSHA256(leaves)
		}()

		// Execution payload root with real data
		execPayloadRoot := func() []byte {
			// Use the actual state root from execution payload
			stateRootBytes := hexToBytes32(b.StateRoot)

			// Standard execution payload fields for Deneb
			roots := [][]byte{
				z32,            // parent_hash
				z32,            // fee_recipient (20 bytes, padded)
				stateRootBytes, // state_root (actual from Geth)
				hexToBytes32("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"), // receipts_root (empty receipts root)
				merkleizeSHA256([][]byte{z32, z32, z32, z32, z32, z32, z32, z32}),                  // logs_bloom (256 bytes = 8 chunks)
				z32,                            // prev_randao
				uint64ToBytes32(b.BlockNumber), // block_number (actual from Geth)
				uint64ToBytes32(5000),          // gas_limit (match JSON response)
				uint64ToBytes32(0),             // gas_used
				uint64ToBytes32(b.Timestamp),   // timestamp (actual from Geth)
				emptyListRoot(),                // extra_data (empty list)
				uint64ToBytes32(0),             // base_fee_per_gas
				z32,                            // block_hash
				emptyListRoot(),                // transactions (empty list)
				emptyListRoot(),                // withdrawals (empty list)
				uint64ToBytes32(0),             // blob_gas_used (Deneb)
				uint64ToBytes32(0),             // excess_blob_gas (Deneb)
			}

			return merkleizeSHA256(roots)
		}()

		// Beacon block body fields for Deneb
		bodyFields := [][]byte{
			blsSignatureRoot,  // randao_reveal
			eth1DataRoot,      // eth1_data
			z32,               // graffiti
			emptyListRoot(),   // proposer_slashings
			emptyListRoot(),   // attester_slashings
			emptyListRoot(),   // attestations
			emptyListRoot(),   // deposits
			emptyListRoot(),   // voluntary_exits
			syncAggregateRoot, // sync_aggregate (Altair+)
			execPayloadRoot,   // execution_payload (Bellatrix+)
			emptyListRoot(),   // bls_to_execution_changes (Capella+)
			emptyListRoot(),   // blob_kzg_commitments (Deneb+)
		}

		// Hash each field into the SSZ hasher
		for _, field := range bodyFields {
			var arr [32]byte
			copy(arr[:], field)
			ssz.HashStaticBytes(has, &arr)
		}
	})
}

// computeBeaconHeaderRoot computes the beacon block header root using proper SSZ
func computeBeaconHeaderRoot(h beaconHeaderFields) string {
	// New: compute both legacy (library-based) root and spec-compliant manual merkle root.
	header := &BeaconHeaderSSZ{
		Slot:          uint64(h.Slot),
		ProposerIndex: 0, // Always 0 in our simplified implementation
		ParentRoot:    h.ParentRoot,
		StateRoot:     h.StateRoot,
		BodyRoot:      h.BodyRoot,
	}

	// Add debug logging
	fmt.Printf("HEADER_ROOT_CALC: Computing beacon header root for:\n")
	fmt.Printf("HEADER_ROOT_CALC:   Slot: %d\n", header.Slot)
	fmt.Printf("HEADER_ROOT_CALC:   ProposerIndex: %d\n", header.ProposerIndex)
	fmt.Printf("HEADER_ROOT_CALC:   ParentRoot: %s\n", header.ParentRoot)
	fmt.Printf("HEADER_ROOT_CALC:   StateRoot: %s\n", header.StateRoot)
	fmt.Printf("HEADER_ROOT_CALC:   BodyRoot: %s\n", header.BodyRoot)

	// Library-based root (current implementation)
	libRoot := ssz.HashSequential(header)
	libResult := "0x" + bytesToHex(libRoot[:])

	// Spec-compliant manual root (explicit merkleization) for cross-check
	specResult := computeBeaconHeaderRootSpec(uint64(h.Slot), 0, h.ParentRoot, h.StateRoot, h.BodyRoot)

	if libResult != specResult {
		fmt.Printf("HEADER_ROOT_CALC:   WARNING mismatch library_root=%s spec_root=%s (using spec_root)\n", libResult, specResult)
	} else {
		fmt.Printf("HEADER_ROOT_CALC:   Result: %s (lib==spec)\n", libResult)
	}

	// Diagnostic: compute alternative variants and log if any matches external mismatches
	altBE := computeBeaconHeaderRootSpecBigEndian(uint64(h.Slot), 0, h.ParentRoot, h.StateRoot, h.BodyRoot)
	altRe := computeBeaconHeaderRootSpecReordered(uint64(h.Slot), 0, h.ParentRoot, h.StateRoot, h.BodyRoot)
	fmt.Printf("HEADER_ROOT_CALC:   Variant big-endian: %s\n", altBE)
	fmt.Printf("HEADER_ROOT_CALC:   Variant reordered: %s\n", altRe)

	// Prefer specResult to align with geth expectations.
	return specResult
}

// BeaconHeaderSSZ represents a beacon block header for SSZ computation
type BeaconHeaderSSZ struct {
	Slot          uint64
	ProposerIndex uint64
	ParentRoot    string
	StateRoot     string
	BodyRoot      string
}

func (h *BeaconHeaderSSZ) SizeSSZ(sizer *ssz.Sizer) uint32 { return 0 }

func (h *BeaconHeaderSSZ) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		// BeaconBlockHeader according to Ethereum spec has exactly 5 fields:
		// 0. slot: uint64
		// 1. proposer_index: uint64
		// 2. parent_root: Root (32 bytes)
		// 3. state_root: Root (32 bytes)
		// 4. body_root: Root (32 bytes)

		// Create 5 chunks for the header fields
		var headerChunks [5][32]byte

		// 0. slot (uint64) - little-endian encoding in first 8 bytes
		slotBytes := make([]byte, 8)
		for i := 0; i < 8; i++ {
			slotBytes[i] = byte(h.Slot >> (8 * i))
		}
		copy(headerChunks[0][:8], slotBytes)
		// remaining 24 bytes are zero-padded

		// 1. proposer_index (uint64) - little-endian encoding in first 8 bytes
		proposerBytes := make([]byte, 8)
		for i := 0; i < 8; i++ {
			proposerBytes[i] = byte(h.ProposerIndex >> (8 * i))
		}
		copy(headerChunks[1][:8], proposerBytes)
		// remaining 24 bytes are zero-padded

		// 2. parent_root (32 bytes)
		parentRoot := hexToBytes32(h.ParentRoot)
		copy(headerChunks[2][:], parentRoot)

		// 3. state_root (32 bytes)
		stateRoot := hexToBytes32(h.StateRoot)
		copy(headerChunks[3][:], stateRoot)

		// 4. body_root (32 bytes)
		bodyRoot := hexToBytes32(h.BodyRoot)
		copy(headerChunks[4][:], bodyRoot)

		// Hash all 5 chunks into the SSZ hasher
		for _, chunk := range headerChunks {
			ssz.HashStaticBytes(has, &chunk)
		}
	})
} // computeBeaconHeaderLeaves - simplified version for computing header chunks
func computeBeaconHeaderLeaves(h beaconHeaderFields) [][]byte {
	// Create simple chunks from header data
	chunks := make([][]byte, 4)

	// Slot as bytes
	slotChunk := make([]byte, 32)
	for i := 0; i < 8; i++ {
		slotChunk[i] = byte(uint64(h.Slot) >> (8 * i))
	}
	chunks[0] = slotChunk

	// ParentRoot as bytes
	chunks[1] = hexToBytes32(h.ParentRoot)

	// StateRoot as bytes
	chunks[2] = hexToBytes32(h.StateRoot)

	// BodyRoot as bytes
	chunks[3] = hexToBytes32(h.BodyRoot)

	return chunks
}

// SSZ structures for proper field calculations (instead of hardcoded constants)

// BLSSignature represents a 96-byte BLS signature
type BLSSignature struct {
	Data [96]byte
}

func (b *BLSSignature) SizeSSZ(s *ssz.Sizer) uint32 { return 96 }
func (b *BLSSignature) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		// 96 bytes = 3 chunks of 32 bytes each
		chunks := make([][]byte, 3)
		for i := 0; i < 3; i++ {
			chunk := make([]byte, 32)
			copy(chunk, b.Data[i*32:(i+1)*32])
			chunks[i] = chunk
		}
		root := merkleizeSHA256(chunks)
		ssz.HashStaticBytes(has, (*[32]byte)(root))
	})
}

// Bytes32 represents a 32-byte value
type Bytes32 struct {
	Data [32]byte
}

func (b *Bytes32) SizeSSZ(s *ssz.Sizer) uint32 { return 32 }
func (b *Bytes32) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		ssz.HashStaticBytes(has, &b.Data)
	})
}

// Eth1Data represents Ethereum 1.0 data
type Eth1Data struct {
	DepositRoot  string
	DepositCount uint64
	BlockHash    string
}

func (e *Eth1Data) SizeSSZ(s *ssz.Sizer) uint32 { return 72 }
func (e *Eth1Data) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		depositRoot := hexToBytes32(e.DepositRoot)
		depositCount := hashUint64(e.DepositCount)
		blockHash := hexToBytes32(e.BlockHash)
		chunks := [][]byte{depositRoot, depositCount, blockHash}
		root := merkleizeSHA256(chunks)
		ssz.HashStaticBytes(has, (*[32]byte)(root))
	})
}

// Empty list structures
type ProposerSlashingsList struct{}

func (p *ProposerSlashingsList) SizeSSZ(s *ssz.Sizer) uint32 { return 0 }
func (p *ProposerSlashingsList) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		// Empty list with max limit
		emptyRoot := mixInLength(zero32(), 0)
		ssz.HashStaticBytes(has, (*[32]byte)(emptyRoot))
	})
}

type AttesterSlashingsList struct{}

func (a *AttesterSlashingsList) SizeSSZ(s *ssz.Sizer) uint32 { return 0 }
func (a *AttesterSlashingsList) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		emptyRoot := mixInLength(zero32(), 0)
		ssz.HashStaticBytes(has, (*[32]byte)(emptyRoot))
	})
}

type AttestationsList struct{}

func (a *AttestationsList) SizeSSZ(s *ssz.Sizer) uint32 { return 0 }
func (a *AttestationsList) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		emptyRoot := mixInLength(zero32(), 0)
		ssz.HashStaticBytes(has, (*[32]byte)(emptyRoot))
	})
}

type DepositsList struct{}

func (d *DepositsList) SizeSSZ(s *ssz.Sizer) uint32 { return 0 }
func (d *DepositsList) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		emptyRoot := mixInLength(zero32(), 0)
		ssz.HashStaticBytes(has, (*[32]byte)(emptyRoot))
	})
}

type VoluntaryExitsList struct{}

func (v *VoluntaryExitsList) SizeSSZ(s *ssz.Sizer) uint32 { return 0 }
func (v *VoluntaryExitsList) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		emptyRoot := mixInLength(zero32(), 0)
		ssz.HashStaticBytes(has, (*[32]byte)(emptyRoot))
	})
}

type BLSToExecutionChangesList struct{}

func (b *BLSToExecutionChangesList) SizeSSZ(s *ssz.Sizer) uint32 { return 0 }
func (b *BLSToExecutionChangesList) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		emptyRoot := mixInLength(zero32(), 0)
		ssz.HashStaticBytes(has, (*[32]byte)(emptyRoot))
	})
}

type BlobKZGCommitmentsList struct{}

func (b *BlobKZGCommitmentsList) SizeSSZ(s *ssz.Sizer) uint32 { return 0 }
func (b *BlobKZGCommitmentsList) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		emptyRoot := mixInLength(zero32(), 0)
		ssz.HashStaticBytes(has, (*[32]byte)(emptyRoot))
	})
}

// SyncAggregate represents sync committee aggregate
type SyncAggregate struct {
	SyncCommitteeBits      []byte
	SyncCommitteeSignature *BLSSignature
}

func (s *SyncAggregate) SizeSSZ(sz *ssz.Sizer) uint32 { return 160 }
func (s *SyncAggregate) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		// Bits: 64 bytes = 2 chunks
		bitsChunks := make([][]byte, 2)
		for i := 0; i < 2; i++ {
			chunk := make([]byte, 32)
			if i*32 < len(s.SyncCommitteeBits) {
				copy(chunk, s.SyncCommitteeBits[i*32:min((i+1)*32, len(s.SyncCommitteeBits))])
			}
			bitsChunks[i] = chunk
		}
		bitsRoot := merkleizeSHA256(bitsChunks)

		// Signature root
		sigRoot := ssz.HashSequential(s.SyncCommitteeSignature)

		// Container: [bits_root, signature_root]
		containerChunks := [][]byte{bitsRoot, sigRoot[:]}
		containerRoot := merkleizeSHA256(containerChunks)
		ssz.HashStaticBytes(has, (*[32]byte)(containerRoot))
	})
}

// ExecutionPayloadSSZ wraps ExecutionPayload for SSZ
type ExecutionPayloadSSZ struct {
	Payload *ExecutionPayload
}

func (e *ExecutionPayloadSSZ) SizeSSZ(s *ssz.Sizer) uint32 { return 0 }
func (e *ExecutionPayloadSSZ) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		// Use existing execution payload root computation
		rootBytes := computeExecutionPayloadRootSpec(e.Payload)
		ssz.HashStaticBytes(has, (*[32]byte)(rootBytes))
	})
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// BeaconBlockBodyCheck - SSZ body structure for self-check
type BeaconBlockBodyCheck struct {
	Payload *ExecutionPayload
}

func (b *BeaconBlockBodyCheck) SizeSSZ(s *ssz.Sizer) uint32 { return 0 }
func (b *BeaconBlockBodyCheck) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		// Use proper SSZ structures instead of hardcoded constants

		// 0. randao_reveal: BLSSignature (96 bytes)
		randaoReveal := &BLSSignature{}
		randaoRoot := ssz.HashSequential(randaoReveal)
		log.Printf("BODY_FIELD_ROOT[0] randao_reveal: 0x%x", randaoRoot[:])
		ssz.HashStaticBytes(has, &randaoRoot)

		// 1. eth1_data: Eth1Data
		eth1Data := &Eth1Data{
			DepositRoot:  "0x0101010101010101010101010101010101010101010101010101010101010101",
			DepositCount: 1,
			BlockHash:    "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
		}
		eth1Root := ssz.HashSequential(eth1Data)
		log.Printf("BODY_FIELD_ROOT[1] eth1_data: 0x%x", eth1Root[:])
		ssz.HashStaticBytes(has, &eth1Root)

		// 2. graffiti: Bytes32
		graffiti := &Bytes32{}
		graffitiRoot := ssz.HashSequential(graffiti)
		log.Printf("BODY_FIELD_ROOT[2] graffiti: 0x%x", graffitiRoot[:])
		ssz.HashStaticBytes(has, &graffitiRoot)

		// 3. proposer_slashings: List[ProposerSlashing, MAX_PROPOSER_SLASHINGS]
		proposerSlashings := &ProposerSlashingsList{}
		proposerRoot := ssz.HashSequential(proposerSlashings)
		log.Printf("BODY_FIELD_ROOT[3] proposer_slashings: 0x%x", proposerRoot[:])
		ssz.HashStaticBytes(has, &proposerRoot)

		// 4. attester_slashings: List[AttesterSlashing, MAX_ATTESTER_SLASHINGS]
		attesterSlashings := &AttesterSlashingsList{}
		attesterRoot := ssz.HashSequential(attesterSlashings)
		log.Printf("BODY_FIELD_ROOT[4] attester_slashings: 0x%x", attesterRoot[:])
		ssz.HashStaticBytes(has, &attesterRoot)

		// 5. attestations: List[Attestation, MAX_ATTESTATIONS]
		attestations := &AttestationsList{}
		attestationsRoot := ssz.HashSequential(attestations)
		log.Printf("BODY_FIELD_ROOT[5] attestations: 0x%x", attestationsRoot[:])
		ssz.HashStaticBytes(has, &attestationsRoot)

		// 6. deposits: List[Deposit, MAX_DEPOSITS]
		deposits := &DepositsList{}
		depositsRoot := ssz.HashSequential(deposits)
		log.Printf("BODY_FIELD_ROOT[6] deposits: 0x%x", depositsRoot[:])
		ssz.HashStaticBytes(has, &depositsRoot)

		// 7. voluntary_exits: List[SignedVoluntaryExit, MAX_VOLUNTARY_EXITS]
		voluntaryExits := &VoluntaryExitsList{}
		exitsRoot := ssz.HashSequential(voluntaryExits)
		log.Printf("BODY_FIELD_ROOT[7] voluntary_exits: 0x%x", exitsRoot[:])
		ssz.HashStaticBytes(has, &exitsRoot)

		// 8. sync_aggregate: SyncAggregate
		syncAggregate := &SyncAggregate{
			SyncCommitteeBits:      make([]byte, 64), // 512 bits = 64 bytes, all zeros
			SyncCommitteeSignature: &BLSSignature{},  // 96 bytes, all zeros
		}
		syncRoot := ssz.HashSequential(syncAggregate)
		log.Printf("BODY_FIELD_ROOT[8] sync_aggregate: 0x%x", syncRoot[:])
		ssz.HashStaticBytes(has, &syncRoot)

		// 9. execution_payload: ExecutionPayload
		execPayload := &ExecutionPayloadSSZ{Payload: b.Payload}
		execRoot := ssz.HashSequential(execPayload)
		log.Printf("BODY_FIELD_ROOT[9] execution_payload: 0x%x", execRoot[:])
		ssz.HashStaticBytes(has, &execRoot)

		// 10. bls_to_execution_changes: List[SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES]
		blsToExecChanges := &BLSToExecutionChangesList{}
		blsRoot := ssz.HashSequential(blsToExecChanges)
		log.Printf("BODY_FIELD_ROOT[10] bls_to_execution_changes: 0x%x", blsRoot[:])
		ssz.HashStaticBytes(has, &blsRoot)

		// 11. blob_kzg_commitments: List[KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK]
		blobCommitments := &BlobKZGCommitmentsList{}
		blobRoot := ssz.HashSequential(blobCommitments)
		log.Printf("BODY_FIELD_ROOT[11] blob_kzg_commitments: 0x%x", blobRoot[:])
		ssz.HashStaticBytes(has, &blobRoot)
	})
}

// BeaconBlockCheck - SSZ block container for self-check; its root should match header root we export
type BeaconBlockCheck struct {
	Slot          uint64
	ProposerIndex uint64
	ParentRoot    string
	StateRoot     string
	Body          *BeaconBlockBodyCheck
}

func (b *BeaconBlockCheck) SizeSSZ(s *ssz.Sizer) uint32 { return 0 }
func (b *BeaconBlockCheck) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
		// Compute body root first
		bodyRoot := ssz.HashSequential(b.Body)
		// 5 header chunks: slot, proposer_index, parent_root, state_root, body_root
		var chunks [5][32]byte
		for i := 0; i < 8; i++ {
			chunks[0][i] = byte(b.Slot >> (8 * i))
		}
		for i := 0; i < 8; i++ {
			chunks[1][i] = byte(b.ProposerIndex >> (8 * i))
		}
		copy(chunks[2][:], hexToBytes32(b.ParentRoot))
		copy(chunks[3][:], hexToBytes32(b.StateRoot))
		copy(chunks[4][:], bodyRoot[:])
		for i := 0; i < 5; i++ {
			ssz.HashStaticBytes(has, &chunks[i])
		}
	})
}

// computeBeaconHeaderRootSpec performs a spec-faithful SSZ hash_tree_root of BeaconBlockHeader:
// root = merkleize(pack([slot, proposer_index, parent_root, state_root, body_root]))
// where basic uint64 values are little-endian 8 bytes, then right padded inside 32-byte chunks.
func computeBeaconHeaderRootSpec(slot uint64, proposerIndex uint64, parentRootHex, stateRootHex, bodyRootHex string) string {
	// Prepare 5 chunks
	chunks := make([][]byte, 5)

	mkUint64Chunk := func(v uint64) []byte {
		b := make([]byte, 32)
		for i := 0; i < 8; i++ { // little-endian
			b[i] = byte(v >> (8 * i))
		}
		return b
	}
	mkRootChunk := func(h string) []byte { return hexToBytes32(h)[:] } // already 32 bytes

	chunks[0] = mkUint64Chunk(slot)
	chunks[1] = mkUint64Chunk(proposerIndex)
	chunks[2] = mkRootChunk(parentRootHex)
	chunks[3] = mkRootChunk(stateRootHex)
	chunks[4] = mkRootChunk(bodyRootHex)

	// Merkleize per SSZ: pad to next power of two (8). Our merkleizeSHA256 handles padding with zero chunks.
	merkleRoot := merkleizeSHA256(chunks)
	return "0x" + bytesToHex(merkleRoot)
}

// Diagnostic helpers to compute alternative (incorrect) variants to match a foreign client's mismatch.
// 1. Big-endian uint64 variant
func computeBeaconHeaderRootSpecBigEndian(slot uint64, proposerIndex uint64, parentRootHex, stateRootHex, bodyRootHex string) string {
	chunks := make([][]byte, 5)
	mkUint64ChunkBE := func(v uint64) []byte {
		b := make([]byte, 32)
		for i := 0; i < 8; i++ { // big-endian
			b[7-i] = byte(v >> (8 * i))
		}
		return b
	}
	mkRootChunk := func(h string) []byte { return hexToBytes32(h)[:] }
	chunks[0] = mkUint64ChunkBE(slot)
	chunks[1] = mkUint64ChunkBE(proposerIndex)
	chunks[2] = mkRootChunk(parentRootHex)
	chunks[3] = mkRootChunk(stateRootHex)
	chunks[4] = mkRootChunk(bodyRootHex)
	merkleRoot := merkleizeSHA256(chunks)
	return "0x" + bytesToHex(merkleRoot)
}

// 2. Field order variant: slot, parent_root, state_root, body_root, proposer_index (wrong order)
func computeBeaconHeaderRootSpecReordered(slot uint64, proposerIndex uint64, parentRootHex, stateRootHex, bodyRootHex string) string {
	chunks := make([][]byte, 5)
	mkUint64Chunk := func(v uint64) []byte {
		b := make([]byte, 32)
		for i := 0; i < 8; i++ {
			b[i] = byte(v >> (8 * i))
		}
		return b
	}
	mkRootChunk := func(h string) []byte { return hexToBytes32(h)[:] }
	chunks[0] = mkUint64Chunk(slot)
	chunks[1] = mkRootChunk(parentRootHex)
	chunks[2] = mkRootChunk(stateRootHex)
	chunks[3] = mkRootChunk(bodyRootHex)
	chunks[4] = mkUint64Chunk(proposerIndex)
	merkleRoot := merkleizeSHA256(chunks)
	return "0x" + bytesToHex(merkleRoot)
}

// hexToBytes32 converts a hex string to 32 bytes
func hexToBytes32(hex string) []byte {
	core := strings.TrimPrefix(normalizeRoot(hex), "0x")
	out := make([]byte, 32)
	for i := 0; i < 32 && i*2+1 < len(core); i++ {
		hi := fromHexNibble(core[2*i])
		lo := fromHexNibble(core[2*i+1])
		if hi >= 0 && lo >= 0 {
			out[i] = byte(hi<<4 | lo)
		}
	}
	return out
}

// fromHexNibble converts hex char to value or -1
func fromHexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}

// hardSelfCheckBeaconBlockBody performs SSZ HashTreeRoot validation on beacon block body
func hardSelfCheckBeaconBlockBody(blk *SignedBeaconBlock, expectedBodyRoot string) error {
	// Create SSZ structure for body validation
	bodyCheck := &BeaconBlockBodyCheck{
		Payload: blk.Message.Body.ExecutionPayload,
	}

	// Compute SSZ hash tree root
	calcBodyRoot := ssz.HashSequential(bodyCheck)
	calcBodyRootHex := "0x" + bytesToHex(calcBodyRoot[:])

	if calcBodyRootHex != expectedBodyRoot {
		return fmt.Errorf("BODY_ROOT_MISMATCH: header=%s recalc=%s", expectedBodyRoot, calcBodyRootHex)
	}

	return nil
}

// hardSelfCheckBeaconBlock performs SSZ HashTreeRoot validation on full beacon block
func hardSelfCheckBeaconBlock(blk *SignedBeaconBlock, expectedBlockRoot string) error {
	// Create SSZ structure for block validation
	blockCheck := &BeaconBlockCheck{
		Slot:          blk.Message.Slot,
		ProposerIndex: blk.Message.ProposerIndex,
		ParentRoot:    blk.Message.ParentRoot,
		StateRoot:     blk.Message.StateRoot,
		Body: &BeaconBlockBodyCheck{
			Payload: blk.Message.Body.ExecutionPayload,
		},
	}

	// Compute SSZ hash tree root
	calcBlockRoot := ssz.HashSequential(blockCheck)
	calcBlockRootHex := "0x" + bytesToHex(calcBlockRoot[:])

	if calcBlockRootHex != expectedBlockRoot {
		return fmt.Errorf("BLOCK_ROOT_MISMATCH: param=%s recalc=%s", expectedBlockRoot, calcBlockRootHex)
	}

	return nil
}
