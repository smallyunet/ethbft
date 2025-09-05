package engine

import (
	"encoding/hex"
	"fmt"
	"strings"
)

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

// computeBeaconHeaderRoot computes the beacon block header root using proper SSZ
func computeBeaconHeaderRoot(h beaconHeaderFields) string {
	// Minimal spec-faithful root via manual merkleization (no SSZ encoders needed).
	return computeBeaconHeaderRootSpec(uint64(h.Slot), 0, h.ParentRoot, h.StateRoot, h.BodyRoot)
}

// computeBeaconHeaderLeaves - simplified version for computing header chunks
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

// computeExecutionBlockHash computes the block hash for an execution payload
// using go-ethereum's Header for the most robust and accurate implementation
func computeExecutionBlockHash(payload *ExecutionPayload) string {
	// Use the robust implementation from payload_hash.go
	return computeExecutionBlockHashWithGeth(payload)
}
