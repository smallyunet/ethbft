package engine

import (
	"crypto/sha256"
	"fmt"
	"strings"

	ssz "github.com/karalabe/ssz"
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
	if strings.HasPrefix(h, "0x") {
		h = h[2:]
	}
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
	fmt.Printf("SSZ_CALC: computeBeaconBodyRootWithStateRoot called with payload\n")
	fmt.Printf("SSZ_CALC:   - parentHash: %s\n", payload.ParentHash)
	fmt.Printf("SSZ_CALC:   - stateRoot: %s\n", payload.StateRoot)
	fmt.Printf("SSZ_CALC:   - blockNumber: %s\n", payload.BlockNumber)
	fmt.Printf("SSZ_CALC:   - gasLimit: %s\n", payload.GasLimit)
	fmt.Printf("SSZ_CALC:   - blockHash: %s\n", payload.BlockHash)

	// Create a proper beacon block body with the complete execution payload
	body := &BeaconBlockBodyWithRealPayload{
		ExecutionPayload: payload,
	}
	root := ssz.HashSequential(body)
	result := "0x" + bytesToHex(root[:])
	fmt.Printf("SSZ_CALC: computeBeaconBodyRootWithStateRoot result=%s\n", result)
	return result
}

// computeBeaconBodyRootWithRealPayload - using complete execution payload for SSZ computation
func computeBeaconBodyRootWithRealPayload(payload *ExecutionPayload) string {
	fmt.Printf("SSZ_CALC: computeBeaconBodyRootWithRealPayload called with complete payload\n")
	fmt.Printf("SSZ_CALC:   - parentHash: %s\n", payload.ParentHash)
	fmt.Printf("SSZ_CALC:   - stateRoot: %s\n", payload.StateRoot)
	fmt.Printf("SSZ_CALC:   - blockNumber: %s\n", payload.BlockNumber)
	fmt.Printf("SSZ_CALC:   - gasLimit: %s\n", payload.GasLimit)
	fmt.Printf("SSZ_CALC:   - blockHash: %s\n", payload.BlockHash)

	// Create a proper beacon block body with the complete execution payload
	body := &BeaconBlockBodyWithRealPayload{
		ExecutionPayload: payload,
	}
	root := ssz.HashSequential(body)
	result := "0x" + bytesToHex(root[:])
	fmt.Printf("SSZ_CALC: computeBeaconBodyRootWithRealPayload result=%s\n", result)
	return result
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
		// Manual implementation of Deneb BeaconBlockBody SSZ hashing
		// This approach avoids complex type constraints and uses the real execution data

		payload := b.ExecutionPayload
		fmt.Printf("SSZ_CALC: Starting manual Deneb beacon body calculation\n")
		fmt.Printf("SSZ_CALC: Using execution payload - blockNumber: %s, stateRoot: %s\n", payload.BlockNumber, payload.StateRoot)

		// Helper function for empty list root
		emptyListRoot := func() [32]byte {
			var root [32]byte
			// Empty list has hash of (merkle_root([]) + length_bytes(0))
			// For empty list, this is just zero hash
			return root
		}

		// Create the 12 fields of Deneb BeaconBlockBody as individual hash chunks
		var bodyChunks [12][32]byte

		// 0. randao_reveal (BLSSignature - 96 bytes = 3 chunks, all zeros)
		bodyChunks[0] = [32]byte{} // randao reveal root (all zeros)

		// 1. eth1_data (Eth1Data container - 3 fields)
		eth1Data := make([]byte, 0, 72) // 32 + 8 + 32 bytes
		depositRoot := [32]byte{}
		eth1Data = append(eth1Data, depositRoot[:]...) // deposit_root (zeros)
		eth1CountBytes := [8]byte{}
		eth1Data = append(eth1Data, eth1CountBytes[:]...) // deposit_count (zero as little-endian)
		blockHashBytes := [32]byte{}
		eth1Data = append(eth1Data, blockHashBytes[:]...) // block_hash (zeros)
		eth1Root := sha256Sum(eth1Data)
		copy(bodyChunks[1][:], eth1Root)

		// 2. graffiti (Bytes32 - all zeros)
		bodyChunks[2] = [32]byte{}

		// 3-7. Various empty lists (proposer_slashings, attester_slashings, attestations, deposits, voluntary_exits)
		bodyChunks[3] = emptyListRoot() // proposer_slashings
		bodyChunks[4] = emptyListRoot() // attester_slashings
		bodyChunks[5] = emptyListRoot() // attestations
		bodyChunks[6] = emptyListRoot() // deposits
		bodyChunks[7] = emptyListRoot() // voluntary_exits

		// 8. sync_aggregate (SyncAggregate - sync_committee_bits + sync_committee_signature)
		syncData := make([]byte, 0, 160) // 64 + 96 bytes
		syncBits := [64]byte{}
		syncData = append(syncData, syncBits[:]...) // sync_committee_bits (zeros)
		syncSig := [96]byte{}
		syncData = append(syncData, syncSig[:]...) // sync_committee_signature (zeros)
		syncRoot := sha256Sum(syncData)
		copy(bodyChunks[8][:], syncRoot)

		// 9. execution_payload (ExecutionPayload with REAL data from Geth)
		execPayloadRoot := func() [32]byte {
			// Create execution payload chunks with real data
			var chunks [][32]byte

			// parent_hash
			parentHash := [32]byte{}
			if payload.ParentHash != "" {
				copy(parentHash[:], hexToBytes32(payload.ParentHash))
			}
			chunks = append(chunks, parentHash)

			// fee_recipient (20 bytes padded to 32)
			feeRecipient := [32]byte{}
			if payload.FeeRecipient != "" {
				copy(feeRecipient[:20], hexToBytes20(payload.FeeRecipient))
			}
			chunks = append(chunks, feeRecipient)

			// state_root (REAL from Geth!)
			stateRoot := [32]byte{}
			if payload.StateRoot != "" {
				copy(stateRoot[:], hexToBytes32(payload.StateRoot))
			}
			chunks = append(chunks, stateRoot)

			// receipts_root
			receiptsRoot := [32]byte{}
			if payload.ReceiptsRoot != "" {
				copy(receiptsRoot[:], hexToBytes32(payload.ReceiptsRoot))
			}
			chunks = append(chunks, receiptsRoot)

			// logs_bloom (256 bytes = 8 chunks)
			if payload.LogsBloom != "" {
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

			// prev_randao
			prevRandao := [32]byte{}
			if payload.PrevRandao != "" {
				copy(prevRandao[:], hexToBytes32(payload.PrevRandao))
			}
			chunks = append(chunks, prevRandao)

			// block_number (REAL from Geth!)
			blockNumber := [32]byte{}
			if payload.BlockNumber != "" {
				num := hexToUint64(payload.BlockNumber)
				for i := 0; i < 8; i++ {
					blockNumber[i] = byte(num >> (8 * i))
				}
			}
			chunks = append(chunks, blockNumber)

			// gas_limit
			gasLimit := [32]byte{}
			if payload.GasLimit != "" {
				limit := hexToUint64(payload.GasLimit)
				for i := 0; i < 8; i++ {
					gasLimit[i] = byte(limit >> (8 * i))
				}
			}
			chunks = append(chunks, gasLimit)

			// gas_used
			gasUsed := [32]byte{}
			if payload.GasUsed != "" {
				used := hexToUint64(payload.GasUsed)
				for i := 0; i < 8; i++ {
					gasUsed[i] = byte(used >> (8 * i))
				}
			}
			chunks = append(chunks, gasUsed)

			// timestamp (REAL from Geth!)
			timestamp := [32]byte{}
			if payload.Timestamp != "" {
				ts := hexToUint64(payload.Timestamp)
				for i := 0; i < 8; i++ {
					timestamp[i] = byte(ts >> (8 * i))
				}
			}
			chunks = append(chunks, timestamp)

			// extra_data (empty)
			chunks = append(chunks, [32]byte{}) // empty list root

			// base_fee_per_gas
			baseFee := [32]byte{}
			if payload.BaseFeePerGas != "" {
				copy(baseFee[:], hexToUint256Bytes(payload.BaseFeePerGas))
			}
			chunks = append(chunks, baseFee)

			// block_hash
			blockHash := [32]byte{}
			if payload.BlockHash != "" {
				copy(blockHash[:], hexToBytes32(payload.BlockHash))
			}
			chunks = append(chunks, blockHash)

			// transactions (empty)
			chunks = append(chunks, [32]byte{}) // empty list root

			// withdrawals (empty)
			chunks = append(chunks, [32]byte{}) // empty list root

			// blob_gas_used (Deneb)
			chunks = append(chunks, [32]byte{}) // zero

			// excess_blob_gas (Deneb)
			chunks = append(chunks, [32]byte{}) // zero

			fmt.Printf("SSZ_CALC: ExecutionPayload has %d chunks\n", len(chunks))

			// Convert to [][]byte for merkleization
			chunkBytes := make([][]byte, len(chunks))
			for i, chunk := range chunks {
				chunkBytes[i] = chunk[:]
			}

			root := merkleizeSHA256(chunkBytes)
			var result [32]byte
			copy(result[:], root)
			return result
		}()
		bodyChunks[9] = execPayloadRoot

		// 10. bls_to_execution_changes (empty list)
		bodyChunks[10] = emptyListRoot()

		// 11. blob_kzg_commitments (empty list)
		bodyChunks[11] = emptyListRoot()

		fmt.Printf("SSZ_CALC: Created 12 body chunks for Deneb beacon block body\n")

		// Merkleize the 12 body chunks
		bodyChunkBytes := make([][]byte, 12)
		for i, chunk := range bodyChunks {
			bodyChunkBytes[i] = chunk[:]
			fmt.Printf("SSZ_CALC: Body chunk %d: %x\n", i, chunk)
		}

		finalRoot := merkleizeSHA256(bodyChunkBytes)
		var finalRootArray [32]byte
		copy(finalRootArray[:], finalRoot)

		fmt.Printf("SSZ_CALC: Final Deneb beacon body root: %x\n", finalRoot)
		ssz.HashStaticBytes(has, &finalRootArray)
	})
} // BeaconBlockBodyDeneb represents a Deneb beacon block body for SSZ computation
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
				z32,                            // parent_beacon_block_root (Deneb)
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

		// Pad to 16 fields if needed for Deneb
		for len(bodyFields) < 16 {
			bodyFields = append(bodyFields, z32)
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
	header := &BeaconHeaderSSZ{
		Slot:       uint64(h.Slot),
		ParentRoot: h.ParentRoot,
		StateRoot:  h.StateRoot,
		BodyRoot:   h.BodyRoot,
	}
	root := ssz.HashSequential(header)
	return "0x" + bytesToHex(root[:])
}

// BeaconHeaderSSZ represents a beacon block header for SSZ computation
type BeaconHeaderSSZ struct {
	Slot       uint64
	ParentRoot string
	StateRoot  string
	BodyRoot   string
}

func (h *BeaconHeaderSSZ) SizeSSZ(sizer *ssz.Sizer) uint32 { return 0 }

func (h *BeaconHeaderSSZ) DefineSSZ(codec *ssz.Codec) {
	codec.DefineHasher(func(has *ssz.Hasher) {
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

		// Beacon block header fields (5 fields total)
		headerFields := [][]byte{
			uint64ToBytes32(h.Slot),    // slot
			uint64ToBytes32(0),         // proposer_index (always 0)
			hexToBytes32(h.ParentRoot), // parent_root
			hexToBytes32(h.StateRoot),  // state_root
			hexToBytes32(h.BodyRoot),   // body_root
		}

		// Hash each field into the SSZ hasher
		for _, field := range headerFields {
			var arr [32]byte
			copy(arr[:], field)
			ssz.HashStaticBytes(has, &arr)
		}
	})
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
