package engine

import (
	"crypto/sha256"
)

// ssz_utils.go contains SSZ (Simple Serialize) merkleization and tree utilities.
// This file was extracted from utils.go to improve code organization.

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

// computeListRoot computes list root without limit consideration
func computeListRoot(elementRoots [][]byte, length uint64) []byte {
	if len(elementRoots) == 0 {
		return mixInLength(zero32(), 0)
	}
	mer := merkleizeChunks(elementRoots)
	return mixInLength(mer, length)
}
