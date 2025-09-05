package engine

import (
	"strings"
)

// hex_utils.go contains hexadecimal conversion utilities and constants.
// This file was extracted from utils.go to improve code organization.

// Constants moved to constants.go (do not redefine here)

// zeroHash32 returns a 32-byte zero hash
func zeroHash32() string {
	return "0x" + strings.Repeat("0", 64)
}

// zeroSig96 returns a 96-byte zero signature
func zeroSig96() string {
	return "0x" + strings.Repeat("0", 192)
}

// zeroHexBytes returns n zero bytes as hex string
func zeroHexBytes(n int) string {
	return "0x" + strings.Repeat("0", n*2)
}

// zeroBloom256 returns a 256-byte zero bloom filter
func zeroBloom256() string {
	return "0x" + strings.Repeat("0", 512) // 256 bytes = 512 hex characters
}

// normalizeRoot normalizes a hex root string
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

// bytesToHex returns lowercase hex without 0x prefix
func bytesToHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[2*i] = hexdigits[v>>4]
		out[2*i+1] = hexdigits[v&0xf]
	}
	return string(out)
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

// hexToBytes20 converts hex string to 20 bytes
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

// hexToBytes256 converts hex string to 256 bytes
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

// hexToUint64 converts hex string to uint64
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

// hexToUint256Bytes converts hex string to 32-byte uint256 representation
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
