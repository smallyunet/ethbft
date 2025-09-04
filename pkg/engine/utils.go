package engine

import "strings"

func zeroHash32() string {
	return "0x" + strings.Repeat("0", 64)
}

func zeroSig96() string {
	return "0x" + strings.Repeat("0", 192)
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
