package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// A simplified JWT generator based on go-ethereum
// Reference: https://github.com/ethereum/go-ethereum/blob/master/rpc/jwt.go

// Header component
type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

// Payload component
type jwtPayload struct {
	ExpiresAt int64 `json:"exp"`
	IAT       int64 `json:"iat"`
}

// GenerateToken creates a JWT token from a hex-encoded secret
func GenerateToken(hexSecret string) (string, error) {
	// 1. Convert hex key to bytes
	secret, err := hex.DecodeString(hexSecret)
	if err != nil {
		return "", fmt.Errorf("failed to parse hex secret: %w", err)
	}

	// 2. Create JWT header
	header := jwtHeader{
		Algorithm: "HS256",
		Type:      "JWT",
	}

	// 3. Create JWT payload
	now := time.Now().Unix()
	payload := jwtPayload{
		IAT:       now,
		ExpiresAt: now + 3600, // Expires in 1 hour
	}

	// 4. Serialize and encode header and payload
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerBase64 := base64URLEncode(headerJSON)

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadBase64 := base64URLEncode(payloadJSON)

	// 5. Generate signature
	signatureInput := headerBase64 + "." + payloadBase64
	signature := createSignature(signatureInput, secret)

	// 6. Assemble complete JWT
	token := headerBase64 + "." + payloadBase64 + "." + signature

	return token, nil
}

// base64URLEncode performs proper base64url encoding
func base64URLEncode(data []byte) string {
	// Using standard library's proper base64url encoding
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// createSignature generates an HMAC-SHA256 signature
func createSignature(data string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(data))
	signature := h.Sum(nil)
	return strings.TrimRight(base64.URLEncoding.EncodeToString(signature), "=")
}

// ParseHexKey extracts a hex key from file content
func ParseHexKey(content string) string {
	return strings.TrimSpace(content)
}
