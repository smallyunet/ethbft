package ethereum

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/smallyunet/ethbft/pkg/config"
)

func TestNewClientLoadsValidJWTSecret(t *testing.T) {
	dir := t.TempDir()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	secretHex := hex.EncodeToString(secret)
	secretPath := filepath.Join(dir, "jwt.hex")
	if err := os.WriteFile(secretPath, []byte(secretHex), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	cfg := &config.Config{}
	cfg.Ethereum.Endpoint = "http://localhost:8545"
	cfg.Ethereum.EngineAPI = "http://localhost:8551"
	cfg.Ethereum.JWTSecret = secretPath

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	if len(client.jwtKey) != len(secret) {
		t.Fatalf("expected jwtKey length %d, got %d", len(secret), len(client.jwtKey))
	}
}

func TestNewClientFailsWithoutSecret(t *testing.T) {
	cfg := &config.Config{}
	cfg.Ethereum.Endpoint = "http://localhost:8545"
	cfg.Ethereum.EngineAPI = "http://localhost:8551"
	cfg.Ethereum.JWTSecret = filepath.Join(t.TempDir(), "missing.hex")

	if _, err := NewClient(cfg); err == nil {
		t.Fatal("expected error when JWT secret file is missing")
	}
}

func TestNewClientFailsWithInvalidSecret(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "jwt.hex")
	if err := os.WriteFile(secretPath, []byte("zz"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	cfg := &config.Config{}
	cfg.Ethereum.Endpoint = "http://localhost:8545"
	cfg.Ethereum.EngineAPI = "http://localhost:8551"
	cfg.Ethereum.JWTSecret = secretPath

	if _, err := NewClient(cfg); err == nil {
		t.Fatal("expected error when JWT secret hex is invalid")
	}
}
