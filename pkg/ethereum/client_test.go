package ethereum

import (
	"context"
	"testing"
	"time"

	"github.com/smallyunet/ethbft/pkg/config"
)

func TestNewClient(t *testing.T) {
	cfg := &config.Config{}
	cfg.Ethereum.Endpoint = "http://localhost:8545"

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create Ethereum client: %v", err)
	}

	if client == nil {
		t.Fatal("Expected non-nil client")
	}
}

func TestCall_InvalidEndpoint(t *testing.T) {
	cfg := &config.Config{}
	cfg.Ethereum.Endpoint = "http://invalid-endpoint:8545"

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create Ethereum client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.Call(ctx, "eth_blockNumber", []interface{}{})
	if err == nil {
		t.Fatal("Expected error when calling invalid endpoint")
	}
}
