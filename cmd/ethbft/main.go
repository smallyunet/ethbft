package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/smallyunet/ethbft/pkg/bridge"
	"github.com/smallyunet/ethbft/pkg/config"
)

func main() {
	fmt.Println("Starting EthBFT - Bridge between Ethereum execution clients and CometBFT consensus")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create and start the bridge
	b, err := bridge.NewBridge(cfg)
	if err != nil {
		log.Fatalf("Failed to create bridge: %v", err)
	}

	if err := b.Start(); err != nil {
		log.Fatalf("Failed to start bridge: %v", err)
	}
	defer b.Stop()

	// Wait for termination signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("Shutting down EthBFT...")
}
