package bridge

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/smallyunet/ethbft/pkg/config"
	"github.com/smallyunet/ethbft/pkg/consensus"
	"github.com/smallyunet/ethbft/pkg/ethereum"
	"github.com/smallyunet/ethbft/pkg/types"
)

// Bridge is the main component that connects Ethereum execution clients with CometBFT consensus
type Bridge struct {
	config      *config.Config
	ethClient   *ethereum.Client
	consClient  *consensus.Client
	abciServer  *ABCIServer
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	running     bool
	runningLock sync.Mutex
}

// NewBridge creates a new bridge instance
func NewBridge(cfg *config.Config) (*Bridge, error) {
	ethClient, err := ethereum.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Ethereum client: %w", err)
	}

	consClient, err := consensus.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create CometBFT client: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	bridge := &Bridge{
		config:     cfg,
		ethClient:  ethClient,
		consClient: consClient,
		ctx:        ctx,
		cancel:     cancel,
	}

	// Create the ABCI server
	bridge.abciServer = NewABCIServer(bridge)

	return bridge, nil
}

// Start starts the bridge
func (b *Bridge) Start() error {
	b.runningLock.Lock()
	defer b.runningLock.Unlock()

	if b.running {
		return fmt.Errorf("bridge is already running")
	}

	log.Println("Starting EthBFT bridge")

	// Start the ABCI server first
	if err := b.abciServer.Start(); err != nil {
		return fmt.Errorf("failed to start ABCI server: %w", err)
	}

	// Start the main processing loop in a goroutine
	b.wg.Add(1)
	go b.run()

	b.running = true
	return nil
}

// Stop stops the bridge
func (b *Bridge) Stop() error {
	b.runningLock.Lock()
	defer b.runningLock.Unlock()

	if !b.running {
		return nil
	}

	log.Println("Stopping EthBFT bridge")

	// Stop the ABCI server
	b.abciServer.Stop()

	// Signal cancellation to all goroutines
	b.cancel()

	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("Bridge stopped successfully")
	case <-time.After(5 * time.Second):
		log.Println("Bridge stop timed out, some goroutines may still be running")
	}

	b.running = false
	return nil
}

// run is the main processing loop
func (b *Bridge) run() {
	defer b.wg.Done()

	normalInterval := time.Duration(b.config.Bridge.RetryInterval) * time.Second
	reconnectInterval := 2 * time.Second // Faster reconnection interval

	ticker := time.NewTicker(normalInterval)
	defer ticker.Stop()

	// Connection status variables
	var connected bool = false
	var consecutiveFailures int = 0

	// Initial connection attempt
	log.Println("Establishing initial connection to Ethereum and CometBFT...")

	// Attempt to connect to both endpoints
	if err := b.checkConnections(); err != nil {
		log.Printf("Warning: %v. Will retry every %d seconds.", err, b.config.Bridge.RetryInterval)
		connected = false
		// Immediately switch to fast reconnection mode
		ticker.Reset(reconnectInterval)
	} else {
		log.Println("Successfully connected to Ethereum and CometBFT endpoints")
		connected = true
	}

	for {
		select {
		case <-b.ctx.Done():
			log.Println("Bridge processing loop terminated")
			return
		case <-ticker.C:
			if !connected {
				// If disconnected, try to reconnect
				log.Println("Attempting to reconnect to services...")
				if err := b.checkConnections(); err != nil {
					consecutiveFailures++
					log.Printf("Connection failed (%d consecutive failures): %v", consecutiveFailures, err)

					// If too many failures, increase log verbosity
					if consecutiveFailures > 5 {
						log.Printf("Connection details - Ethereum endpoint: %s, Engine API: %s, CometBFT endpoint: %s",
							b.config.Ethereum.Endpoint,
							b.config.Ethereum.EngineAPI,
							b.config.CometBFT.Endpoint)
					}

					// Maintain fast reconnection mode
					ticker.Reset(reconnectInterval)
				} else {
					log.Println("Reconnection successful! Resuming normal processing.")
					connected = true
					consecutiveFailures = 0
					ticker.Reset(normalInterval)
				}
			} else {
				// Normal block processing
				if err := b.processNextBlock(); err != nil {
					log.Printf("Error processing block: %v", err)
					consecutiveFailures++

					// Check if it's a connection issue
					if consecutiveFailures > 3 {
						log.Println("Multiple consecutive failures detected, checking connection status...")
						if connErr := b.checkConnections(); connErr != nil {
							log.Printf("Connection lost: %v", connErr)
							connected = false
							ticker.Reset(reconnectInterval)
						}
					}
				} else {
					// Successfully processed block, reset failure counter
					consecutiveFailures = 0
				}
			}
		}
	}
}

// checkConnections verifies connections to Ethereum and CometBFT
func (b *Bridge) checkConnections() error {
	var ethErr, cometErr error

	// Check Ethereum connection with multiple retries
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		log.Printf("Attempting to connect to Ethereum (%d/3): %s", i+1, b.config.Ethereum.Endpoint)
		version, err := b.ethClient.CheckConnection(ctx)
		if err == nil {
			log.Printf("Successfully connected to Ethereum, client version: %s", version)
			ethErr = nil
			break
		}
		ethErr = err
		log.Printf("Failed to connect to Ethereum: %v, retrying...", err)
		time.Sleep(2 * time.Second)
	}

	if ethErr != nil {
		return fmt.Errorf("unable to connect to Ethereum service %s after multiple attempts: %w",
			b.config.Ethereum.Endpoint, ethErr)
	}

	// Check CometBFT connection with multiple retries
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		log.Printf("Attempting to connect to CometBFT (%d/3): %s", i+1, b.config.CometBFT.Endpoint)
		status, err := b.consClient.GetStatus(ctx)
		if err == nil {
			log.Printf("Successfully connected to CometBFT, status: %+v", status)
			cometErr = nil
			break
		}
		cometErr = err
		log.Printf("Failed to connect to CometBFT: %v, retrying...", err)
		time.Sleep(2 * time.Second)
	}

	if cometErr != nil {
		return fmt.Errorf("unable to connect to CometBFT service %s after multiple attempts: %w",
			b.config.CometBFT.Endpoint, cometErr)
	}

	return nil
}

// processNextBlock processes the next block from Ethereum and proposes it to CometBFT
func (b *Bridge) processNextBlock() error {
	ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
	defer cancel()

	// Get the latest block from Ethereum
	block, err := b.ethClient.GetLatestBlock(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest block: %w", err)
	}

	// Convert the block to CometBFT consensus data
	consensusData := &types.ConsensusData{
		BlockHash:       block.Hash,
		BlockNumber:     block.Number.Int64(),
		ParentHash:      block.ParentHash,
		StateRoot:       block.StateRoot,
		ReceiptsRoot:    block.ReceiptsRoot,
		TransactionRoot: block.TransactionsRoot,
		Timestamp:       block.Timestamp.Int64(),
	}

	// Propose the block to CometBFT
	if err := b.consClient.ProposeBlock(ctx, consensusData); err != nil {
		return fmt.Errorf("failed to propose block to CometBFT: %w", err)
	}

	log.Printf("Successfully processed block %d (%s)", block.Number.Int64(), block.Hash)
	return nil
}
