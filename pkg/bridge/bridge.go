package bridge

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/smallyunet/ethbft/pkg/config"
	"github.com/smallyunet/ethbft/pkg/consensus"
	"github.com/smallyunet/ethbft/pkg/engine"
	"github.com/smallyunet/ethbft/pkg/ethereum"
	"github.com/smallyunet/ethbft/pkg/state"
)

// Bridge is the main component that connects Ethereum execution clients with CometBFT consensus
type Bridge struct {
	config       *config.Config
	ethClient    *ethereum.Client
	consClient   *consensus.Client
	abciServer   *ABCIServer
	engineServer *engine.Server
	stateManager *state.Manager
	abciApp      *ABCIApplication
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	running      bool
	runningLock  sync.Mutex
}

// NewBridge creates a new bridge instance with enhanced architecture
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

	// Create state manager
	stateManager := state.NewManager(ethClient)

	bridge := &Bridge{
		config:       cfg,
		ethClient:    ethClient,
		consClient:   consClient,
		stateManager: stateManager,
		ctx:          ctx,
		cancel:       cancel,
	}

	// Create enhanced ABCI application
	bridge.abciApp = NewABCIApplication(bridge, stateManager)

	// Create the ABCI server with enhanced app
	bridge.abciServer = NewABCIServer(bridge)

	// Create Engine API server
	bridge.engineServer, err = engine.NewServer(cfg, bridge.abciApp)
	if err != nil {
		return nil, fmt.Errorf("failed to create Engine API server: %w", err)
	}

	return bridge, nil
}

// Start starts the bridge with new architecture
func (b *Bridge) Start() error {
	b.runningLock.Lock()
	defer b.runningLock.Unlock()

	if b.running {
		return fmt.Errorf("bridge is already running")
	}

	log.Println("Starting EthBFT bridge with enhanced architecture")

	// Start the Engine API server first
	if err := b.engineServer.Start(); err != nil {
		return fmt.Errorf("failed to start Engine API server: %w", err)
	}

	// Start the ABCI server
	if err := b.abciServer.Start(); err != nil {
		b.engineServer.Stop()
		return fmt.Errorf("failed to start ABCI server: %w", err)
	}

	// Start connection monitoring (simplified, no more block pushing)
	b.wg.Add(1)
	go b.runConnectionMonitor()

	b.running = true
	log.Println("EthBFT bridge started successfully")
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

	// Stop the Engine API server
	if b.engineServer != nil {
		b.engineServer.Stop()
	}

	// Stop the ABCI server
	if b.abciServer != nil {
		b.abciServer.Stop()
	}

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

// runConnectionMonitor monitors the connection status (simplified)
func (b *Bridge) runConnectionMonitor() {
	defer b.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-b.ctx.Done():
			log.Println("Connection monitor stopped")
			return
		case <-ticker.C:
			// Just log the status periodically
			if err := b.checkConnections(); err != nil {
				log.Printf("Connection check failed: %v", err)
			} else {
				log.Println("All services are connected and healthy")
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
