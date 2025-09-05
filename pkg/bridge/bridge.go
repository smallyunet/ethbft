package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/smallyunet/ethbft/pkg/config"
	"github.com/smallyunet/ethbft/pkg/consensus"
	"github.com/smallyunet/ethbft/pkg/ethereum"
)

// Bridge is the main component that connects Ethereum execution clients with CometBFT consensus
type Bridge struct {
	config      *config.Config
	ethClient   *ethereum.Client
	consClient  *consensus.Client
	abciServer  *ABCIServer
	abciApp     *ABCIApplication
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	running     bool
	runningLock sync.Mutex
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

	bridge := &Bridge{
		config:     cfg,
		ethClient:  ethClient,
		consClient: consClient,
		ctx:        ctx,
		cancel:     cancel,
	}

	// Create enhanced ABCI application
	bridge.abciApp = NewABCIApplication(bridge)

	// Create the ABCI server with enhanced app
	bridge.abciServer = NewABCIServer(bridge)

	log.Println("EthBFT will only act as a client to Geth")

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

	// Start the ABCI server
	if err := b.abciServer.Start(); err != nil {
		return fmt.Errorf("failed to start ABCI server: %w", err)
	}

	// Start connection monitoring and block bridging
	b.wg.Add(1)
	go b.runConnectionMonitor()

	// Start block bridging if enabled
	if b.config.Bridge.EnableBridging {
		b.wg.Add(1)
		go b.runBlockBridging()
		log.Println("Block bridging enabled - will forward CometBFT blocks to Geth")
	} else {
		log.Println("Block bridging disabled")
	}

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

// runBlockBridging handles forwarding blocks from CometBFT to Geth
func (b *Bridge) runBlockBridging() {
	defer b.wg.Done()

	log.Println("Starting block bridging service")

	// Poll for new blocks every 2 seconds
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastHeight int64 = 0

	for {
		select {
		case <-b.ctx.Done():
			log.Println("Block bridging stopped")
			return
		case <-ticker.C:
			// Get latest block from CometBFT
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			status, err := b.consClient.GetStatus(ctx)
			cancel()

			if err != nil {
				log.Printf("Failed to get CometBFT status: %v", err)
				continue
			}

			// Extract current height from status map
			var currentHeight int64
			if syncInfo, ok := status["sync_info"].(map[string]interface{}); ok {
				if heightStr, ok := syncInfo["latest_block_height"].(string); ok {
					// Parse height string to int64
					if h, err := fmt.Sscanf(heightStr, "%d", &currentHeight); err != nil || h != 1 {
						log.Printf("Failed to parse block height: %s", heightStr)
						continue
					}
				} else {
					log.Printf("No latest_block_height in sync_info")
					continue
				}
			} else {
				log.Printf("No sync_info in status response")
				continue
			}

			if currentHeight > lastHeight {
				log.Printf("New block detected: height %d -> %d", lastHeight, currentHeight)

				// Process all blocks between lastHeight and currentHeight
				for height := lastHeight + 1; height <= currentHeight; height++ {
					if err := b.processBlock(height); err != nil {
						log.Printf("Failed to process block %d: %v", height, err)
						// Don't break - try next block
					} else {
						log.Printf("Successfully processed block %d", height)
						lastHeight = height
					}
				}
			}
		}
	}
}

// processBlock converts a CometBFT block to an execution payload and sends it to Geth
func (b *Bridge) processBlock(height int64) error {
	log.Printf("Processing CometBFT block %d", height)

	// Convert to execution payload (simplified for now)
	payload, err := b.convertBlockToPayload(height)
	if err != nil {
		return fmt.Errorf("failed to convert block to payload: %w", err)
	}

	// Send newPayload to Geth
	if err := b.sendNewPayload(payload); err != nil {
		return fmt.Errorf("failed to send new payload: %w", err)
	}

	// Send forkchoiceUpdated to Geth
	if err := b.sendForkchoiceUpdate(payload.BlockHash); err != nil {
		return fmt.Errorf("failed to send forkchoice update: %w", err)
	}

	return nil
}

// convertBlockToPayload converts a CometBFT block to an Ethereum execution payload
func (b *Bridge) convertBlockToPayload(height int64) (*ExecutionPayload, error) {
	// This is a simplified conversion - you'll need to implement proper conversion logic
	// based on your specific requirements

	// Generate more realistic block and parent hashes
	blockHash := fmt.Sprintf("0x%064x", height*1000000+12345) // More realistic hash
	var parentHash string
	if height > 1 {
		parentHash = fmt.Sprintf("0x%064x", (height-1)*1000000+12345)
	} else {
		// Genesis block parent hash
		parentHash = "0x0000000000000000000000000000000000000000000000000000000000000000"
	}

	// For now, create a basic payload with empty transactions
	payload := &ExecutionPayload{
		ParentHash:    parentHash,
		FeeRecipient:  "0x0000000000000000000000000000000000000000",
		StateRoot:     "0x0000000000000000000000000000000000000000000000000000000000000000",
		ReceiptsRoot:  "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421", // Empty receipts root
		LogsBloom:     "0x" + strings.Repeat("0", 512),
		PrevRandao:    "0x0000000000000000000000000000000000000000000000000000000000000000",
		BlockNumber:   fmt.Sprintf("0x%x", height),
		GasLimit:      "0x1c9c380", // 30M gas
		GasUsed:       "0x0",
		Timestamp:     fmt.Sprintf("0x%x", time.Now().Unix()),
		ExtraData:     "0x",
		BaseFeePerGas: "0x7", // 7 wei base fee
		BlockHash:     blockHash,
		Transactions:  []string{}, // Empty for now
		// Deneb fields (can be empty for now)
		Withdrawals:           []string{},
		BlobGasUsed:           "0x0",
		ExcessBlobGas:         "0x0",
		ParentBeaconBlockRoot: "0x0000000000000000000000000000000000000000000000000000000000000000",
	}

	return payload, nil
}

// sendNewPayload sends a newPayload call to Geth's Engine API
func (b *Bridge) sendNewPayload(payload *ExecutionPayload) error {
	log.Printf("Sending engine_newPayloadV3 for block %s", payload.BlockNumber)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Prepare the params for engine_newPayloadV3
	params := []interface{}{payload, []string{}, "0x0"} // payload, versioned hashes, parent beacon block root

	// Make the Engine API call
	result, err := b.ethClient.Call(ctx, "engine_newPayloadV3", params)
	if err != nil {
		return fmt.Errorf("failed to call engine_newPayloadV3: %w", err)
	}

	// Parse the response
	var response struct {
		Status          string `json:"status"`
		LatestValidHash string `json:"latestValidHash,omitempty"`
		ValidationError string `json:"validationError,omitempty"`
	}

	if err := json.Unmarshal(result, &response); err != nil {
		return fmt.Errorf("failed to parse newPayload response: %w", err)
	}

	log.Printf("engine_newPayloadV3 response: status=%s, latestValidHash=%s",
		response.Status, response.LatestValidHash)

	if response.Status != "VALID" && response.Status != "ACCEPTED" {
		return fmt.Errorf("payload rejected with status: %s, error: %s",
			response.Status, response.ValidationError)
	}

	return nil
}

// sendForkchoiceUpdate sends a forkchoiceUpdated call to Geth's Engine API
func (b *Bridge) sendForkchoiceUpdate(blockHash string) error {
	log.Printf("Sending engine_forkchoiceUpdatedV2 for block %s", blockHash)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Prepare the forkchoice state
	forkchoiceState := map[string]string{
		"headBlockHash":      blockHash,
		"safeBlockHash":      blockHash, // For simplicity, treat head as safe
		"finalizedBlockHash": blockHash, // For simplicity, treat head as finalized
	}

	// No payload attributes for now (not building a new block)
	params := []interface{}{forkchoiceState, nil}

	// Make the Engine API call
	result, err := b.ethClient.Call(ctx, "engine_forkchoiceUpdatedV2", params)
	if err != nil {
		return fmt.Errorf("failed to call engine_forkchoiceUpdatedV2: %w", err)
	}

	// Parse the response
	var response struct {
		PayloadStatus struct {
			Status          string `json:"status"`
			LatestValidHash string `json:"latestValidHash,omitempty"`
			ValidationError string `json:"validationError,omitempty"`
		} `json:"payloadStatus"`
		PayloadID string `json:"payloadId,omitempty"`
	}

	if err := json.Unmarshal(result, &response); err != nil {
		return fmt.Errorf("failed to parse forkchoiceUpdated response: %w", err)
	}

	log.Printf("engine_forkchoiceUpdatedV2 response: status=%s, latestValidHash=%s",
		response.PayloadStatus.Status, response.PayloadStatus.LatestValidHash)

	if response.PayloadStatus.Status != "VALID" {
		return fmt.Errorf("forkchoice update rejected with status: %s, error: %s",
			response.PayloadStatus.Status, response.PayloadStatus.ValidationError)
	}

	return nil
}
