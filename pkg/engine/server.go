package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/smallyunet/ethbft/pkg/config"
)

// Server implements the Engine API server that acts as a mock beacon client for Geth
type Server struct {
	config     *config.Config
	httpServer *http.Server
	jwtSecret  string

	// State tracking
	latestPayload   *ExecutionPayload
	forkchoiceState *ForkchoiceState
	payloadCounter  uint64

	// Communication with ABCI app
	abciClient ABCIClient

	// Block tracking
	latestBlockHeight int64
	latestBlockHash   string
	headRoot          string                        // beacon header root (computed)
	slotRoots         map[int64]string              // slot -> header root
	rootSlots         map[string]int64              // header root -> slot
	headerData        map[string]beaconHeaderFields // header root -> fields
	payloadsBySlot    map[int64]*ExecutionPayload   // slot -> execution payload used for body root
	blockSSZByRoot    map[string][]byte             // header root -> persisted SSZ bytes (only trusted source)
	blockJSONByRoot   map[string][]byte             // header root -> pre-built beacon block JSON response (stable)
	blockMutex        sync.RWMutex

	// Event stream clients
	eventClients    map[chan []byte]bool
	eventClientsMux sync.RWMutex
}

// NewServer creates a new Engine API server
func NewServer(cfg *config.Config, abciClient ABCIClient) (*Server, error) {
	// Load JWT secret
	jwtSecret := ""
	if cfg.Ethereum.JWTSecret != "" {
		secret, err := loadJWTSecret(cfg.Ethereum.JWTSecret)
		if err != nil {
			log.Printf("Warning: Failed to load JWT secret: %v", err)
		} else {
			jwtSecret = secret
		}
	}

	server := &Server{
		config:     cfg,
		jwtSecret:  jwtSecret,
		abciClient: abciClient,
		forkchoiceState: &ForkchoiceState{
			HeadBlockHash:      "0x0000000000000000000000000000000000000000000000000000000000000000",
			SafeBlockHash:      "0x0000000000000000000000000000000000000000000000000000000000000000",
			FinalizedBlockHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
		},
		eventClients:    make(map[chan []byte]bool),
		slotRoots:       make(map[int64]string),
		rootSlots:       make(map[string]int64),
		headerData:      make(map[string]beaconHeaderFields),
		payloadsBySlot:  make(map[int64]*ExecutionPayload),
		blockSSZByRoot:  make(map[string][]byte),
		blockJSONByRoot: make(map[string][]byte),
	}

	// Start block monitoring
	go server.monitorBlocks()

	// Debug verifier (can be disabled by removing)
	go func() {
		for {
			time.Sleep(15 * time.Second)
			server.blockMutex.RLock()
			for root, fields := range server.headerData {
				recalc := computeBeaconHeaderRoot(fields)
				if recalc != root {
					leaves := computeBeaconHeaderLeaves(fields)
					log.Printf("DEBUG MISMATCH storedRoot=%s recalc=%s slot=%d parent=%s state=%s body=%s leaves0=%x", root, recalc, fields.Slot, fields.ParentRoot, fields.StateRoot, fields.BodyRoot, leaves[0])
				}
			}
			server.blockMutex.RUnlock()
		}
	}()

	return server, nil
}

// storeRootToBytes stores SSZ bytes for a beacon block root (only trusted source)
func (s *Server) storeRootToBytes(root string, sszBytes []byte) {
	s.blockMutex.Lock()
	defer s.blockMutex.Unlock()
	s.blockSSZByRoot[root] = sszBytes
}

// storeSlotToRoot stores slot to root mapping
func (s *Server) storeSlotToRoot(slot int64, root string) {
	s.blockMutex.Lock()
	defer s.blockMutex.Unlock()
	s.slotRoots[slot] = root
	s.rootSlots[root] = slot
}

// loadBytesByRoot loads SSZ bytes by beacon block root
func (s *Server) loadBytesByRoot(root string) ([]byte, bool) {
	s.blockMutex.RLock()
	defer s.blockMutex.RUnlock()
	sszBytes, ok := s.blockSSZByRoot[root]
	return sszBytes, ok
}

// Start starts the Engine API server
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	// Parse the engine API endpoint to get the port
	// Format: http://host:port, we want just the port part
	addr := ":8551" // Default port
	if s.config.Ethereum.EngineAPI != "" {
		parts := strings.Split(s.config.Ethereum.EngineAPI, ":")
		if len(parts) >= 3 {
			addr = ":" + parts[2]
		}
	}

	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("Starting Engine API server on %s", addr)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Engine API server error: %v", err)
		}
	}()

	return nil
}

// Stop stops the Engine API server
func (s *Server) Stop() error {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// handleRequest handles all JSON-RPC requests
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Handle both POST (JSON-RPC) and GET (Beacon API) requests
	if r.Method == "POST" {
		s.handleJSONRPC(w, r)
	} else if r.Method == "GET" {
		s.handleBeaconAPI(w, r)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleJSONRPC handles JSON-RPC requests (Engine API)
func (s *Server) handleJSONRPC(w http.ResponseWriter, r *http.Request) {
	// Verify JWT authentication
	if s.jwtSecret != "" {
		if err := s.verifyJWT(r); err != nil {
			log.Printf("JWT verification failed: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Parse JSON-RPC request
	var req jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Failed to decode request: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	log.Printf("Engine API request: %s", req.Method)

	// Handle the method
	var result interface{}
	var err error

	switch req.Method {
	case "engine_newPayloadV1":
		result, err = s.handleNewPayload(req.Params)
	case "engine_newPayloadV2":
		result, err = s.handleNewPayload(req.Params)
	case "engine_newPayloadV3":
		result, err = s.handleNewPayload(req.Params)
	case "engine_forkchoiceUpdatedV1":
		result, err = s.handleForkchoiceUpdated(req.Params)
	case "engine_forkchoiceUpdatedV2":
		result, err = s.handleForkchoiceUpdated(req.Params)
	case "engine_forkchoiceUpdatedV3":
		result, err = s.handleForkchoiceUpdated(req.Params)
	case "engine_getPayloadV1":
		result, err = s.handleGetPayload(req.Params)
	case "engine_getPayloadV2":
		result, err = s.handleGetPayload(req.Params)
	case "engine_getPayloadV3":
		result, err = s.handleGetPayload(req.Params)
	case "engine_exchangeTransitionConfigurationV1":
		result, err = s.handleExchangeTransitionConfiguration(req.Params)
	case "engine_getPayloadBodiesByHashV1":
		result, err = s.handleGetPayloadBodiesByHash(req.Params)
	case "engine_getPayloadBodiesByRangeV1":
		result, err = s.handleGetPayloadBodiesByRange(req.Params)
	default:
		err = fmt.Errorf("method %s not found", req.Method)
	}

	// Send response
	s.sendResponse(w, req.ID, result, err)
}

// monitorBlocks continuously monitors for new blocks from CometBFT
func (s *Server) monitorBlocks() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	height, hash, err := s.abciClient.GetLatestBlock(context.Background())
	if err != nil {
		s.blockMutex.Lock()
		s.latestBlockHeight = 0
		s.latestBlockHash = zeroHash32()
		s.headRoot = s.latestBlockHash
		s.blockMutex.Unlock()
	} else {
		s.blockMutex.Lock()
		s.latestBlockHeight = height

		// Try to get the execution state root from ABCI client first
		var stateRoot string
		if execStateRoot, err := s.abciClient.GetLatestExecutionStateRoot(context.Background()); err == nil {
			stateRoot = normalizeRoot(execStateRoot)
			log.Printf("Initial setup: using execution state root from Geth: %s", stateRoot)
		} else {
			// Fall back to using the latest payload's state root if available
			if s.latestPayload != nil && s.latestPayload.StateRoot != "" {
				stateRoot = normalizeRoot(s.latestPayload.StateRoot)
				log.Printf("Initial setup: using execution state root from payload: %s", stateRoot)
			} else {
				stateRoot = normalizeRoot(hash)
				log.Printf("Initial setup: using CometBFT hash as fallback: %s (warning: this may cause state root mismatch)", stateRoot)
			}
		}
		s.latestBlockHash = stateRoot

		parent := zeroHash32()
		if s.headRoot != "" {
			parent = s.headRoot
		}
		// Use CometBFT block hash as execution block hash (non-zero) for payload block_hash field
		// Static mainnet genesis execution payload (slot-aligned synthetic) per user instruction
		initialPayload := &ExecutionPayload{
			ParentHash:            zeroHash32(),
			FeeRecipient:          zeroHexBytes(20),
			StateRoot:             "0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544",
			ReceiptsRoot:          "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			LogsBloom:             zeroBloom256(),
			PrevRandao:            zeroHash32(),
			BlockNumber:           "0x0",
			GasLimit:              "0x1388",
			GasUsed:               "0x0",
			Timestamp:             "0x0",
			ExtraData:             "0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa",
			BaseFeePerGas:         "0x0",
			BlockHash:             "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
			Transactions:          []string{},
			Withdrawals:           []string{},
			BlobGasUsed:           "0x0",
			ExcessBlobGas:         "0x0",
			ParentBeaconBlockRoot: zeroHash32(),
		}
		bodyRoot := computeBeaconBodyRootWithStateRoot(initialPayload)
		blk := &SignedBeaconBlock{Message: &BeaconBlock{Slot: uint64(height), ProposerIndex: 0, ParentRoot: parent, StateRoot: s.latestBlockHash, Body: &BeaconBlockBody{ExecutionPayload: initialPayload}}}

		// Store SSZ bytes and root mapping (only trust SSZ bytes, not objects)
		sszBytes := marshalSignedBeaconBlockSSZ(blk)
		root := computeSignedBeaconBlockRoot(blk)
		s.storeRootToBytes(root, sszBytes)
		s.storeSlotToRoot(height, root)

		// Legacy storage for compatibility (will be removed)
		hdr := beaconHeaderFields{Slot: height, ParentRoot: parent, StateRoot: s.latestBlockHash, BodyRoot: bodyRoot}
		s.headRoot = root
		s.headerData[root] = hdr
		s.payloadsBySlot[height] = initialPayload
		s.blockJSONByRoot[root] = buildBeaconBlockJSON(hdr, initialPayload)
		// Verify creation consistency
		verifyBody := computeBeaconBodyRootWithStateRoot(initialPayload)
		if verifyBody != bodyRoot {
			log.Printf("BODY_ROOT_INIT_MISMATCH slot=%d stored=%s recomputed=%s", height, bodyRoot, verifyBody)
		}
		s.blockMutex.Unlock()
	}

	for {
		<-ticker.C
		h, hsh, err := s.abciClient.GetLatestBlock(context.Background())
		if err != nil {
			log.Printf("GetLatestBlock: %v", err)
			continue
		}
		s.blockMutex.Lock()
		if h > s.latestBlockHeight {
			prevHead := s.headRoot
			s.latestBlockHeight = h

			// Try to get the execution state root from ABCI client first
			var stateRoot string
			if execStateRoot, err := s.abciClient.GetLatestExecutionStateRoot(context.Background()); err == nil {
				stateRoot = normalizeRoot(execStateRoot)
				log.Printf("Using execution state root from Geth: %s", stateRoot)
			} else {
				// Fall back to using the latest payload's state root if available
				if s.latestPayload != nil && s.latestPayload.StateRoot != "" {
					stateRoot = normalizeRoot(s.latestPayload.StateRoot)
					log.Printf("Using execution state root from payload: %s", stateRoot)
				} else {
					stateRoot = normalizeRoot(hsh)
					log.Printf("Using CometBFT hash as fallback: %s (warning: this may cause state root mismatch)", stateRoot)
				}
			}
			s.latestBlockHash = stateRoot

			parent := prevHead
			if parent == "" {
				parent = zeroHash32()
			}
			// Reuse existing deterministic payload if present (slot should not change contents after first creation)
			var payloadForSlot *ExecutionPayload
			if p, ok := s.payloadsBySlot[h]; ok {
				payloadForSlot = p
			} else {
				// Reuse the static genesis execution payload for all subsequent slots (demo mode)
				payloadForSlot = &ExecutionPayload{
					ParentHash:            zeroHash32(),
					FeeRecipient:          zeroHexBytes(20),
					StateRoot:             "0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544",
					ReceiptsRoot:          "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
					LogsBloom:             zeroBloom256(),
					PrevRandao:            zeroHash32(),
					BlockNumber:           "0x0",
					GasLimit:              "0x1388",
					GasUsed:               "0x0",
					Timestamp:             "0x0",
					ExtraData:             "0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa",
					BaseFeePerGas:         "0x0",
					BlockHash:             "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
					Transactions:          []string{},
					Withdrawals:           []string{},
					BlobGasUsed:           "0x0",
					ExcessBlobGas:         "0x0",
					ParentBeaconBlockRoot: zeroHash32(),
				}
				s.payloadsBySlot[h] = payloadForSlot
			}
			bodyRoot := computeBeaconBodyRootWithStateRoot(payloadForSlot)
			blk := &SignedBeaconBlock{Message: &BeaconBlock{Slot: uint64(h), ProposerIndex: 0, ParentRoot: parent, StateRoot: s.latestBlockHash, Body: &BeaconBlockBody{ExecutionPayload: payloadForSlot}}}

			// Store SSZ bytes and root mapping (only trust SSZ bytes, not objects)
			sszBytes := marshalSignedBeaconBlockSSZ(blk)
			newRoot := computeSignedBeaconBlockRoot(blk)
			s.storeRootToBytes(newRoot, sszBytes)
			s.storeSlotToRoot(h, newRoot)

			// Verify recomputation stability
			if recompute := computeBeaconBodyRootWithStateRoot(payloadForSlot); recompute != bodyRoot {
				log.Printf("BODY_ROOT_DRIFT slot=%d bodyRoot=%s recompute=%s", h, bodyRoot, recompute)
			}

			// Legacy storage for compatibility (will be removed)
			hdr := beaconHeaderFields{Slot: h, ParentRoot: parent, StateRoot: s.latestBlockHash, BodyRoot: bodyRoot}
			s.headRoot = newRoot
			s.headerData[newRoot] = hdr
			s.blockJSONByRoot[newRoot] = buildBeaconBlockJSON(hdr, payloadForSlot)

			if true { // verbose chunk debug (spec header chunks expected=4 for Deneb)
				chunks := computeBeaconHeaderLeaves(hdr)
				if len(chunks) == 4 {
					log.Printf("DEBUG header slot=%d parent=%s state=%s body=%s chunks=[%x %x %x %x] root=%s", h, hdr.ParentRoot, hdr.StateRoot, hdr.BodyRoot, chunks[0], chunks[1], chunks[2], chunks[3], newRoot)
				} else {
					log.Printf("DEBUG header slot=%d chunkCount=%d root=%s", h, len(chunks), newRoot)
				}
			}

			// Debug: log the complete block processing
			log.Printf("BLOCK_PROCESS: New block from CometBFT:")
			log.Printf("BLOCK_PROCESS:   - height: %d", h)
			log.Printf("BLOCK_PROCESS:   - exec_hash_from_geth: %s", stateRoot)
			log.Printf("BLOCK_PROCESS:   - parent_root: %s", parent)
			log.Printf("BLOCK_PROCESS:   - body_root: %s", bodyRoot)
			log.Printf("BLOCK_PROCESS:   - computed_beacon_root: %s", newRoot)
			log.Printf("BLOCK_PROCESS: This beacon root will be used when Geth requests beacon block data")
			s.blockMutex.Unlock()
			log.Printf("New block: height=%d headerRoot=%s execHash=%s", h, s.headRoot, s.latestBlockHash)
			s.broadcastHeadEvent(h, s.headRoot)
		} else {
			s.blockMutex.Unlock()
		}
	}
}

// verifyJWT verifies the JWT token in the request
func (s *Server) verifyJWT(r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return fmt.Errorf("missing authorization header")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return fmt.Errorf("invalid authorization header format")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	// For now, just check if the token matches our secret
	// In a real implementation, you'd verify the JWT signature
	if token != s.jwtSecret {
		return fmt.Errorf("invalid token")
	}

	return nil
}

// loadJWTSecret loads the JWT secret from file
func loadJWTSecret(path string) (string, error) {
	// Read the JWT secret from the file
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read JWT secret file %s: %w", path, err)
	}

	// Trim any whitespace and newlines
	secret := strings.TrimSpace(string(content))
	if secret == "" {
		return "", fmt.Errorf("JWT secret file %s is empty", path)
	}

	return secret, nil
}

// buildBeaconBlockJSON constructs a stable beacon block JSON (Deneb) from stored header & payload.
// It returns the serialized bytes to be served directly by handlers to avoid any 'latest' lookups.
func buildBeaconBlockJSON(hdr beaconHeaderFields, payload *ExecutionPayload) []byte {
	txList := make([]interface{}, 0)
	withdrawals := make([]interface{}, 0)
	resp := map[string]interface{}{
		"version": "deneb",
		"data": map[string]interface{}{
			"message": map[string]interface{}{
				"slot":           fmt.Sprintf("%d", hdr.Slot),
				"proposer_index": "0",
				"parent_root":    hdr.ParentRoot,
				"state_root":     hdr.StateRoot,
				"body_root":      hdr.BodyRoot,
				"body": map[string]interface{}{
					"randao_reveal": zeroSig96(),
					"eth1_data": map[string]interface{}{
						"deposit_root":  zeroHash32(),
						"deposit_count": "0",
						"block_hash":    zeroHash32(),
					},
					"graffiti":           zeroHash32(),
					"proposer_slashings": []interface{}{},
					"attester_slashings": []interface{}{},
					"attestations":       []interface{}{},
					"deposits":           []interface{}{},
					"voluntary_exits":    []interface{}{},
					"sync_aggregate": map[string]interface{}{
						"sync_committee_bits":      zeroHexBytes(64),
						"sync_committee_signature": zeroSig96(),
					},
					"execution_payload": map[string]interface{}{
						"parent_hash":              payload.ParentHash,
						"fee_recipient":            payload.FeeRecipient,
						"state_root":               payload.StateRoot,
						"receipts_root":            payload.ReceiptsRoot,
						"logs_bloom":               payload.LogsBloom,
						"prev_randao":              payload.PrevRandao,
						"block_number":             payload.BlockNumber,
						"gas_limit":                payload.GasLimit,
						"gas_used":                 payload.GasUsed,
						"timestamp":                payload.Timestamp,
						"extra_data":               payload.ExtraData,
						"base_fee_per_gas":         payload.BaseFeePerGas,
						"block_hash":               payload.BlockHash,
						"transactions":             txList,
						"withdrawals":              withdrawals,
						"blob_gas_used":            payload.BlobGasUsed,
						"excess_blob_gas":          payload.ExcessBlobGas,
						"parent_beacon_block_root": payload.ParentBeaconBlockRoot,
					},
					"blob_kzg_commitments": []interface{}{},
				},
			},
			"signature": zeroSig96(),
		},
	}
	bytes, _ := json.Marshal(resp)
	return bytes
}

// verifyJWT verifies the JWT token in the request
