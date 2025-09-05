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

	// Readiness gating
	readyMu      sync.RWMutex
	gethReady    bool // at least one successful call to GetLatestExecutionStateRoot
	cometReady   bool // at least one successful call to GetLatestBlock
	presetLoaded bool // preset constants loaded
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
		presetLoaded:    true, // constants in constants.go are compile-time, mark as loaded
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

// storeBlock atomically persists SSZ bytes and mappings (slot->root, root->slot, updates head)
func (s *Server) storeBlock(slot int64, root string, sszBytes []byte, hdr beaconHeaderFields, payload *ExecutionPayload) {
	s.blockMutex.Lock()
	defer s.blockMutex.Unlock()
	s.blockSSZByRoot[root] = sszBytes
	s.slotRoots[slot] = root
	s.rootSlots[root] = slot
	s.headerData[root] = hdr // legacy cache
	s.payloadsBySlot[slot] = payload
	s.blockJSONByRoot[root] = buildBeaconBlockJSON(hdr, payload) // legacy JSON (may be removed later)
	s.headRoot = root
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
	// Health endpoints bypass JSON-RPC / Beacon API gating
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
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

	// Initial probe (do not create blocks until fully ready)
	height, _, err := s.abciClient.GetLatestBlock(context.Background())
	if err == nil {
		s.readyMu.Lock()
		s.cometReady = true
		s.readyMu.Unlock()
		s.blockMutex.Lock()
		s.latestBlockHeight = height
		s.blockMutex.Unlock()
	}

	for {
		<-ticker.C
		h, _, err := s.abciClient.GetLatestBlock(context.Background())
		if err != nil {
			log.Printf("GetLatestBlock: %v", err)
			s.readyMu.Lock()
			s.cometReady = false
			s.readyMu.Unlock()
			continue
		}
		s.readyMu.Lock()
		s.cometReady = true
		s.readyMu.Unlock()
		s.blockMutex.Lock()
		if h > s.latestBlockHeight {
			prevHead := s.headRoot
			s.latestBlockHeight = h

			// Attempt to get execution state root; if fail, mark not ready & skip block production
			execStateRoot, err := s.abciClient.GetLatestExecutionStateRoot(context.Background())
			if err != nil {
				log.Printf("GetLatestExecutionStateRoot failed (will not fallback): %v", err)
				s.readyMu.Lock()
				s.gethReady = false
				s.readyMu.Unlock()
				s.blockMutex.Unlock()
				continue
			}
			stateRoot := normalizeRoot(execStateRoot)
			s.readyMu.Lock()
			s.gethReady = true
			readyNow := s.gethReady && s.cometReady && s.presetLoaded
			s.readyMu.Unlock()
			s.latestBlockHash = stateRoot

			parent := prevHead
			if parent == "" {
				parent = zeroHash32()
			}

			if !readyNow {
				// Not fully ready yet; do not produce/beacon block structures
				s.blockMutex.Unlock()
				continue
			}

			// Create a new ExecutionPayload for each slot with proper fields
			var payloadForSlot *ExecutionPayload
			if p, ok := s.payloadsBySlot[h]; ok {
				payloadForSlot = p
			} else {
				// Get previous payload hash for parent_hash
				prevPayloadHash := zeroHash32()
				if h > 0 {
					if pPrev, ok := s.payloadsBySlot[h-1]; ok {
						prevPayloadHash = pPrev.BlockHash
					}
				}

				// Get timestamp from CometBFT (or use current time)
				ts := uint64(time.Now().Unix())

				payloadForSlot = &ExecutionPayload{
					ParentHash:            prevPayloadHash, // Previous payload's block_hash
					FeeRecipient:          "0x0000000000000000000000000000000000000000",
					StateRoot:             s.latestBlockHash,                                                    // Execution layer state root from ABCI
					ReceiptsRoot:          "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421", // Empty receipts root
					LogsBloom:             "0x" + strings.Repeat("0", 512),
					PrevRandao:            zeroHash32(),
					BlockNumber:           fmt.Sprintf("0x%x", h), // Use slot as block number for monotonic increase
					GasLimit:              "0x1c9c380",            // 30,000,000 gas limit
					GasUsed:               "0x0",
					Timestamp:             fmt.Sprintf("0x%x", ts),
					ExtraData:             "0x",
					BaseFeePerGas:         "0x0",      // Demo value, can be 0
					Transactions:          []string{}, // Empty transaction list
					Withdrawals:           []string{}, // Empty withdrawals
					BlobGasUsed:           "0x0",
					ExcessBlobGas:         "0x0",
					ParentBeaconBlockRoot: s.headRoot, // Previous beacon header
				}

				// Compute and set the payload BlockHash
				payloadForSlot.BlockHash = computeExecutionBlockHash(payloadForSlot)

				// Store the payload
				s.payloadsBySlot[h] = payloadForSlot
			}

			// Create complete BeaconBlockBody with ExecutionPayload and default values for other fields
			body := &BeaconBlockBody{
				ExecutionPayload: payloadForSlot,
				// All other fields are zero/empty by default which is correct for our demo
			}
			bodyRoot := computeBeaconBodyRootDeneb(body)
			blk := &SignedBeaconBlock{
				Message: &BeaconBlock{
					Slot:          uint64(h),
					ProposerIndex: 0,
					ParentRoot:    parent,
					StateRoot:     s.latestBlockHash,
					Body:          body,
				},
			}
			// Use canonical serialization wrapper (currently fallback to legacy bytes) for future real SSZ integration.
			newRoot, sszBytes, serr := serializeCanonicalSSZ(blk)
			if serr != nil {
				log.Printf("serializeCanonicalSSZ error: %v", serr)
				s.blockMutex.Unlock()
				continue
			}
			hdr := beaconHeaderFields{Slot: h, ParentRoot: parent, StateRoot: s.latestBlockHash, BodyRoot: bodyRoot}
			s.storeBlock(h, newRoot, sszBytes, hdr, payloadForSlot)

			// Verify recomputation stability
			if recompute := computeBeaconBodyRootDeneb(body); recompute != bodyRoot {
				log.Printf("BODY_ROOT_DRIFT slot=%d bodyRoot=%s recompute=%s", h, bodyRoot, recompute)
			}

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

// Readiness helpers
func (s *Server) isReady() bool {
	s.readyMu.RLock()
	defer s.readyMu.RUnlock()
	return s.gethReady && s.cometReady && s.presetLoaded
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if s.isReady() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("not ready"))
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
