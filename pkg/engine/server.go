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
	"github.com/smallyunet/ethbft/pkg/ethereum"
)

// Server implements the Engine API server that acts as a mock beacon client for Geth
type Server struct {
	config     *config.Config
	httpServer *http.Server
	jwtSecret  string
	ethClient  *ethereum.Client

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

	// Execution layer chain tracking
	lastValidExecHash string // hash of last VALID execution payload accepted by geth (genesis at start)

	// Event stream clients
	eventClients    map[chan []byte]bool
	eventClientsMux sync.RWMutex

	// Readiness gating
	readyMu      sync.RWMutex
	gethReady    bool // at least one successful call to GetLatestExecutionStateRoot
	cometReady   bool // at least one successful call to GetLatestBlock
	presetLoaded bool // preset constants loaded

	// Fallback synthetic production when CometBFT unreachable
	syntheticMode   bool  // true if we're fabricating heights locally
	syntheticHeight int64 // last synthetic height produced
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

	// Create an Ethereum client for Engine API outbound calls
	ethCli, err := ethereum.NewClient(cfg)
	if err != nil {
		log.Printf("Warning: failed to create Ethereum engine client: %v", err)
	}

	server := &Server{
		config:     cfg,
		jwtSecret:  jwtSecret,
		ethClient:  ethCli,
		abciClient: abciClient,
		forkchoiceState: &ForkchoiceState{
			HeadBlockHash:      "0x0000000000000000000000000000000000000000000000000000000000000000",
			SafeBlockHash:      "0x0000000000000000000000000000000000000000000000000000000000000000",
			FinalizedBlockHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
		},
		eventClients:      make(map[chan []byte]bool),
		slotRoots:         make(map[int64]string),
		rootSlots:         make(map[string]int64),
		headerData:        make(map[string]beaconHeaderFields),
		payloadsBySlot:    make(map[int64]*ExecutionPayload),
		blockSSZByRoot:    make(map[string][]byte),
		blockJSONByRoot:   make(map[string][]byte),
		presetLoaded:      true, // constants in constants.go are compile-time, mark as loaded
		lastValidExecHash: genesisExecutionPayload().BlockHash,
	}

	// Synchronous genesis hash probe (short timeout) so first produced payload has correct parent
	if ethCli != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		res, err := ethCli.Call(ctx, "eth_getBlockByNumber", []interface{}{"0x0", false})
		cancel()
		if err == nil {
			var blk map[string]interface{}
			if json.Unmarshal(res, &blk) == nil {
				if h, ok := blk["hash"].(string); ok && strings.HasPrefix(h, "0x") {
					server.lastValidExecHash = h
					log.Printf("(sync) Initialized lastValidExecHash with EL genesis hash %s", h)
				}
			}
		} else {
			log.Printf("(sync) genesis hash probe failed: %v (will retry async)", err)
		}
	}

	// Asynchronously probe actual EL genesis hash to ensure correct parent linkage
	go func() {
		if ethCli == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, err := ethCli.Call(ctx, "eth_getBlockByNumber", []interface{}{"0x0", false})
		if err != nil {
			log.Printf("genesis hash probe failed: %v", err)
			return
		}
		var blk map[string]interface{}
		if err := json.Unmarshal(res, &blk); err != nil {
			log.Printf("genesis hash decode failed: %v", err)
			return
		}
		if h, ok := blk["hash"].(string); ok && strings.HasPrefix(h, "0x") {
			server.blockMutex.Lock()
			server.lastValidExecHash = h
			server.blockMutex.Unlock()
			log.Printf("Initialized lastValidExecHash with actual EL genesis hash %s", h)
		}
	}()

	// Attempt an initial forkchoiceUpdated pointing to genesis so EL is primed
	go func() {
		if server.ethClient == nil {
			return
		}
		// Retry indefinitely (with backoff) until success so early slow geth startup does not block us permanently
		for attempt := 1; ; attempt++ {
			// Exponential-ish backoff capped at 15s
			delay := time.Duration(2+attempt/3) * time.Second
			if delay > 15*time.Second {
				delay = 15 * time.Second
			}
			time.Sleep(delay)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			state := &ForkchoiceState{
				HeadBlockHash:      server.lastValidExecHash,
				SafeBlockHash:      server.lastValidExecHash,
				FinalizedBlockHash: server.lastValidExecHash,
			}
			_, err := server.ethClient.Call(ctx, "engine_forkchoiceUpdatedV2", []interface{}{state})
			cancel()
			if err != nil {
				// Classify common startup errors
				if strings.Contains(err.Error(), "connection refused") {
					log.Printf("initial forkchoice attempt %d: engine port not open yet (%v)", attempt, err)
				} else if strings.Contains(err.Error(), "401") || strings.Contains(strings.ToLower(err.Error()), "unauthorized") {
					log.Printf("initial forkchoice attempt %d: auth failed (JWT mismatch?) (%v)", attempt, err)
				} else {
					log.Printf("initial forkchoice attempt %d failed: %v", attempt, err)
				}
				continue
			}
			log.Printf("initial forkchoiceUpdated succeeded after %d attempts head=%s", attempt, state.HeadBlockHash)
			break
		}
	}()

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

// LatestLocalPayload returns the most recently built execution payload
// used to construct the latest beacon body/header. This avoids any
// accidental divergence between what we return to geth and what we
// embed into SSZ/ABCI.
func (s *Server) LatestLocalPayload() *ExecutionPayload {
	s.blockMutex.RLock()
	defer s.blockMutex.RUnlock()
	if s.latestBlockHeight > 0 {
		if p, ok := s.payloadsBySlot[s.latestBlockHeight]; ok {
			return p
		}
	}
	// Fallback to last seen payload if any
	return s.latestPayload
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

	// Initial probe: mark comet reachable but do not advance latestBlockHeight,
	// so the first observed height will trigger block production.
	if _, _, err := s.abciClient.GetLatestBlock(context.Background()); err == nil {
		s.readyMu.Lock()
		s.cometReady = true
		s.readyMu.Unlock()
		s.blockMutex.Lock()
		// Start from -1 so first observed height (>=0) triggers block production
		s.latestBlockHeight = -1
		s.blockMutex.Unlock()
	}

	for {
		<-ticker.C
		// Default: try real CometBFT first
		h, _, err := s.abciClient.GetLatestBlock(context.Background())
		if err != nil {
			// Enable synthetic mode
			if !s.syntheticMode {
				log.Printf("GetLatestBlock error (%v) -> entering synthetic production mode", err)
			}
			s.syntheticMode = true
			// Derive next synthetic height
			s.blockMutex.RLock()
			curr := s.latestBlockHeight
			s.blockMutex.RUnlock()
			if curr < 0 {
				curr = -1
			}
			h = curr + 1
		} else {
			// Successful real height fetch; if we were synthetic, exit mode
			if s.syntheticMode {
				log.Printf("Recovered CometBFT connectivity at height=%d, leaving synthetic mode", h)
			}
			s.syntheticMode = false
			s.readyMu.Lock()
			s.cometReady = true
			s.readyMu.Unlock()
		}
		// Debug current height vs last
		s.blockMutex.RLock()
		last := s.latestBlockHeight
		s.blockMutex.RUnlock()
		if h < last {
			log.Printf("MONITOR: non-monotonic CometBFT height h=%d < last=%d", h, last)
		}
		// If synthetic mode, mark cometReady false (unless prior success) but still allow production via gethReady path.
		if s.syntheticMode {
			s.readyMu.Lock()
			s.cometReady = false
			s.readyMu.Unlock()
		}
		s.blockMutex.Lock()
		// Decide whether to produce a block for this tick.
		shouldProduce := false
		if h > s.latestBlockHeight {
			shouldProduce = true
		}
		if !shouldProduce && s.headRoot == "" {
			// Force initial production to bootstrap head even if height hasn't advanced yet.
			shouldProduce = true
		}
		if shouldProduce {
			prevHead := s.headRoot
			s.latestBlockHeight = h

			// Attempt to get execution state root; if fail, fallback to previous or zero to bootstrap
			execStateRoot, err := s.abciClient.GetLatestExecutionStateRoot(context.Background())
			var stateRoot string
			if err != nil {
				log.Printf("GetLatestExecutionStateRoot failed (fallback to previous/zero): %v", err)
				// Fallback: use last known execution hash if any, else zero
				if s.latestBlockHash != "" {
					stateRoot = s.latestBlockHash
				} else {
					stateRoot = zeroHash32()
				}
				// Probe geth basic reachability to set readiness signal
				if s.ethClient != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					_, pingErr := s.ethClient.Call(ctx, "eth_blockNumber", []interface{}{})
					cancel()
					s.readyMu.Lock()
					s.gethReady = (pingErr == nil)
					s.readyMu.Unlock()
				}
			} else {
				stateRoot = normalizeRoot(execStateRoot)
				s.readyMu.Lock()
				s.gethReady = true
				s.readyMu.Unlock()
			}
			// Compute readiness: allow production if either cometReady OR (gethReady and preset) so we can start even if comet DNS not ready yet
			s.readyMu.RLock()
			readyNow := (s.cometReady || s.gethReady) && s.presetLoaded
			s.readyMu.RUnlock()
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
				// Use lastValidExecHash (genesis hash at start) as parent for first payload; then chain
				prevPayloadHash := s.lastValidExecHash
				if h > 0 {
					if pPrev, ok := s.payloadsBySlot[h-1]; ok {
						prevPayloadHash = pPrev.BlockHash
					}
				}

				// Timestamp (monotonic seconds)
				ts := uint64(time.Now().Unix())

				payloadForSlot = &ExecutionPayload{
					ParentHash:            prevPayloadHash,
					FeeRecipient:          "0x0000000000000000000000000000000000000000",
					StateRoot:             s.latestBlockHash,
					ReceiptsRoot:          "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
					LogsBloom:             "0x" + strings.Repeat("0", 512),
					PrevRandao:            zeroHash32(),
					BlockNumber:           fmt.Sprintf("0x%x", h+1), // Advance execution number (genesis is 0)
					GasLimit:              "0x1c9c380",
					GasUsed:               "0x0",
					Timestamp:             fmt.Sprintf("0x%x", ts),
					ExtraData:             "0x",
					BaseFeePerGas:         "0x0", // temporary, will be replaced below
					Transactions:          []string{},
					Withdrawals:           []string{},
					BlobGasUsed:           "0x0",
					ExcessBlobGas:         "0x0",
					ParentBeaconBlockRoot: s.headRoot,
				}

				// Determine BaseFeePerGas using parent block (or previous payload) for validity
				parentBaseFee := "0x0"
				if h == 0 {
					// Query genesis block for base fee
					if s.ethClient != nil {
						ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
						if res, err := s.ethClient.Call(ctx2, "eth_getBlockByNumber", []interface{}{"0x0", false}); err == nil {
							var blk map[string]interface{}
							if json.Unmarshal(res, &blk) == nil {
								if bf, ok := blk["baseFeePerGas"].(string); ok && strings.HasPrefix(bf, "0x") {
									parentBaseFee = bf
								}
								// Also reuse genesis state root if we have none (ensure EL acceptance for empty block)
								if sr, ok := blk["stateRoot"].(string); ok && strings.HasPrefix(sr, "0x") {
									payloadForSlot.StateRoot = sr
								}
							}
						} else {
							log.Printf("base fee genesis fetch error: %v", err)
						}
						cancel2()
					}
				} else if pPrev, ok := s.payloadsBySlot[h-1]; ok && pPrev.BaseFeePerGas != "" {
					parentBaseFee = pPrev.BaseFeePerGas
					// Attempt to query parent block to inherit accurate state root (empty blocks stay constant)
					if s.ethClient != nil {
						parentExecNum := fmt.Sprintf("0x%x", h) // parent execution number (h maps to BlockNumber h for previous payload since we add +1)
						ctx3, cancel3 := context.WithTimeout(context.Background(), 1500*time.Millisecond)
						if res, err := s.ethClient.Call(ctx3, "eth_getBlockByNumber", []interface{}{parentExecNum, false}); err == nil {
							var blk map[string]interface{}
							if json.Unmarshal(res, &blk) == nil {
								if sr, ok := blk["stateRoot"].(string); ok && strings.HasPrefix(sr, "0x") {
									payloadForSlot.StateRoot = sr
								}
							}
						}
						cancel3()
					}
				}
				// For empty block, EIP-1559 formula keeps base fee ~ parent (no gas used change). Use same.
				payloadForSlot.BaseFeePerGas = parentBaseFee

				payloadForSlot.BlockHash = computeExecutionBlockHash(payloadForSlot)
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
			log.Printf("BLOCK_PROCESS:   - last_valid_exec_parent: %s", s.lastValidExecHash)
			log.Printf("BLOCK_PROCESS:   - parent_root: %s", parent)
			log.Printf("BLOCK_PROCESS:   - body_root: %s", bodyRoot)
			log.Printf("BLOCK_PROCESS:   - computed_beacon_root: %s", newRoot)
			log.Printf("BLOCK_PROCESS: This beacon root will be used when Geth requests beacon block data")
			s.blockMutex.Unlock()
			log.Printf("New block: height=%d headerRoot=%s execHash=%s", h, s.headRoot, s.latestBlockHash)
			s.broadcastHeadEvent(h, s.headRoot)

			// Push execution payload and forkchoice to Geth via Engine API
			go s.pushToGeth(payloadForSlot)
		} else {
			s.blockMutex.Unlock()
			// No production this tick
		}
	}
}

// pushToGeth submits the new payload and updates forkchoice on the EL
func (s *Server) pushToGeth(payload *ExecutionPayload) {
	if s.ethClient == nil {
		log.Printf("Engine push skipped: Ethereum client unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	log.Printf("ENGINE_PUSH: submitting payload parent=%s number=%s stateRoot=%s blockHash=%s ts=%s", payload.ParentHash, payload.BlockNumber, payload.StateRoot, payload.BlockHash, payload.Timestamp)

	// Record the payload in the ABCI application to keep ABCI/AppHash in sync
	if s.abciClient != nil && payload != nil {
		if err := s.abciClient.ExecutePayload(context.Background(), payload); err != nil {
			log.Printf("warning: abci ExecutePayload failed: %v", err)
		}
	}

	// Try V3 -> V2 -> V1
	var resp json.RawMessage
	var err error
	if resp, err = s.ethClient.Call(ctx, "engine_newPayloadV3", []interface{}{payload}); err != nil {
		log.Printf("engine_newPayloadV3 error: %v", err)
		if resp, err = s.ethClient.Call(ctx, "engine_newPayloadV2", []interface{}{payload}); err != nil {
			log.Printf("engine_newPayloadV2 error: %v", err)
			if resp, err = s.ethClient.Call(ctx, "engine_newPayloadV1", []interface{}{payload}); err != nil {
				log.Printf("engine_newPayloadV1 error: %v", err)
				return
			}
		}
	}
	// Log status field if present
	var status struct {
		Status          string  `json:"status"`
		LatestValidHash *string `json:"latestValidHash"`
		ValidationError *string `json:"validationError"`
	}
	if err := json.Unmarshal(resp, &status); err == nil && status.Status != "" {
		log.Printf("engine_newPayload status=%s latestValid=%v error=%v", status.Status, status.LatestValidHash, status.ValidationError)
		if status.Status == "VALID" {
			// Record as last valid execution hash for next parent linkage
			if status.LatestValidHash != nil {
				s.blockMutex.Lock()
				s.lastValidExecHash = *status.LatestValidHash
				s.blockMutex.Unlock()
			}
		}
	} else {
		log.Printf("engine_newPayload raw response: %s", string(resp))
	}

	// Update forkchoice to set the new head/safe/finalized to this payload (demo behavior)
	state := &ForkchoiceState{
		HeadBlockHash:      payload.BlockHash,
		SafeBlockHash:      payload.BlockHash,
		FinalizedBlockHash: payload.BlockHash,
	}
	if resp, err = s.ethClient.Call(ctx, "engine_forkchoiceUpdatedV2", []interface{}{state}); err != nil {
		log.Printf("engine_forkchoiceUpdatedV2 error: %v", err)
	} else {
		var fcr struct {
			PayloadStatus struct {
				Status          string  `json:"status"`
				LatestValidHash *string `json:"latestValidHash"`
				ValidationError *string `json:"validationError"`
			} `json:"payloadStatus"`
			PayloadId *string `json:"payloadId"`
		}
		if err := json.Unmarshal(resp, &fcr); err == nil && fcr.PayloadStatus.Status != "" {
			log.Printf("engine_forkchoiceUpdatedV2 status=%s latestValid=%v payloadId=%v error=%v", fcr.PayloadStatus.Status, fcr.PayloadStatus.LatestValidHash, fcr.PayloadId, fcr.PayloadStatus.ValidationError)
		} else {
			log.Printf("engine_forkchoiceUpdatedV2 raw response: %s", string(resp))
		}
	}
}

// Readiness helpers
func (s *Server) isReady() bool {
	s.readyMu.RLock()
	defer s.readyMu.RUnlock()
	// Consider service ready as soon as CometBFT is reachable and presets are loaded,
	// so Beacon API endpoints and event stream can start for Geth to subscribe.
	return s.cometReady && s.presetLoaded
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
