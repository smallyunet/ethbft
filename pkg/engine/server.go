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
		eventClients: make(map[chan []byte]bool),
		slotRoots:    make(map[int64]string),
		rootSlots:    make(map[string]int64),
		headerData:   make(map[string]beaconHeaderFields),
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
		bodyRoot := computeBeaconBodyRootWithStateRoot(&ExecutionPayload{StateRoot: stateRoot})
		hdr := beaconHeaderFields{ // initial head header
			Slot:       height,
			ParentRoot: parent,
			StateRoot:  s.latestBlockHash,
			BodyRoot:   bodyRoot,
		}
		root := computeBeaconHeaderRoot(hdr)
		s.headRoot = root
		s.slotRoots[height] = root
		s.rootSlots[root] = height
		s.headerData[root] = hdr
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
			bodyRoot := computeBeaconBodyRootWithStateRoot(&ExecutionPayload{StateRoot: stateRoot})
			hdr := beaconHeaderFields{
				Slot:       h,
				ParentRoot: parent,
				StateRoot:  s.latestBlockHash,
				BodyRoot:   bodyRoot,
			}
			newRoot := computeBeaconHeaderRoot(hdr)
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

			s.headRoot = newRoot
			s.slotRoots[h] = newRoot
			s.rootSlots[newRoot] = h
			s.headerData[newRoot] = hdr
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

// verifyJWT verifies the JWT token in the request
