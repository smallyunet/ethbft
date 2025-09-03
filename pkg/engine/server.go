package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
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
}

// ABCIClient defines the interface to communicate with ABCI application
type ABCIClient interface {
	GetPendingPayload(ctx context.Context) (*ExecutionPayload, error)
	ExecutePayload(ctx context.Context, payload *ExecutionPayload) error
	UpdateForkchoice(ctx context.Context, state *ForkchoiceState) error
}

// ExecutionPayload represents an execution payload
type ExecutionPayload struct {
	ParentHash    string   `json:"parentHash"`
	FeeRecipient  string   `json:"feeRecipient"`
	StateRoot     string   `json:"stateRoot"`
	ReceiptsRoot  string   `json:"receiptsRoot"`
	LogsBloom     string   `json:"logsBloom"`
	PrevRandao    string   `json:"prevRandao"`
	BlockNumber   string   `json:"blockNumber"`
	GasLimit      string   `json:"gasLimit"`
	GasUsed       string   `json:"gasUsed"`
	Timestamp     string   `json:"timestamp"`
	ExtraData     string   `json:"extraData"`
	BaseFeePerGas string   `json:"baseFeePerGas"`
	BlockHash     string   `json:"blockHash"`
	Transactions  []string `json:"transactions"`
}

// ForkchoiceState represents the forkchoice state
type ForkchoiceState struct {
	HeadBlockHash      string `json:"headBlockHash"`
	SafeBlockHash      string `json:"safeBlockHash"`
	FinalizedBlockHash string `json:"finalizedBlockHash"`
}

// PayloadAttributes represents payload building attributes
type PayloadAttributes struct {
	Timestamp             string   `json:"timestamp"`
	PrevRandao            string   `json:"prevRandao"`
	SuggestedFeeRecipient string   `json:"suggestedFeeRecipient"`
	Withdrawals           []string `json:"withdrawals,omitempty"`
}

// PayloadStatus represents the payload execution status
type PayloadStatus struct {
	Status          string  `json:"status"`          // VALID, INVALID, SYNCING, ACCEPTED
	LatestValidHash *string `json:"latestValidHash"` // Hash of the most recent valid block
	ValidationError *string `json:"validationError"` // Error message if invalid
}

// ForkchoiceUpdatedResponse represents the response to forkchoice update
type ForkchoiceUpdatedResponse struct {
	PayloadStatus PayloadStatus `json:"payloadStatus"`
	PayloadId     *string       `json:"payloadId"` // Identifier of the payload build process
}

// TransitionConfiguration represents the transition configuration
type TransitionConfiguration struct {
	TerminalTotalDifficulty string `json:"terminalTotalDifficulty"`
	TerminalBlockHash       string `json:"terminalBlockHash"`
	TerminalBlockNumber     string `json:"terminalBlockNumber"`
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
	}

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
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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
	default:
		err = fmt.Errorf("method %s not found", req.Method)
	}

	// Send response
	s.sendResponse(w, req.ID, result, err)
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
	// This should read from the JWT file
	// For now, return a placeholder
	return "your-jwt-secret", nil
}

// JSON-RPC types
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

type jsonRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// sendResponse sends a JSON-RPC response
func (s *Server) sendResponse(w http.ResponseWriter, id interface{}, result interface{}, err error) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
	}

	if err != nil {
		resp.Error = &rpcError{
			Code:    -32000,
			Message: err.Error(),
		}
	} else {
		resp.Result = result
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Engine API method handlers

func (s *Server) handleNewPayload(params json.RawMessage) (interface{}, error) {
	var payload ExecutionPayload
	if err := json.Unmarshal(params, &[]interface{}{&payload}); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}

	log.Printf("Received new payload: block %s", payload.BlockNumber)

	// Execute the payload via ABCI
	if err := s.abciClient.ExecutePayload(context.Background(), &payload); err != nil {
		errMsg := err.Error()
		return PayloadStatus{
			Status:          "INVALID",
			LatestValidHash: nil,
			ValidationError: &errMsg,
		}, nil
	}

	s.latestPayload = &payload

	validHash := payload.BlockHash
	return PayloadStatus{
		Status:          "VALID",
		LatestValidHash: &validHash,
		ValidationError: nil,
	}, nil
}

func (s *Server) handleForkchoiceUpdated(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}

	if len(args) < 1 {
		return nil, fmt.Errorf("missing forkchoice state")
	}

	var state ForkchoiceState
	if err := json.Unmarshal(args[0], &state); err != nil {
		return nil, fmt.Errorf("invalid forkchoice state: %v", err)
	}

	log.Printf("Forkchoice updated: head=%s, safe=%s, finalized=%s",
		state.HeadBlockHash, state.SafeBlockHash, state.FinalizedBlockHash)

	// Update our state
	s.forkchoiceState = &state

	// Notify ABCI
	if err := s.abciClient.UpdateForkchoice(context.Background(), &state); err != nil {
		return nil, fmt.Errorf("failed to update forkchoice: %v", err)
	}

	response := ForkchoiceUpdatedResponse{
		PayloadStatus: PayloadStatus{
			Status:          "VALID",
			LatestValidHash: &state.HeadBlockHash,
			ValidationError: nil,
		},
		PayloadId: nil,
	}

	// If there are payload attributes, prepare a new payload
	if len(args) >= 2 {
		var attrs PayloadAttributes
		if err := json.Unmarshal(args[1], &attrs); err == nil {
			s.payloadCounter++
			payloadId := fmt.Sprintf("0x%x", s.payloadCounter)
			response.PayloadId = &payloadId

			log.Printf("Prepared payload with ID: %s", payloadId)
		}
	}

	return response, nil
}

func (s *Server) handleGetPayload(params json.RawMessage) (interface{}, error) {
	var payloadId string
	if err := json.Unmarshal(params, &[]interface{}{&payloadId}); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}

	log.Printf("Getting payload for ID: %s", payloadId)

	// Get payload from ABCI
	payload, err := s.abciClient.GetPendingPayload(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get payload: %v", err)
	}

	return payload, nil
}

func (s *Server) handleExchangeTransitionConfiguration(params json.RawMessage) (interface{}, error) {
	// Return default transition configuration
	return TransitionConfiguration{
		TerminalTotalDifficulty: "0x0",
		TerminalBlockHash:       "0x0000000000000000000000000000000000000000000000000000000000000000",
		TerminalBlockNumber:     "0x0",
	}, nil
}
