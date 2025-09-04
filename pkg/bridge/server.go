package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	abciserver "github.com/cometbft/cometbft/abci/server"
	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/smallyunet/ethbft/pkg/engine"
)

// ABCIApplication implements the CometBFT ABCI interface
type ABCIApplication struct {
	bridge *Bridge
}

// NewABCIApplication creates a new ABCI application instance
func NewABCIApplication(bridge *Bridge) *ABCIApplication {
	return &ABCIApplication{
		bridge: bridge,
	}
}

// Info implements abcitypes.Application.Info
func (app *ABCIApplication) Info(ctx context.Context, req *abcitypes.RequestInfo) (*abcitypes.ResponseInfo, error) {
	return &abcitypes.ResponseInfo{
		Data:             "ethbft",
		Version:          "1.0.0",
		AppVersion:       1,
		LastBlockHeight:  0,
		LastBlockAppHash: []byte{},
	}, nil
}

// Query implements abcitypes.Application.Query
func (app *ABCIApplication) Query(ctx context.Context, req *abcitypes.RequestQuery) (*abcitypes.ResponseQuery, error) {
	return &abcitypes.ResponseQuery{}, nil
}

// CheckTx implements abcitypes.Application.CheckTx
func (app *ABCIApplication) CheckTx(ctx context.Context, req *abcitypes.RequestCheckTx) (*abcitypes.ResponseCheckTx, error) {
	return &abcitypes.ResponseCheckTx{Code: abcitypes.CodeTypeOK}, nil
}

// InitChain implements abcitypes.Application.InitChain
func (app *ABCIApplication) InitChain(ctx context.Context, req *abcitypes.RequestInitChain) (*abcitypes.ResponseInitChain, error) {
	return &abcitypes.ResponseInitChain{}, nil
}

// PrepareProposal implements abcitypes.Application.PrepareProposal
func (app *ABCIApplication) PrepareProposal(ctx context.Context, req *abcitypes.RequestPrepareProposal) (*abcitypes.ResponsePrepareProposal, error) {
	return &abcitypes.ResponsePrepareProposal{}, nil
}

// ProcessProposal implements abcitypes.Application.ProcessProposal
func (app *ABCIApplication) ProcessProposal(ctx context.Context, req *abcitypes.RequestProcessProposal) (*abcitypes.ResponseProcessProposal, error) {
	return &abcitypes.ResponseProcessProposal{
		Status: abcitypes.ResponseProcessProposal_ACCEPT,
	}, nil
}

// FinalizeBlock implements abcitypes.Application.FinalizeBlock
func (app *ABCIApplication) FinalizeBlock(ctx context.Context, req *abcitypes.RequestFinalizeBlock) (*abcitypes.ResponseFinalizeBlock, error) {
	// Create transaction results for each transaction in the block
	txResults := make([]*abcitypes.ExecTxResult, len(req.Txs))
	for i, tx := range req.Txs {
		txResults[i] = &abcitypes.ExecTxResult{
			Code: abcitypes.CodeTypeOK,
			Data: tx,
		}
	}

	return &abcitypes.ResponseFinalizeBlock{
		TxResults: txResults,
	}, nil
}

// ExtendVote implements abcitypes.Application.ExtendVote
func (app *ABCIApplication) ExtendVote(ctx context.Context, req *abcitypes.RequestExtendVote) (*abcitypes.ResponseExtendVote, error) {
	return &abcitypes.ResponseExtendVote{}, nil
}

// VerifyVoteExtension implements abcitypes.Application.VerifyVoteExtension
func (app *ABCIApplication) VerifyVoteExtension(ctx context.Context, req *abcitypes.RequestVerifyVoteExtension) (*abcitypes.ResponseVerifyVoteExtension, error) {
	return &abcitypes.ResponseVerifyVoteExtension{}, nil
}

// Commit implements abcitypes.Application.Commit
func (app *ABCIApplication) Commit(ctx context.Context, req *abcitypes.RequestCommit) (*abcitypes.ResponseCommit, error) {
	return &abcitypes.ResponseCommit{}, nil
}

// ListSnapshots implements abcitypes.Application.ListSnapshots
func (app *ABCIApplication) ListSnapshots(ctx context.Context, req *abcitypes.RequestListSnapshots) (*abcitypes.ResponseListSnapshots, error) {
	return &abcitypes.ResponseListSnapshots{}, nil
}

// OfferSnapshot implements abcitypes.Application.OfferSnapshot
func (app *ABCIApplication) OfferSnapshot(ctx context.Context, req *abcitypes.RequestOfferSnapshot) (*abcitypes.ResponseOfferSnapshot, error) {
	return &abcitypes.ResponseOfferSnapshot{}, nil
}

// LoadSnapshotChunk implements abcitypes.Application.LoadSnapshotChunk
func (app *ABCIApplication) LoadSnapshotChunk(ctx context.Context, req *abcitypes.RequestLoadSnapshotChunk) (*abcitypes.ResponseLoadSnapshotChunk, error) {
	return &abcitypes.ResponseLoadSnapshotChunk{}, nil
}

// ApplySnapshotChunk implements abcitypes.Application.ApplySnapshotChunk
func (app *ABCIApplication) ApplySnapshotChunk(ctx context.Context, req *abcitypes.RequestApplySnapshotChunk) (*abcitypes.ResponseApplySnapshotChunk, error) {
	return &abcitypes.ResponseApplySnapshotChunk{}, nil
}

// ABCIClient interface implementation for Engine API
func (app *ABCIApplication) GetPendingPayload(ctx context.Context) (*engine.ExecutionPayload, error) {
	if app.bridge.ethClient == nil {
		return nil, fmt.Errorf("ethereum client not available")
	}

	// Get the latest block from Geth which contains the execution payload data
	result, err := app.bridge.ethClient.Call(ctx, "eth_getBlockByNumber", []interface{}{"latest", true})
	if err != nil {
		return nil, fmt.Errorf("failed to get block from Geth: %w", err)
	}

	var block map[string]interface{}
	if err := json.Unmarshal(result, &block); err != nil {
		return nil, fmt.Errorf("failed to unmarshal block: %w", err)
	}

	// Extract execution payload fields from the block
	payload := &engine.ExecutionPayload{
		ParentHash:    getStringField(block, "parentHash"),
		FeeRecipient:  getStringField(block, "miner"), // miner is fee_recipient in execution layer
		StateRoot:     getStringField(block, "stateRoot"),
		ReceiptsRoot:  getStringField(block, "receiptsRoot"),
		LogsBloom:     getStringField(block, "logsBloom"),
		PrevRandao:    getStringField(block, "mixHash"), // mixHash is prevRandao post-merge
		BlockNumber:   getStringField(block, "number"),
		GasLimit:      getStringField(block, "gasLimit"),
		GasUsed:       getStringField(block, "gasUsed"),
		Timestamp:     getStringField(block, "timestamp"),
		ExtraData:     getStringField(block, "extraData"),
		BaseFeePerGas: getStringField(block, "baseFeePerGas"),
		BlockHash:     getStringField(block, "hash"),
		Transactions:  getTransactions(block),
	}

	log.Printf("Retrieved execution payload from Geth: blockNumber=%s, stateRoot=%s, hash=%s",
		payload.BlockNumber, payload.StateRoot, payload.BlockHash)

	return payload, nil
}

// Helper function to safely get string fields from block data
func getStringField(block map[string]interface{}, field string) string {
	if value, ok := block[field].(string); ok {
		return value
	}
	return "0x0" // Default value for missing fields
}

// Helper function to get transactions from block data
func getTransactions(block map[string]interface{}) []string {
	if txsInterface, ok := block["transactions"].([]interface{}); ok {
		transactions := make([]string, len(txsInterface))
		for i, tx := range txsInterface {
			if txStr, ok := tx.(string); ok {
				transactions[i] = txStr
			} else {
				transactions[i] = "0x" // Handle transaction objects by defaulting to empty
			}
		}
		return transactions
	}
	return []string{} // Return empty slice if no transactions
}

func (app *ABCIApplication) ExecutePayload(ctx context.Context, payload *engine.ExecutionPayload) error {
	// TODO: Implement payload execution logic
	return nil
}

func (app *ABCIApplication) UpdateForkchoice(ctx context.Context, state *engine.ForkchoiceState) error {
	// TODO: Implement forkchoice update logic
	return nil
}

func (app *ABCIApplication) GetLatestBlock(ctx context.Context) (height int64, hash string, err error) {
	// Get latest block from CometBFT
	status, err := app.bridge.consClient.GetStatus(ctx)
	if err != nil {
		// Return default values instead of error when CometBFT is not available
		log.Printf("Warning: Failed to get CometBFT status: %v, returning default values", err)
		return 0, "0x0000000000000000000000000000000000000000000000000000000000000000", nil
	}

	// Extract block height and hash from status
	if syncInfo, ok := status["sync_info"].(map[string]interface{}); ok {
		if heightStr, ok := syncInfo["latest_block_height"].(string); ok {
			// Convert string to int64
			if heightInt, err := fmt.Sscanf(heightStr, "%d", &height); err != nil {
				log.Printf("Warning: Failed to parse block height: %v, using default", err)
				return 0, "0x0000000000000000000000000000000000000000000000000000000000000000", nil
			} else if heightInt != 1 {
				log.Printf("Warning: Failed to parse block height: expected 1 item, got %d, using default", heightInt)
				return 0, "0x0000000000000000000000000000000000000000000000000000000000000000", nil
			}
		}

		// Get the state root from Geth instead of using CometBFT block hash
		if gethStateRoot, err := app.getGethStateRoot(ctx, height); err != nil {
			log.Printf("Warning: Failed to get Geth state root: %v, using CometBFT hash as fallback", err)
			// Fallback to CometBFT hash
			if hashStr, ok := syncInfo["latest_block_hash"].(string); ok {
				hash = "0x" + hashStr
			}
		} else {
			hash = gethStateRoot
		}

		return height, hash, nil
	}

	// Return default values if no sync info available
	log.Printf("Warning: No sync info available, returning default values")
	return 0, "0x0000000000000000000000000000000000000000000000000000000000000000", nil
}

// getGethStateRoot gets the state root from the latest executed payload
func (app *ABCIApplication) getGethStateRoot(ctx context.Context, height int64) (string, error) {
	// First, try to get the state root from the bridge's engine server
	// This is more reliable as it tracks the actual execution state

	if app.bridge.ethClient == nil {
		return "", fmt.Errorf("ethereum client not available")
	}

	// Get the latest block from Geth to get the state root
	result, err := app.bridge.ethClient.Call(ctx, "eth_getBlockByNumber", []interface{}{"latest", false})
	if err != nil {
		return "", fmt.Errorf("failed to get block from Geth: %w", err)
	}

	var block map[string]interface{}
	if err := json.Unmarshal(result, &block); err != nil {
		return "", fmt.Errorf("failed to unmarshal block: %w", err)
	}

	stateRoot, ok := block["stateRoot"].(string)
	if !ok {
		return "", fmt.Errorf("state root not found in block")
	}

	log.Printf("Retrieved Geth state root for height %d: %s", height, stateRoot)
	return stateRoot, nil
}

// GetLatestExecutionStateRoot gets the state root from the latest execution,
// which should be used by the Engine API server for beacon header construction
func (app *ABCIApplication) GetLatestExecutionStateRoot(ctx context.Context) (string, error) {
	return app.getGethStateRoot(ctx, 0) // height is not used in current implementation
}

// ABCIServer implements a socket server using the official CometBFT ABCI server
type ABCIServer struct {
	bridge *Bridge
	srv    interface {
		Start() error
		Stop() error
	}
	httpServer *http.Server
	listenAddr string
	healthAddr string
}

// NewABCIServer creates a new ABCI server instance
func NewABCIServer(bridge *Bridge) *ABCIServer {
	addr := "0.0.0.0:8080"
	health := "0.0.0.0:8081"
	if bridge.config != nil {
		if bridge.config.Bridge.ListenAddr != "" {
			addr = bridge.config.Bridge.ListenAddr
		}
	}
	return &ABCIServer{
		bridge:     bridge,
		listenAddr: addr,
		healthAddr: health,
	}
}

// Start starts the ABCI server
func (s *ABCIServer) Start() error {
	log.Printf("Starting ABCI socket server on %s", s.listenAddr)

	if s.bridge.abciApp == nil {
		return fmt.Errorf("no ABCI application available")
	}

	srv, err := abciserver.NewServer(s.listenAddr, "socket", s.bridge.abciApp)
	if err != nil {
		return fmt.Errorf("failed to create ABCI socket server on %s: %w", s.listenAddr, err)
	}
	s.srv = srv

	// Start health check HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	s.httpServer = &http.Server{
		Addr:              s.healthAddr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}
	go func() {
		ln, err := net.Listen("tcp", s.healthAddr)
		if err != nil {
			log.Printf("health server listen error: %v", err)
			return
		}
		log.Printf("Starting HTTP health check server on %s", s.healthAddr)
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("health server error: %v", err)
		}
	}()

	if err := s.srv.Start(); err != nil {
		return fmt.Errorf("failed to start ABCI socket server: %w", err)
	}
	return nil
}

// Stop stops the ABCI server
func (s *ABCIServer) Stop() {
	if s.srv != nil {
		_ = s.srv.Stop()
	}
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(ctx)
	}
}
