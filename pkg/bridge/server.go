package bridge

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	abciserver "github.com/cometbft/cometbft/abci/server"
	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	currentHeight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ethbft_current_height",
		Help: "Current CometBFT block height processed by ABCI",
	})
	txsBridged = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ethbft_txs_bridged_total",
		Help: "Total number of transactions bridged to Geth",
	})
)

// ABCIApplication implements minimal CometBFT ABCI to drive heights.
// We do not execute transactions here for the demo; Geth builds empty blocks.
type ABCIApplication struct {
	bridge        *Bridge
	lastPayload   *ExecutionPayload
	lastPayloadMu sync.RWMutex
	logger        *slog.Logger
}

func NewABCIApplication(bridge *Bridge) *ABCIApplication {
	return &ABCIApplication{
		bridge: bridge,
		logger: slog.Default().With("component", "abci_app"),
	}
}

func (app *ABCIApplication) Info(ctx context.Context, req *abcitypes.RequestInfo) (*abcitypes.ResponseInfo, error) {
	app.logger.Info("ABCI Info", "version", req.Version, "block_version", req.BlockVersion, "p2p_version", req.P2PVersion)
	return &abcitypes.ResponseInfo{
		Data:             "ethbft",
		Version:          "1.0.0",
		AppVersion:       1,
		LastBlockHeight:  0,
		LastBlockAppHash: []byte{},
	}, nil
}

func (app *ABCIApplication) Query(ctx context.Context, req *abcitypes.RequestQuery) (*abcitypes.ResponseQuery, error) {
	return &abcitypes.ResponseQuery{}, nil
}

func (app *ABCIApplication) CheckTx(ctx context.Context, req *abcitypes.RequestCheckTx) (*abcitypes.ResponseCheckTx, error) {
	return &abcitypes.ResponseCheckTx{Code: abcitypes.CodeTypeOK}, nil
}

func (app *ABCIApplication) InitChain(ctx context.Context, req *abcitypes.RequestInitChain) (*abcitypes.ResponseInitChain, error) {
	app.logger.Info("ABCI InitChain", "chain_id", req.ChainId, "initial_height", req.InitialHeight)
	return &abcitypes.ResponseInitChain{}, nil
}

func (app *ABCIApplication) PrepareProposal(ctx context.Context, req *abcitypes.RequestPrepareProposal) (*abcitypes.ResponsePrepareProposal, error) {
	return &abcitypes.ResponsePrepareProposal{Txs: req.Txs}, nil
}

func (app *ABCIApplication) ProcessProposal(ctx context.Context, req *abcitypes.RequestProcessProposal) (*abcitypes.ResponseProcessProposal, error) {
	return &abcitypes.ResponseProcessProposal{Status: abcitypes.ResponseProcessProposal_ACCEPT}, nil
}

func (app *ABCIApplication) FinalizeBlock(ctx context.Context, req *abcitypes.RequestFinalizeBlock) (*abcitypes.ResponseFinalizeBlock, error) {
	// Capture transactions and store them in the pool for the bridge to pick up.
	currentHeight.Set(float64(req.Height))
	if len(req.Txs) > 0 {
		app.logger.Info("ABCI FinalizeBlock received txs", "height", req.Height, "count", len(req.Txs))
		app.bridge.txPool.AddTxs(req.Height, req.Txs)
		txsBridged.Add(float64(len(req.Txs)))
	}

	txResults := make([]*abcitypes.ExecTxResult, len(req.Txs))
	for i, tx := range req.Txs {
		txResults[i] = &abcitypes.ExecTxResult{Code: abcitypes.CodeTypeOK, Data: tx}
	}
	return &abcitypes.ResponseFinalizeBlock{TxResults: txResults}, nil
}

func (app *ABCIApplication) ExtendVote(ctx context.Context, req *abcitypes.RequestExtendVote) (*abcitypes.ResponseExtendVote, error) {
	return &abcitypes.ResponseExtendVote{}, nil
}

func (app *ABCIApplication) VerifyVoteExtension(ctx context.Context, req *abcitypes.RequestVerifyVoteExtension) (*abcitypes.ResponseVerifyVoteExtension, error) {
	return &abcitypes.ResponseVerifyVoteExtension{}, nil
}

func (app *ABCIApplication) Commit(ctx context.Context, req *abcitypes.RequestCommit) (*abcitypes.ResponseCommit, error) {
	// Minimal commit; CometBFT accepts empty app hash for demo purposes.
	return &abcitypes.ResponseCommit{}, nil
}

func (app *ABCIApplication) ListSnapshots(ctx context.Context, req *abcitypes.RequestListSnapshots) (*abcitypes.ResponseListSnapshots, error) {
	return &abcitypes.ResponseListSnapshots{}, nil
}

func (app *ABCIApplication) OfferSnapshot(ctx context.Context, req *abcitypes.RequestOfferSnapshot) (*abcitypes.ResponseOfferSnapshot, error) {
	return &abcitypes.ResponseOfferSnapshot{}, nil
}

func (app *ABCIApplication) LoadSnapshotChunk(ctx context.Context, req *abcitypes.RequestLoadSnapshotChunk) (*abcitypes.ResponseLoadSnapshotChunk, error) {
	return &abcitypes.ResponseLoadSnapshotChunk{}, nil
}

func (app *ABCIApplication) ApplySnapshotChunk(ctx context.Context, req *abcitypes.RequestApplySnapshotChunk) (*abcitypes.ResponseApplySnapshotChunk, error) {
	return &abcitypes.ResponseApplySnapshotChunk{}, nil
}

// --- Convenience helpers retained for optional fallback/debug ---

// GetPendingPayload returns the last payload we saw or a best-effort latest block from EL.
func (app *ABCIApplication) GetPendingPayload(ctx context.Context) (*ExecutionPayload, error) {
	app.lastPayloadMu.RLock()
	if app.lastPayload != nil {
		defer app.lastPayloadMu.RUnlock()
		return app.lastPayload, nil
	}
	app.lastPayloadMu.RUnlock()

	if app.bridge.ethClient == nil {
		return nil, fmt.Errorf("ethereum client not available")
	}
	result, err := app.bridge.ethClient.Call(ctx, "eth_getBlockByNumber", []interface{}{"latest", false})
	if err != nil {
		return nil, fmt.Errorf("failed to get block from Geth: %w", err)
	}
	var block map[string]interface{}
	if err := json.Unmarshal(result, &block); err != nil {
		return nil, fmt.Errorf("failed to unmarshal block: %w", err)
	}
	hexToUint64 := func(s string) uint64 {
		var v uint64
		_, _ = fmt.Sscanf(strings.TrimPrefix(s, "0x"), "%x", &v)
		return v
	}
	payload := &ExecutionPayload{
		ParentHash:   common.HexToHash(getStringField(block, "parentHash")),
		FeeRecipient: common.HexToAddress(getStringField(block, "miner")),
		StateRoot:    common.HexToHash(getStringField(block, "stateRoot")),
		ReceiptsRoot: common.HexToHash(getStringField(block, "receiptsRoot")),
		LogsBloom: func() []byte {
			b, _ := hex.DecodeString(strings.TrimPrefix(getStringField(block, "logsBloom"), "0x"))
			// Ensure logs bloom is exactly 256 bytes (2048 bits) as expected by EL types.
			if len(b) < 256 {
				pad := make([]byte, 256)
				copy(pad[256-len(b):], b)
				return pad
			}
			if len(b) > 256 {
				return b[len(b)-256:]
			}
			return b
		}(),
		Random:    common.HexToHash(getStringField(block, "mixHash")),
		Number:    hexToUint64(getStringField(block, "number")),
		GasLimit:  hexToUint64(getStringField(block, "gasLimit")),
		GasUsed:   hexToUint64(getStringField(block, "gasUsed")),
		Timestamp: hexToUint64(getStringField(block, "timestamp")),
		ExtraData: func() []byte {
			d, _ := hex.DecodeString(strings.TrimPrefix(getStringField(block, "extraData"), "0x"))
			return d
		}(),
		BaseFeePerGas: func() *big.Int {
			bf, _ := new(big.Int).SetString(strings.TrimPrefix(getStringField(block, "baseFeePerGas"), "0x"), 16)
			return bf
		}(),
		BlockHash:    common.HexToHash(getStringField(block, "hash")),
		Transactions: [][]byte{},
		Withdrawals:  nil,
	}
	app.logger.Info("Fallback payload from EL", "number", payload.Number, "hash", payload.BlockHash.Hex())
	return payload, nil
}

// Safe getter for a string field; returns a 32-byte zero hex for missing hashes.
func getStringField(block map[string]interface{}, field string) string {
	if value, ok := block[field].(string); ok && value != "" {
		return value
	}
	return "0x" + strings.Repeat("0", 64)
}

func (app *ABCIApplication) ExecutePayload(ctx context.Context, payload *ExecutionPayload) error {
	app.lastPayloadMu.Lock()
	app.lastPayload = payload
	app.lastPayloadMu.Unlock()
	return nil
}

func (app *ABCIApplication) UpdateForkchoice(ctx context.Context, state *ForkchoiceState) error {
	// Not used in the minimal demo.
	return nil
}

func (app *ABCIApplication) GetLatestBlock(ctx context.Context) (height int64, hash string, err error) {
	status, err := app.bridge.consClient.GetStatus(ctx)
	if err != nil {
		app.logger.Warn("Failed to get CometBFT status", "error", err)
		return 0, "0x" + strings.Repeat("0", 64), nil
	}
	if syncInfo, ok := status["sync_info"].(map[string]interface{}); ok {
		if heightStr, ok := syncInfo["latest_block_height"].(string); ok {
			if parsed, err := strconv.ParseInt(heightStr, 10, 64); err == nil {
				height = parsed
			}
		}
		// For demo we return EL latest state root as "hash" (not required anymore).
		if gethStateRoot, err := app.getGethStateRoot(ctx, height); err == nil {
			return height, gethStateRoot, nil
		}
		if hashStr, ok := syncInfo["latest_block_hash"].(string); ok {
			return height, "0x" + strings.ToLower(hashStr), nil
		}
	}
	return 0, "0x" + strings.Repeat("0", 64), nil
}

func (app *ABCIApplication) getGethStateRoot(ctx context.Context, height int64) (string, error) {
	if app.bridge.ethClient == nil {
		return "", fmt.Errorf("ethereum client not available")
	}
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
	// app.logger.Debug("Retrieved EL state root", "height", height, "stateRoot", stateRoot)
	return stateRoot, nil
}

// ABCIServer wraps the official CometBFT ABCI socket server plus an HTTP health endpoint.
type ABCIServer struct {
	bridge *Bridge
	srv    interface {
		Start() error
		Stop() error
	}
	httpServer *http.Server
	listenAddr string
	healthAddr string
	logger     *slog.Logger
}

func NewABCIServer(bridge *Bridge) *ABCIServer {
	addr := "0.0.0.0:8080"
	health := "0.0.0.0:8081"
	if bridge.config != nil && bridge.config.Bridge.ListenAddr != "" {
		addr = bridge.config.Bridge.ListenAddr
	}
	return &ABCIServer{
		bridge:     bridge,
		listenAddr: addr,
		healthAddr: health,
		logger:     slog.Default().With("component", "abci_server"),
	}
}

func (s *ABCIServer) Start() error {
	s.logger.Info("Starting ABCI socket server", "addr", s.listenAddr)
	if s.bridge.abciApp == nil {
		return fmt.Errorf("no ABCI application available")
	}
	srv, err := abciserver.NewServer(s.listenAddr, "socket", s.bridge.abciApp)
	if err != nil {
		return fmt.Errorf("failed to create ABCI socket server on %s: %w", s.listenAddr, err)
	}
	s.srv = srv

	// Health HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.Handle("/metrics", promhttp.Handler())

	s.httpServer = &http.Server{
		Addr:              s.healthAddr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}
	go func() {
		ln, err := net.Listen("tcp", s.healthAddr)
		if err != nil {
			s.logger.Error("Health/Metrics server listen error", "error", err)
			return
		}
		s.logger.Info("Starting HTTP health/metrics server", "addr", s.healthAddr)
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger.Error("Health/Metrics server error", "error", err)
		}
	}()

	if err := s.srv.Start(); err != nil {
		return fmt.Errorf("failed to start ABCI socket server: %w", err)
	}
	return nil
}

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
