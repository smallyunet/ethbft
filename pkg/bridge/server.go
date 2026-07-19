package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	abciserver "github.com/cometbft/cometbft/abci/server"
	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/smallyunet/ethbft/pkg/config"
	"github.com/smallyunet/ethbft/pkg/protocol"
)

var (
	currentHeight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ethbft_current_height",
		Help: "Current CometBFT block height processed by ABCI",
	})
	txsBridged = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ethbft_txs_bridged_total",
		Help: "Total number of transactions committed in BFT-validated execution payloads",
	})
	rpcErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ethbft_rpc_errors_total",
		Help: "Total number of RPC errors communicating with Geth or CometBFT",
	})
	blockProductionDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "ethbft_block_production_duration_seconds",
		Help:    "Time taken to produce a block via Engine API",
		Buckets: prometheus.DefBuckets,
	})
	txsRejected = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ethbft_txs_rejected_total",
		Help: "Total number of transactions rejected by ABCI CheckTx",
	})
	txsInjectionFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ethbft_txs_injection_failed_total",
		Help: "Total number of transactions that failed injection into Geth",
	})
)

func bridgeProgressError(enabled bool, cometHeight, bridgeHeight int64, ethereumHeight uint64, maxLag int64, lastProgress time.Time, stallTimeout time.Duration) string {
	if enabled && cometHeight > 0 && (bridgeHeight == 0 || ethereumHeight == 0) {
		return "CometBFT is producing blocks but no execution block has been produced"
	}
	if enabled && maxLag > 0 && cometHeight-bridgeHeight > maxLag {
		return fmt.Sprintf("bridge is %d blocks behind CometBFT (maximum %d)", cometHeight-bridgeHeight, maxLag)
	}
	if enabled && cometHeight > bridgeHeight && stallTimeout > 0 && !lastProgress.IsZero() && time.Since(lastProgress) > stallTimeout {
		return fmt.Sprintf("bridge has made no progress for %s", time.Since(lastProgress).Round(time.Second))
	}
	return ""
}

func validateTransaction(raw []byte, chainID *big.Int) (uint32, string) {
	if len(raw) > 128*1024 {
		return 1, "tx too large"
	}
	if protocol.IsEnvelope(raw) {
		return 6, "reserved EthBFT execution envelope"
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(raw); err != nil {
		return 2, fmt.Sprintf("invalid transaction encoding: %v", err)
	}
	if chainID == nil {
		return 4, "bridge not initialized: chainID unknown"
	}
	if tx.ChainId().Cmp(chainID) != 0 {
		return 3, fmt.Sprintf("wrong chainID: got %v want %v", tx.ChainId(), chainID)
	}
	if _, err := types.Sender(types.LatestSignerForChainID(chainID), &tx); err != nil {
		return 5, fmt.Sprintf("invalid signature: %v", err)
	}
	if tx.Type() > types.DynamicFeeTxType {
		return 7, fmt.Sprintf("transaction type %d is not supported by Engine API V2", tx.Type())
	}
	return abcitypes.CodeTypeOK, "accepted into the EthBFT transaction mempool"
}

// ABCIApplication implements minimal CometBFT ABCI to drive heights.
type ABCIApplication struct {
	bridge *Bridge
	logger *slog.Logger
}

func NewABCIApplication(bridge *Bridge) *ABCIApplication {
	return &ABCIApplication{
		bridge: bridge,
		logger: slog.Default().With("component", "abci_app"),
	}
}

func (app *ABCIApplication) Info(ctx context.Context, req *abcitypes.RequestInfo) (*abcitypes.ResponseInfo, error) {
	version := config.DefaultAppVersion
	if app.bridge.config != nil && app.bridge.config.Bridge.AppVersion != "" {
		version = app.bridge.config.Bridge.AppVersion
	}
	app.logger.Info("ABCI Info", "version", req.Version, "app_version", version)
	return &abcitypes.ResponseInfo{
		Data:             "ethbft",
		Version:          version,
		AppVersion:       1,
		LastBlockHeight:  app.bridge.abciLastBlockHeight.Load(),
		LastBlockAppHash: app.bridge.appHash(),
	}, nil
}

func (app *ABCIApplication) Query(ctx context.Context, req *abcitypes.RequestQuery) (*abcitypes.ResponseQuery, error) {
	return &abcitypes.ResponseQuery{}, nil
}

func (app *ABCIApplication) CheckTx(ctx context.Context, req *abcitypes.RequestCheckTx) (*abcitypes.ResponseCheckTx, error) {
	code, message := validateTransaction(req.Tx, app.bridge.chainID)
	if code != abcitypes.CodeTypeOK {
		txsRejected.Inc()
	}
	return &abcitypes.ResponseCheckTx{Code: code, Log: message}, nil
}

func (app *ABCIApplication) InitChain(ctx context.Context, req *abcitypes.RequestInitChain) (*abcitypes.ResponseInitChain, error) {
	app.logger.Info("ABCI InitChain", "chain_id", req.ChainId, "initial_height", req.InitialHeight)
	return &abcitypes.ResponseInitChain{}, nil
}

func (app *ABCIApplication) PrepareProposal(ctx context.Context, req *abcitypes.RequestPrepareProposal) (*abcitypes.ResponsePrepareProposal, error) {
	app.bridge.consensusMu.Lock()
	defer app.bridge.consensusMu.Unlock()
	start := time.Now()
	proposal, err := app.bridge.buildExecutionProposal(req.Height, req.Time, req.Txs, req.MaxTxBytes)
	observeProposalValidation(start, err)
	if err != nil {
		app.logger.Error("Could not build execution proposal", "height", req.Height, "error", err)
		// Returning an empty proposal keeps the ABCI connection alive. Peers will
		// reject it in ProcessProposal and CometBFT can move to the next proposer.
		return &abcitypes.ResponsePrepareProposal{}, nil
	}
	app.logger.Info("Built execution proposal", "height", req.Height, "transactions", len(proposal)-1)
	return &abcitypes.ResponsePrepareProposal{Txs: proposal}, nil
}

func (app *ABCIApplication) ProcessProposal(ctx context.Context, req *abcitypes.RequestProcessProposal) (*abcitypes.ResponseProcessProposal, error) {
	app.bridge.consensusMu.Lock()
	defer app.bridge.consensusMu.Unlock()
	start := time.Now()
	validationCtx, cancel := context.WithTimeout(ctx, app.bridge.operationTimeout())
	defer cancel()
	_, err := app.bridge.validateExecutionProposal(validationCtx, req.Height, req.Time, req.Txs)
	observeProposalValidation(start, err)
	if err != nil {
		app.logger.Warn("Rejected execution proposal", "height", req.Height, "error", err)
		return &abcitypes.ResponseProcessProposal{Status: abcitypes.ResponseProcessProposal_REJECT}, nil
	}
	return &abcitypes.ResponseProcessProposal{Status: abcitypes.ResponseProcessProposal_ACCEPT}, nil
}

func (app *ABCIApplication) FinalizeBlock(ctx context.Context, req *abcitypes.RequestFinalizeBlock) (*abcitypes.ResponseFinalizeBlock, error) {
	app.bridge.consensusMu.Lock()
	defer app.bridge.consensusMu.Unlock()

	pending, err := app.bridge.stageExecutionCommit(req.Height, req.Time, req.Txs)
	if err != nil {
		return nil, fmt.Errorf("stage decided execution payload: %w", err)
	}
	txResults := make([]*abcitypes.ExecTxResult, len(req.Txs))
	if len(txResults) > 0 {
		txResults[0] = &abcitypes.ExecTxResult{Code: abcitypes.CodeTypeOK, Log: "execution payload metadata committed"}
	}
	for i, tx := range pending.txs {
		txResults[i+1] = &abcitypes.ExecTxResult{Code: abcitypes.CodeTypeOK, Data: tx, Log: "executed in BFT-committed payload"}
	}
	app.logger.Info("Finalized execution proposal", "height", req.Height, "block_hash", pending.payload.BlockHash, "transactions", len(pending.txs))
	return &abcitypes.ResponseFinalizeBlock{TxResults: txResults, AppHash: append([]byte(nil), pending.appHash...)}, nil
}

func (app *ABCIApplication) ExtendVote(ctx context.Context, req *abcitypes.RequestExtendVote) (*abcitypes.ResponseExtendVote, error) {
	return &abcitypes.ResponseExtendVote{}, nil
}

func (app *ABCIApplication) VerifyVoteExtension(ctx context.Context, req *abcitypes.RequestVerifyVoteExtension) (*abcitypes.ResponseVerifyVoteExtension, error) {
	return &abcitypes.ResponseVerifyVoteExtension{}, nil
}

func (app *ABCIApplication) Commit(ctx context.Context, req *abcitypes.RequestCommit) (*abcitypes.ResponseCommit, error) {
	app.bridge.consensusMu.Lock()
	defer app.bridge.consensusMu.Unlock()
	if app.bridge.pendingCommit == nil {
		return nil, fmt.Errorf("no finalized execution payload to commit")
	}
	if err := app.bridge.commitPendingExecution(); err != nil {
		return nil, err
	}
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
	if bridge.config != nil {
		if bridge.config.Bridge.ListenAddr != "" {
			addr = bridge.config.Bridge.ListenAddr
		}
		if bridge.config.Bridge.HealthAddr != "" {
			health = bridge.config.Bridge.HealthAddr
		}
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
	mux.HandleFunc("/live", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		status := http.StatusOK
		response := make(map[string]any)
		response["status"] = "ok"

		// Check Geth
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ethBlockRaw, err := s.bridge.ethClient.Call(ctx, "eth_blockNumber", nil)
		var ethereumHeight uint64
		if err != nil {
			status = http.StatusServiceUnavailable
			response["status"] = "error"
			response["ethereum_error"] = err.Error()
		} else {
			response["ethereum"] = "connected"
			var blockHex string
			if err := json.Unmarshal(ethBlockRaw, &blockHex); err != nil {
				status = http.StatusServiceUnavailable
				response["status"] = "error"
				response["ethereum_error"] = "invalid eth_blockNumber response"
			} else if ethereumHeight, err = strconv.ParseUint(strings.TrimPrefix(blockHex, "0x"), 16, 64); err != nil {
				status = http.StatusServiceUnavailable
				response["status"] = "error"
				response["ethereum_error"] = "invalid eth_blockNumber value"
			} else {
				response["ethereum_height"] = ethereumHeight
			}
		}

		// Check CometBFT
		ctxCons, cancelCons := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelCons()
		cometStatus, err := s.bridge.consClient.GetStatus(ctxCons)
		if err != nil {
			status = http.StatusServiceUnavailable
			response["status"] = "error"
			response["cometbft_error"] = err.Error()
		} else {
			response["cometbft"] = "connected"
			response["cometbft_height"] = cometStatus.SyncInfo.LatestBlockHeight
		}

		bridgeHeight := s.bridge.lastProducedHeight.Load()
		response["bridge_height"] = bridgeHeight
		bridgingEnabled := s.bridge.config != nil && s.bridge.config.Bridge.EnableBridging
		var cometHeight int64
		if cometStatus != nil {
			cometHeight = cometStatus.SyncInfo.LatestBlockHeight
		}
		maxLag := s.bridge.config.Bridge.MaxBridgeLag
		stallTimeout := time.Duration(s.bridge.config.Bridge.StallTimeout) * time.Second
		lastProgressUnix := s.bridge.lastProgressUnix.Load()
		var lastProgress time.Time
		if lastProgressUnix > 0 {
			lastProgress = time.Unix(lastProgressUnix, 0)
		}
		response["bridge_lag"] = cometHeight - bridgeHeight
		response["last_progress_at"] = lastProgress.UTC().Format(time.RFC3339)
		if progressErr := bridgeProgressError(bridgingEnabled, cometHeight, bridgeHeight, ethereumHeight, maxLag, lastProgress, stallTimeout); progressErr != "" {
			status = http.StatusServiceUnavailable
			response["status"] = "error"
			response["bridge_error"] = progressErr
		}
		statePersisted := s.bridge.statePersisted.Load()
		response["state_persisted"] = statePersisted
		if bridgingEnabled && bridgeHeight > 0 && !statePersisted {
			status = http.StatusServiceUnavailable
			response["status"] = "error"
			response["state_error"] = "bridge state has not been persisted"
		}
		if bridgingEnabled && bridgeHeight > 0 {
			ctxReconcile, cancelReconcile := context.WithTimeout(context.Background(), 2*time.Second)
			if err := s.bridge.reconcileState(ctxReconcile); err != nil {
				status = http.StatusServiceUnavailable
				response["status"] = "error"
				response["state_error"] = err.Error()
			}
			cancelReconcile()
		}

		// Also check bridge running state
		s.bridge.runningLock.Lock()
		running := s.bridge.running
		s.bridge.runningLock.Unlock()
		if !running {
			status = http.StatusServiceUnavailable
			response["status"] = "error"
			response["bridge_running"] = false
		} else {
			response["bridge_running"] = true
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(response)
	})
	mux.HandleFunc("/tx/", func(w http.ResponseWriter, r *http.Request) {
		hashText := strings.TrimPrefix(r.URL.Path, "/tx/")
		decodedHash, err := hexutil.Decode(hashText)
		if err != nil || len(decodedHash) != common.HashLength {
			http.Error(w, "invalid transaction hash", http.StatusBadRequest)
			return
		}
		delivery, ok := s.bridge.txPool.GetDelivery(common.BytesToHash(decodedHash))
		if !ok {
			http.Error(w, "transaction delivery status not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(delivery)
	})
	mux.Handle("/metrics", promhttp.Handler())

	s.httpServer = &http.Server{
		Addr:              s.healthAddr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}
	ln, err := net.Listen("tcp", s.healthAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on health/metrics address %s: %w", s.healthAddr, err)
	}
	go func() {
		s.logger.Info("Starting HTTP health/metrics server", "addr", s.healthAddr)
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger.Error("Health/Metrics server error", "error", err)
		}
	}()

	if err := s.srv.Start(); err != nil {
		_ = s.httpServer.Close()
		return fmt.Errorf("failed to start ABCI socket server: %w", err)
	}
	return nil
}

func (s *ABCIServer) Stop() {
	if s.srv != nil {
		if err := s.srv.Stop(); err != nil {
			s.logger.Error("Failed to stop ABCI server", "error", err)
		}
	}
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.Error("Failed to shutdown health server", "error", err)
		}
	}
}
