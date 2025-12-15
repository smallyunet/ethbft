package bridge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	abciserver "github.com/cometbft/cometbft/abci/server"
	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
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
	rpcErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ethbft_rpc_errors_total",
		Help: "Total number of RPC errors communicating with Geth or CometBFT",
	})
	blockProductionDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "ethbft_block_production_duration_seconds",
		Help:    "Time taken to produce a block via Engine API",
		Buckets: prometheus.DefBuckets,
	})
)

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
	// Basic validation: check size
	if len(req.Tx) > 128*1024 { // 128KB limit
		return &abcitypes.ResponseCheckTx{Code: 1, Log: "tx too large"}, nil
	}

	// Decode transaction to ensure it is a valid Ethereum transaction
	var tx types.Transaction
	if err := rlp.DecodeBytes(req.Tx, &tx); err != nil {
		return &abcitypes.ResponseCheckTx{Code: 2, Log: fmt.Sprintf("invalid rlp: %v", err)}, nil
	}

	// Optional: Check chainID if available in config, or other basic checks.
	// For now, just ensuring it decodes is a huge step up from accepting random bytes.

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
