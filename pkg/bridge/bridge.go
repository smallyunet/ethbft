package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smallyunet/ethbft/pkg/config"
	"github.com/smallyunet/ethbft/pkg/consensus"
	"github.com/smallyunet/ethbft/pkg/ethereum"
)

type executionClient interface {
	Call(context.Context, string, interface{}) (json.RawMessage, error)
	GetChainID(context.Context) (*big.Int, error)
}

// Bridge wires CometBFT (consensus) to a Geth execution client via the Engine API.
type Bridge struct {
	config     *config.Config
	ethClient  executionClient
	consClient *consensus.Client
	abciServer *ABCIServer
	abciApp    *ABCIApplication
	txPool     *TxPool
	chainID    *big.Int

	ctx    context.Context
	cancel context.CancelFunc

	running             bool
	runningLock         sync.Mutex
	consensusMu         sync.Mutex
	lastProducedHeight  atomic.Int64
	lastProgressUnix    atomic.Int64
	statePersisted      atomic.Bool
	stateMu             sync.Mutex
	abciLastBlockHeight atomic.Int64
	appHashMu           sync.RWMutex
	abciAppHash         []byte

	heightToHash map[int64]common.Hash
	heightOrder  []int64
	heightMu     sync.RWMutex
	maxHistory   int

	elGenesis common.Hash
	logger    *slog.Logger

	tsCache map[common.Hash]uint64
	tsMu    sync.RWMutex

	pendingCommit *pendingExecutionCommit
}

// NewBridge builds all clients and servers, reads EL genesis hash for initial forkchoice.
func NewBridge(cfg *config.Config) (*Bridge, error) {
	logger := slog.Default().With("component", "bridge")

	ethClient, err := ethereum.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create ethereum client: %w", err)
	}
	consClient, err := consensus.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create cometbft client: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())

	b := &Bridge{
		config:       cfg,
		ethClient:    ethClient,
		consClient:   consClient,
		txPool:       NewTxPool(),
		ctx:          ctx,
		cancel:       cancel,
		heightToHash: make(map[int64]common.Hash),
		heightOrder:  make([]int64, 0, 1024),
		maxHistory:   4096,
		logger:       logger,
		tsCache:      make(map[common.Hash]uint64),
	}

	// Fetch ChainID from EL
	{
		timeout := 5 * time.Second
		if cfg.Bridge.Timeout > 0 {
			timeout = time.Duration(cfg.Bridge.Timeout) * time.Second
		}
		ctx2, cancel2 := context.WithTimeout(ctx, timeout)
		defer cancel2()
		cid, err := ethClient.GetChainID(ctx2)
		if err != nil {
			return nil, fmt.Errorf("failed to get chainID: %w", err)
		}
		b.chainID = cid
		b.logger.Info("Connected to Ethereum", "chainID", cid.String())
	}

	// Try to read EL genesis hash
	{
		timeout := 5 * time.Second
		if cfg.Bridge.Timeout > 0 {
			timeout = time.Duration(cfg.Bridge.Timeout) * time.Second
		}
		ctx2, cancel2 := context.WithTimeout(ctx, timeout)
		defer cancel2()
		res, err := ethClient.Call(ctx2, "eth_getBlockByNumber", []interface{}{"0x0", false})
		if err == nil {
			var blk map[string]any
			if json.Unmarshal(res, &blk) == nil {
				if h, _ := blk["hash"].(string); h != "" {
					b.elGenesis = common.HexToHash(h)
					b.logger.Info("EL genesis hash found", "hash", b.elGenesis.Hex())
				}
			}
		} else {
			b.logger.Warn("Failed to fetch EL genesis hash", "error", err)
		}
	}
	if b.elGenesis == (common.Hash{}) {
		return nil, fmt.Errorf("failed to determine execution genesis hash")
	}
	if err := b.loadState(); err != nil {
		return nil, fmt.Errorf("load bridge state: %w", err)
	}
	{
		timeout := 5 * time.Second
		if cfg.Bridge.Timeout > 0 {
			timeout = time.Duration(cfg.Bridge.Timeout) * time.Second
		}
		ctx2, cancel2 := context.WithTimeout(ctx, timeout)
		defer cancel2()
		if err := b.reconcileState(ctx2); err != nil {
			return nil, fmt.Errorf("reconcile bridge state: %w", err)
		}
	}
	if height := b.lastProducedHeight.Load(); height > 0 {
		head := b.getHeightHash(height)
		if err := b.sendForkchoiceUpdate(head, head, head); err != nil {
			return nil, fmt.Errorf("restore committed execution forkchoice: %w", err)
		}
	}

	b.abciApp = NewABCIApplication(b)
	b.abciServer = NewABCIServer(b)

	return b, nil
}

// Start launches the ABCI server and the bridging loop when enabled.
func (b *Bridge) Start() error {
	b.runningLock.Lock()
	defer b.runningLock.Unlock()
	if b.running {
		return fmt.Errorf("bridge already running")
	}
	if b.abciServer != nil {
		if err := b.abciServer.Start(); err != nil {
			return err
		}
	}
	b.running = true
	b.lastProgressUnix.Store(time.Now().Unix())
	b.logger.Info("Bridge started", "protocol", "execution-payload-consensus-v1")
	return nil
}

// Stop shuts down services gracefully.
func (b *Bridge) Stop() error {
	b.runningLock.Lock()
	defer b.runningLock.Unlock()
	if !b.running {
		return nil
	}
	if b.abciServer != nil {
		b.abciServer.Stop()
	}
	if b.consClient != nil {
		if err := b.consClient.Stop(); err != nil {
			b.logger.Error("Failed to stop consensus client", "error", err)
		}
	}
	b.cancel()
	b.running = false
	return nil
}
