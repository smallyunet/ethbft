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

// Bridge wires CometBFT (consensus) to a Geth execution client via the Engine API.
type Bridge struct {
	config     *config.Config
	ethClient  *ethereum.Client
	consClient *consensus.Client
	abciServer *ABCIServer
	abciApp    *ABCIApplication
	txPool     *TxPool
	chainID    *big.Int

	ctx    context.Context
	cancel context.CancelFunc

	wg                  sync.WaitGroup
	running             bool
	runningLock         sync.Mutex
	lastProducedHeight  atomic.Int64
	lastProgressUnix    atomic.Int64
	statePersisted      atomic.Bool
	stateMu             sync.Mutex
	abciLastBlockHeight atomic.Int64
	legacyEmptyAppHash  atomic.Bool
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
	if b.config != nil && b.config.Bridge.EnableBridging {
		b.wg.Add(1)
		go b.runBlockBridging()
	}
	b.running = true
	b.lastProgressUnix.Store(time.Now().Unix())
	b.logger.Info("Bridge started", "bridging_enabled", b.config != nil && b.config.Bridge.EnableBridging)
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
	done := make(chan struct{})
	go func() { b.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		b.logger.Warn("Bridge stop timeout, continuing")
	}
	b.running = false
	return nil
}

// runBlockBridging polls CometBFT latest height and triggers the Engine API loop.
func (b *Bridge) runBlockBridging() {
	defer b.wg.Done()
	b.logger.Info("Block bridging loop started (Event-Driven)")

	heightCh, err := b.consClient.SubscribeNewBlocks(b.ctx)
	if err != nil {
		b.logger.Error("Failed to subscribe to new blocks, falling back to polling", "error", err)
		b.runPollingLoop()
		return
	}
	defer func() {
		if err := b.consClient.UnsubscribeAll(context.Background()); err != nil {
			b.logger.Error("Failed to unsubscribe from all events", "error", err)
		}
	}()

	// Resume after the last successfully produced and persisted CometBFT height.
	// Starting from the current consensus height would skip blocks committed while
	// the bridge was down, while starting from zero would replay execution blocks.
	lastHeight := b.lastProducedHeight.Load()
	retryTicker := time.NewTicker(2 * time.Second)
	defer retryTicker.Stop()

	for {
		select {
		case <-b.ctx.Done():
			b.logger.Info("Block bridging loop stopped")
			return
		case <-retryTicker.C:
			h, fetchErr := b.fetchCometHeight()
			if fetchErr != nil {
				b.logger.Warn("Failed to fetch height for retry", "error", fetchErr)
				continue
			}
			b.processThrough(&lastHeight, h)
		case h, ok := <-heightCh:
			if !ok {
				b.logger.Warn("Subscription channel closed, attempting to reconnect...")
				time.Sleep(2 * time.Second)
				heightCh, err = b.consClient.SubscribeNewBlocks(b.ctx)
				if err != nil {
					b.logger.Warn("Failed to reconnect subscription, falling back to polling", "error", err)
					b.runPollingLoop()
					return
				}
				continue
			}
			if h <= lastHeight {
				continue
			}
			b.processThrough(&lastHeight, h)
		}
	}
}

func (b *Bridge) processThrough(lastHeight *int64, target int64) {
	for height := *lastHeight + 1; height <= target; height++ {
		if err := b.processHeight(height); err != nil {
			b.logger.Error("Failed to process height", "height", height, "error", err)
			return
		}
		*lastHeight = height
		b.txPool.Prune(height - int64(b.maxHistory))
	}
}

func (b *Bridge) runPollingLoop() {
	b.logger.Info("Starting polling loop fallback")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	lastHeight := b.lastProducedHeight.Load()

	for {
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
			currentHeight, err := b.fetchCometHeight()
			if err != nil {
				b.logger.Error("Failed to fetch CometBFT height", "error", err)
				continue
			}

			if currentHeight <= lastHeight {
				continue
			}

			b.processThrough(&lastHeight, currentHeight)
		}
	}
}

func (b *Bridge) fetchCometHeight() (int64, error) {
	timeout := 5 * time.Second
	if b.config.Bridge.Timeout > 0 {
		timeout = time.Duration(b.config.Bridge.Timeout) * time.Second
	}
	ctx, cancel := context.WithTimeout(b.ctx, timeout)
	defer cancel()
	status, err := b.consClient.GetStatus(ctx)
	if err != nil {
		return 0, err
	}
	return status.SyncInfo.LatestBlockHeight, nil
}

// processHeight triggers block production for the given CometBFT height.
func (b *Bridge) processHeight(height int64) error {
	return b.produceBlockAtHeight(height)
}
