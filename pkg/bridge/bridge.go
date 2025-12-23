package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smallyunet/ethbft/pkg/config"
	"github.com/smallyunet/ethbft/pkg/consensus"
	"github.com/smallyunet/ethbft/pkg/ethereum"
)

const (
	pruneDepth = 100
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

	wg          sync.WaitGroup
	running     bool
	runningLock sync.Mutex

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

	b.loadState()

	b.abciApp = NewABCIApplication(b)
	b.abciServer = NewABCIServer(b)

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

	var lastHeight int64 = 0
	if h, err := b.fetchCometHeight(); err == nil {
		lastHeight = h
	}

	for {
		select {
		case <-b.ctx.Done():
			b.logger.Info("Block bridging loop stopped")
			return
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
			for i := lastHeight + 1; i <= h; i++ {
				if err := b.processHeight(i); err != nil {
					b.logger.Error("Failed to process height", "height", i, "error", err)
					break
				} else {
					lastHeight = i
					b.txPool.Prune(i - pruneDepth)
				}
			}
		}
	}
}

func (b *Bridge) runPollingLoop() {
	b.logger.Info("Starting polling loop fallback")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastHeight int64 = 0
	if h, err := b.fetchCometHeight(); err == nil {
		lastHeight = h
	}

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

			for h := lastHeight + 1; h <= currentHeight; h++ {
				if err := b.processHeight(h); err != nil {
					b.logger.Error("Failed to process height", "height", h, "error", err)
					break
				} else {
					lastHeight = h
					b.txPool.Prune(h - pruneDepth)
				}
			}
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
