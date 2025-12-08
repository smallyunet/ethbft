package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/smallyunet/ethbft/pkg/config"
	"github.com/smallyunet/ethbft/pkg/consensus"
	"github.com/smallyunet/ethbft/pkg/ethereum"
)

// Bridge wires CometBFT (consensus) to a Geth execution client via the Engine API.
// Minimal demo principle: let Geth build blocks; EthBFT only drives the Engine API loop.
type Bridge struct {
	config     *config.Config
	ethClient  *ethereum.Client
	consClient *consensus.Client
	abciServer *ABCIServer
	abciApp    *ABCIApplication
	txPool     *TxPool

	ctx    context.Context
	cancel context.CancelFunc

	wg          sync.WaitGroup
	running     bool
	runningLock sync.Mutex

	// heightToHash tracks EL head hashes by CometBFT height.
	// Guarded by heightMu to be safe if accessed from multiple goroutines.
	heightToHash map[int64]common.Hash
	heightOrder  []int64      // insertion order for pruning
	heightMu     sync.RWMutex // protects heightToHash and heightOrder
	maxHistory   int          // maximum entries retained in heightToHash

	elGenesis common.Hash // cached EL genesis (or zero if not found)
	logger    *slog.Logger
}

// getHeightHash returns the stored EL head hash for a given CometBFT height.
// It is safe for concurrent use.
func (b *Bridge) getHeightHash(h int64) common.Hash {
	b.heightMu.RLock()
	defer b.heightMu.RUnlock()
	return b.heightToHash[h]
}

// setHeightHash stores the hash for the given height and prunes old entries
// to limit memory usage. It is safe for concurrent use.
func (b *Bridge) setHeightHash(h int64, hash common.Hash) {
	b.heightMu.Lock()
	defer b.heightMu.Unlock()
	if _, exists := b.heightToHash[h]; !exists {
		b.heightOrder = append(b.heightOrder, h)
	}
	b.heightToHash[h] = hash
	// prune if exceeding maxHistory
	for b.maxHistory > 0 && len(b.heightOrder) > b.maxHistory {
		oldH := b.heightOrder[0]
		b.heightOrder = b.heightOrder[1:]
		delete(b.heightToHash, oldH)
	}
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
	}

	b.abciApp = NewABCIApplication(b)
	b.abciServer = NewABCIServer(b)

	// Try to read EL genesis hash (block 0). If not found, keep zero hash as fallback.
	{
		ctx2, cancel2 := context.WithTimeout(ctx, 5*time.Second)
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

// runBlockBridging polls CometBFT latest height and for each new height triggers the Engine API loop.
func (b *Bridge) runBlockBridging() {
	defer b.wg.Done()
	b.logger.Info("Block bridging loop started (Event-Driven)")

	// Subscribe to new blocks
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

	// Initial fetch to set lastHeight
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
				b.logger.Warn("Subscription channel closed, falling back to polling")
				b.runPollingLoop()
				return
			}
			if h <= lastHeight {
				continue
			}
			// Process missing heights sequentially (if any gap)
			for i := lastHeight + 1; i <= h; i++ {
				if err := b.processHeight(i); err != nil {
					b.logger.Error("Failed to process height", "height", i, "error", err)
					// If we fail, we might want to retry?
					// For now, log and continue to keep up with the stream,
					// or maybe we should break and retry?
					// In event stream, if we fail, we might miss it.
					// Let's retry a few times then move on?
					// Or just break and let the next event trigger the gap fill again?
					// If we break here, lastHeight is not updated.
					// Next event h+1 comes, we loop from lastHeight+1 again.
					// So breaking is safe and correct for retrying.
					break
				} else {
					lastHeight = i
					b.txPool.Prune(i - 100)
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
	// Try to get current height
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
					b.txPool.Prune(h - 100)
				}
			}
		}
	}
}

func (b *Bridge) fetchCometHeight() (int64, error) {
	ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
	defer cancel()
	status, err := b.consClient.GetStatus(ctx)
	if err != nil {
		return 0, err
	}
	// Extract latest_block_height from CometBFT status robustly.
	if syncInfo, ok := status["sync_info"].(map[string]interface{}); ok {
		if hstr, ok2 := syncInfo["latest_block_height"].(string); ok2 {
			// Prefer strconv for strict parsing; support both decimal and 0x-prefixed hex just in case.
			if strings.HasPrefix(hstr, "0x") || strings.HasPrefix(hstr, "0X") {
				if v, err := strconv.ParseInt(strings.TrimPrefix(strings.ToLower(hstr), "0x"), 16, 64); err == nil {
					return v, nil
				}
			} else {
				if v, err := strconv.ParseInt(hstr, 10, 64); err == nil {
					return v, nil
				}
			}
		}
	}
	return 0, fmt.Errorf("could not parse latest_block_height from status")
}

func zeroHash() common.Hash { return common.Hash{} }

// getELHead returns the current EL head hash and its timestamp.
func (b *Bridge) getELHead(ctx context.Context) (common.Hash, uint64, error) {
	res, err := b.ethClient.Call(ctx, "eth_getBlockByNumber", []interface{}{"latest", false})
	if err != nil {
		return common.Hash{}, 0, fmt.Errorf("eth_getBlockByNumber(latest): %w", err)
	}
	var blk map[string]any
	if err := json.Unmarshal(res, &blk); err != nil {
		return common.Hash{}, 0, fmt.Errorf("decode latest block: %w", err)
	}
	h, _ := blk["hash"].(string)
	tsStr, _ := blk["timestamp"].(string)
	if h == "" || tsStr == "" {
		return common.Hash{}, 0, fmt.Errorf("latest block missing hash/timestamp")
	}
	// ts is hex string like "0x..."
	var ts uint64
	_, _ = fmt.Sscanf(strings.TrimPrefix(tsStr, "0x"), "%x", &ts)
	return common.HexToHash(h), ts, nil
}

// getBlockTimestampByHash returns timestamp for a given block hash (0 on failure).
func (b *Bridge) getBlockTimestampByHash(ctx context.Context, h common.Hash) uint64 {
	if (h == common.Hash{}) {
		return 0
	}
	res, err := b.ethClient.Call(ctx, "eth_getBlockByHash", []interface{}{h.Hex(), false})
	if err != nil {
		return 0
	}
	var blk map[string]any
	if json.Unmarshal(res, &blk) != nil {
		return 0
	}
	tsStr, _ := blk["timestamp"].(string)
	if tsStr == "" {
		return 0
	}
	var ts uint64
	_, _ = fmt.Sscanf(strings.TrimPrefix(tsStr, "0x"), "%x", &ts)
	return ts
}

// produceBlockAtHeight executes the minimal Engine API loop to let Geth build a block.
//
// Sequence:
// 1) engine_forkchoiceUpdatedV2(state=parent,parent,parent, attrs={timestamp, prevRandao, feeRecipient}) -> payloadId
// 2) engine_getPayloadV2(payloadId) -> payload built by Geth
// 3) engine_newPayloadV2(payload) -> VALID/ACCEPTED
// 4) engine_forkchoiceUpdatedV2(state=head=headOfPayload, safe=head, finalized=head)
func (b *Bridge) produceBlockAtHeight(height int64) error {
	// 0) Inject transactions from TxPool into Geth Mempool
	txs := b.txPool.GetTxs(height)
	if len(txs) > 0 {
		b.logger.Info("Injecting transactions into Geth", "height", height, "count", len(txs))
		ctxTx, cancelTx := context.WithTimeout(b.ctx, 5*time.Second)
		defer cancelTx()
		for _, tx := range txs {
			// Assume tx is RLP-encoded bytes. Convert to hex string for JSON-RPC.
			txHex := hexutil.Encode(tx)
			_, err := b.ethClient.Call(ctxTx, "eth_sendRawTransaction", []interface{}{txHex})
			if err != nil {
				// Log but continue; maybe it's already in pool or invalid
				b.logger.Warn("Failed to inject tx", "error", err)
			}
		}
	}

	// 1) Choose parent: prefer last height's head; otherwise EL head; otherwise genesis.
	parent := b.getHeightHash(height - 1)

	// Determine a sane parent and parent timestamp.
	var parentTs uint64
	if (parent == common.Hash{}) {
		ctxHead, cancelHead := context.WithTimeout(b.ctx, 4*time.Second)
		head, headTs, err := b.getELHead(ctxHead)
		cancelHead()
		if err == nil && (head != common.Hash{}) {
			parent = head
			parentTs = headTs
		} else if b.elGenesis != (common.Hash{}) {
			parent = b.elGenesis
			// best-effort get genesis timestamp
			ctxTs, cancelTs := context.WithTimeout(b.ctx, 4*time.Second)
			parentTs = b.getBlockTimestampByHash(ctxTs, parent)
			cancelTs()
		}
	} else {
		// We had a cached parent; fetch its timestamp.
		ctxTs, cancelTs := context.WithTimeout(b.ctx, 4*time.Second)
		parentTs = b.getBlockTimestampByHash(ctxTs, parent)
		cancelTs()
	}

	// Absolute guard: never send zero-hash to forkchoice.
	if (parent == common.Hash{}) {
		return fmt.Errorf("no valid parent available (zero hash); ensure EL is up and has a head")
	}

	// 2) Pre-forkchoice without attributes (align head to parent).
	if err := b.sendForkchoiceUpdate(parent, parent, parent); err != nil {
		return fmt.Errorf("pre-fcu failed: %w", err)
	}

	// 3) Minimal attributes: timestamp > parentTs, prevRandao (32-bytes zero), fee recipient (zero addr OK).
	now := uint64(time.Now().Unix())
	ts := now
	if parentTs > 0 && ts <= parentTs {
		ts = parentTs + 1
	}
	attrs := &PayloadAttributes{
		Timestamp:             ts,
		Random:                zeroHash(),       // prevRandao (field name is Random in go-ethereum ExecutableData/Attributes)
		SuggestedFeeRecipient: common.Address{}, // zero address for demo
	}

	// 4) Forkchoice with attributes to get payloadId.
	ctx, cancel := context.WithTimeout(b.ctx, 8*time.Second)
	defer cancel()
	type fcuReq struct {
		Head      common.Hash `json:"headBlockHash"`
		Safe      common.Hash `json:"safeBlockHash"`
		Finalized common.Hash `json:"finalizedBlockHash"`
	}
	req := []any{
		&fcuReq{Head: parent, Safe: parent, Finalized: parent},
		attrs,
	}
	// b.logger.Debug("engine_forkchoiceUpdatedV2.req", "req", req)
	raw, err := b.ethClient.Call(ctx, "engine_forkchoiceUpdatedV2", req)
	if err != nil {
		return fmt.Errorf("fcu (with attrs) call: %w", err)
	}
	var fcuResp struct {
		PayloadStatus struct {
			Status          string `json:"status"`
			LatestValidHash string `json:"latestValidHash"`
			ValidationError string `json:"validationError"`
		} `json:"payloadStatus"`
		PayloadID hexutil.Bytes `json:"payloadId"`
	}
	if err := json.Unmarshal(raw, &fcuResp); err != nil {
		return fmt.Errorf("decode fcu resp: %w", err)
	}
	if len(fcuResp.PayloadID) == 0 {
		// Rarely EL may reply without payloadId; retry once after a short delay.
		time.Sleep(200 * time.Millisecond)
		rawRetry, err := b.ethClient.Call(ctx, "engine_forkchoiceUpdatedV2", req)
		if err != nil {
			return fmt.Errorf("fcu retry call: %w", err)
		}
		if err := json.Unmarshal(rawRetry, &fcuResp); err != nil || len(fcuResp.PayloadID) == 0 {
			return fmt.Errorf("no payloadId from fcu, status=%s err=%s",
				fcuResp.PayloadStatus.Status, fcuResp.PayloadStatus.ValidationError)
		}
	}

	// 5) Ask Geth to materialize the payload.
	raw2, err := b.ethClient.Call(ctx, "engine_getPayloadV2", []any{fcuResp.PayloadID})
	if err != nil {
		return fmt.Errorf("getPayloadV2: %w", err)
	}
	var gp struct {
		ExecutionPayload ExecutionPayload `json:"executionPayload"`
	}
	if err := json.Unmarshal(raw2, &gp); err != nil {
		return fmt.Errorf("decode getPayloadV2: %w", err)
	}
	payload := &gp.ExecutionPayload

	// 6) Feed the payload back to Geth for validation/import.
	raw3, err := b.ethClient.Call(ctx, "engine_newPayloadV2", []any{payload})
	if err != nil {
		return fmt.Errorf("newPayloadV2: %w", err)
	}
	var np struct {
		Status          string `json:"status"`
		LatestValidHash string `json:"latestValidHash"`
		ValidationError string `json:"validationError"`
	}
	if err := json.Unmarshal(raw3, &np); err != nil {
		return fmt.Errorf("decode newPayloadV2: %w", err)
	}
	switch np.Status {
	case "VALID", "ACCEPTED", "SYNCING":
	default:
		return fmt.Errorf("newPayloadV2 status=%s err=%s", np.Status, np.ValidationError)
	}

	// 7) Final forkchoice: set head/safe/finalized to payload block hash for the demo.
	head := payload.BlockHash
	if err := b.sendForkchoiceUpdate(head, head, head); err != nil {
		return fmt.Errorf("final fcu failed: %w", err)
	}

	// Track mapping: height -> head hash (used to pick parent next time).
	b.setHeightHash(height, head)
	b.logger.Info("Produced block", "height", height, "head", head.Hex(), "txs", len(payload.Transactions))
	return nil
}

// processHeight triggers block production for the given CometBFT height.
func (b *Bridge) processHeight(height int64) error {
	return b.produceBlockAtHeight(height)
}

// parseCometHash converts upper-case/no-0x hex to go-ethereum common.Hash (0x-prefixed, lower-case).
func parseCometHash(h string) common.Hash {
	hs := strings.TrimSpace(h)
	if hs == "" {
		return common.Hash{}
	}
	if !strings.HasPrefix(hs, "0x") {
		hs = "0x" + strings.ToLower(hs)
	}
	return common.HexToHash(hs)
}

// sendForkchoiceUpdate sets head/safe/finalized. Used both before and after producing a block.
func (b *Bridge) sendForkchoiceUpdate(head, safe, finalized common.Hash) error {
	ctx, cancel := context.WithTimeout(b.ctx, 8*time.Second)
	defer cancel()
	type fcuReq struct {
		Head      common.Hash `json:"headBlockHash"`
		Safe      common.Hash `json:"safeBlockHash"`
		Finalized common.Hash `json:"finalizedBlockHash"`
	}
	state := &fcuReq{Head: head, Safe: safe, Finalized: finalized}
	res, err := b.ethClient.Call(ctx, "engine_forkchoiceUpdatedV2", []interface{}{state, nil})
	if err != nil {
		return err
	}
	var resp struct {
		PayloadStatus struct {
			Status          string `json:"status"`
			LatestValidHash string `json:"latestValidHash"`
			ValidationError string `json:"validationError"`
		} `json:"payloadStatus"`
		PayloadID string `json:"payloadId"`
	}
	if err := json.Unmarshal(res, &resp); err != nil {
		return fmt.Errorf("decode forkchoiceUpdated: %w", err)
	}
	if resp.PayloadStatus.Status != "VALID" &&
		resp.PayloadStatus.Status != "ACCEPTED" &&
		resp.PayloadStatus.Status != "SYNCING" {
		return fmt.Errorf("forkchoice status=%s validationError=%s", resp.PayloadStatus.Status, resp.PayloadStatus.ValidationError)
	}
	return nil
}
