package bridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
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
		ctx:          ctx,
		cancel:       cancel,
		heightToHash: make(map[int64]common.Hash),
		heightOrder:  make([]int64, 0, 1024),
		maxHistory:   4096,
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
					log.Printf("[bridge] EL genesis hash: %s", b.elGenesis.Hex())
				}
			}
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
	log.Printf("Bridge started (bridging=%v)", b.config != nil && b.config.Bridge.EnableBridging)
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
	b.cancel()
	done := make(chan struct{})
	go func() { b.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		log.Printf("bridge stop timeout, continuing")
	}
	b.running = false
	return nil
}

// Healthy is a basic health indicator.
func (b *Bridge) Healthy() bool { return b.running }

// runBlockBridging polls CometBFT latest height and for each new height triggers the Engine API loop.
func (b *Bridge) runBlockBridging() {
	defer b.wg.Done()
	log.Printf("[bridge] block bridging loop started")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastHeight int64 = 0
	for {
		select {
		case <-b.ctx.Done():
			log.Printf("[bridge] block bridging loop stopped")
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
			status, err := b.consClient.GetStatus(ctx)
			cancel()
			if err != nil {
				log.Printf("[bridge] get status error: %v", err)
				continue
			}
			// Extract latest_block_height from CometBFT status robustly.
			var currentHeight int64
			if syncInfo, ok := status["sync_info"].(map[string]interface{}); ok {
				if hstr, ok2 := syncInfo["latest_block_height"].(string); ok2 {
					// Prefer strconv for strict parsing; support both decimal and 0x-prefixed hex just in case.
					if strings.HasPrefix(hstr, "0x") || strings.HasPrefix(hstr, "0X") {
						if v, err := strconv.ParseInt(strings.TrimPrefix(strings.ToLower(hstr), "0x"), 16, 64); err == nil {
							currentHeight = v
						}
					} else {
						if v, err := strconv.ParseInt(hstr, 10, 64); err == nil {
							currentHeight = v
						}
					}
				}
			}
			if currentHeight <= lastHeight {
				continue
			}
			// Process missing heights sequentially.
			for h := lastHeight + 1; h <= currentHeight; h++ {
				if err := b.processHeight(h); err != nil {
					log.Printf("[bridge] process height %d error: %v", h, err)
					// Continue trying subsequent heights.
				} else {
					lastHeight = h
				}
			}
		}
	}
}

func zeroHash() common.Hash { return common.Hash{} }

// dumpJSON is handy for debugging the exact JSON arguments we send to Geth.
func dumpJSON(tag string, v any) {
	b, _ := json.Marshal(v)
	log.Printf("%s %s", tag, string(b))
}

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
	dumpJSON("engine_forkchoiceUpdatedV2.req", req)
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
	log.Printf("[bridge] produced by EL: height=%d head=%s", height, head.Hex())
	return nil
}

// processHeight now only calls produceBlockAtHeight.
func (b *Bridge) processHeight(height int64) error {
	if err := b.produceBlockAtHeight(height); err != nil {
		return fmt.Errorf("produceBlockAtHeight: %w", err)
	}
	return nil
}

// -----------------------------------------------------------------------------
// The two functions below were used for hand-building payloads. Keep them for
// reference but they are NOT used in the minimal demo (Geth builds the payload).
// -----------------------------------------------------------------------------

// buildPayloadFromCometBlock maps CometBFT block to an (synthetic) ExecutionPayload.
// Not used by minimal demo.
func (b *Bridge) buildPayloadFromCometBlock(height int64) (*ExecutionPayload, common.Hash, error) {
	ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
	defer cancel()
	params := map[string]interface{}{"height": fmt.Sprintf("%d", height)}
	raw, err := b.consClient.Call(ctx, "block", params)
	if err != nil {
		return nil, common.Hash{}, err
	}
	var resp struct {
		Result struct {
			BlockID struct {
				Hash string `json:"hash"`
			} `json:"block_id"`
			Block struct {
				Header struct {
					Height      string `json:"height"`
					Time        string `json:"time"`
					LastBlockID struct {
						Hash string `json:"hash"`
					} `json:"last_block_id"`
				} `json:"header"`
				Data struct {
					Txs []string `json:"txs"`
				} `json:"data"`
			} `json:"block"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, common.Hash{}, fmt.Errorf("decode comet block: %w", err)
	}
	cometHash := parseCometHash(resp.Result.BlockID.Hash)
	var parentHash common.Hash
	if resp.Result.Block.Header.LastBlockID.Hash != "" {
		parentHash = parseCometHash(resp.Result.Block.Header.LastBlockID.Hash)
	}
	txBytes := make([][]byte, 0, len(resp.Result.Block.Data.Txs))
	for _, tx := range resp.Result.Block.Data.Txs {
		bts, err := base64.StdEncoding.DecodeString(tx) // CometBFT TX are base64
		if err != nil {
			log.Printf("[bridge] tx base64 decode failed (height=%d): %v", height, err)
			continue
		}
		txBytes = append(txBytes, bts)
	}
	receiptsRoot := common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421") // empty list
	payload := &ExecutionPayload{
		ParentHash:    parentHash,
		FeeRecipient:  common.Address{},
		StateRoot:     common.Hash{}, // placeholder only
		ReceiptsRoot:  receiptsRoot,
		LogsBloom:     make([]byte, 256),
		Random:        common.Hash{},
		Number:        uint64(height),
		GasLimit:      30_000_000,
		GasUsed:       0,
		Timestamp:     uint64(time.Now().Unix()),
		ExtraData:     []byte("ethbft"),
		BaseFeePerGas: big.NewInt(7),
		Transactions:  txBytes, // NOT valid for EL unless RLP-encoded ETH txs
		Withdrawals:   nil,
	}
	payload.BlockHash = pseudoHash(height, parentHash, len(txBytes), cometHash)
	return payload, payload.BlockHash, nil
}

// buildPlaceholderPayload creates a synthetic payload. Not used by minimal demo.
func (b *Bridge) buildPlaceholderPayload(height int64) (*ExecutionPayload, error) {
	var parentHash common.Hash
	if height > 1 {
		parentHash = common.BigToHash(big.NewInt((height-1)*1_000_000 + 12345))
	}
	receiptsRoot := common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
	return &ExecutionPayload{
		ParentHash:    parentHash,
		FeeRecipient:  common.Address{},
		StateRoot:     common.Hash{},
		ReceiptsRoot:  receiptsRoot,
		LogsBloom:     make([]byte, 256),
		Random:        common.Hash{},
		Number:        uint64(height),
		GasLimit:      30_000_000,
		GasUsed:       0,
		Timestamp:     uint64(time.Now().Unix()),
		ExtraData:     []byte("ethbft"),
		BaseFeePerGas: big.NewInt(7),
		BlockHash:     pseudoHash(height, parentHash, 0, common.Hash{}),
		Transactions:  [][]byte{},
		Withdrawals:   nil,
	}, nil
}

// updateForkchoice computes safe/finalized from history and calls engine_forkchoiceUpdatedV2.
// Not used by minimal demo; we set head/safe/finalized to the same hash when producing.
func (b *Bridge) updateForkchoice(headHeight int64, headHash common.Hash) error {
	safeHash := headHash
	if h := headHeight - 2; h > 0 {
		if hh := b.getHeightHash(h); hh != (common.Hash{}) {
			safeHash = hh
		}
	}
	finalizedHash := safeHash
	if h := headHeight - 5; h > 0 {
		if hh := b.getHeightHash(h); hh != (common.Hash{}) {
			finalizedHash = hh
		}
	}
	return b.sendForkchoiceUpdate(headHash, safeHash, finalizedHash)
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

// sendNewPayload is kept for reference. Minimal demo uses newPayloadV2 inside produceBlockAtHeight.
func (b *Bridge) sendNewPayload(p *ExecutionPayload) error {
	ctx, cancel := context.WithTimeout(b.ctx, 8*time.Second)
	defer cancel()
	res, err := b.ethClient.Call(ctx, "engine_newPayloadV2", []interface{}{p})
	if err != nil {
		return err
	}
	var resp struct {
		Status          string `json:"status"`
		LatestValidHash string `json:"latestValidHash"`
		ValidationError string `json:"validationError"`
	}
	if err := json.Unmarshal(res, &resp); err != nil {
		return fmt.Errorf("decode newPayload: %w", err)
	}
	switch resp.Status {
	case "VALID", "ACCEPTED", "SYNCING":
	default:
		return fmt.Errorf("payload status=%s validationError=%s", resp.Status, resp.ValidationError)
	}
	return nil
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

// pseudoHash creates a deterministic synthetic hash; kept only for legacy helpers.
func pseudoHash(height int64, parent common.Hash, txCount int, cometHash common.Hash) common.Hash {
	h := new(big.Int).SetInt64(height & 0xFFFFFFFFFFFF) // 48 bits height
	h.Lsh(h, 16).Or(h, new(big.Int).SetInt64(int64(txCount&0xFFFF)))
	cometPart := new(big.Int).SetBytes(cometHash.Bytes()[20:32])
	h.Lsh(h, 96).Or(h, cometPart)
	parentPart := new(big.Int).SetBytes(parent.Bytes()[20:32])
	h.Lsh(h, 96).Or(h, parentPart)
	return common.BigToHash(h)
}
