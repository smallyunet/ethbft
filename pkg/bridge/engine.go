package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/prometheus/client_golang/prometheus"
)

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

	// Check cache
	b.tsMu.RLock()
	ts, ok := b.tsCache[h]
	b.tsMu.RUnlock()
	if ok {
		return ts
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
	var timestamp uint64
	_, _ = fmt.Sscanf(strings.TrimPrefix(tsStr, "0x"), "%x", &timestamp)

	// Save to cache
	b.tsMu.Lock()
	b.tsCache[h] = timestamp
	// Bound cache size
	if len(b.tsCache) > 1024 {
		for k := range b.tsCache {
			delete(b.tsCache, k)
			break
		}
	}
	b.tsMu.Unlock()

	return timestamp
}

// produceBlockAtHeight executes the minimal Engine API loop to let Geth build a block.
func (b *Bridge) produceBlockAtHeight(height int64) (err error) {
	timer := prometheus.NewTimer(blockProductionDuration)
	defer timer.ObserveDuration()
	defer func() {
		if err != nil {
			rpcErrors.Inc()
		}
	}()

	// 0) Inject transactions from TxPool into Geth Mempool
	txs := b.txPool.GetTxs(height)
	timeout := 8 * time.Second
	if b.config.Bridge.Timeout > 0 {
		timeout = time.Duration(b.config.Bridge.Timeout) * time.Second
	}

	if len(txs) > 0 {
		b.logger.Info("Injecting transactions into Geth", "height", height, "count", len(txs))
		ctxTx, cancelTx := context.WithTimeout(b.ctx, timeout)
		defer cancelTx()

		var wg sync.WaitGroup
		for _, tx := range txs {
			wg.Add(1)
			go func(txBytes []byte) {
				defer wg.Done()
				txHex := hexutil.Encode(txBytes)
				_, err := b.ethClient.Call(ctxTx, "eth_sendRawTransaction", []interface{}{txHex})
				if err != nil {
					b.logger.Warn("Failed to inject tx", "error", err)
				}
			}(tx)
		}
		wg.Wait()
	}

	// 1) Choose parent: prefer last height's head; otherwise EL head; otherwise genesis.
	parent := b.getHeightHash(height - 1)

	var parentTs uint64
	if (parent == common.Hash{}) {
		ctxHead, cancelHead := context.WithTimeout(b.ctx, timeout)
		head, headTs, err := b.getELHead(ctxHead)
		cancelHead()
		if err == nil && (head != common.Hash{}) {
			parent = head
			parentTs = headTs
		} else if b.elGenesis != (common.Hash{}) {
			parent = b.elGenesis
			ctxTs, cancelTs := context.WithTimeout(b.ctx, timeout)
			parentTs = b.getBlockTimestampByHash(ctxTs, parent)
			cancelTs()
		}
	} else {
		ctxTs, cancelTs := context.WithTimeout(b.ctx, timeout)
		parentTs = b.getBlockTimestampByHash(ctxTs, parent)
		cancelTs()
	}

	if (parent == common.Hash{}) {
		return fmt.Errorf("no valid parent available (zero hash); ensure EL is up and has a head")
	}

	// 2) Pre-forkchoice without attributes
	if err := b.sendForkchoiceUpdate(parent, parent, parent); err != nil {
		return fmt.Errorf("pre-fcu failed: %w", err)
	}

	// 3) Minimal attributes
	now := uint64(time.Now().Unix())
	ts := now
	if parentTs > 0 && ts <= parentTs {
		ts = parentTs + 1
	}
	feeRecipient := common.Address{}
	if b.config.Bridge.FeeRecipient != "" {
		feeRecipient = common.HexToAddress(b.config.Bridge.FeeRecipient)
	}
	attrs := &PayloadAttributes{
		Timestamp:             ts,
		Random:                zeroHash(),
		SuggestedFeeRecipient: feeRecipient,
		Withdrawals:           []*types.Withdrawal{},
	}

	// 4) Forkchoice with attributes
	ctx, cancel := context.WithTimeout(b.ctx, timeout)
	defer cancel()

	safeHash := parent
	finalizedHash := parent
	depth := b.config.Bridge.FinalityDepth
	if depth > 0 && height > int64(depth) {
		h := b.getHeightHash(height - int64(depth))
		if (h != common.Hash{}) {
			finalizedHash = h
			safeHash = h
		} else if b.elGenesis != (common.Hash{}) {
			finalizedHash = b.elGenesis
			safeHash = b.elGenesis
		}
	}

	req := []any{
		&FCURequest{Head: parent, Safe: safeHash, Finalized: finalizedHash},
		attrs,
	}
	raw, err := b.ethClient.Call(ctx, "engine_forkchoiceUpdatedV2", req)
	if err != nil {
		return fmt.Errorf("fcu (with attrs) call: %w", err)
	}
	var fcuResp FCUResponse
	if err := json.Unmarshal(raw, &fcuResp); err != nil {
		return fmt.Errorf("decode fcu resp: %w", err)
	}
	if fcuResp.PayloadID == nil {
		if fcuResp.PayloadStatus.Status == "SYNCING" {
			return fmt.Errorf("engine is SYNCING, cannot produce payload")
		}
		time.Sleep(200 * time.Millisecond)
		rawRetry, err := b.ethClient.Call(ctx, "engine_forkchoiceUpdatedV2", req)
		if err != nil {
			return fmt.Errorf("fcu retry call: %w", err)
		}
		if err := json.Unmarshal(rawRetry, &fcuResp); err != nil || fcuResp.PayloadID == nil {
			return fmt.Errorf("no payloadId from fcu, status=%s err=%s",
				fcuResp.PayloadStatus.Status, fcuResp.PayloadStatus.ValidationError)
		}
	}

	// 5) engine_getPayloadV2
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

	// 6) engine_newPayloadV2
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
	case "VALID", "ACCEPTED":
	case "SYNCING":
		return fmt.Errorf("newPayloadV2 returned SYNCING, execution not ready")
	default:
		return fmt.Errorf("newPayloadV2 status=%s err=%s", np.Status, np.ValidationError)
	}

	// 7) Final forkchoice
	head := payload.BlockHash
	newSafe := head
	newFinalized := head
	if depth > 0 {
		finalizedHeight := height - int64(depth)
		if finalizedHeight == height {
			newFinalized = head
		} else {
			h := b.getHeightHash(finalizedHeight)
			if (h != common.Hash{}) {
				newFinalized = h
			} else if b.elGenesis != (common.Hash{}) {
				newFinalized = b.elGenesis
			}
		}
		newSafe = newFinalized
	}

	if err := b.sendForkchoiceUpdate(head, newSafe, newFinalized); err != nil {
		return fmt.Errorf("final fcu failed: %w", err)
	}

	b.setHeightHash(height, head)
	b.saveState()
	b.logger.Info("Produced block", "height", height, "head", head.Hex(), "txs", len(payload.Transactions))
	return nil
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
	timeout := 8 * time.Second
	if b.config.Bridge.Timeout > 0 {
		timeout = time.Duration(b.config.Bridge.Timeout) * time.Second
	}
	ctx, cancel := context.WithTimeout(b.ctx, timeout)
	defer cancel()
	state := &FCURequest{Head: head, Safe: safe, Finalized: finalized}
	res, err := b.ethClient.Call(ctx, "engine_forkchoiceUpdatedV2", []interface{}{state, nil})
	if err != nil {
		return err
	}
	var resp FCUResponse
	if err := json.Unmarshal(res, &resp); err != nil {
		return fmt.Errorf("decode forkchoiceUpdated: %w", err)
	}
	if resp.PayloadStatus.Status != "VALID" &&
		resp.PayloadStatus.Status != "ACCEPTED" {
		if resp.PayloadStatus.Status == "SYNCING" {
			b.logger.Warn("Engine is SYNCING during forkchoice update")
			return nil
		}
		return fmt.Errorf("forkchoice status=%s validationError=%s", resp.PayloadStatus.Status, resp.PayloadStatus.ValidationError)
	}
	return nil
}
