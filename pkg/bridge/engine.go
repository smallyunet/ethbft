package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/prometheus/client_golang/prometheus"
)

func zeroHash() common.Hash { return common.Hash{} }

func (b *Bridge) finalityHashes(head common.Hash, height int64) (common.Hash, common.Hash) {
	hashAtDepth := func(depth int) common.Hash {
		if depth <= 0 {
			return head
		}
		target := height - int64(depth)
		if target <= 0 {
			return b.elGenesis
		}
		if hash := b.getHeightHash(target); hash != (common.Hash{}) {
			return hash
		}
		return b.elGenesis
	}
	safeDepth := b.config.Bridge.SafeDepth
	finalizedDepth := b.config.Bridge.FinalizedDepth
	if b.config.Bridge.FinalityDepth > 0 {
		if safeDepth == 0 {
			safeDepth = b.config.Bridge.FinalityDepth
		}
		if finalizedDepth == 0 {
			finalizedDepth = b.config.Bridge.FinalityDepth
		}
	}
	return hashAtDepth(safeDepth), hashAtDepth(finalizedDepth)
}

func missingTransactionHashes(expected, included [][]byte) ([]common.Hash, error) {
	includedHashes := make(map[common.Hash]struct{}, len(included))
	for _, raw := range included {
		hash, err := transactionHash(raw)
		if err != nil {
			return nil, fmt.Errorf("decode payload transaction: %w", err)
		}
		includedHashes[hash] = struct{}{}
	}
	missing := make([]common.Hash, 0)
	for _, raw := range expected {
		hash, err := transactionHash(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := includedHashes[hash]; !ok {
			missing = append(missing, hash)
		}
	}
	return missing, nil
}

func terminalInjectionError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, fragment := range []string{
		"nonce too low",
		"insufficient funds",
		"intrinsic gas too low",
		"exceeds block gas limit",
		"invalid sender",
		"transaction type not supported",
	} {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
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

		for _, tx := range txs {
			txHex := hexutil.Encode(tx)
			_, injectErr := b.ethClient.Call(ctxTx, "eth_sendRawTransaction", []interface{}{txHex})
			if injectErr != nil && !strings.Contains(strings.ToLower(injectErr.Error()), "already known") {
				txsInjectionFailed.Inc()
				if terminalInjectionError(injectErr) {
					b.txPool.Reject(tx, injectErr)
					b.logger.Warn("Rejected non-includable transaction", "error", injectErr)
					continue
				}
				attempts := b.txPool.MarkRetrying(tx, injectErr)
				maxAttempts := b.config.Bridge.MaxDeliveryAttempts
				if maxAttempts > 0 && attempts >= maxAttempts {
					b.txPool.Reject(tx, fmt.Errorf("delivery retry limit reached after %d attempts: %w", attempts, injectErr))
					continue
				}
				if stateErr := b.saveState(); stateErr != nil {
					b.logger.Error("Failed to persist transaction retry state", "error", stateErr)
				}
				return fmt.Errorf("inject transaction: %w", injectErr)
			}
			b.txPool.MarkInjected(tx)
		}
		txs = b.txPool.GetTxs(height)
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

	// 2) Pre-forkchoice without attributes. Preserve configured safe/finalized depths.
	preSafe, preFinalized := b.finalityHashes(parent, height-1)
	if err := b.sendForkchoiceUpdate(parent, preSafe, preFinalized); err != nil {
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

	req := []any{
		&FCURequest{Head: parent, Safe: preSafe, Finalized: preFinalized},
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
	missing, err := missingTransactionHashes(txs, payload.Transactions)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		deliveryErr := fmt.Errorf("payload is missing %d accepted transactions: %v", len(missing), missing)
		missingSet := make(map[common.Hash]struct{}, len(missing))
		for _, hash := range missing {
			missingSet[hash] = struct{}{}
		}
		remainingMissing := false
		for _, tx := range txs {
			hash, _ := transactionHash(tx)
			if _, ok := missingSet[hash]; !ok {
				continue
			}
			attempts := b.txPool.MarkRetrying(tx, deliveryErr)
			maxAttempts := b.config.Bridge.MaxDeliveryAttempts
			if maxAttempts > 0 && attempts >= maxAttempts {
				b.txPool.Reject(tx, fmt.Errorf("delivery retry limit reached after %d attempts: %w", attempts, deliveryErr))
			} else {
				remainingMissing = true
			}
		}
		if stateErr := b.saveState(); stateErr != nil {
			b.logger.Error("Failed to persist missing transaction state", "error", stateErr)
		}
		if remainingMissing {
			return deliveryErr
		}
		txs = b.txPool.GetTxs(height)
	}
	if len(txs) > 0 {
		b.logger.Info("Block produced with all accepted transactions", "height", height, "expected", len(txs), "included", len(payload.Transactions))
	} else {
		b.logger.Info("Produced block", "height", height, "head", head.Hex(), "txs", len(payload.Transactions))
	}
	newSafe, newFinalized := b.finalityHashes(head, height)

	if err := b.sendForkchoiceUpdate(head, newSafe, newFinalized); err != nil {
		return fmt.Errorf("final fcu failed: %w", err)
	}

	previousHeight := b.lastProducedHeight.Load()
	previousHash := b.getHeightHash(height)
	pendingSnapshot, deliverySnapshot := b.txPool.Snapshot()
	b.setHeightHash(height, head)
	b.lastProducedHeight.Store(height)
	b.lastProgressUnix.Store(time.Now().Unix())
	b.txPool.CompleteHeight(height, head)
	if err := b.saveState(); err != nil {
		b.txPool.Restore(pendingSnapshot, deliverySnapshot)
		b.heightMu.Lock()
		if previousHash == (common.Hash{}) {
			delete(b.heightToHash, height)
			for i, h := range b.heightOrder {
				if h == height {
					b.heightOrder = append(b.heightOrder[:i], b.heightOrder[i+1:]...)
					break
				}
			}
		} else {
			b.heightToHash[height] = previousHash
		}
		b.heightMu.Unlock()
		b.lastProducedHeight.Store(previousHeight)
		return err
	}
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
	if resp.PayloadStatus.Status != "VALID" && resp.PayloadStatus.Status != "ACCEPTED" {
		return fmt.Errorf("forkchoice status=%s validationError=%s", resp.PayloadStatus.Status, resp.PayloadStatus.ValidationError)
	}
	return nil
}
