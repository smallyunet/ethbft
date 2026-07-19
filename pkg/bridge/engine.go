package bridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	gethengine "github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/smallyunet/ethbft/pkg/protocol"
)

type pendingExecutionCommit struct {
	height  int64
	payload *ExecutionPayload
	appHash []byte
	txs     [][]byte
}

func (b *Bridge) operationTimeout() time.Duration {
	timeout := 8 * time.Second
	if b.config != nil && b.config.Bridge.Timeout > 0 {
		timeout = time.Duration(b.config.Bridge.Timeout) * time.Second
	}
	return timeout
}

func (b *Bridge) committedExecutionParent(height int64) common.Hash {
	if height > 1 {
		return b.getHeightHash(height - 1)
	}
	return b.elGenesis
}

func (b *Bridge) configuredFeeRecipient() (common.Address, error) {
	if b.config == nil || strings.TrimSpace(b.config.Bridge.FeeRecipient) == "" {
		return common.Address{}, nil
	}
	if !common.IsHexAddress(b.config.Bridge.FeeRecipient) {
		return common.Address{}, fmt.Errorf("invalid fee recipient %q", b.config.Bridge.FeeRecipient)
	}
	return common.HexToAddress(b.config.Bridge.FeeRecipient), nil
}

func (b *Bridge) proposalRandao(height int64) common.Hash {
	chainID := make([]byte, 32)
	if b.chainID != nil {
		b.chainID.FillBytes(chainID)
	}
	var heightBytes [8]byte
	binary.BigEndian.PutUint64(heightBytes[:], uint64(height))
	return crypto.Keccak256Hash(
		[]byte("ETHBFT_PREVRANDAO_V1"),
		chainID,
		heightBytes[:],
		b.appHash(),
	)
}

func (b *Bridge) getBlockTimestampByHash(ctx context.Context, hash common.Hash) uint64 {
	if hash == (common.Hash{}) {
		return 0
	}
	b.tsMu.RLock()
	if timestamp, ok := b.tsCache[hash]; ok {
		b.tsMu.RUnlock()
		return timestamp
	}
	b.tsMu.RUnlock()
	raw, err := b.ethClient.Call(ctx, "eth_getBlockByHash", []interface{}{hash.Hex(), false})
	if err != nil {
		return 0
	}
	var block struct {
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal(raw, &block); err != nil || block.Timestamp == "" {
		return 0
	}
	timestamp, err := hexutil.DecodeUint64(block.Timestamp)
	if err != nil {
		return 0
	}
	b.tsMu.Lock()
	if len(b.tsCache) >= 1024 {
		for cached := range b.tsCache {
			delete(b.tsCache, cached)
			break
		}
	}
	b.tsCache[hash] = timestamp
	b.tsMu.Unlock()
	return timestamp
}

func (b *Bridge) injectProposalCandidates(ctx context.Context, candidates [][]byte) {
	for _, raw := range candidates {
		if protocol.IsEnvelope(raw) {
			continue
		}
		if code, message := validateTransaction(raw, b.chainID); code != 0 {
			b.logger.Debug("Skipping invalid proposal candidate", "reason", message)
			continue
		}
		_, err := b.ethClient.Call(ctx, "eth_sendRawTransaction", []interface{}{hexutil.Encode(raw)})
		if err != nil && !strings.Contains(strings.ToLower(err.Error()), "already known") {
			b.logger.Debug("Skipping non-injectable proposal candidate", "error", err)
		}
	}
}

// buildExecutionProposal asks the proposer's dedicated EL to build the complete
// payload, then turns the payload into the exact CometBFT proposal contents.
func (b *Bridge) buildExecutionProposal(height int64, proposalTime time.Time, candidates [][]byte, maxTxBytes int64) ([][]byte, error) {
	if height <= 0 {
		return nil, fmt.Errorf("invalid proposal height %d", height)
	}
	parent := b.committedExecutionParent(height)
	if parent == (common.Hash{}) {
		return nil, fmt.Errorf("no committed execution parent for height %d", height)
	}
	feeRecipient, err := b.configuredFeeRecipient()
	if err != nil {
		return nil, err
	}
	if proposalTime.IsZero() || proposalTime.Unix() <= 0 {
		return nil, fmt.Errorf("invalid CometBFT proposal time")
	}
	timestamp := uint64(proposalTime.Unix())
	ctx, cancel := context.WithTimeout(b.ctx, b.operationTimeout())
	defer cancel()
	parentTimestamp := b.getBlockTimestampByHash(ctx, parent)
	if parentTimestamp > 0 && timestamp <= parentTimestamp {
		return nil, fmt.Errorf("proposal timestamp %d is not greater than parent timestamp %d", timestamp, parentTimestamp)
	}

	b.injectProposalCandidates(ctx, candidates)
	if err := b.sendForkchoiceUpdate(parent, parent, parent); err != nil {
		return nil, fmt.Errorf("prepare parent forkchoice: %w", err)
	}

	attrs := &PayloadAttributes{
		Timestamp:             timestamp,
		Random:                b.proposalRandao(height),
		SuggestedFeeRecipient: feeRecipient,
		Withdrawals:           []*types.Withdrawal{},
	}
	req := []any{&FCURequest{Head: parent, Safe: parent, Finalized: parent}, attrs}
	raw, err := b.ethClient.Call(ctx, "engine_forkchoiceUpdatedV2", req)
	if err != nil {
		return nil, fmt.Errorf("start payload build: %w", err)
	}
	var response FCUResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("decode payload build response: %w", err)
	}
	if response.PayloadStatus.Status != "VALID" {
		return nil, fmt.Errorf("payload build forkchoice status=%s error=%s", response.PayloadStatus.Status, response.PayloadStatus.ValidationError)
	}
	if response.PayloadID == nil {
		return nil, fmt.Errorf("payload build returned no payload ID")
	}

	raw, err = b.ethClient.Call(ctx, "engine_getPayloadV2", []any{response.PayloadID})
	if err != nil {
		return nil, fmt.Errorf("get execution payload: %w", err)
	}
	var result struct {
		ExecutionPayload ExecutionPayload `json:"executionPayload"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("decode execution payload: %w", err)
	}
	payload := &result.ExecutionPayload
	if payload.ParentHash != parent || payload.Timestamp != timestamp || payload.Random != attrs.Random || payload.FeeRecipient != feeRecipient {
		return nil, fmt.Errorf("builder returned payload with non-deterministic attributes")
	}
	if payload.Withdrawals == nil || len(payload.Withdrawals) != 0 {
		return nil, fmt.Errorf("protocol v1 requires an explicit empty withdrawals list")
	}
	if _, err := gethengine.ExecutableDataToBlock(*payload, nil, nil, nil); err != nil {
		return nil, fmt.Errorf("builder returned invalid payload: %w", err)
	}

	metadata, err := protocol.NewExecutionMetadataV1(b.chainID, height, b.appHash(), payload)
	if err != nil {
		return nil, err
	}
	envelope, err := protocol.EncodeEnvelope(metadata)
	if err != nil {
		return nil, err
	}
	proposal := make([][]byte, 1, len(payload.Transactions)+1)
	proposal[0] = envelope
	totalBytes := int64(len(envelope))
	for _, tx := range payload.Transactions {
		copy := append([]byte(nil), tx...)
		proposal = append(proposal, copy)
		totalBytes += int64(len(copy))
	}
	if maxTxBytes > 0 && totalBytes > maxTxBytes {
		return nil, fmt.Errorf("execution proposal uses %d bytes, maximum is %d", totalBytes, maxTxBytes)
	}
	return proposal, nil
}

// validateExecutionProposal performs deterministic checks and asks the local EL
// to independently validate the exact execution payload.
func (b *Bridge) validateExecutionProposal(ctx context.Context, height int64, proposalTime time.Time, proposal [][]byte) (*ExecutionPayload, error) {
	if len(proposal) == 0 {
		return nil, fmt.Errorf("proposal has no execution envelope")
	}
	metadata, err := protocol.DecodeEnvelope(proposal[0])
	if err != nil {
		return nil, err
	}
	if metadata.ConsensusHeight != uint64(height) {
		return nil, fmt.Errorf("metadata height %d does not match proposal height %d", metadata.ConsensusHeight, height)
	}
	if b.chainID == nil || metadata.ChainID.Cmp(b.chainID) != 0 {
		return nil, fmt.Errorf("metadata chain ID %s does not match local chain ID", metadata.ChainID)
	}
	if !bytes.Equal(metadata.PreviousAppHash, b.appHash()) {
		return nil, fmt.Errorf("metadata previous app hash does not match committed state")
	}
	parent := b.committedExecutionParent(height)
	if metadata.ParentHash != parent {
		return nil, fmt.Errorf("execution parent %s does not match committed parent %s", metadata.ParentHash, parent)
	}
	if proposalTime.IsZero() || metadata.Timestamp != uint64(proposalTime.Unix()) {
		return nil, fmt.Errorf("execution timestamp %d does not match CometBFT time %d", metadata.Timestamp, proposalTime.Unix())
	}
	if metadata.PrevRandao != b.proposalRandao(height) {
		return nil, fmt.Errorf("invalid deterministic prevRandao")
	}
	feeRecipient, err := b.configuredFeeRecipient()
	if err != nil {
		return nil, err
	}
	if metadata.FeeRecipient != feeRecipient {
		return nil, fmt.Errorf("invalid fee recipient %s", metadata.FeeRecipient)
	}
	if len(metadata.Withdrawals) != 0 {
		return nil, fmt.Errorf("protocol v1 requires empty withdrawals")
	}

	seen := make(map[common.Hash]struct{}, len(proposal)-1)
	for _, rawTx := range proposal[1:] {
		if protocol.IsEnvelope(rawTx) {
			return nil, fmt.Errorf("multiple execution envelopes in proposal")
		}
		if code, message := validateTransaction(rawTx, b.chainID); code != 0 {
			return nil, fmt.Errorf("invalid execution transaction: %s", message)
		}
		hash, err := transactionHash(rawTx)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[hash]; exists {
			return nil, fmt.Errorf("duplicate execution transaction %s", hash)
		}
		seen[hash] = struct{}{}
	}

	payload := metadata.Payload(proposal[1:])
	if _, err := gethengine.ExecutableDataToBlock(payload, nil, nil, nil); err != nil {
		return nil, fmt.Errorf("invalid execution payload commitment: %w", err)
	}
	raw, err := b.ethClient.Call(ctx, "engine_newPayloadV2", []any{&payload})
	if err != nil {
		return nil, fmt.Errorf("validate execution payload: %w", err)
	}
	var status PayloadStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		return nil, fmt.Errorf("decode execution validation status: %w", err)
	}
	if status.Status != "VALID" {
		return nil, fmt.Errorf("execution payload status=%s error=%s", status.Status, status.ValidationError)
	}
	if status.LatestValidHash != "" && status.LatestValidHash != "0x" && common.HexToHash(status.LatestValidHash) != payload.BlockHash {
		return nil, fmt.Errorf("latest valid hash %s does not match payload block %s", status.LatestValidHash, payload.BlockHash)
	}
	return &payload, nil
}

func (b *Bridge) stageExecutionCommit(height int64, proposalTime time.Time, proposal [][]byte) (*pendingExecutionCommit, error) {
	ctx, cancel := context.WithTimeout(b.ctx, b.operationTimeout())
	defer cancel()
	payload, err := b.validateExecutionProposal(ctx, height, proposalTime, proposal)
	if err != nil {
		return nil, err
	}
	if err := b.sendForkchoiceUpdate(payload.BlockHash, payload.BlockHash, payload.BlockHash); err != nil {
		return nil, fmt.Errorf("commit execution forkchoice: %w", err)
	}
	appHash, err := b.executionAppHash(height, payload)
	if err != nil {
		return nil, err
	}
	pending := &pendingExecutionCommit{
		height:  height,
		payload: payload,
		appHash: appHash,
		txs:     cloneRawTransactions(payload.Transactions),
	}
	b.pendingCommit = pending
	return pending, nil
}

func (b *Bridge) executionAppHash(height int64, payload *ExecutionPayload) ([]byte, error) {
	block, err := gethengine.ExecutableDataToBlock(*payload, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("ETHBFT_APP_HASH_V1"))
	_, _ = h.Write(b.appHash())
	chainID := make([]byte, 32)
	b.chainID.FillBytes(chainID)
	_, _ = h.Write(chainID)
	var heightBytes [8]byte
	binary.BigEndian.PutUint64(heightBytes[:], uint64(height))
	_, _ = h.Write(heightBytes[:])
	_, _ = h.Write(payload.ParentHash[:])
	_, _ = h.Write(payload.BlockHash[:])
	_, _ = h.Write(payload.StateRoot[:])
	_, _ = h.Write(payload.ReceiptsRoot[:])
	txRoot := block.TxHash()
	_, _ = h.Write(txRoot[:])
	return h.Sum(nil), nil
}

func cloneRawTransactions(transactions [][]byte) [][]byte {
	out := make([][]byte, len(transactions))
	for i := range transactions {
		out[i] = append([]byte(nil), transactions[i]...)
	}
	return out
}

// sendForkchoiceUpdate sets head, safe, and finalized. Protocol v1 finalizes a
// payload only after CometBFT has decided the containing proposal.
func (b *Bridge) sendForkchoiceUpdate(head, safe, finalized common.Hash) error {
	ctx, cancel := context.WithTimeout(b.ctx, b.operationTimeout())
	defer cancel()
	state := &FCURequest{Head: head, Safe: safe, Finalized: finalized}
	res, err := b.ethClient.Call(ctx, "engine_forkchoiceUpdatedV2", []interface{}{state, nil})
	if err != nil {
		return err
	}
	var response FCUResponse
	if err := json.Unmarshal(res, &response); err != nil {
		return fmt.Errorf("decode forkchoiceUpdated: %w", err)
	}
	if response.PayloadStatus.Status != "VALID" {
		return fmt.Errorf("forkchoice status=%s validationError=%s", response.PayloadStatus.Status, response.PayloadStatus.ValidationError)
	}
	return nil
}

func observeProposalValidation(start time.Time, err error) {
	blockProductionDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		rpcErrors.Inc()
	}
}
