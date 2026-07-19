package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

const persistedStateVersion = 2

type persistedBridgeState struct {
	Version             int                            `json:"version"`
	ChainID             string                         `json:"chainId"`
	ELGenesis           common.Hash                    `json:"elGenesis"`
	LastProducedHeight  int64                          `json:"lastProducedHeight"`
	HeightToHash        map[int64]common.Hash          `json:"heightToHash"`
	PendingTransactions map[int64][][]byte             `json:"pendingTransactions,omitempty"`
	Deliveries          map[common.Hash]DeliveryStatus `json:"deliveries,omitempty"`
	ABCILastBlockHeight int64                          `json:"abciLastBlockHeight"`
	ABCILastAppHash     []byte                         `json:"abciLastAppHash,omitempty"`
	LegacyEmptyAppHash  bool                           `json:"legacyEmptyAppHash,omitempty"`
}

func (b *Bridge) getHeightHash(h int64) common.Hash {
	b.heightMu.RLock()
	defer b.heightMu.RUnlock()
	return b.heightToHash[h]
}

func (b *Bridge) setHeightHash(h int64, hash common.Hash) {
	b.heightMu.Lock()
	defer b.heightMu.Unlock()
	if _, exists := b.heightToHash[h]; !exists {
		b.heightOrder = append(b.heightOrder, h)
	}
	b.heightToHash[h] = hash
	for b.maxHistory > 0 && len(b.heightOrder) > b.maxHistory {
		oldH := b.heightOrder[0]
		b.heightOrder = b.heightOrder[1:]
		delete(b.heightToHash, oldH)
	}
}

func (b *Bridge) appHash() []byte {
	b.appHashMu.RLock()
	defer b.appHashMu.RUnlock()
	return append([]byte(nil), b.abciAppHash...)
}

func (b *Bridge) setAppHash(hash []byte) {
	b.appHashMu.Lock()
	b.abciAppHash = append([]byte(nil), hash...)
	b.appHashMu.Unlock()
}

func (b *Bridge) snapshotState() persistedBridgeState {
	b.heightMu.RLock()
	heights := make(map[int64]common.Hash, len(b.heightToHash))
	for height, hash := range b.heightToHash {
		heights[height] = hash
	}
	b.heightMu.RUnlock()
	pending, deliveries := b.txPool.Snapshot()
	chainID := ""
	if b.chainID != nil {
		chainID = b.chainID.String()
	}
	return persistedBridgeState{
		Version:             persistedStateVersion,
		ChainID:             chainID,
		ELGenesis:           b.elGenesis,
		LastProducedHeight:  b.lastProducedHeight.Load(),
		HeightToHash:        heights,
		PendingTransactions: pending,
		Deliveries:          deliveries,
		ABCILastBlockHeight: b.abciLastBlockHeight.Load(),
		ABCILastAppHash:     b.appHash(),
		LegacyEmptyAppHash:  b.legacyEmptyAppHash.Load(),
	}
}

func (b *Bridge) saveState() error {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()

	data, err := json.Marshal(b.snapshotState())
	if err != nil {
		b.statePersisted.Store(false)
		return fmt.Errorf("marshal state: %w", err)
	}
	path := b.config.Bridge.StateFile
	if path == "" {
		path = "ethbft_state.json"
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		b.statePersisted.Store(false)
		return fmt.Errorf("write temp state file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		b.statePersisted.Store(false)
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename temp state file: %w", err)
	}
	b.statePersisted.Store(true)
	return nil
}

func (b *Bridge) loadState() error {
	path := b.config.Bridge.StateFile
	if path == "" {
		path = "ethbft_state.json"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read state file: %w", err)
	}

	var state persistedBridgeState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("unmarshal state: %w", err)
	}
	if state.Version == 0 && state.HeightToHash == nil {
		var legacy map[int64]common.Hash
		if err := json.Unmarshal(data, &legacy); err != nil {
			return fmt.Errorf("unmarshal legacy state: %w", err)
		}
		state.HeightToHash = legacy
		for height := range legacy {
			if height > state.LastProducedHeight {
				state.LastProducedHeight = height
			}
		}
		// v0.0.9 committed an empty app hash. Reporting the last delivered height
		// lets CometBFT replay only any consensus blocks the bridge had not handled.
		state.ABCILastBlockHeight = state.LastProducedHeight
		state.LegacyEmptyAppHash = true
		b.logger.Warn("Loaded legacy state; it will be migrated after reconciliation")
	} else if state.Version != persistedStateVersion {
		return fmt.Errorf("unsupported state version %d", state.Version)
	}
	if state.ChainID != "" && b.chainID != nil && state.ChainID != b.chainID.String() {
		return fmt.Errorf("state chain ID %s does not match execution chain ID %s", state.ChainID, b.chainID)
	}
	if state.ELGenesis != (common.Hash{}) && b.elGenesis != (common.Hash{}) && state.ELGenesis != b.elGenesis {
		return fmt.Errorf("state genesis %s does not match execution genesis %s", state.ELGenesis, b.elGenesis)
	}

	b.heightMu.Lock()
	b.heightToHash = state.HeightToHash
	if b.heightToHash == nil {
		b.heightToHash = make(map[int64]common.Hash)
	}
	b.heightOrder = make([]int64, 0, len(b.heightToHash))
	for height := range b.heightToHash {
		b.heightOrder = append(b.heightOrder, height)
	}
	sort.Slice(b.heightOrder, func(i, j int) bool { return b.heightOrder[i] < b.heightOrder[j] })
	b.heightMu.Unlock()

	b.lastProducedHeight.Store(state.LastProducedHeight)
	b.abciLastBlockHeight.Store(state.ABCILastBlockHeight)
	b.legacyEmptyAppHash.Store(state.LegacyEmptyAppHash)
	b.setAppHash(state.ABCILastAppHash)
	b.txPool.Restore(state.PendingTransactions, state.Deliveries)
	b.statePersisted.Store(true)
	b.logger.Info("Loaded state", "bridge_height", state.LastProducedHeight, "abci_height", state.ABCILastBlockHeight, "pending_heights", len(state.PendingTransactions))
	return nil
}

// reconcileState refuses to bridge when persisted state points at another or non-canonical EL history.
func (b *Bridge) reconcileState(ctx context.Context) error {
	height := b.lastProducedHeight.Load()
	if height == 0 {
		return nil
	}
	hash := b.getHeightHash(height)
	if hash == (common.Hash{}) {
		return fmt.Errorf("state has bridge height %d but no execution hash", height)
	}
	raw, err := b.ethClient.Call(ctx, "eth_getBlockByHash", []interface{}{hash.Hex(), false})
	if err != nil {
		return fmt.Errorf("look up persisted execution block %s: %w", hash, err)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("persisted execution block %s is missing", hash)
	}
	var block struct {
		Hash   common.Hash `json:"hash"`
		Number string      `json:"number"`
	}
	if err := json.Unmarshal(raw, &block); err != nil || block.Number == "" {
		return fmt.Errorf("decode persisted execution block %s", hash)
	}
	numberText := strings.TrimPrefix(block.Number, "0x")
	if numberText == "" {
		return fmt.Errorf("persisted execution block has invalid number %q", block.Number)
	}
	number, err := strconv.ParseUint(numberText, 16, 64)
	if err != nil {
		return fmt.Errorf("decode persisted execution block number %q: %w", block.Number, err)
	}
	canonicalRaw, err := b.ethClient.Call(ctx, "eth_getBlockByNumber", []interface{}{fmt.Sprintf("0x%x", number), false})
	if err != nil {
		return fmt.Errorf("look up canonical execution block %d: %w", number, err)
	}
	var canonical struct {
		Hash common.Hash `json:"hash"`
	}
	if err := json.Unmarshal(canonicalRaw, &canonical); err != nil || canonical.Hash != hash {
		return fmt.Errorf("persisted execution block %s is not canonical at EL height %d", hash, number)
	}
	return nil
}
