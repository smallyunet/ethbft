package bridge

import (
	"encoding/json"
	"os"
	"sort"

	"github.com/ethereum/go-ethereum/common"
)

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

func (b *Bridge) saveState() {
	b.heightMu.RLock()
	defer b.heightMu.RUnlock()

	if len(b.heightToHash) == 0 {
		return
	}

	data, err := json.Marshal(b.heightToHash)
	if err != nil {
		b.logger.Error("Failed to marshal state", "error", err)
		return
	}

	path := b.config.Bridge.StateFile
	if path == "" {
		path = "ethbft_state.json"
	}

	// Atomic write: write to temp file then rename
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		b.logger.Error("Failed to write temp state file", "error", err)
		return
	}

	if err := os.Rename(tmpPath, path); err != nil {
		b.logger.Error("Failed to rename temp state file", "error", err)
		_ = os.Remove(tmpPath)
	}
}

func (b *Bridge) loadState() {
	path := b.config.Bridge.StateFile
	if path == "" {
		path = "ethbft_state.json"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			b.logger.Error("Failed to read state file", "error", err)
		}
		return
	}

	var m map[int64]common.Hash
	if err := json.Unmarshal(data, &m); err != nil {
		b.logger.Error("Failed to unmarshal state", "error", err)
		return
	}

	b.heightMu.Lock()
	defer b.heightMu.Unlock()
	b.heightToHash = m

	// Rebuild heightOrder
	b.heightOrder = make([]int64, 0, len(m))
	for h := range m {
		b.heightOrder = append(b.heightOrder, h)
	}
	sort.Slice(b.heightOrder, func(i, j int) bool {
		return b.heightOrder[i] < b.heightOrder[j]
	})
	b.logger.Info("Loaded state", "entries", len(m))
}
