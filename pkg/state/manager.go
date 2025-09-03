package state

import (
	"fmt"
	"sync"

	"github.com/smallyunet/ethbft/pkg/engine"
	"github.com/smallyunet/ethbft/pkg/ethereum"
)

// Manager manages the state synchronization between Ethereum execution and CometBFT consensus
type Manager struct {
	mu sync.RWMutex

	// State tracking
	latestHeight    int64
	safeHeight      int64
	finalizedHeight int64

	// Block hash mappings
	heightToHash map[int64]string
	hashToHeight map[string]int64

	// Ethereum client for state queries
	ethClient *ethereum.Client
}

// BlockState represents the state of a block
type BlockState struct {
	Height    int64  `json:"height"`
	Hash      string `json:"hash"`
	StateRoot string `json:"stateRoot"`
	Status    string `json:"status"` // "latest", "safe", "finalized"
}

// NewManager creates a new state manager
func NewManager(ethClient *ethereum.Client) *Manager {
	return &Manager{
		heightToHash: make(map[int64]string),
		hashToHeight: make(map[string]int64),
		ethClient:    ethClient,
	}
}

// UpdateLatest updates the latest block state
func (m *Manager) UpdateLatest(height int64, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.latestHeight = height
	m.heightToHash[height] = hash
	m.hashToHeight[hash] = height

	return nil
}

// UpdateSafe updates the safe block state
func (m *Manager) UpdateSafe(height int64, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if height > m.latestHeight {
		return fmt.Errorf("safe height %d cannot be greater than latest height %d", height, m.latestHeight)
	}

	m.safeHeight = height
	m.heightToHash[height] = hash
	m.hashToHeight[hash] = height

	return nil
}

// UpdateFinalized updates the finalized block state
func (m *Manager) UpdateFinalized(height int64, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if height > m.safeHeight {
		return fmt.Errorf("finalized height %d cannot be greater than safe height %d", height, m.safeHeight)
	}

	m.finalizedHeight = height
	m.heightToHash[height] = hash
	m.hashToHeight[hash] = height

	return nil
}

// GetLatest returns the latest block state
func (m *Manager) GetLatest() BlockState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return BlockState{
		Height: m.latestHeight,
		Hash:   m.heightToHash[m.latestHeight],
		Status: "latest",
	}
}

// GetSafe returns the safe block state
func (m *Manager) GetSafe() BlockState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return BlockState{
		Height: m.safeHeight,
		Hash:   m.heightToHash[m.safeHeight],
		Status: "safe",
	}
}

// GetFinalized returns the finalized block state
func (m *Manager) GetFinalized() BlockState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return BlockState{
		Height: m.finalizedHeight,
		Hash:   m.heightToHash[m.finalizedHeight],
		Status: "finalized",
	}
}

// GetForkchoiceState returns the current forkchoice state for Engine API
func (m *Manager) GetForkchoiceState() *engine.ForkchoiceState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return &engine.ForkchoiceState{
		HeadBlockHash:      m.heightToHash[m.latestHeight],
		SafeBlockHash:      m.heightToHash[m.safeHeight],
		FinalizedBlockHash: m.heightToHash[m.finalizedHeight],
	}
}

// GetBlockByHeight returns block info by height
func (m *Manager) GetBlockByHeight(height int64) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hash, exists := m.heightToHash[height]
	if !exists {
		return "", fmt.Errorf("block at height %d not found", height)
	}

	return hash, nil
}

// GetHeightByHash returns height by block hash
func (m *Manager) GetHeightByHash(hash string) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	height, exists := m.hashToHeight[hash]
	if !exists {
		return 0, fmt.Errorf("block with hash %s not found", hash)
	}

	return height, nil
}

// Reorg handles blockchain reorganization
func (m *Manager) Reorg(newHead int64, newHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove invalidated blocks
	for height := newHead + 1; height <= m.latestHeight; height++ {
		if hash, exists := m.heightToHash[height]; exists {
			delete(m.hashToHeight, hash)
			delete(m.heightToHash, height)
		}
	}

	// Update to new head
	m.latestHeight = newHead
	m.heightToHash[newHead] = newHash
	m.hashToHeight[newHash] = newHead

	// Adjust safe and finalized if needed
	if m.safeHeight > newHead {
		m.safeHeight = newHead
	}
	if m.finalizedHeight > newHead {
		m.finalizedHeight = newHead
	}

	return nil
}

// GetStats returns current state statistics
func (m *Manager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"latest_height":    m.latestHeight,
		"safe_height":      m.safeHeight,
		"finalized_height": m.finalizedHeight,
		"total_blocks":     len(m.heightToHash),
	}
}
