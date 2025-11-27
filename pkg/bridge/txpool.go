package bridge

import (
	"sync"
)

// TxPool stores transactions received from CometBFT ABCI, keyed by block height.
// These transactions are waiting to be injected into the EL (Geth) before block production.
type TxPool struct {
	mu   sync.RWMutex
	pool map[int64][][]byte
}

func NewTxPool() *TxPool {
	return &TxPool{
		pool: make(map[int64][][]byte),
	}
}

// AddTxs stores transactions for a specific height.
func (tp *TxPool) AddTxs(height int64, txs [][]byte) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.pool[height] = txs
}

// GetTxs retrieves transactions for a specific height.
func (tp *TxPool) GetTxs(height int64) [][]byte {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return tp.pool[height]
}

// Prune removes transactions for heights older than the given height.
func (tp *TxPool) Prune(height int64) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	for h := range tp.pool {
		if h < height {
			delete(tp.pool, h)
		}
	}
}
