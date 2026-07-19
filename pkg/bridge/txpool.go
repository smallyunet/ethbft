package bridge

import (
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

const (
	DeliveryAccepted = "accepted"
	DeliveryInjected = "injected"
	DeliveryIncluded = "included"
	DeliveryRetrying = "retrying"
	DeliveryRejected = "rejected"
)

// DeliveryStatus describes asynchronous delivery of a CometBFT transaction to the EL.
// A successful CometBFT result means accepted; Included is the terminal EL success state.
type DeliveryStatus struct {
	TxHash      common.Hash `json:"txHash"`
	Height      int64       `json:"height"`
	Status      string      `json:"status"`
	LastError   string      `json:"lastError,omitempty"`
	ELBlockHash common.Hash `json:"elBlockHash,omitempty"`
	Attempts    int         `json:"attempts,omitempty"`
}

// TxPool stores transactions accepted by CometBFT until exact inclusion in an EL block.
type TxPool struct {
	mu         sync.RWMutex
	pool       map[int64][][]byte
	deliveries map[common.Hash]DeliveryStatus
}

func NewTxPool() *TxPool {
	return &TxPool{
		pool:       make(map[int64][][]byte),
		deliveries: make(map[common.Hash]DeliveryStatus),
	}
}

func transactionHash(txBytes []byte) (common.Hash, error) {
	var tx types.Transaction
	if err := tx.UnmarshalBinary(txBytes); err != nil {
		return common.Hash{}, fmt.Errorf("decode transaction: %w", err)
	}
	return tx.Hash(), nil
}

// AddTxs stores transactions and marks them accepted for asynchronous EL delivery.
func (tp *TxPool) AddTxs(height int64, txs [][]byte) error {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	copied := make([][]byte, len(txs))
	for i, raw := range txs {
		hash, err := transactionHash(raw)
		if err != nil {
			return err
		}
		copied[i] = append([]byte(nil), raw...)
		tp.deliveries[hash] = DeliveryStatus{TxHash: hash, Height: height, Status: DeliveryAccepted}
	}
	tp.pool[height] = copied
	return nil
}

func (tp *TxPool) GetTxs(height int64) [][]byte {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	txs := tp.pool[height]
	out := make([][]byte, len(txs))
	for i := range txs {
		out[i] = append([]byte(nil), txs[i]...)
	}
	return out
}

func (tp *TxPool) mark(raw []byte, status, lastError string, blockHash common.Hash) {
	hash, err := transactionHash(raw)
	if err != nil {
		return
	}
	tp.mu.Lock()
	defer tp.mu.Unlock()
	delivery := tp.deliveries[hash]
	delivery.TxHash = hash
	delivery.Status = status
	delivery.LastError = lastError
	if blockHash != (common.Hash{}) {
		delivery.ELBlockHash = blockHash
	}
	tp.deliveries[hash] = delivery
}

func (tp *TxPool) MarkInjected(raw []byte) { tp.mark(raw, DeliveryInjected, "", common.Hash{}) }

func (tp *TxPool) MarkRetrying(raw []byte, err error) int {
	message := ""
	if err != nil {
		message = err.Error()
	}
	hash, hashErr := transactionHash(raw)
	if hashErr != nil {
		return 0
	}
	tp.mu.Lock()
	defer tp.mu.Unlock()
	delivery := tp.deliveries[hash]
	delivery.TxHash = hash
	delivery.Status = DeliveryRetrying
	delivery.LastError = message
	delivery.Attempts++
	tp.deliveries[hash] = delivery
	return delivery.Attempts
}

func (tp *TxPool) Reject(raw []byte, err error) {
	hash, hashErr := transactionHash(raw)
	if hashErr != nil {
		return
	}
	tp.mu.Lock()
	defer tp.mu.Unlock()
	delivery := tp.deliveries[hash]
	delivery.TxHash = hash
	delivery.Status = DeliveryRejected
	if err != nil {
		delivery.LastError = err.Error()
	}
	tp.deliveries[hash] = delivery
	txs := tp.pool[delivery.Height]
	filtered := txs[:0]
	for _, candidate := range txs {
		candidateHash, candidateErr := transactionHash(candidate)
		if candidateErr != nil || candidateHash != hash {
			filtered = append(filtered, candidate)
		}
	}
	if len(filtered) == 0 {
		delete(tp.pool, delivery.Height)
	} else {
		tp.pool[delivery.Height] = filtered
	}
}

func (tp *TxPool) CompleteHeight(height int64, blockHash common.Hash) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	for _, raw := range tp.pool[height] {
		hash, err := transactionHash(raw)
		if err != nil {
			continue
		}
		delivery := tp.deliveries[hash]
		delivery.TxHash = hash
		delivery.Height = height
		delivery.Status = DeliveryIncluded
		delivery.LastError = ""
		delivery.ELBlockHash = blockHash
		tp.deliveries[hash] = delivery
	}
	delete(tp.pool, height)
}

func (tp *TxPool) GetDelivery(hash common.Hash) (DeliveryStatus, bool) {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	status, ok := tp.deliveries[hash]
	return status, ok
}

func (tp *TxPool) Snapshot() (map[int64][][]byte, map[common.Hash]DeliveryStatus) {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	pool := make(map[int64][][]byte, len(tp.pool))
	for height, txs := range tp.pool {
		pool[height] = make([][]byte, len(txs))
		for i := range txs {
			pool[height][i] = append([]byte(nil), txs[i]...)
		}
	}
	deliveries := make(map[common.Hash]DeliveryStatus, len(tp.deliveries))
	for hash, delivery := range tp.deliveries {
		deliveries[hash] = delivery
	}
	return pool, deliveries
}

func (tp *TxPool) Restore(pool map[int64][][]byte, deliveries map[common.Hash]DeliveryStatus) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.pool = pool
	if tp.pool == nil {
		tp.pool = make(map[int64][][]byte)
	}
	tp.deliveries = deliveries
	if tp.deliveries == nil {
		tp.deliveries = make(map[common.Hash]DeliveryStatus)
	}
}

// Prune bounds completed delivery history. Pending heights are never discarded.
func (tp *TxPool) Prune(beforeHeight int64) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	for hash, delivery := range tp.deliveries {
		if delivery.Status == DeliveryIncluded && delivery.Height < beforeHeight {
			delete(tp.deliveries, hash)
		}
	}
}
