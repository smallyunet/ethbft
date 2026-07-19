package bridge

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/smallyunet/ethbft/pkg/config"
)

func TestParseCometHash(t *testing.T) {
	h := parseCometHash("AABBCC")
	if h.Hex() != "0x0000000000000000000000000000000000000000000000000000000000aabbcc" {
		t.Fatalf("unexpected hash: %s", h.Hex())
	}
	h2 := parseCometHash("0xABCDEF")
	if h2.Hex() != "0x0000000000000000000000000000000000000000000000000000000000abcdef" {
		t.Fatalf("unexpected hash: %s", h2.Hex())
	}
}

func TestHeightCacheSetGet(t *testing.T) {
	b := &Bridge{
		heightToHash: make(map[int64]common.Hash),
		heightOrder:  make([]int64, 0),
		maxHistory:   4,
	}
	// concurrent sets and gets
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.setHeightHash(int64(i), common.BigToHash(common.Big1))
			_ = b.getHeightHash(int64(i))
		}()
	}
	wg.Wait()
	// Ensure pruning kept at most maxHistory entries
	b.heightMu.RLock()
	if len(b.heightOrder) > b.maxHistory {
		t.Fatalf("heightOrder length exceeded: %d > %d", len(b.heightOrder), b.maxHistory)
	}
	if len(b.heightToHash) > b.maxHistory {
		t.Fatalf("heightToHash length exceeded: %d > %d", len(b.heightToHash), b.maxHistory)
	}
	b.heightMu.RUnlock()
}

func TestBridgeProgressError(t *testing.T) {
	tests := []struct {
		name           string
		enabled        bool
		cometHeight    int64
		bridgeHeight   int64
		ethereumHeight uint64
		wantError      bool
	}{
		{name: "disabled", enabled: false, cometHeight: 10, wantError: false},
		{name: "waiting for consensus", enabled: true, cometHeight: 0, wantError: false},
		{name: "no execution progress", enabled: true, cometHeight: 10, bridgeHeight: 0, ethereumHeight: 0, wantError: true},
		{name: "execution client stuck", enabled: true, cometHeight: 10, bridgeHeight: 10, ethereumHeight: 0, wantError: true},
		{name: "healthy progress", enabled: true, cometHeight: 10, bridgeHeight: 9, ethereumHeight: 9, wantError: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bridgeProgressError(tt.enabled, tt.cometHeight, tt.bridgeHeight, tt.ethereumHeight, 5, time.Now(), 30*time.Second)
			if (got != "") != tt.wantError {
				t.Fatalf("bridgeProgressError() = %q, wantError %v", got, tt.wantError)
			}
		})
	}
}

func TestLoadStateRestoresResumeHeight(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state.json")
	state := map[int64]common.Hash{
		40: common.HexToHash("0x40"),
		42: common.HexToHash("0x42"),
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	b := &Bridge{
		config: &config.Config{},
		logger: slog.Default(),
		txPool: NewTxPool(),
	}
	b.config.Bridge.StateFile = stateFile
	if err := b.loadState(); err != nil {
		t.Fatal(err)
	}

	if got := b.lastProducedHeight.Load(); got != 42 {
		t.Fatalf("resume height = %d, want 42", got)
	}
	if !b.statePersisted.Load() {
		t.Fatal("loaded state should be marked persisted")
	}
}

func testTransactionBytes(t *testing.T, nonce uint64) []byte {
	t.Helper()
	tx := types.NewTx(&types.LegacyTx{Nonce: nonce, GasPrice: big.NewInt(1), Gas: 21_000, To: &common.Address{1}})
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestMissingTransactionHashesChecksExactHashes(t *testing.T) {
	first := testTransactionBytes(t, 1)
	second := testTransactionBytes(t, 2)
	direct := testTransactionBytes(t, 3)
	missing, err := missingTransactionHashes([][]byte{first, second}, [][]byte{first, direct})
	if err != nil {
		t.Fatal(err)
	}
	secondHash, _ := transactionHash(second)
	if len(missing) != 1 || missing[0] != secondHash {
		t.Fatalf("missing = %v, want [%s]", missing, secondHash)
	}
}

func TestTxPoolDeliveryLifecycle(t *testing.T) {
	tp := NewTxPool()
	raw := testTransactionBytes(t, 1)
	hash, _ := transactionHash(raw)
	if err := tp.AddTxs(7, [][]byte{raw}); err != nil {
		t.Fatal(err)
	}
	if status, ok := tp.GetDelivery(hash); !ok || status.Status != DeliveryAccepted {
		t.Fatalf("accepted status = %+v, found=%v", status, ok)
	}
	tp.MarkInjected(raw)
	if status, _ := tp.GetDelivery(hash); status.Status != DeliveryInjected {
		t.Fatalf("injected status = %+v", status)
	}
	blockHash := common.HexToHash("0xbeef")
	tp.CompleteHeight(7, blockHash)
	if status, _ := tp.GetDelivery(hash); status.Status != DeliveryIncluded || status.ELBlockHash != blockHash {
		t.Fatalf("included status = %+v", status)
	}
	if txs := tp.GetTxs(7); len(txs) != 0 {
		t.Fatalf("completed height still has %d pending transactions", len(txs))
	}
}

func TestFinalityHashesRespectDepth(t *testing.T) {
	cfg := &config.Config{}
	cfg.Bridge.SafeDepth = 2
	cfg.Bridge.FinalizedDepth = 3
	b := &Bridge{
		config:       cfg,
		elGenesis:    common.HexToHash("0x01"),
		heightToHash: map[int64]common.Hash{},
	}
	for height := int64(1); height <= 4; height++ {
		b.heightToHash[height] = common.BigToHash(big.NewInt(height))
	}
	head := common.BigToHash(big.NewInt(5))
	safe, finalized := b.finalityHashes(head, 5)
	if safe != b.heightToHash[3] || finalized != b.heightToHash[2] {
		t.Fatalf("safe=%s finalized=%s", safe, finalized)
	}
}

func TestBridgeProgressDetectsLagAndStall(t *testing.T) {
	if got := bridgeProgressError(true, 20, 10, 10, 5, time.Now(), 30*time.Second); got == "" {
		t.Fatal("expected excessive lag error")
	}
	if got := bridgeProgressError(true, 11, 10, 10, 5, time.Now().Add(-time.Minute), 30*time.Second); got == "" {
		t.Fatal("expected stalled bridge error")
	}
}

func TestRejectRemovesPendingTransaction(t *testing.T) {
	tp := NewTxPool()
	raw := testTransactionBytes(t, 9)
	hash, _ := transactionHash(raw)
	if err := tp.AddTxs(12, [][]byte{raw}); err != nil {
		t.Fatal(err)
	}
	tp.Reject(raw, fmt.Errorf("insufficient funds"))
	if len(tp.GetTxs(12)) != 0 {
		t.Fatal("rejected transaction remains pending")
	}
	status, ok := tp.GetDelivery(hash)
	if !ok || status.Status != DeliveryRejected {
		t.Fatalf("rejected status = %+v, found=%v", status, ok)
	}
}

func TestTerminalInjectionError(t *testing.T) {
	if !terminalInjectionError(fmt.Errorf("JSON-RPC error: insufficient funds for gas * price + value")) {
		t.Fatal("expected insufficient funds to be terminal")
	}
	if terminalInjectionError(fmt.Errorf("connection reset by peer")) {
		t.Fatal("expected transport error to be retryable")
	}
}
