package bridge

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
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
			got := bridgeProgressError(tt.enabled, tt.cometHeight, tt.bridgeHeight, tt.ethereumHeight)
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
	}
	b.config.Bridge.StateFile = stateFile
	b.loadState()

	if got := b.lastProducedHeight.Load(); got != 42 {
		t.Fatalf("resume height = %d, want 42", got)
	}
	if !b.statePersisted.Load() {
		t.Fatal("loaded state should be marked persisted")
	}
}
