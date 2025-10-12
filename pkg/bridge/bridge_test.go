package bridge
package bridge

import (
    "sync"
    "testing"

    "github.com/ethereum/go-ethereum/common"
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

func TestPseudoHashDeterminism(t *testing.T) {
    parent := common.HexToHash("0x1234")
    comet := common.HexToHash("0x5678")
    h1 := pseudoHash(10, parent, 3, comet)
    h2 := pseudoHash(10, parent, 3, comet)
    if h1 != h2 {
        t.Fatalf("pseudoHash not deterministic: %s vs %s", h1.Hex(), h2.Hex())
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
