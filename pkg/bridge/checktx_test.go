package bridge

import (
	"context"
	"math/big"
	"path/filepath"
	"testing"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/smallyunet/ethbft/pkg/config"
)

func TestCheckTx(t *testing.T) {
	// Setup
	chainID := big.NewInt(1337)
	b := &Bridge{
		chainID: chainID,
		config:  &config.Config{},
		txPool:  NewTxPool(),
	}
	b.config.Bridge.StateFile = filepath.Join(t.TempDir(), "state.json")
	app := NewABCIApplication(b)

	// Helper to create signed tx
	key, _ := crypto.GenerateKey()

	createTx := func(nonce uint64, cid *big.Int, sign bool) []byte {
		txData := &types.LegacyTx{
			Nonce:    nonce,
			GasPrice: big.NewInt(100),
			Gas:      21000,
			To:       &common.Address{},
			Value:    big.NewInt(1),
			Data:     nil,
		}
		tx := types.NewTx(txData)
		if sign {
			signer := types.LatestSignerForChainID(cid)
			var err error
			tx, err = types.SignTx(tx, signer, key)
			if err != nil {
				t.Fatalf("failed to sign tx: %v", err)
			}
		}
		out, _ := rlp.EncodeToBytes(tx)
		return out
	}

	t.Run("Valid Transaction", func(t *testing.T) {
		txBytes := createTx(0, chainID, true)
		resp, _ := app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: txBytes})
		if resp.Code != abcitypes.CodeTypeOK {
			t.Fatalf("expected OK, got code %d log %s", resp.Code, resp.Log)
		}
	})

	t.Run("Invalid ChainID", func(t *testing.T) {
		txBytes := createTx(1, big.NewInt(9999), true)
		resp, _ := app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: txBytes})
		if resp.Code != 3 { // Code 3 is wrong chainID
			t.Fatalf("expected code 3, got code %d log %s", resp.Code, resp.Log)
		}
	})

	t.Run("Invalid RLP", func(t *testing.T) {
		txBytes := []byte("invalid-garbage")
		resp, _ := app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: txBytes})
		if resp.Code != 2 { // Code 2 is invalid rlp
			t.Fatalf("expected code 2, got code %d log %s", resp.Code, resp.Log)
		}
	})

	t.Run("ProcessProposal Rejects Invalid Transaction", func(t *testing.T) {
		resp, _ := app.ProcessProposal(context.Background(), &abcitypes.RequestProcessProposal{Txs: [][]byte{[]byte("invalid")}})
		if resp.Status != abcitypes.ResponseProcessProposal_REJECT {
			t.Fatalf("expected rejected proposal, got %v", resp.Status)
		}
	})

	t.Run("Finalize Persists Accepted Delivery And App State", func(t *testing.T) {
		txBytes := createTx(2, chainID, true)
		resp, err := app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{Height: 1, Txs: [][]byte{txBytes}})
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.AppHash) == 0 {
			t.Fatal("expected deterministic app hash")
		}
		hash, _ := transactionHash(txBytes)
		status, ok := b.txPool.GetDelivery(hash)
		if !ok || status.Status != DeliveryAccepted {
			t.Fatalf("delivery status = %+v, found=%v", status, ok)
		}
		info, err := app.Info(context.Background(), &abcitypes.RequestInfo{})
		if err != nil || info.LastBlockHeight != 1 || len(info.LastBlockAppHash) == 0 {
			t.Fatalf("info = %+v, err=%v", info, err)
		}
	})

	t.Run("Finalize Rolls Back Delivery When Persistence Fails", func(t *testing.T) {
		previousHeight := b.abciLastBlockHeight.Load()
		previousHash := b.appHash()
		previousPending, previousDeliveries := b.txPool.Snapshot()
		b.config.Bridge.StateFile = t.TempDir() // Renaming a state file over a directory must fail.
		txBytes := createTx(3, chainID, true)
		if _, err := app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{Height: 2, Txs: [][]byte{txBytes}}); err == nil {
			t.Fatal("expected persistence failure")
		}
		if got := b.abciLastBlockHeight.Load(); got != previousHeight {
			t.Fatalf("ABCI height = %d, want rollback to %d", got, previousHeight)
		}
		if got := b.appHash(); string(got) != string(previousHash) {
			t.Fatalf("app hash was not rolled back")
		}
		pending, deliveries := b.txPool.Snapshot()
		if len(pending) != len(previousPending) || len(deliveries) != len(previousDeliveries) {
			t.Fatalf("delivery queue was not rolled back: pending=%d deliveries=%d", len(pending), len(deliveries))
		}
		hash, _ := transactionHash(txBytes)
		if _, ok := b.txPool.GetDelivery(hash); ok {
			t.Fatal("uncommitted transaction remains in delivery queue")
		}
	})
}
