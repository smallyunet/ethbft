package bridge

import (
	"context"
	"math/big"
	"testing"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

func TestCheckTx(t *testing.T) {
	// Setup
	chainID := big.NewInt(1337)
	b := &Bridge{
		chainID: chainID,
	}
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
}
