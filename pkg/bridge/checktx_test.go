package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/smallyunet/ethbft/pkg/protocol"
)

func TestCheckTxAdmissionRules(t *testing.T) {
	b := newTestBridge(t, func(context.Context, string, interface{}) (json.RawMessage, error) {
		return nil, fmt.Errorf("unexpected engine call")
	})
	app := NewABCIApplication(b)
	valid := signedTransactionBytes(t, 0)
	response, err := app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: valid})
	if err != nil || response.Code != abcitypes.CodeTypeOK {
		t.Fatalf("valid transaction rejected: response=%+v error=%v", response, err)
	}

	response, _ = app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: []byte("invalid")})
	if response.Code == abcitypes.CodeTypeOK {
		t.Fatal("invalid encoding accepted")
	}
	response, _ = app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: append(append([]byte(nil), protocol.EnvelopePrefix...), 1)})
	if response.Code != 6 {
		t.Fatalf("reserved envelope returned code %d", response.Code)
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := types.NewTx(&types.LegacyTx{GasPrice: big.NewInt(1), Gas: 21_000, To: &common.Address{1}})
	wrongChain, err := types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(9999)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := wrongChain.MarshalBinary()
	response, _ = app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: raw})
	if response.Code != 3 {
		t.Fatalf("wrong-chain transaction returned code %d", response.Code)
	}
}

func TestABCIExecutionProposalLifecycle(t *testing.T) {
	b := newTestBridge(t, func(_ context.Context, method string, _ interface{}) (json.RawMessage, error) {
		switch method {
		case "engine_newPayloadV2":
			return json.RawMessage(`{"status":"VALID"}`), nil
		case "engine_forkchoiceUpdatedV2":
			return json.RawMessage(`{"payloadStatus":{"status":"VALID"},"payloadId":null}`), nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	})
	app := NewABCIApplication(b)
	proposalTime := time.Unix(1_800_000_000, 0).UTC()
	proposal, payload := testProposal(t, b, 1, proposalTime, [][]byte{signedTransactionBytes(t, 0)})

	processed, err := app.ProcessProposal(context.Background(), &abcitypes.RequestProcessProposal{Height: 1, Time: proposalTime, Txs: proposal})
	if err != nil || processed.Status != abcitypes.ResponseProcessProposal_ACCEPT {
		t.Fatalf("proposal not accepted: response=%+v error=%v", processed, err)
	}

	finalized, err := app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{Height: 1, Time: proposalTime, Txs: proposal})
	if err != nil || len(finalized.AppHash) != common.HashLength {
		t.Fatalf("proposal not finalized: response=%+v error=%v", finalized, err)
	}
	info, _ := app.Info(context.Background(), &abcitypes.RequestInfo{})
	if info.LastBlockHeight != 0 {
		t.Fatal("finalized proposal became committed before Commit")
	}
	if _, err := app.Commit(context.Background(), &abcitypes.RequestCommit{}); err != nil {
		t.Fatal(err)
	}
	info, _ = app.Info(context.Background(), &abcitypes.RequestInfo{})
	if info.LastBlockHeight != 1 || info.LastBlockAppHash == nil || b.getHeightHash(1) != payload.BlockHash {
		t.Fatalf("committed info mismatch: %+v", info)
	}
}

func TestCommitRollsBackWhenPersistenceFails(t *testing.T) {
	b := newTestBridge(t, func(_ context.Context, method string, _ interface{}) (json.RawMessage, error) {
		switch method {
		case "engine_newPayloadV2":
			return json.RawMessage(`{"status":"VALID"}`), nil
		case "engine_forkchoiceUpdatedV2":
			return json.RawMessage(`{"payloadStatus":{"status":"VALID"},"payloadId":null}`), nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	})
	app := NewABCIApplication(b)
	proposalTime := time.Unix(1_800_000_000, 0).UTC()
	proposal, _ := testProposal(t, b, 1, proposalTime, [][]byte{signedTransactionBytes(t, 0)})
	if _, err := app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{Height: 1, Time: proposalTime, Txs: proposal}); err != nil {
		t.Fatal(err)
	}
	b.config.Bridge.StateFile = t.TempDir()
	if _, err := app.Commit(context.Background(), &abcitypes.RequestCommit{}); err == nil {
		t.Fatal("expected persistence failure")
	}
	if b.abciLastBlockHeight.Load() != 0 || len(b.appHash()) != 0 || b.getHeightHash(1) != (common.Hash{}) {
		t.Fatal("failed commit was not rolled back")
	}
}
