package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	gethengine "github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/smallyunet/ethbft/pkg/config"
	"github.com/smallyunet/ethbft/pkg/protocol"
)

type mockExecutionClient struct {
	chainID *big.Int
	call    func(context.Context, string, interface{}) (json.RawMessage, error)
}

func (m *mockExecutionClient) Call(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	return m.call(ctx, method, params)
}

func (m *mockExecutionClient) GetChainID(context.Context) (*big.Int, error) {
	return new(big.Int).Set(m.chainID), nil
}

func newTestBridge(t *testing.T, call func(context.Context, string, interface{}) (json.RawMessage, error)) *Bridge {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Bridge.StateFile = filepath.Join(t.TempDir(), "state.json")
	ctx, cancel := context.WithCancel(context.Background())
	b := &Bridge{
		config:       cfg,
		ethClient:    &mockExecutionClient{chainID: big.NewInt(1337), call: call},
		txPool:       NewTxPool(),
		chainID:      big.NewInt(1337),
		ctx:          ctx,
		cancel:       cancel,
		heightToHash: make(map[int64]common.Hash),
		heightOrder:  make([]int64, 0),
		maxHistory:   16,
		elGenesis:    common.HexToHash("0x100"),
		logger:       slog.Default(),
		tsCache:      make(map[common.Hash]uint64),
	}
	t.Cleanup(cancel)
	return b
}

func signedTransactionBytes(t *testing.T, nonce uint64) []byte {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		GasPrice: big.NewInt(1),
		Gas:      21_000,
		To:       &common.Address{1},
		Value:    big.NewInt(0),
	})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(1337)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testExecutionPayload(t *testing.T, parent common.Hash, timestamp uint64, random common.Hash, txs [][]byte) *ExecutionPayload {
	t.Helper()
	payload := &ExecutionPayload{
		ParentHash:    parent,
		FeeRecipient:  common.Address{},
		StateRoot:     common.HexToHash("0x200"),
		ReceiptsRoot:  common.HexToHash("0x300"),
		LogsBloom:     make([]byte, types.BloomByteLength),
		Random:        random,
		Number:        1,
		GasLimit:      30_000_000,
		GasUsed:       21_000 * uint64(len(txs)),
		Timestamp:     timestamp,
		ExtraData:     []byte("ethbft"),
		BaseFeePerGas: big.NewInt(1),
		Transactions:  cloneRawTransactions(txs),
		Withdrawals:   []*types.Withdrawal{},
	}
	block, err := gethengine.ExecutableDataToBlockNoHash(*payload, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload.BlockHash = block.Hash()
	return payload
}

func testProposal(t *testing.T, b *Bridge, height int64, proposalTime time.Time, txs [][]byte) ([][]byte, *ExecutionPayload) {
	t.Helper()
	payload := testExecutionPayload(t, b.committedExecutionParent(height), uint64(proposalTime.Unix()), b.proposalRandao(height), txs)
	metadata, err := protocol.NewExecutionMetadataV1(b.chainID, height, b.appHash(), payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := protocol.EncodeEnvelope(metadata)
	if err != nil {
		t.Fatal(err)
	}
	proposal := [][]byte{envelope}
	proposal = append(proposal, cloneRawTransactions(txs)...)
	return proposal, payload
}

func TestHeightCacheSetGet(t *testing.T) {
	b := &Bridge{heightToHash: make(map[int64]common.Hash), heightOrder: make([]int64, 0), maxHistory: 4}
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
	b.heightMu.RLock()
	defer b.heightMu.RUnlock()
	if len(b.heightOrder) > b.maxHistory || len(b.heightToHash) > b.maxHistory {
		t.Fatalf("height history exceeded limit: order=%d map=%d", len(b.heightOrder), len(b.heightToHash))
	}
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
		{name: "disabled", enabled: false, cometHeight: 10},
		{name: "waiting", enabled: true},
		{name: "no execution progress", enabled: true, cometHeight: 10, wantError: true},
		{name: "healthy", enabled: true, cometHeight: 10, bridgeHeight: 9, ethereumHeight: 9},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := bridgeProgressError(test.enabled, test.cometHeight, test.bridgeHeight, test.ethereumHeight, 5, time.Now(), 30*time.Second)
			if (got != "") != test.wantError {
				t.Fatalf("bridgeProgressError() = %q, want error %v", got, test.wantError)
			}
		})
	}
}

func TestLoadStateRestoresExecutionConsensusState(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state.json")
	state := persistedBridgeState{
		Version:             persistedStateVersion,
		ProtocolVersion:     protocol.VersionV1,
		ChainID:             "1337",
		ELGenesis:           common.HexToHash("0x100"),
		LastProducedHeight:  42,
		HeightToHash:        map[int64]common.Hash{42: common.HexToHash("0x42")},
		ABCILastBlockHeight: 42,
		ABCILastAppHash:     common.HexToHash("0xaa").Bytes(),
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	b := &Bridge{
		config:    config.DefaultConfig(),
		logger:    slog.Default(),
		txPool:    NewTxPool(),
		chainID:   big.NewInt(1337),
		elGenesis: common.HexToHash("0x100"),
	}
	b.config.Bridge.StateFile = stateFile
	if err := b.loadState(); err != nil {
		t.Fatal(err)
	}
	if b.lastProducedHeight.Load() != 42 || b.abciLastBlockHeight.Load() != 42 {
		t.Fatalf("state heights not restored")
	}
}

func TestLoadStateRejectsLegacyProtocol(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(stateFile, []byte(`{"version":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	b := &Bridge{config: config.DefaultConfig(), logger: slog.Default(), txPool: NewTxPool()}
	b.config.Bridge.StateFile = stateFile
	if err := b.loadState(); err == nil {
		t.Fatal("expected legacy state to be rejected")
	}
}

func TestValidateExecutionProposalChecksPayloadAndEL(t *testing.T) {
	var validated bool
	b := newTestBridge(t, func(_ context.Context, method string, _ interface{}) (json.RawMessage, error) {
		if method != "engine_newPayloadV2" {
			return nil, fmt.Errorf("unexpected method %s", method)
		}
		validated = true
		return json.RawMessage(`{"status":"VALID"}`), nil
	})
	proposalTime := time.Unix(1_800_000_000, 0).UTC()
	proposal, payload := testProposal(t, b, 1, proposalTime, [][]byte{signedTransactionBytes(t, 0)})
	got, err := b.validateExecutionProposal(context.Background(), 1, proposalTime, proposal)
	if err != nil {
		t.Fatal(err)
	}
	if !validated || got.BlockHash != payload.BlockHash {
		t.Fatalf("payload validation did not complete")
	}
	proposal[1][len(proposal[1])-1] ^= 1
	if _, err := b.validateExecutionProposal(context.Background(), 1, proposalTime, proposal); err == nil {
		t.Fatal("expected tampered transaction to be rejected")
	}
}

func TestBuildExecutionProposalUsesPayloadOrder(t *testing.T) {
	proposalTime := time.Unix(1_800_000_000, 0).UTC()
	first := signedTransactionBytes(t, 0)
	second := signedTransactionBytes(t, 1)
	var b *Bridge
	b = newTestBridge(t, func(_ context.Context, method string, _ interface{}) (json.RawMessage, error) {
		switch method {
		case "eth_getBlockByHash":
			return json.RawMessage(`{"timestamp":"0x0"}`), nil
		case "eth_sendRawTransaction":
			return json.RawMessage(`"0x01"`), nil
		case "engine_forkchoiceUpdatedV2":
			return json.RawMessage(`{"payloadStatus":{"status":"VALID"},"payloadId":"0x0102030405060708"}`), nil
		case "engine_getPayloadV2":
			payload := testExecutionPayload(t, b.elGenesis, uint64(proposalTime.Unix()), b.proposalRandao(1), [][]byte{second, first})
			encoded, err := json.Marshal(map[string]interface{}{"executionPayload": payload})
			if err != nil {
				t.Fatal(err)
			}
			return encoded, nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	})
	proposal, err := b.buildExecutionProposal(1, proposalTime, [][]byte{first, second}, 1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(proposal) != 3 || !bytes.Equal(proposal[1], second) || !bytes.Equal(proposal[2], first) {
		t.Fatal("proposal did not preserve the EL payload transaction order")
	}
	metadata, err := protocol.DecodeEnvelope(proposal[0])
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ParentHash != b.elGenesis || metadata.Timestamp != uint64(proposalTime.Unix()) {
		t.Fatalf("unexpected proposal metadata: %+v", metadata)
	}
}

func TestPrepareProposalBuildFailureLetsConsensusChangeProposer(t *testing.T) {
	b := newTestBridge(t, func(_ context.Context, method string, _ interface{}) (json.RawMessage, error) {
		return nil, fmt.Errorf("execution client unavailable during %s", method)
	})
	app := &ABCIApplication{bridge: b, logger: slog.Default()}
	response, err := app.PrepareProposal(context.Background(), &abcitypes.RequestPrepareProposal{
		Height:     1,
		Time:       time.Unix(1_800_000_000, 0).UTC(),
		MaxTxBytes: 1_000_000,
	})
	if err != nil {
		t.Fatalf("PrepareProposal terminated ABCI on a local EL failure: %v", err)
	}
	if response == nil || len(response.Txs) != 0 {
		t.Fatalf("failed proposer response = %+v, want an empty rejectable proposal", response)
	}
}

func TestFourValidatorsAgreeOnExecutionCommitment(t *testing.T) {
	validatorCall := func(_ context.Context, method string, _ interface{}) (json.RawMessage, error) {
		if method != "engine_newPayloadV2" {
			return nil, fmt.Errorf("unexpected method %s", method)
		}
		return json.RawMessage(`{"status":"VALID"}`), nil
	}
	validators := make([]*Bridge, 4)
	for i := range validators {
		validators[i] = newTestBridge(t, validatorCall)
	}
	proposalTime := time.Unix(1_800_000_000, 0).UTC()
	proposal, _ := testProposal(t, validators[0], 1, proposalTime, [][]byte{signedTransactionBytes(t, 0)})
	var expected []byte
	for i, validator := range validators {
		payload, err := validator.validateExecutionProposal(context.Background(), 1, proposalTime, proposal)
		if err != nil {
			t.Fatalf("validator %d rejected proposal: %v", i, err)
		}
		commitment, err := validator.executionAppHash(1, payload)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			expected = commitment
		} else if !bytes.Equal(commitment, expected) {
			t.Fatalf("validator %d derived a different app hash", i)
		}
	}
}

func TestCommitPendingExecutionPersistsBFTResult(t *testing.T) {
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
	proposalTime := time.Unix(1_800_000_000, 0).UTC()
	tx := signedTransactionBytes(t, 0)
	proposal, payload := testProposal(t, b, 1, proposalTime, [][]byte{tx})
	pending, err := b.stageExecutionCommit(1, proposalTime, proposal)
	if err != nil {
		t.Fatal(err)
	}
	if b.abciLastBlockHeight.Load() != 0 {
		t.Fatal("FinalizeBlock stage became visible before Commit")
	}
	if err := b.commitPendingExecution(); err != nil {
		t.Fatal(err)
	}
	if b.abciLastBlockHeight.Load() != 1 || b.getHeightHash(1) != payload.BlockHash {
		t.Fatal("committed execution state not applied")
	}
	if !bytes.Equal(b.appHash(), pending.appHash) {
		t.Fatal("committed app hash mismatch")
	}
	hash, _ := transactionHash(tx)
	delivery, ok := b.txPool.GetDelivery(hash)
	if !ok || delivery.Status != DeliveryIncluded || delivery.ELBlockHash != payload.BlockHash {
		t.Fatalf("transaction commitment = %+v, found=%v", delivery, ok)
	}
}

func TestTxPoolDeliveryLifecycle(t *testing.T) {
	tp := NewTxPool()
	raw := signedTransactionBytes(t, 1)
	hash, _ := transactionHash(raw)
	if err := tp.AddTxs(7, [][]byte{raw}); err != nil {
		t.Fatal(err)
	}
	tp.CompleteHeight(7, common.HexToHash("0xbeef"))
	if status, ok := tp.GetDelivery(hash); !ok || status.Status != DeliveryIncluded {
		t.Fatalf("included status = %+v, found=%v", status, ok)
	}
}
