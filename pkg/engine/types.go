package engine

import (
	"context"
	"encoding/json"
)

// ABCIClient defines the interface to communicate with ABCI application
type ABCIClient interface {
	GetPendingPayload(ctx context.Context) (*ExecutionPayload, error)
	ExecutePayload(ctx context.Context, payload *ExecutionPayload) error
	UpdateForkchoice(ctx context.Context, state *ForkchoiceState) error
	GetLatestBlock(ctx context.Context) (height int64, hash string, err error)
}

// ExecutionPayload represents an execution payload
type ExecutionPayload struct {
	ParentHash    string   `json:"parentHash"`
	FeeRecipient  string   `json:"feeRecipient"`
	StateRoot     string   `json:"stateRoot"`
	ReceiptsRoot  string   `json:"receiptsRoot"`
	LogsBloom     string   `json:"logsBloom"`
	PrevRandao    string   `json:"prevRandao"`
	BlockNumber   string   `json:"blockNumber"`
	GasLimit      string   `json:"gasLimit"`
	GasUsed       string   `json:"gasUsed"`
	Timestamp     string   `json:"timestamp"`
	ExtraData     string   `json:"extraData"`
	BaseFeePerGas string   `json:"baseFeePerGas"`
	BlockHash     string   `json:"blockHash"`
	Transactions  []string `json:"transactions"`
}

// ForkchoiceState represents the forkchoice state
type ForkchoiceState struct {
	HeadBlockHash      string `json:"headBlockHash"`
	SafeBlockHash      string `json:"safeBlockHash"`
	FinalizedBlockHash string `json:"finalizedBlockHash"`
}

// PayloadAttributes represents payload building attributes
type PayloadAttributes struct {
	Timestamp             string   `json:"timestamp"`
	PrevRandao            string   `json:"prevRandao"`
	SuggestedFeeRecipient string   `json:"suggestedFeeRecipient"`
	Withdrawals           []string `json:"withdrawals,omitempty"`
}

// PayloadStatus represents the payload execution status
type PayloadStatus struct {
	Status          string  `json:"status"`          // VALID, INVALID, SYNCING, ACCEPTED
	LatestValidHash *string `json:"latestValidHash"` // Hash of the most recent valid block
	ValidationError *string `json:"validationError"` // Error message if invalid
}

// ForkchoiceUpdatedResponse represents the response to forkchoice update
type ForkchoiceUpdatedResponse struct {
	PayloadStatus PayloadStatus `json:"payloadStatus"`
	PayloadId     *string       `json:"payloadId"` // Identifier of the payload build process
}

// TransitionConfiguration represents the transition configuration
type TransitionConfiguration struct {
	TerminalTotalDifficulty string `json:"terminalTotalDifficulty"`
	TerminalBlockHash       string `json:"terminalBlockHash"`
	TerminalBlockNumber     string `json:"terminalBlockNumber"`
}

// JSON-RPC types
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

type jsonRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Beacon API types
type BeaconHeader struct {
	Slot          string `json:"slot"`
	ProposerIndex string `json:"proposer_index"`
	ParentRoot    string `json:"parent_root"`
	StateRoot     string `json:"state_root"`
	BodyRoot      string `json:"body_root"`
}

type BeaconBlockHeader struct {
	Beacon BeaconHeader `json:"beacon"`
}

type BeaconBlockResponse struct {
	Data BeaconBlockHeader `json:"data"`
}

type BeaconHeadResponse struct {
	Data struct {
		ExecutionOptimistic bool         `json:"execution_optimistic"`
		Finalized           bool         `json:"finalized"`
		Header              BeaconHeader `json:"header"`
	} `json:"data"`
}

type BeaconStateResponse struct {
	Data struct {
		GenesisValidatorsRoot string `json:"genesis_validators_root"`
		GenesisTime           string `json:"genesis_time"`
		GenesisForkVersion    string `json:"genesis_fork_version"`
		CurrentForkVersion    string `json:"current_fork_version"`
		Slot                  string `json:"slot"`
		Epoch                 string `json:"epoch"`
		FinalizedCheckpoint   struct {
			Epoch string `json:"epoch"`
			Root  string `json:"root"`
		} `json:"finalized_checkpoint"`
		CurrentJustifiedCheckpoint struct {
			Epoch string `json:"epoch"`
			Root  string `json:"root"`
		} `json:"current_justified_checkpoint"`
		PreviousJustifiedCheckpoint struct {
			Epoch string `json:"epoch"`
			Root  string `json:"root"`
		} `json:"previous_justified_checkpoint"`
	} `json:"data"`
}

type BeaconForkResponse struct {
	Data struct {
		PreviousVersion string `json:"previous_version"`
		CurrentVersion  string `json:"current_version"`
		Epoch           string `json:"epoch"`
	} `json:"data"`
}

type BeaconLightClientBootstrapResponse struct {
	Data struct {
		Header BeaconBlockHeader `json:"header"`
	} `json:"data"`
}
