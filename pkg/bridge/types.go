package bridge

// ExecutionPayload represents an Ethereum execution payload for Engine API
type ExecutionPayload struct {
	ParentHash            string   `json:"parentHash"`
	FeeRecipient          string   `json:"feeRecipient"`
	StateRoot             string   `json:"stateRoot"`
	ReceiptsRoot          string   `json:"receiptsRoot"`
	LogsBloom             string   `json:"logsBloom"`
	PrevRandao            string   `json:"prevRandao"`
	BlockNumber           string   `json:"blockNumber"`
	GasLimit              string   `json:"gasLimit"`
	GasUsed               string   `json:"gasUsed"`
	Timestamp             string   `json:"timestamp"`
	ExtraData             string   `json:"extraData"`
	BaseFeePerGas         string   `json:"baseFeePerGas"`
	BlockHash             string   `json:"blockHash"`
	Transactions          []string `json:"transactions"`
	Withdrawals           []string `json:"withdrawals"`
	BlobGasUsed           string   `json:"blobGasUsed"`
	ExcessBlobGas         string   `json:"excessBlobGas"`
	ParentBeaconBlockRoot string   `json:"parentBeaconBlockRoot"`
}

// ForkchoiceState represents the fork choice state for Engine API
type ForkchoiceState struct {
	HeadBlockHash      string `json:"headBlockHash"`
	SafeBlockHash      string `json:"safeBlockHash"`
	FinalizedBlockHash string `json:"finalizedBlockHash"`
}
