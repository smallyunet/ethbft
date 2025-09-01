package types

import (
	"encoding/json"
	"fmt"
	"math/big"
)

// Block represents an Ethereum block
type Block struct {
	Number           *big.Int      `json:"number"`
	Hash             string        `json:"hash"`
	ParentHash       string        `json:"parentHash"`
	Nonce            string        `json:"nonce"`
	Sha3Uncles       string        `json:"sha3Uncles"`
	LogsBloom        string        `json:"logsBloom"`
	TransactionsRoot string        `json:"transactionsRoot"`
	StateRoot        string        `json:"stateRoot"`
	ReceiptsRoot     string        `json:"receiptsRoot"`
	Miner            string        `json:"miner"`
	Difficulty       *big.Int      `json:"difficulty"`
	TotalDifficulty  *big.Int      `json:"totalDifficulty"`
	ExtraData        string        `json:"extraData"`
	Size             *big.Int      `json:"size"`
	GasLimit         *big.Int      `json:"gasLimit"`
	GasUsed          *big.Int      `json:"gasUsed"`
	Timestamp        *big.Int      `json:"timestamp"`
	Transactions     []Transaction `json:"transactions"`
	Uncles           []string      `json:"uncles"`
	BaseFeePerGas    *big.Int      `json:"baseFeePerGas"`
}

// Transaction represents an Ethereum transaction
type Transaction struct {
	Hash             string   `json:"hash"`
	Nonce            *big.Int `json:"nonce"`
	BlockHash        string   `json:"blockHash"`
	BlockNumber      *big.Int `json:"blockNumber"`
	TransactionIndex *big.Int `json:"transactionIndex"`
	From             string   `json:"from"`
	To               string   `json:"to"`
	Value            *big.Int `json:"value"`
	GasPrice         *big.Int `json:"gasPrice"`
	Gas              *big.Int `json:"gas"`
	Input            string   `json:"input"`
	V                *big.Int `json:"v"`
	R                *big.Int `json:"r"`
	S                *big.Int `json:"s"`
}

// MarshalJSON customizes JSON marshaling for big.Int
func (b *Block) MarshalJSON() ([]byte, error) {
	type Alias Block
	return json.Marshal(&struct {
		Number          string `json:"number"`
		Difficulty      string `json:"difficulty"`
		TotalDifficulty string `json:"totalDifficulty"`
		Size            string `json:"size"`
		GasLimit        string `json:"gasLimit"`
		GasUsed         string `json:"gasUsed"`
		Timestamp       string `json:"timestamp"`
		BaseFeePerGas   string `json:"baseFeePerGas,omitempty"`
		*Alias
	}{
		Number:          b.Number.String(),
		Difficulty:      b.Difficulty.String(),
		TotalDifficulty: b.TotalDifficulty.String(),
		Size:            b.Size.String(),
		GasLimit:        b.GasLimit.String(),
		GasUsed:         b.GasUsed.String(),
		Timestamp:       b.Timestamp.String(),
		BaseFeePerGas:   b.BaseFeePerGas.String(),
		Alias:           (*Alias)(b),
	})
}

// UnmarshalJSON customizes JSON unmarshaling for Block
func (b *Block) UnmarshalJSON(data []byte) error {
	type Alias Block
	aux := &struct {
		Number          interface{} `json:"number"`
		Difficulty      interface{} `json:"difficulty"`
		TotalDifficulty interface{} `json:"totalDifficulty"`
		Size            interface{} `json:"size"`
		GasLimit        interface{} `json:"gasLimit"`
		GasUsed         interface{} `json:"gasUsed"`
		Timestamp       interface{} `json:"timestamp"`
		BaseFeePerGas   interface{} `json:"baseFeePerGas"`
		*Alias
	}{
		Alias: (*Alias)(b),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Helper function to convert interface{} to *big.Int
	fromInterface := func(v interface{}) (*big.Int, error) {
		switch val := v.(type) {
		case string:
			if len(val) >= 2 && val[0:2] == "0x" {
				// Convert hex string to big.Int
				n := new(big.Int)
				n, ok := n.SetString(val[2:], 16)
				if !ok {
					return nil, json.Unmarshal([]byte(`"`+val+`"`), &n)
				}
				return n, nil
			}
			// Regular string to big.Int
			n := new(big.Int)
			n, ok := n.SetString(val, 10)
			if !ok {
				return nil, json.Unmarshal([]byte(`"`+val+`"`), &n)
			}
			return n, nil
		case float64:
			return big.NewInt(int64(val)), nil
		case nil:
			return big.NewInt(0), nil
		default:
			return nil, json.Unmarshal([]byte(fmt.Sprintf("%v", val)), new(big.Int))
		}
	}

	var err error

	if b.Number, err = fromInterface(aux.Number); err != nil {
		return err
	}

	if b.Difficulty, err = fromInterface(aux.Difficulty); err != nil {
		return err
	}

	if b.TotalDifficulty, err = fromInterface(aux.TotalDifficulty); err != nil {
		return err
	}

	if b.Size, err = fromInterface(aux.Size); err != nil {
		return err
	}

	if b.GasLimit, err = fromInterface(aux.GasLimit); err != nil {
		return err
	}

	if b.GasUsed, err = fromInterface(aux.GasUsed); err != nil {
		return err
	}

	if b.Timestamp, err = fromInterface(aux.Timestamp); err != nil {
		return err
	}

	if aux.BaseFeePerGas != nil {
		if b.BaseFeePerGas, err = fromInterface(aux.BaseFeePerGas); err != nil {
			return err
		}
	}

	return nil
}

// TxResults represents results from CometBFT transaction processing
type TxResults struct {
	Height int64    `json:"height"`
	TxHash string   `json:"tx_hash"`
	Result TxResult `json:"result"`
}

// TxResult represents a result from a single transaction
type TxResult struct {
	Code      uint32 `json:"code"`
	Data      []byte `json:"data"`
	Log       string `json:"log"`
	GasUsed   int64  `json:"gas_used"`
	GasWanted int64  `json:"gas_wanted"`
}

// UnmarshalJSON customizes JSON unmarshaling for Transaction
func (t *Transaction) UnmarshalJSON(data []byte) error {
	type Alias Transaction
	aux := &struct {
		Nonce            interface{} `json:"nonce"`
		BlockNumber      interface{} `json:"blockNumber"`
		TransactionIndex interface{} `json:"transactionIndex"`
		Value            interface{} `json:"value"`
		GasPrice         interface{} `json:"gasPrice"`
		Gas              interface{} `json:"gas"`
		V                interface{} `json:"v"`
		R                interface{} `json:"r"`
		S                interface{} `json:"s"`
		*Alias
	}{
		Alias: (*Alias)(t),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Helper function to convert interface{} to *big.Int
	fromInterface := func(v interface{}) (*big.Int, error) {
		switch val := v.(type) {
		case string:
			if len(val) >= 2 && val[0:2] == "0x" {
				// Convert hex string to big.Int
				n := new(big.Int)
				n, ok := n.SetString(val[2:], 16)
				if !ok {
					return nil, json.Unmarshal([]byte(`"`+val+`"`), &n)
				}
				return n, nil
			}
			// Regular string to big.Int
			n := new(big.Int)
			n, ok := n.SetString(val, 10)
			if !ok {
				return nil, json.Unmarshal([]byte(`"`+val+`"`), &n)
			}
			return n, nil
		case float64:
			return big.NewInt(int64(val)), nil
		case nil:
			return big.NewInt(0), nil
		default:
			return nil, json.Unmarshal([]byte(fmt.Sprintf("%v", val)), new(big.Int))
		}
	}

	var err error

	if t.Nonce, err = fromInterface(aux.Nonce); err != nil {
		return err
	}

	if aux.BlockNumber != nil {
		if t.BlockNumber, err = fromInterface(aux.BlockNumber); err != nil {
			return err
		}
	}

	if aux.TransactionIndex != nil {
		if t.TransactionIndex, err = fromInterface(aux.TransactionIndex); err != nil {
			return err
		}
	}

	if t.Value, err = fromInterface(aux.Value); err != nil {
		return err
	}

	if t.GasPrice, err = fromInterface(aux.GasPrice); err != nil {
		return err
	}

	if t.Gas, err = fromInterface(aux.Gas); err != nil {
		return err
	}

	if aux.V != nil {
		if t.V, err = fromInterface(aux.V); err != nil {
			return err
		}
	}

	if aux.R != nil {
		if t.R, err = fromInterface(aux.R); err != nil {
			return err
		}
	}

	if aux.S != nil {
		if t.S, err = fromInterface(aux.S); err != nil {
			return err
		}
	}

	return nil
}

// ConsensusData represents data used to bridge between Ethereum and CometBFT
type ConsensusData struct {
	BlockHash       string `json:"block_hash"`
	BlockNumber     int64  `json:"block_number"`
	ParentHash      string `json:"parent_hash"`
	StateRoot       string `json:"state_root"`
	ReceiptsRoot    string `json:"receipts_root"`
	TransactionRoot string `json:"transaction_root"`
	Timestamp       int64  `json:"timestamp"`
}
