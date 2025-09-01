package ethereum

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/smallyunet/ethbft/pkg/config"
	"github.com/smallyunet/ethbft/pkg/types"
)

// Client represents an Ethereum execution client adapter
type Client struct {
	config          *config.Config
	httpClient      *http.Client
	engineAPIClient *http.Client // Dedicated client for Engine API
	jwtSecret       string       // JWT secret key
}

// NewClient creates a new Ethereum client
func NewClient(cfg *config.Config) (*Client, error) {
	// Add HTTP client timeout settings
	httpClient := &http.Client{
		Timeout: 10 * time.Second, // Set 10 second timeout
	}

	// Create a dedicated HTTP client for Engine API
	engineAPIClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Validate Ethereum endpoint format
	if cfg.Ethereum.Endpoint == "" {
		return nil, fmt.Errorf("Ethereum endpoint cannot be empty")
	}

	// Read JWT secret file
	var jwtSecret string
	if cfg.Ethereum.JWTSecret != "" {
		jwtBytes, err := os.ReadFile(cfg.Ethereum.JWTSecret)
		if err != nil {
			log.Printf("Warning: Unable to read JWT secret file: %v", err)
		} else {
			// Use hex format as key
			jwtSecret = strings.TrimSpace(string(jwtBytes))
			log.Printf("JWT secret loaded (length: %d)", len(jwtSecret))
		}
	}

	log.Printf("Initializing Ethereum client, endpoint: %s, Engine API: %s",
		cfg.Ethereum.Endpoint, cfg.Ethereum.EngineAPI)

	return &Client{
		config:          cfg,
		httpClient:      httpClient,
		engineAPIClient: engineAPIClient,
		jwtSecret:       jwtSecret,
	}, nil
}

// jsonRPCRequest represents a JSON-RPC request
type jsonRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	ID      int         `json:"id"`
}

// jsonRPCResponse represents a JSON-RPC response
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
	ID      int             `json:"id"`
}

// jsonRPCError represents a JSON-RPC error
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Call makes a JSON-RPC call to the Ethereum client
func (c *Client) Call(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	// Check if this is an Engine API call
	isEngineAPI := strings.HasPrefix(method, "engine_")

	request := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	// Add logging for debugging
	log.Printf("Calling Ethereum method: %s, params: %+v", method, params)

	// Choose the correct endpoint
	endpoint := c.config.Ethereum.Endpoint
	if isEngineAPI && c.config.Ethereum.EngineAPI != "" {
		endpoint = c.config.Ethereum.EngineAPI
		log.Printf("Using Engine API endpoint: %s", endpoint)
	}

	log.Printf("Using endpoint: %s", endpoint)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(string(requestBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add JWT authentication for Engine API calls
	if isEngineAPI && c.jwtSecret != "" {
		log.Printf("Adding JWT auth header using hex key")
		// Note: Using the hex key string directly as token
		// Geth expects the hex string itself, not standard JWT
		req.Header.Set("Authorization", "Bearer "+c.jwtSecret)
	}

	// Choose the correct client
	client := c.httpClient
	if isEngineAPI {
		client = c.engineAPIClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status code: %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Add logging for debugging
	log.Printf("Ethereum response: %s", string(respBody))

	var response jsonRPCResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		// Add detailed error information for debugging
		log.Printf("JSON parse failed: %v", err)
		log.Printf("Raw response: %s", string(respBody))

		// Try to determine where the problem is
		if strings.Contains(err.Error(), "looking for beginning of value") {
			// If empty response or format error, log details
			if len(respBody) > 0 {
				log.Printf("Problem character position: %c (ASCII: %d)", respBody[0], respBody[0])
			} else {
				log.Printf("Response body is empty")
			}
		}

		return nil, fmt.Errorf("failed to unmarshal response: %w, raw response: %s", err, string(respBody))
	}

	if response.Error != nil {
		return nil, fmt.Errorf("JSON-RPC error: %d %s", response.Error.Code, response.Error.Message)
	}

	return response.Result, nil
}

// GetLatestBlock retrieves the latest block from the Ethereum client
func (c *Client) GetLatestBlock(ctx context.Context) (*types.Block, error) {
	result, err := c.Call(ctx, "eth_getBlockByNumber", []interface{}{"latest", true})
	if err != nil {
		return nil, err
	}

	// Convert raw JSON to string for further processing if needed for debugging
	_ = string(result)

	// Define a temporary structure with string types for big.Int fields
	type BlockTemp struct {
		Number           string        `json:"number"`
		Hash             string        `json:"hash"`
		ParentHash       string        `json:"parentHash"`
		Nonce            string        `json:"nonce"`
		Sha3Uncles       string        `json:"sha3Uncles"`
		LogsBloom        string        `json:"logsBloom"`
		TransactionsRoot string        `json:"transactionsRoot"`
		StateRoot        string        `json:"stateRoot"`
		ReceiptsRoot     string        `json:"receiptsRoot"`
		Miner            string        `json:"miner"`
		Difficulty       string        `json:"difficulty"`
		TotalDifficulty  string        `json:"totalDifficulty"`
		ExtraData        string        `json:"extraData"`
		Size             string        `json:"size"`
		GasLimit         string        `json:"gasLimit"`
		GasUsed          string        `json:"gasUsed"`
		Timestamp        string        `json:"timestamp"`
		Transactions     []interface{} `json:"transactions"`
		Uncles           []string      `json:"uncles"`
		BaseFeePerGas    string        `json:"baseFeePerGas"`
	}

	var blockTemp BlockTemp
	if err := json.Unmarshal(result, &blockTemp); err != nil {
		log.Printf("[ERROR] Failed to parse block JSON: %v", err)

		// Try manual JSON parsing
		var rawMap map[string]interface{}
		if jsonErr := json.Unmarshal(result, &rawMap); jsonErr != nil {
			log.Printf("[ERROR] Also failed to parse as map: %v", jsonErr)
			return nil, fmt.Errorf("failed to unmarshal block JSON: %w, original error: %v", jsonErr, err)
		}

		// Print raw value types for key fields to help debugging
		for _, key := range []string{"number", "difficulty", "totalDifficulty", "gasLimit", "gasUsed", "timestamp", "baseFeePerGas"} {
			if val, ok := rawMap[key]; ok {
				log.Printf("[DEBUG] Field %s raw value: %v (type: %T)", key, val, val)
				// Log the value for debugging
				log.Printf("[DEBUG] Found field %s with value %v", key, val)
			}
		}

		// Could not parse JSON properly, return the error
		return nil, err
	}

	// Function to parse hex strings to big.Int
	tryParseHexString := func(hexStr string) (*big.Int, error) {
		// Clean up string - remove quotes, backslashes and other artifacts
		s := strings.Trim(hexStr, "\"")
		s = strings.ReplaceAll(s, "\\", "")

		// Handle 0x prefix
		s = strings.TrimPrefix(s, "0x")

		// Convert to big.Int
		n := new(big.Int)
		if _, success := n.SetString(s, 16); success {
			return n, nil
		}

		// Last attempt with JSON parsing
		var str string
		if err := json.Unmarshal([]byte(hexStr), &str); err == nil {
			str = strings.TrimPrefix(str, "0x")
			if _, success := n.SetString(str, 16); success {
				return n, nil
			}
		}

		return nil, fmt.Errorf("failed to parse hex string: %s", hexStr)
	}

	// Create and populate the actual block structure
	block := &types.Block{
		Hash:             blockTemp.Hash,
		ParentHash:       blockTemp.ParentHash,
		Nonce:            blockTemp.Nonce,
		Sha3Uncles:       blockTemp.Sha3Uncles,
		LogsBloom:        blockTemp.LogsBloom,
		TransactionsRoot: blockTemp.TransactionsRoot,
		StateRoot:        blockTemp.StateRoot,
		ReceiptsRoot:     blockTemp.ReceiptsRoot,
		Miner:            blockTemp.Miner,
		ExtraData:        blockTemp.ExtraData,
		Uncles:           blockTemp.Uncles,
	}

	var convErr error

	block.Number, convErr = tryParseHexString(blockTemp.Number)
	if convErr != nil {
		return nil, fmt.Errorf("failed to convert Number: %w (raw value: %s)", convErr, blockTemp.Number)
	}

	block.Difficulty, convErr = tryParseHexString(blockTemp.Difficulty)
	if convErr != nil {
		return nil, fmt.Errorf("failed to convert Difficulty: %w (raw value: %s)", convErr, blockTemp.Difficulty)
	}

	block.TotalDifficulty, convErr = tryParseHexString(blockTemp.TotalDifficulty)
	if convErr != nil {
		return nil, fmt.Errorf("failed to convert TotalDifficulty: %w (raw value: %s)", convErr, blockTemp.TotalDifficulty)
	}

	block.Size, convErr = tryParseHexString(blockTemp.Size)
	if convErr != nil {
		return nil, fmt.Errorf("failed to convert Size: %w (raw value: %s)", convErr, blockTemp.Size)
	}

	// Parse GasLimit field
	block.GasLimit, convErr = tryParseHexString(blockTemp.GasLimit)
	if convErr != nil {
		return nil, fmt.Errorf("failed to convert GasLimit: %w (raw value: %s)", convErr, blockTemp.GasLimit)
	}

	block.GasUsed, convErr = tryParseHexString(blockTemp.GasUsed)
	if convErr != nil {
		return nil, fmt.Errorf("failed to convert GasUsed: %w (raw value: %s)", convErr, blockTemp.GasUsed)
	}

	block.Timestamp, convErr = tryParseHexString(blockTemp.Timestamp)
	if convErr != nil {
		return nil, fmt.Errorf("failed to convert Timestamp: %w (raw value: %s)", convErr, blockTemp.Timestamp)
	}

	if blockTemp.BaseFeePerGas != "" {
		block.BaseFeePerGas, convErr = tryParseHexString(blockTemp.BaseFeePerGas)
		if convErr != nil {
			return nil, fmt.Errorf("failed to convert BaseFeePerGas: %w (raw value: %s)", convErr, blockTemp.BaseFeePerGas)
		}
	}

	// Handle transactions separately as they are more complex
	block.Transactions = make([]types.Transaction, 0, len(blockTemp.Transactions))
	for _, txRaw := range blockTemp.Transactions {
		// Convert to raw json first
		txJSON, err := json.Marshal(txRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal transaction: %w", err)
		}

		// Define a temporary transaction structure with string types
		type TxTemp struct {
			Hash             string `json:"hash"`
			Nonce            string `json:"nonce"`
			BlockHash        string `json:"blockHash"`
			BlockNumber      string `json:"blockNumber"`
			TransactionIndex string `json:"transactionIndex"`
			From             string `json:"from"`
			To               string `json:"to"`
			Value            string `json:"value"`
			GasPrice         string `json:"gasPrice"`
			Gas              string `json:"gas"`
			Input            string `json:"input"`
			V                string `json:"v"`
			R                string `json:"r"`
			S                string `json:"s"`
		}

		var txTemp TxTemp
		if err := json.Unmarshal(txJSON, &txTemp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal transaction: %w", err)
		}

		// Convert and create Transaction object
		tx := types.Transaction{
			Hash:      txTemp.Hash,
			BlockHash: txTemp.BlockHash,
			From:      txTemp.From,
			To:        txTemp.To,
			Input:     txTemp.Input,
		}

		tx.Nonce, convErr = tryParseHexString(txTemp.Nonce)
		if convErr != nil {
			return nil, fmt.Errorf("failed to convert tx.Nonce: %w (raw value: %s)", convErr, txTemp.Nonce)
		}

		if txTemp.BlockNumber != "" {
			tx.BlockNumber, convErr = tryParseHexString(txTemp.BlockNumber)
			if convErr != nil {
				return nil, fmt.Errorf("failed to convert tx.BlockNumber: %w (raw value: %s)", convErr, txTemp.BlockNumber)
			}
		}

		if txTemp.TransactionIndex != "" {
			tx.TransactionIndex, convErr = tryParseHexString(txTemp.TransactionIndex)
			if convErr != nil {
				return nil, fmt.Errorf("failed to convert tx.TransactionIndex: %w (raw value: %s)", convErr, txTemp.TransactionIndex)
			}
		}

		tx.Value, convErr = tryParseHexString(txTemp.Value)
		if convErr != nil {
			return nil, fmt.Errorf("failed to convert tx.Value: %w (raw value: %s)", convErr, txTemp.Value)
		}

		tx.GasPrice, convErr = tryParseHexString(txTemp.GasPrice)
		if convErr != nil {
			return nil, fmt.Errorf("failed to convert tx.GasPrice: %w (raw value: %s)", convErr, txTemp.GasPrice)
		}

		tx.Gas, convErr = tryParseHexString(txTemp.Gas)
		if convErr != nil {
			return nil, fmt.Errorf("failed to convert tx.Gas: %w (raw value: %s)", convErr, txTemp.Gas)
		}

		if txTemp.V != "" {
			tx.V, convErr = tryParseHexString(txTemp.V)
			if convErr != nil {
				return nil, fmt.Errorf("failed to convert tx.V: %w (raw value: %s)", convErr, txTemp.V)
			}
		}

		if txTemp.R != "" {
			tx.R, convErr = tryParseHexString(txTemp.R)
			if convErr != nil {
				return nil, fmt.Errorf("failed to convert tx.R: %w (raw value: %s)", convErr, txTemp.R)
			}
		}

		if txTemp.S != "" {
			tx.S, convErr = tryParseHexString(txTemp.S)
			if convErr != nil {
				return nil, fmt.Errorf("failed to convert tx.S: %w (raw value: %s)", convErr, txTemp.S)
			}
		}

		block.Transactions = append(block.Transactions, tx)
	}

	return block, nil
}

// SubmitBlock submits a block to the Ethereum client using the Engine API
func (c *Client) SubmitBlock(ctx context.Context, block *types.Block) error {
	// Submit block to Ethereum Engine API with JWT auth enabled automatically
	log.Printf("Submitting block to Ethereum Engine API: %s, Block number: %s",
		c.config.Ethereum.EngineAPI, block.Number.String())
	_, err := c.Call(ctx, "engine_newPayloadV1", []interface{}{block})
	return err
}

// CheckConnection verifies connectivity to the Ethereum client
func (c *Client) CheckConnection(ctx context.Context) (string, error) {
	// Try multiple possible methods to verify connection
	methods := []string{"eth_blockNumber", "net_version", "web3_clientVersion"}

	var lastError error
	for _, method := range methods {
		log.Printf("[DEBUG] Trying to verify Ethereum connection using %s method", method)

		_, err := c.Call(ctx, method, nil)
		if err == nil {
			// Connection successful
			return fmt.Sprintf("Connected using %s", method), nil
		}

		lastError = err
		log.Printf("[DEBUG] Method %s failed: %v, trying next method", method, err)
	}

	return "", fmt.Errorf("All connection methods failed, last error: %v", lastError)
}
