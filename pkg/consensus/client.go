package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/smallyunet/ethbft/pkg/config"
)

// Client represents a CometBFT consensus client
type Client struct {
	config     *config.Config
	httpClient *http.Client
	endpoint   string
}

// NewClient creates a new CometBFT client
func NewClient(cfg *config.Config) (*Client, error) {
	return &Client{
		config:     cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		endpoint:   cfg.CometBFT.Endpoint,
	}, nil
}

// RPCRequest represents an RPC request to CometBFT
type RPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      string      `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

// RPCResponse represents an RPC response from CometBFT
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError represents an RPC error
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

// Call makes an RPC call to CometBFT
func (c *Client) Call(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	request := RPCRequest{
		JSONRPC: "2.0",
		ID:      "1",
		Method:  method,
		Params:  params,
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize request: %w", err)
	}

	// Add debug log
	fmt.Printf("CometBFT request [%s]: %s\n", method, string(requestBody))

	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request [%s]: %w", c.endpoint, err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request [%s]: %w", c.endpoint, err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request returned non-success status code: %d", resp.StatusCode)
	}

	// Read the entire response body
	var respBody bytes.Buffer
	_, err = respBody.ReadFrom(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Add debug log
	fmt.Printf("CometBFT response [%s]: %s\n", method, respBody.String())

	// Decode JSON response
	var rpcResp RPCResponse
	if err := json.NewDecoder(bytes.NewReader(respBody.Bytes())).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %w, raw response: %s", err, respBody.String())
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error: code=%d, message=%s, data=%s",
			rpcResp.Error.Code, rpcResp.Error.Message, rpcResp.Error.Data)
	}

	return rpcResp.Result, nil
}

// GetStatus gets the status of CometBFT node
func (c *Client) GetStatus(ctx context.Context) (map[string]interface{}, error) {
	result, err := c.Call(ctx, "status", nil)
	if err != nil {
		return nil, err
	}

	var status map[string]interface{}
	if err := json.Unmarshal(result, &status); err != nil {
		return nil, err
	}

	return status, nil
}
