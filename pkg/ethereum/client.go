package ethereum

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/smallyunet/ethbft/pkg/config"
)

// Client represents an Ethereum execution client adapter
type Client struct {
	config          *config.Config
	httpClient      *http.Client
	engineAPIClient *http.Client // Dedicated client for Engine API
	jwtKey          []byte       // JWT secret key bytes
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

	jwtKey, err := loadJWTSecret(cfg.Ethereum.JWTSecret)
	if err != nil {
		return nil, err
	}

	log.Printf("Initializing Ethereum client, endpoint: %s, Engine API: %s", cfg.Ethereum.Endpoint, cfg.Ethereum.EngineAPI)
	log.Printf("JWT secret loaded (%d bytes)", len(jwtKey))

	return &Client{
		config:          cfg,
		httpClient:      httpClient,
		engineAPIClient: engineAPIClient,
		jwtKey:          jwtKey,
	}, nil
}

func loadJWTSecret(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("ethereum jwtSecret path cannot be empty")
	}
	jwtBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read jwt secret %q: %w", path, err)
	}
	secretHex := strings.TrimSpace(string(jwtBytes))
	if secretHex == "" {
		return nil, fmt.Errorf("jwt secret file %q is empty", path)
	}
	secretHex = strings.TrimPrefix(secretHex, "0x")
	key, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, fmt.Errorf("invalid jwt secret hex in %q: %w", path, err)
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("jwt secret must be at least 32 bytes, got %d", len(key))
	}
	return key, nil
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

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add JWT authentication for Engine API calls (HS256 as per Engine API spec)
	if isEngineAPI {
		if token, err := c.generateJWT(); err != nil {
			return nil, fmt.Errorf("failed to generate JWT: %w", err)
		} else {
			req.Header.Set("Authorization", "Bearer "+token)
		}
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

// generateJWT builds a short-lived HS256 JWT using the preloaded secret key
func (c *Client) generateJWT() (string, error) {
	if len(c.jwtKey) == 0 {
		return "", fmt.Errorf("jwt secret not loaded")
	}

	// Header and payload
	header := `{"alg":"HS256","typ":"JWT"}`
	now := time.Now().Unix()
	// Keep token lifetime short (e.g., 60s)
	payload := fmt.Sprintf(`{"iat":%d,"exp":%d}`, now, now+60)

	// Base64 URL encode without padding
	enc := func(b []byte) string {
		return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
	}
	headEnc := enc([]byte(header))
	payEnc := enc([]byte(payload))
	signingInput := headEnc + "." + payEnc

	mac := hmac.New(sha256.New, c.jwtKey)
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	sigEnc := enc(sig)

	return signingInput + "." + sigEnc, nil
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
