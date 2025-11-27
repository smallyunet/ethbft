package consensus

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	rpchttp "github.com/cometbft/cometbft/rpc/client/http"
	"github.com/cometbft/cometbft/types"
	"github.com/smallyunet/ethbft/pkg/config"
)

// Client represents a CometBFT consensus client
type Client struct {
	config    *config.Config
	rpcClient *rpchttp.HTTP
	endpoint  string
	logger    *slog.Logger
}

// NewClient creates a new CometBFT client
func NewClient(cfg *config.Config) (*Client, error) {
	endpoint, err := normalizeEndpoint(cfg.CometBFT.Endpoint)
	if err != nil {
		return nil, err
	}

	// Create the CometBFT HTTP/WS client
	rpcClient, err := rpchttp.New(endpoint, "/websocket")
	if err != nil {
		return nil, fmt.Errorf("failed to create cometbft client: %w", err)
	}

	return &Client{
		config:    cfg,
		rpcClient: rpcClient,
		endpoint:  endpoint,
		logger:    slog.Default().With("component", "consensus_client"),
	}, nil
}

func normalizeEndpoint(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("cometbft endpoint cannot be empty")
	}
	// rpchttp.New expects full URL
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid cometbft endpoint %q: %w", raw, err)
	}
	switch u.Scheme {
	case "http", "https", "tcp":
		return u.String(), nil
	default:
		return "", fmt.Errorf("unsupported cometbft endpoint scheme %q", u.Scheme)
	}
}

// Call makes an RPC call to CometBFT (legacy wrapper, prefer using rpcClient methods directly if possible)
// Kept for backward compatibility with existing bridge logic if needed, but we should migrate.
// For now, we implement a basic wrapper or just use the rpcClient.
func (c *Client) Call(ctx context.Context, method string, params map[string]interface{}) (json.RawMessage, error) {
	// This is a bit hacky because rpchttp.HTTP doesn't expose a generic Call easily without internal types.
	// But for our specific needs (block, status), we can use the typed methods.
	// If generic call is strictly needed, we might need to keep the old HTTP client or use reflection.
	// For "block" and "status", let's use the typed methods.

	switch method {
	case "status":
		status, err := c.rpcClient.Status(ctx)
		if err != nil {
			return nil, err
		}
		// Marshal back to JSON to match old interface expectation
		return json.Marshal(map[string]interface{}{
			"sync_info": map[string]interface{}{
				"latest_block_height": strconv.FormatInt(status.SyncInfo.LatestBlockHeight, 10),
				"latest_block_hash":   status.SyncInfo.LatestBlockHash.String(),
			},
		})
	case "block":
		heightStr, ok := params["height"].(string)
		var height *int64
		if ok {
			h, _ := strconv.ParseInt(heightStr, 10, 64)
			height = &h
		}
		block, err := c.rpcClient.Block(ctx, height)
		if err != nil {
			return nil, err
		}
		// Map to structure expected by bridge (simplified)
		// This is getting complex to map 1:1.
		// Better approach: Update Bridge to use typed responses if possible, or do best effort mapping here.
		// For now, let's do best effort mapping to keep bridge.go happy without major refactor there yet.
		res := map[string]interface{}{
			"result": map[string]interface{}{
				"block_id": map[string]interface{}{
					"hash": block.BlockID.Hash.String(),
				},
				"block": map[string]interface{}{
					"header": map[string]interface{}{
						"height": strconv.FormatInt(block.Block.Height, 10),
						"time":   block.Block.Time.Format(time.RFC3339),
						"last_block_id": map[string]interface{}{
							"hash": block.Block.LastBlockID.Hash.String(),
						},
					},
					"data": map[string]interface{}{
						"txs": block.Block.Data.Txs, // This is [][]byte, might need base64 encoding if caller expects string
					},
				},
			},
		}
		// Txs need to be base64 strings for the old bridge logic?
		// bridge.go: bts, err := base64.StdEncoding.DecodeString(tx)
		// Yes, bridge expects base64 strings.
		txs := make([]string, len(block.Block.Data.Txs))
		for i, tx := range block.Block.Data.Txs {
			txs[i] = string(tx) // Actually wait, if it's []byte, json.Marshal handles base64 for []byte automatically?
			// No, standard json marshals []byte as base64 string.
			// So we can just leave it as [][]byte in the map, and when we marshal the whole map, it becomes base64 strings.
		}
		res["result"].(map[string]interface{})["block"].(map[string]interface{})["data"] = map[string]interface{}{"txs": block.Block.Data.Txs}

		return json.Marshal(res)
	}

	return nil, fmt.Errorf("unsupported method %s", method)
}

// GetStatus gets the status of CometBFT node
func (c *Client) GetStatus(ctx context.Context) (map[string]interface{}, error) {
	status, err := c.rpcClient.Status(ctx)
	if err != nil {
		return nil, err
	}
	// Return map structure expected by bridge
	return map[string]interface{}{
		"sync_info": map[string]interface{}{
			"latest_block_height": strconv.FormatInt(status.SyncInfo.LatestBlockHeight, 10),
			"latest_block_hash":   status.SyncInfo.LatestBlockHash.String(),
		},
	}, nil
}

// SubscribeNewBlocks subscribes to NewBlock events and returns a channel of block heights.
func (c *Client) SubscribeNewBlocks(ctx context.Context) (<-chan int64, error) {
	if err := c.rpcClient.Start(); err != nil {
		// It might be already started
		if !strings.Contains(err.Error(), "already started") {
			return nil, fmt.Errorf("failed to start rpc client: %w", err)
		}
	}

	query := "tm.event = 'NewBlock'"
	out, err := c.rpcClient.Subscribe(ctx, "ethbft-bridge", query, 100)
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to new blocks: %w", err)
	}

	heightCh := make(chan int64, 100)
	go func() {
		defer close(heightCh)
		for {
			select {
			case <-ctx.Done():
				return
			case e, ok := <-out:
				if !ok {
					return
				}
				data, ok := e.Data.(types.EventDataNewBlock)
				if ok {
					heightCh <- data.Block.Height
				}
			}
		}
	}()

	return heightCh, nil
}

// UnsubscribeAll unsubscribes from all events.
func (c *Client) UnsubscribeAll(ctx context.Context) error {
	return c.rpcClient.UnsubscribeAll(ctx, "ethbft-bridge")
}
