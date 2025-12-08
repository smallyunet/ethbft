package consensus

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	rpchttp "github.com/cometbft/cometbft/rpc/client/http"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"
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

// GetStatus gets the status of CometBFT node
func (c *Client) GetStatus(ctx context.Context) (*coretypes.ResultStatus, error) {
	return c.rpcClient.Status(ctx)
}

// GetBlock gets a block at a specific height
func (c *Client) GetBlock(ctx context.Context, height *int64) (*coretypes.ResultBlock, error) {
	return c.rpcClient.Block(ctx, height)
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

// Stop stops the CometBFT client
func (c *Client) Stop() error {
	return c.rpcClient.Stop()
}
