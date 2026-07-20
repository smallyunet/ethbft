package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"gopkg.in/yaml.v3"
)

const DefaultAppVersion = "0.1.1"

// Config stores all configuration for the EthBFT application
type Config struct {
	// Ethereum execution client configuration
	Ethereum struct {
		Endpoint  string `yaml:"endpoint"`  // Endpoint for Ethereum client (e.g., "http://localhost:8545")
		EngineAPI string `yaml:"engineAPI"` // Engine API endpoint for post-merge Ethereum clients
		JWTSecret string `yaml:"jwtSecret"` // Path to JWT secret file for authentication
	} `yaml:"ethereum"`

	// CometBFT configuration
	CometBFT struct {
		Endpoint string `yaml:"endpoint"` // Endpoint for CometBFT node (e.g., "http://localhost:26657")
		HomeDir  string `yaml:"homeDir"`  // Home directory for CometBFT config and data
	} `yaml:"cometbft"`

	// Bridge configuration
	Bridge struct {
		ListenAddr     string `yaml:"listenAddr"`     // Address to listen on (e.g., "0.0.0.0:8080")
		LogLevel       string `yaml:"logLevel"`       // Log level (debug, info, warn, error)
		EnableBridging bool   `yaml:"enableBridging"` // Whether to enable actual CometBFT->Geth bridging
		Timeout        int    `yaml:"timeout"`        // Global timeout in seconds for operations
		FeeRecipient   string `yaml:"feeRecipient"`   // Address to receive block rewards
		FinalityDepth  int    `yaml:"finalityDepth"`  // Deprecated: use SafeDepth/FinalizedDepth
		SafeDepth      int    `yaml:"safeDepth"`      // Number of blocks behind head for safe
		FinalizedDepth int    `yaml:"finalizedDepth"` // Number of blocks behind head for finalized
		StateFile      string `yaml:"stateFile"`      // Path to state persistence file
		HealthAddr     string `yaml:"healthAddr"`     // Address for health/metrics server
		AppVersion     string `yaml:"appVersion"`     // Application version reported to ABCI
		MaxBridgeLag   int64  `yaml:"maxBridgeLag"`   // Maximum healthy CometBFT-to-bridge height lag
		StallTimeout   int    `yaml:"stallTimeout"`   // Seconds without bridge progress before unhealthy
	} `yaml:"bridge"`
}

// DefaultConfig returns a config with default values
func DefaultConfig() *Config {
	cfg := &Config{}

	// Default Ethereum settings
	cfg.Ethereum.Endpoint = "http://localhost:8545"
	cfg.Ethereum.EngineAPI = "http://localhost:8551"
	cfg.Ethereum.JWTSecret = "./jwt.hex"

	// Default CometBFT settings
	cfg.CometBFT.Endpoint = "http://localhost:26657"
	cfg.CometBFT.HomeDir = "./cometbft_home"

	// Default Bridge settings
	cfg.Bridge.ListenAddr = "0.0.0.0:8080"
	cfg.Bridge.LogLevel = "info"
	cfg.Bridge.EnableBridging = true // Default to enabled for actual bridging
	cfg.Bridge.Timeout = 10          // Default 10s timeout
	cfg.Bridge.FinalityDepth = 0     // Default to 0 (deprecated)
	cfg.Bridge.SafeDepth = 0         // Default to 0 (safe immediately for demo)
	cfg.Bridge.FinalizedDepth = 0    // Default to 0 (finalized immediately for demo)
	cfg.Bridge.StateFile = "ethbft_state.json"
	cfg.Bridge.HealthAddr = "0.0.0.0:8081"
	cfg.Bridge.AppVersion = DefaultAppVersion
	cfg.Bridge.MaxBridgeLag = 5
	cfg.Bridge.StallTimeout = 30

	return cfg
}

// Load loads configuration from file and environment variables
func Load() (*Config, error) {
	cfg := DefaultConfig()

	// Try to load from config file
	configPath := os.Getenv("ETHBFT_CONFIG")
	if configPath == "" {
		configPath = "config.yaml"
	}

	if _, err := os.Stat(configPath); err == nil {
		file, err := os.Open(configPath)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		decoder := yaml.NewDecoder(file)
		if err := decoder.Decode(cfg); err != nil {
			return nil, err
		}
	}

	// Override with environment variables if provided
	if host := os.Getenv("ETHEREUM_HOST"); host != "" {
		cfg.Ethereum.Endpoint = replaceHost(cfg.Ethereum.Endpoint, host)
		cfg.Ethereum.EngineAPI = replaceHost(cfg.Ethereum.EngineAPI, host)
	}

	if host := os.Getenv("COMETBFT_HOST"); host != "" {
		cfg.CometBFT.Endpoint = replaceHost(cfg.CometBFT.Endpoint, host)
	}

	// Ensure directories exist
	if err := os.MkdirAll(filepath.Dir(cfg.Ethereum.JWTSecret), 0755); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(cfg.CometBFT.HomeDir, 0755); err != nil {
		return nil, err
	}

	if cfg.Bridge.StateFile != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.Bridge.StateFile), 0755); err != nil {
			return nil, err
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate rejects local configuration that could make execution consensus
// differ between validators. Protocol v1 deliberately supports Engine API V2
// only and finalizes exactly the block decided by CometBFT.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Ethereum.Endpoint) == "" {
		return fmt.Errorf("ethereum endpoint cannot be empty")
	}
	if strings.TrimSpace(c.Ethereum.EngineAPI) == "" {
		return fmt.Errorf("ethereum engineAPI cannot be empty")
	}
	if strings.TrimSpace(c.CometBFT.Endpoint) == "" {
		return fmt.Errorf("cometbft endpoint cannot be empty")
	}
	if !c.Bridge.EnableBridging {
		return fmt.Errorf("execution-payload consensus v1 requires enableBridging=true")
	}
	if c.Bridge.SafeDepth != 0 || c.Bridge.FinalizedDepth != 0 || c.Bridge.FinalityDepth != 0 {
		return fmt.Errorf("execution-payload consensus v1 finalizes CometBFT-decided blocks; local finality depths must be zero")
	}
	if c.Bridge.Timeout <= 0 {
		return fmt.Errorf("bridge timeout must be positive")
	}
	if c.Bridge.FeeRecipient != "" && !common.IsHexAddress(c.Bridge.FeeRecipient) {
		return fmt.Errorf("invalid bridge feeRecipient %q", c.Bridge.FeeRecipient)
	}
	switch strings.ToLower(c.Bridge.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid bridge logLevel %q", c.Bridge.LogLevel)
	}
	return nil
}

func replaceHost(rawURL, newHost string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Fallback to simple replacement if parsing fails
		return strings.Replace(rawURL, "localhost", newHost, 1)
	}

	// Handle host with port
	host := u.Host
	port := ""
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		host = parts[0]
		if len(parts) > 1 {
			port = ":" + parts[1]
		}
	}

	u.Host = newHost + port
	return u.String()
}

// Save writes the configuration to a file
func (c *Config) Save(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	defer encoder.Close()
	encoder.SetIndent(2)
	return encoder.Encode(c)
}
