package config

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

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
		Endpoint string `yaml:"endpoint"` // Endpoint for CometBFT node (e.g., "tcp://localhost:26657")
		HomeDir  string `yaml:"homeDir"`  // Home directory for CometBFT config and data
	} `yaml:"cometbft"`

	// Bridge configuration
	Bridge struct {
		ListenAddr     string `yaml:"listenAddr"`     // Address to listen on (e.g., "0.0.0.0:8080")
		LogLevel       string `yaml:"logLevel"`       // Log level (debug, info, warn, error)
		RetryInterval  int    `yaml:"retryInterval"`  // Seconds between connection retry attempts
		EnableBridging bool   `yaml:"enableBridging"` // Whether to enable actual CometBFT->Geth bridging
	} `yaml:"bridge"`
}

// DefaultConfig returns a config with default values
func DefaultConfig() *Config {
	cfg := &Config{}

	// Default Ethereum settings
	cfg.Ethereum.Endpoint = "http://localhost:8545"
	cfg.Ethereum.EngineAPI = "http://localhost:8551"
	cfg.Ethereum.JWTSecret = "jwtsecret"

	// Default CometBFT settings
	cfg.CometBFT.Endpoint = "tcp://localhost:26657"
	cfg.CometBFT.HomeDir = "./cometbft_home"

	// Default Bridge settings
	cfg.Bridge.ListenAddr = "0.0.0.0:8080"
	cfg.Bridge.LogLevel = "info"
	cfg.Bridge.RetryInterval = 5
	cfg.Bridge.EnableBridging = true // Default to enabled for actual bridging

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
		// Replace localhost with the Docker service name
		cfg.Ethereum.Endpoint = strings.Replace(cfg.Ethereum.Endpoint, "localhost", host, 1)
		cfg.Ethereum.EngineAPI = strings.Replace(cfg.Ethereum.EngineAPI, "localhost", host, 1)
	}

	if host := os.Getenv("COMETBFT_HOST"); host != "" {
		// Replace localhost with the Docker service name
		cfg.CometBFT.Endpoint = strings.Replace(cfg.CometBFT.Endpoint, "localhost", host, 1)
	}

	// Ensure directories exist
	if err := os.MkdirAll(filepath.Dir(cfg.Ethereum.JWTSecret), 0755); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(cfg.CometBFT.HomeDir, 0755); err != nil {
		return nil, err
	}

	return cfg, nil
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
