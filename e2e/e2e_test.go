package e2e

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

const (
	// Pre-funded account private key (for testing only)
	testPrivKeyHex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	testAddr       = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
)

func TestE2E(t *testing.T) {
	// 1. Setup environment
	rootDir, err := setupEnvironment(t)
	if err != nil {
		t.Fatalf("Failed to setup environment: %v", err)
	}
	defer teardownEnvironment(t, rootDir)

	// 2. Start Docker environment
	t.Log("Starting Docker environment...")
	cmd := exec.Command("docker-compose",
		"-f", "docker-compose.yml",
		"-f", "e2e/docker-compose.override.yml",
		"up", "-d", "--build",
	)
	cmd.Dir = rootDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to start docker-compose: %v", err)
	}

	// 3. Wait for services to be ready
	t.Log("Waiting for services to be ready...")
	client, err := waitForGeth(t, "http://localhost:8545")
	if err != nil {
		t.Fatalf("Geth failed to become ready: %v", err)
	}
	defer client.Close()

	// 4. Run tests
	t.Run("CheckBalance", func(t *testing.T) {
		testCheckBalance(t, client)
	})

	t.Run("SendTransaction", func(t *testing.T) {
		testSendTransaction(t, client)
	})
}

func setupEnvironment(t *testing.T) (string, error) {
	// Get project root directory (assuming we are running from e2e/ or root)
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// If we are in e2e directory, go up one level
	rootDir := cwd
	if filepath.Base(cwd) == "e2e" {
		rootDir = filepath.Dir(cwd)
	}

	dataDir := filepath.Join(rootDir, "e2e", "data")
	if err := os.RemoveAll(dataDir); err != nil {
		return "", fmt.Errorf("failed to clean data dir: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create data dir: %w", err)
	}

	// Create subdirectories
	if err := os.MkdirAll(filepath.Join(dataDir, "geth"), 0777); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "cometbft"), 0777); err != nil {
		return "", err
	}

	// 1. Generate JWT secret
	// Simple random hex
	jwtHex := "0000000000000000000000000000000000000000000000000000000000000000" // valid hex
	if err := os.WriteFile(filepath.Join(dataDir, "jwt.hex"), []byte(jwtHex), 0644); err != nil {
		return "", err
	}

	// 2. Create genesis.json
	genesisContent := fmt.Sprintf(`{
  "config": {
    "chainId": 1337,
    "homesteadBlock": 0,
    "eip150Block": 0,
    "eip155Block": 0,
    "eip158Block": 0,
    "byzantiumBlock": 0,
    "constantinopleBlock": 0,
    "petersburgBlock": 0,
    "istanbulBlock": 0,
    "berlinBlock": 0,
    "londonBlock": 0,
    "mergeForkBlock": 0,
    "terminalTotalDifficulty": 0
  },
  "alloc": {
    "%s": { "balance": "1000000000000000000000" }
  },
  "difficulty": "1",
  "gasLimit": "30000000"
}`, testAddr[2:]) // remove 0x prefix for genesis

	if err := os.WriteFile(filepath.Join(dataDir, "geth", "genesis.json"), []byte(genesisContent), 0644); err != nil {
		return "", err
	}

	// 3. Create config.yaml for ethbft
	configContent := `ethereum:
  endpoint: "http://ethbft-geth:8545"
  engineAPI: "http://ethbft-geth:8551"
  jwtSecret: "/app/jwt.hex"

cometbft:
  endpoint: "http://ethbft-cometbft:26657"
  homeDir: "/cometbft"

bridge:
  listenAddr: "0.0.0.0:8080"
  logLevel: "debug"
  retryInterval: 1
`
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte(configContent), 0644); err != nil {
		return "", err
	}

	return rootDir, nil
}

func teardownEnvironment(t *testing.T, rootDir string) {
	if t.Failed() {
		t.Log("Test failed, keeping environment for debugging")
		// Print logs
		cmdLogs := exec.Command("docker-compose",
			"-f", "docker-compose.yml",
			"-f", "e2e/docker-compose.override.yml",
			"logs", "--tail=100",
		)
		cmdLogs.Dir = rootDir
		output, _ := cmdLogs.CombinedOutput()
		t.Logf("Docker logs:\n%s", string(output))
		return // Uncomment to keep env on failure
	}

	t.Log("Tearing down Docker environment...")
	cmd := exec.Command("docker-compose",
		"-f", "docker-compose.yml",
		"-f", "e2e/docker-compose.override.yml",
		"down", "-v",
	)
	cmd.Dir = rootDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Logf("Failed to tear down docker-compose: %v", err)
	}

	// Cleanup data dir
	// os.RemoveAll(filepath.Join(rootDir, "e2e", "data"))
}

func waitForGeth(t *testing.T, url string) (*ethclient.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for Geth")
		case <-ticker.C:
			// Try to connect
			rpcClient, err := rpc.DialContext(ctx, url)
			if err != nil {
				continue
			}
			client := ethclient.NewClient(rpcClient)

			// Try to get block number to verify connection
			_, err = client.BlockNumber(ctx)
			if err == nil {
				return client, nil
			}
			client.Close()
		}
	}
}

func testCheckBalance(t *testing.T, client *ethclient.Client) {
	account := common.HexToAddress(testAddr)
	balance, err := client.BalanceAt(context.Background(), account, nil)
	if err != nil {
		t.Fatalf("Failed to get balance: %v", err)
	}

	expected := new(big.Int)
	expected.SetString("1000000000000000000000", 10) // 1000 ETH

	if balance.Cmp(expected) != 0 {
		t.Errorf("Expected balance %s, got %s", expected.String(), balance.String())
	}
}

func testSendTransaction(t *testing.T, client *ethclient.Client) {
	privateKey, err := crypto.HexToECDSA(testPrivKeyHex)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("Cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		t.Fatalf("Failed to get nonce: %v", err)
	}

	value := big.NewInt(1000000000000000000) // 1 ETH
	gasLimit := uint64(21000)
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		t.Fatalf("Failed to get gas price: %v", err)
	}

	toAddress := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8") // Another test address
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		t.Fatalf("Failed to get chainID: %v", err)
	}

	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		t.Fatalf("Failed to sign tx: %v", err)
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		t.Fatalf("Failed to send tx: %v", err)
	}

	t.Logf("Transaction sent: %s", signedTx.Hash().Hex())

	// Wait for transaction to be mined
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	receipt, err := waitMinedWithRetry(ctx, client, signedTx)
	if err != nil {
		t.Fatalf("Failed to wait for tx mining: %v", err)
	}

	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Errorf("Transaction failed status: %v", receipt.Status)
	}
	t.Logf("Transaction mined in block %v", receipt.BlockNumber)
}

func waitMinedWithRetry(ctx context.Context, client *ethclient.Client, tx *types.Transaction) (*types.Receipt, error) {
	queryTicker := time.NewTicker(time.Second)
	defer queryTicker.Stop()

	for {
		receipt, err := client.TransactionReceipt(ctx, tx.Hash())
		if err == nil {
			return receipt, nil
		}

		if err.Error() == "not found" || err.Error() == "transaction indexing is in progress" {
			// Retry
		} else {
			// Check if it's the specific json error structure stringified
			// "transaction indexing is in progress" might be wrapped
			// For now, just log and retry if it contains "indexing"
			// But better to be safe.
			// Actually, let's just retry on any error until timeout, assuming it's transient.
			// But real errors should fail.
			// Geth returns "transaction indexing is in progress" as the error string.
		}

		// Wait for the next round
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-queryTicker.C:
		}
	}
}
