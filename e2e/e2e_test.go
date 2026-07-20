package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
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
	if os.Getenv("ETHBFT_E2E") != "1" {
		t.Skip("Skipping E2E tests. Set ETHBFT_E2E=1 to run them.")
	}

	// 1. Setup environment
	rootDir, err := setupEnvironment(t)
	if err != nil {
		t.Fatalf("Failed to setup environment: %v", err)
	}
	defer teardownEnvironment(t, rootDir)

	// 2. Start Docker environment
	t.Log("Starting Docker environment...")
	args := []string{"-f", "docker-compose.yml", "-f", "e2e/docker-compose.override.yml", "up", "-d"}
	if os.Getenv("ETHBFT_E2E_NO_BUILD") != "1" {
		args = append(args, "--build")
	}
	cmd := getDockerComposeCommand(args...)
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

	// Wait for CometBFT as well
	if err := waitForCometBFT(t, "http://localhost:26657"); err != nil {
		t.Fatalf("CometBFT failed to become ready: %v", err)
	}

	// 4. Run tests
	t.Run("CheckBalance", func(t *testing.T) {
		testCheckBalance(t, client)
	})

	t.Run("SendTransaction", func(t *testing.T) {
		testSendTransaction(t, client)
	})

	t.Run("BridgedTransaction", func(t *testing.T) {
		testBridgedTransaction(t, client)
	})

	t.Run("NonExecutableTransactionDoesNotStall", func(t *testing.T) {
		testNonExecutableTransactionDoesNotStall(t, client)
	})

	t.Run("RestartRecovery", func(t *testing.T) {
		testRestartRecovery(t, rootDir, client)
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

	// A previous local stack may still hold bind mounts under e2e/data. Stop it
	// before replacing the test directories, otherwise a restarted container can
	// observe an unlinked datadir and lose the execution block it just committed.
	down := getDockerComposeCommand(
		"-f", "docker-compose.yml",
		"-f", "e2e/docker-compose.override.yml",
		"down", "-v", "--remove-orphans",
	)
	down.Dir = rootDir
	if output, downErr := down.CombinedOutput(); downErr != nil {
		t.Logf("pre-test docker-compose down failed: %v\n%s", downErr, output)
	}

	dataDir := filepath.Join(rootDir, "e2e", "data")
	if err := os.RemoveAll(dataDir); err != nil {
		return "", fmt.Errorf("failed to clean data dir: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create data dir: %w", err)
	}

	// Create bind-mount directories and explicitly apply their permissions.
	// MkdirAll is affected by the host umask (022 on GitHub runners), which
	// otherwise leaves the non-root ethbft container unable to persist state.
	for _, name := range []string{"geth", "cometbft", "ethbft"} {
		path := filepath.Join(dataDir, name)
		if err := os.MkdirAll(path, 0777); err != nil {
			return "", err
		}
		if err := os.Chmod(path, 0777); err != nil {
			return "", fmt.Errorf("failed to make %s writable: %w", path, err)
		}
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
    "terminalTotalDifficulty": 0,
    "shanghaiTime": 0
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
  healthAddr: "0.0.0.0:8081"
  stateFile: "/app/data/ethbft_state.json"
  logLevel: "debug"
  retryInterval: 1
  enableBridging: true
`
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte(configContent), 0644); err != nil {
		return "", err
	}
	// Docker Desktop may observe bind-mounted files a moment after the host has
	// recreated the directory tree.
	time.Sleep(500 * time.Millisecond)

	return rootDir, nil
}

func teardownEnvironment(t *testing.T, rootDir string) {
	if t.Failed() {
		t.Log("Test failed, keeping environment for debugging")
		// Print logs
		cmdLogs := getDockerComposeCommand(
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
	cmd := getDockerComposeCommand(
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

func waitForCometBFT(t *testing.T, url string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	statusURL := fmt.Sprintf("%s/status", url)

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for CometBFT")
		case <-ticker.C:
			resp, err := http.Get(statusURL)
			if err != nil {
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
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

func createSignedTx(t *testing.T, client *ethclient.Client, toAddress common.Address, value *big.Int) (*types.Transaction, *ecdsa.PrivateKey) {
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

	gasLimit := uint64(21000)
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		t.Fatalf("Failed to get gas price: %v", err)
	}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		t.Fatalf("Failed to get chainID: %v", err)
	}

	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		t.Fatalf("Failed to sign tx: %v", err)
	}
	return signedTx, privateKey
}

func testSendTransaction(t *testing.T, client *ethclient.Client) {
	// This test sends directly to Geth, bypassing the bridge logic for ingestion,
	// but relying on the bridge to produce the block.
	toAddress := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8") // Another test address
	value := big.NewInt(1000000000000000000)                                       // 1 ETH

	signedTx, _ := createSignedTx(t, client, toAddress, value)

	err := client.SendTransaction(context.Background(), signedTx)
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

func testBridgedTransaction(t *testing.T, client *ethclient.Client) {
	// This test sends a transaction to CometBFT, which should be bridged to Geth.
	toAddress := common.HexToAddress("0x9999999999999999999999999999999999999999")
	value := big.NewInt(500000000000000000) // 0.5 ETH

	signedTx, _ := createSignedTx(t, client, toAddress, value)

	// Encode tx to RLP
	var buf bytes.Buffer
	if err := signedTx.EncodeRLP(&buf); err != nil {
		t.Fatalf("Failed to encode tx: %v", err)
	}
	txBytes := buf.Bytes()
	txBase64 := base64.StdEncoding.EncodeToString(txBytes)

	// Send to CometBFT via broadcast_tx_sync
	// CometBFT is at localhost:26657
	cometURL := "http://localhost:26657"
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "broadcast_tx_sync",
		"params":  []interface{}{txBase64},
	}
	reqBytes, _ := json.Marshal(reqBody)

	resp, err := http.Post(cometURL, "application/json", bytes.NewReader(reqBytes))
	if err != nil {
		t.Fatalf("Failed to send tx to CometBFT: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CometBFT returned status %d", resp.StatusCode)
	}

	// Check response for error
	var rpcResp struct {
		Result struct {
			Code int    `json:"code"`
			Log  string `json:"log"`
			Hash string `json:"hash"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		t.Fatalf("Failed to decode CometBFT response: %v", err)
	}
	if rpcResp.Error != nil {
		t.Fatalf("CometBFT RPC error: %s", rpcResp.Error.Message)
	}
	if rpcResp.Result.Code != 0 {
		t.Fatalf("CometBFT broadcast error code %d: %s", rpcResp.Result.Code, rpcResp.Result.Log)
	}

	t.Logf("Transaction broadcast to CometBFT: %s (CometHash: %s)", signedTx.Hash().Hex(), rpcResp.Result.Hash)

	// Wait for transaction to be mined in Geth
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	receipt, err := waitMinedWithRetry(ctx, client, signedTx)
	if err != nil {
		t.Fatalf("Failed to wait for tx mining (bridged): %v", err)
	}

	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Errorf("Bridged transaction failed status: %v", receipt.Status)
	}
	t.Logf("Bridged transaction mined in block %v", receipt.BlockNumber)

	deliveryURL := "http://localhost:8081/tx/" + signedTx.Hash().Hex()
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get(deliveryURL)
		if err == nil {
			var delivery struct {
				Status      string `json:"status"`
				ELBlockHash string `json:"elBlockHash"`
			}
			decodeErr := json.NewDecoder(resp.Body).Decode(&delivery)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && decodeErr == nil && delivery.Status == "included" && delivery.ELBlockHash != "" {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("transaction receipt exists but durable delivery status did not become included")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func testRestartRecovery(t *testing.T, rootDir string, client *ethclient.Client) {
	before, err := client.BlockNumber(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cmd := getDockerComposeCommand("-f", "docker-compose.yml", "-f", "e2e/docker-compose.override.yml", "up", "-d", "--force-recreate", "--no-deps", "ethbft")
	cmd.Dir = rootDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("restart bridge: %v", err)
	}

	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, healthErr := http.Get("http://localhost:8081/health")
		if healthErr == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				after, blockErr := client.BlockNumber(context.Background())
				if blockErr == nil && after > before {
					return
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("bridge did not recover and advance after restart; EL height remained at %d", before)
		}
		time.Sleep(time.Second)
	}
}

func testNonExecutableTransactionDoesNotStall(t *testing.T, client *ethclient.Client) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tx := types.NewTransaction(0, common.HexToAddress("0x8888888888888888888888888888888888888888"), big.NewInt(1), 21_000, big.NewInt(1_000_000_000), nil)
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), key)
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := signed.EncodeRLP(&encoded); err != nil {
		t.Fatal(err)
	}
	requestBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "broadcast_tx_sync",
		"params":  []interface{}{base64.StdEncoding.EncodeToString(encoded.Bytes())},
	})
	resp, err := http.Post("http://localhost:26657", "application/json", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rpcResp struct {
		Result struct {
			Code int    `json:"code"`
			Log  string `json:"log"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		t.Fatal(err)
	}
	if rpcResp.Result.Code != 0 {
		t.Fatalf("CometBFT rejected syntactically valid transaction: %s", rpcResp.Result.Log)
	}

	before, err := client.BlockNumber(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		after, blockErr := client.BlockNumber(context.Background())
		if blockErr == nil && after > before {
			if _, receiptErr := client.TransactionReceipt(context.Background(), signed.Hash()); receiptErr == nil {
				t.Fatal("non-executable transaction unexpectedly entered a committed payload")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("non-executable transaction stalled BFT execution block production")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func waitMinedWithRetry(ctx context.Context, client *ethclient.Client, tx *types.Transaction) (*types.Receipt, error) {
	queryTicker := time.NewTicker(time.Second)
	defer queryTicker.Stop()

	for {
		receipt, err := client.TransactionReceipt(ctx, tx.Hash())
		if err == nil {
			return receipt, nil
		}

		// Wait for the next round
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-queryTicker.C:
		}
	}
}

func getDockerComposeCommand(args ...string) *exec.Cmd {
	if _, err := exec.LookPath("docker-compose"); err == nil {
		return exec.Command("docker-compose", args...)
	}
	// Fallback to "docker compose"
	newArgs := append([]string{"compose"}, args...)
	return exec.Command("docker", newArgs...)
}
