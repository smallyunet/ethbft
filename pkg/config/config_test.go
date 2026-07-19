package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCreatesStateDirectory(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "state", "ethbft_state.json")
	configFile := filepath.Join(dir, "config.yaml")
	configYAML := []byte("bridge:\n  stateFile: " + stateFile + "\n")
	if err := os.WriteFile(configFile, configYAML, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("ETHBFT_CONFIG", configFile)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Bridge.StateFile != stateFile {
		t.Fatalf("StateFile = %q, want %q", cfg.Bridge.StateFile, stateFile)
	}
	if info, err := os.Stat(filepath.Dir(stateFile)); err != nil || !info.IsDir() {
		t.Fatalf("state directory was not created: %v", err)
	}
}
