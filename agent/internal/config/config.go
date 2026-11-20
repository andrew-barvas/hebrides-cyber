// Package config stores the agent's server origin and device token.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Config is the on-disk agent configuration.
type Config struct {
	Server string `json:"server"`
	Token  string `json:"token"`
}

// DefaultPath is the machine-wide config file for goos. getenv is os.Getenv
// outside tests.
func DefaultPath(goos string, getenv func(string) string) string {
	switch goos {
	case "windows":
		base := getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "HebridesCyber", "agent.json")
	case "darwin":
		return "/Library/Application Support/HebridesCyber/agent.json"
	default:
		return "/etc/hebrides-agent/agent.json"
	}
}

// Load reads the config file.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, fmt.Errorf("no agent config at %s: run `hebrides-agent enrol --token <token>` first", path)
		}
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("agent config %s is not valid JSON: %w", path, err)
	}
	return c, nil
}

// Save writes the config readable by its owner only (0600; on Windows the
// ProgramData ACL applies, and the packaging step tightens it to
// Administrators and SYSTEM).
func Save(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
