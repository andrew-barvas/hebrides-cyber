package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultPath(t *testing.T) {
	env := func(k string) string {
		if k == "ProgramData" {
			return `D:\PD`
		}
		return ""
	}
	if p := DefaultPath("windows", env); !strings.HasSuffix(p, filepath.Join("HebridesCyber", "agent.json")) || !strings.HasPrefix(p, `D:\PD`) {
		t.Errorf("windows: %s", p)
	}
	if p := DefaultPath("windows", func(string) string { return "" }); !strings.HasPrefix(p, `C:\ProgramData`) {
		t.Errorf("windows fallback: %s", p)
	}
	if DefaultPath("darwin", env) != "/Library/Application Support/HebridesCyber/agent.json" {
		t.Error("darwin path")
	}
	if DefaultPath("linux", env) != "/etc/hebrides-agent/agent.json" {
		t.Error("linux path")
	}
}

func TestSaveLoadRoundTripOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "agent.json")
	want := Config{Server: "https://www.hebridescyber.co.uk", Token: "hcd_x"}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got != want {
		t.Fatalf("got %#v %v", got, err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Errorf("config must be 0600, is %o", info.Mode().Perm())
		}
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil || !strings.Contains(err.Error(), "enrol") {
		t.Errorf("missing file should say to enrol: %v", err)
	}
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("{"), 0o600)
	if _, err := Load(bad); err == nil {
		t.Error("bad JSON must fail")
	}
}
