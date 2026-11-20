package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrew-barvas/hebrides-cyber/agent/internal/config"
)

const token = "hcd_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersionAndHelp(t *testing.T) {
	if code, out, _ := runCLI("version"); code != 0 || !strings.HasPrefix(out, "hebrides-agent ") {
		t.Errorf("version: %d %q", code, out)
	}
	if code, out, _ := runCLI("help"); code != 0 || !strings.Contains(out, "enrol") {
		t.Errorf("help: %d %q", code, out)
	}
	if code, _, _ := runCLI(); code != 2 {
		t.Error("no command is a usage error")
	}
	if code, _, errs := runCLI("scan"); code != 2 || !strings.Contains(errs, "unknown command") {
		t.Error("unknown command is a usage error")
	}
}

func TestEnrolValidatesAndSaves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if code, _, _ := runCLI("enrol", "--config", path, "--token", "bad"); code != 2 {
		t.Error("bad token must be refused")
	}
	if code, _, _ := runCLI("enrol", "--config", path, "--token", token, "--server", "http://evil.example"); code != 2 {
		t.Error("http server must be refused")
	}
	code, out, errs := runCLI("enrol", "--config", path, "--token", token)
	if code != 0 || !strings.Contains(out, "Saved") {
		t.Fatalf("enrol: %d %q %q", code, out, errs)
	}
	cfg, err := config.Load(path)
	if err != nil || cfg.Token != token || cfg.Server != "https://www.hebridescyber.co.uk" {
		t.Fatalf("saved config wrong: %#v %v", cfg, err)
	}
}

func TestReportWithoutConfig(t *testing.T) {
	code, _, errs := runCLI("report", "--config", filepath.Join(t.TempDir(), "none.json"))
	if code != 1 || !strings.Contains(errs, "enrol") {
		t.Errorf("report without config: %d %q", code, errs)
	}
}

func TestReportRefusesInsecureSavedServer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	_ = config.Save(path, config.Config{Server: "http://evil.example", Token: token})
	if code, _, errs := runCLI("report", "--config", path); code != 1 || !strings.Contains(errs, "https") {
		t.Errorf("a tampered config must not send over http: %d %q", code, errs)
	}
}
