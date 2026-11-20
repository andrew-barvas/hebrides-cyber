// Package collect reads the device inventory from the operating system's own
// sources. It only runs local, read-only commands and reads local files: it
// never opens a network connection of its own and never scans anything.
// (macOS's softwareupdate and Windows Update ask the vendor's update service
// what is available, exactly as the OS does on its own schedule.)
//
// Every parser is a pure function over command output, so the tests run on
// any OS from fixture files in testdata/.
package collect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/andrew-barvas/hebrides-cyber/agent/internal/inventory"
)

// Result is a finished command. A non-zero exit is not an error: dnf
// check-update exits 100 when updates are available.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// RunFunc runs a command. It returns an error only when the command couldn't
// be run at all (not found, timed out, output too large).
type RunFunc func(ctx context.Context, name string, args ...string) (Result, error)

// Env is everything a collector touches, so tests can replace it.
type Env struct {
	Run      RunFunc
	ReadFile func(path string) ([]byte, error)
	Hostname func() (string, error)
	Now      func() time.Time
	GOOS     string
	GOARCH   string
}

// maxOutputBytes caps any one command's output.
const maxOutputBytes = 64 * 1024 * 1024

// commandTimeout bounds each command. Windows Update and softwareupdate
// searches can take many minutes: a Windows Update search on a Windows 11
// test machine took 20 minutes while another search was running. The agent
// runs once a day from the OS scheduler, so waiting is cheap; a timeout is
// recorded as "pending updates unknown", never as up to date.
const commandTimeout = 30 * time.Minute

type cappedBuffer struct {
	buf      bytes.Buffer
	overflow bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > maxOutputBytes {
		c.overflow = true
		return 0, errors.New("output too large")
	}
	return c.buf.Write(p)
}

// ExecRun runs a real command with stdin closed, a C locale (stable output
// to parse) and a timeout.
func ExecRun(ctx context.Context, name string, args ...string) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	// A nil Stdin is the null device, so nothing can block waiting for input.
	cmd.Stdin = nil
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	var stdout, stderr cappedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if stdout.overflow {
		return Result{}, fmt.Errorf("%s: output over %d bytes", name, maxOutputBytes)
	}
	if ctx.Err() != nil {
		return Result{}, fmt.Errorf("%s: timed out after %s", name, commandTimeout)
	}
	res := Result{Stdout: stdout.buf.Bytes(), Stderr: stderr.buf.Bytes()}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	if err != nil {
		return Result{}, err
	}
	return res, nil
}

// SystemEnv is the real environment.
func SystemEnv() Env {
	return Env{
		Run:      ExecRun,
		ReadFile: os.ReadFile,
		Hostname: os.Hostname,
		Now:      time.Now,
		GOOS:     runtime.GOOS,
		GOARCH:   runtime.GOARCH,
	}
}

// Collect gathers the inventory for env.GOOS. Collector failures are
// recorded in Errors and leave the matching *Checked flag false; they never
// abort the whole report.
func Collect(ctx context.Context, env Env, agentVersion string) inventory.Inventory {
	inv := inventory.Inventory{
		SchemaVersion: inventory.SchemaVersion,
		AgentVersion:  agentVersion,
		CollectedAt:   env.Now().UTC().Format(time.RFC3339),
	}
	if h, err := env.Hostname(); err == nil {
		inv.Hostname = h
	}
	switch env.GOOS {
	case "windows":
		collectWindows(ctx, env, &inv)
	case "darwin":
		collectMacOS(ctx, env, &inv)
	case "linux":
		collectLinux(ctx, env, &inv)
	default:
		inv.OS = inventory.OS{Family: env.GOOS, Name: env.GOOS, Arch: env.GOARCH}
		inv.Errors = append(inv.Errors, "unsupported operating system: "+env.GOOS)
	}
	inv.Normalise()
	return inv
}

// addErr records a collector failure without leaking a whole stderr dump.
func addErr(inv *inventory.Inventory, what string, err error) {
	msg := what + ": " + strings.TrimSpace(err.Error())
	inv.Errors = append(inv.Errors, inventory.Clip(msg, inventory.MaxErrorString))
}

// runOK runs a command and turns a non-zero exit into an error carrying the
// first line of stderr.
func runOK(ctx context.Context, env Env, name string, args ...string) ([]byte, error) {
	res, err := env.Run(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("%s exited %d: %s", name, res.ExitCode, firstLine(res.Stderr))
	}
	return res.Stdout, nil
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return inventory.Clip(s, 200)
}

// lines splits output on LF, dropping a trailing CR from each line.
func lines(b []byte) []string {
	raw := strings.Split(string(b), "\n")
	out := make([]string, 0, len(raw))
	for _, l := range raw {
		out = append(out, strings.TrimRight(l, "\r"))
	}
	return out
}

// stripBOM removes a UTF-8 byte-order mark (PowerShell may emit one).
func stripBOM(b []byte) []byte {
	return bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
}
