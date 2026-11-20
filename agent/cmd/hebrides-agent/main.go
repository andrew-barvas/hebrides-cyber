// Command hebrides-agent reports a device's OS version, installed software
// and pending updates to HebridesCyber, for the Cyber Essentials 14-day
// patching check. It makes outbound HTTPS calls to one server only, collects
// inventory only, and never scans the network.
//
//	hebrides-agent enrol --token hcd_… [--server https://www.hebridescyber.co.uk]
//	hebrides-agent report            collect and send once (run daily by the OS scheduler)
//	hebrides-agent inventory         print exactly what would be sent, send nothing
//	hebrides-agent version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"

	"github.com/andrew-barvas/hebrides-cyber/agent/internal/collect"
	"github.com/andrew-barvas/hebrides-cyber/agent/internal/config"
	"github.com/andrew-barvas/hebrides-cyber/agent/internal/upload"
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = "0.0.0-dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `usage: hebrides-agent <command> [flags]

commands:
  enrol      save the device token from the dashboard (--token, optional --server)
  report     collect the inventory and send it once
  inventory  print the inventory that would be sent, and send nothing
  version    print the agent version

common flags:
  --config <path>   config file (default: the machine-wide path for this OS)`)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	cmd, rest := args[0], args[1:]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultPath(runtime.GOOS, os.Getenv), "config file path")
	token := fs.String("token", "", "device token from the dashboard (enrol)")
	server := fs.String("server", upload.DefaultServer, "API origin (enrol)")
	insecure := fs.Bool("allow-insecure-localhost", false, "allow http://localhost (development only)")

	switch cmd {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "hebrides-agent", version, runtime.GOOS+"/"+runtime.GOARCH)
		return 0
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	case "enrol", "enroll", "report", "inventory":
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", cmd)
		usage(stderr)
		return 2
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}

	switch cmd {
	case "enrol", "enroll":
		return enrol(*cfgPath, strings.TrimSpace(*token), *server, *insecure, stdout, stderr)
	case "inventory":
		inv := collect.Collect(ctx, collect.SystemEnv(), version)
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(inv); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		return 0
	default: // report
		return report(ctx, *cfgPath, *insecure, stdout, stderr)
	}
}

func enrol(path, token, server string, insecure bool, stdout, stderr io.Writer) int {
	if !upload.TokenPattern.MatchString(token) {
		fmt.Fprintln(stderr, "error: --token must be the device token from the dashboard (starts hcd_)")
		return 2
	}
	u, err := upload.ValidateServer(server, insecure)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if err := config.Save(path, config.Config{Server: u.String(), Token: token}); err != nil {
		fmt.Fprintln(stderr, "error: saving config:", err)
		return 1
	}
	fmt.Fprintln(stdout, "Saved. Run `hebrides-agent report` to send the first inventory.")
	return 0
}

func report(ctx context.Context, path string, insecure bool, stdout, stderr io.Writer) int {
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	u, err := upload.ValidateServer(cfg.Server, insecure)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	inv := collect.Collect(ctx, collect.SystemEnv(), version)
	for _, e := range inv.Errors {
		fmt.Fprintln(stderr, "warning:", e)
	}
	client := &upload.Client{
		Server:    u,
		Token:     cfg.Token,
		UserAgent: fmt.Sprintf("hebrides-agent/%s (%s/%s)", version, runtime.GOOS, runtime.GOARCH),
	}
	res, err := client.Send(ctx, inv)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		if errors.Is(err, upload.ErrTokenRejected) {
			return 3
		}
		return 1
	}
	fmt.Fprintf(stdout, "Sent: %d software items, %d pending updates. %s\n", len(inv.Software), len(inv.PendingUpdates), res.Summary)
	return 0
}
