// Package upload sends an inventory to the HebridesCyber API over HTTPS.
package upload

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/andrew-barvas/hebrides-cyber/agent/internal/inventory"
)

// DefaultServer is the production API origin (the www host: the bare
// domain only redirects, and the agent never follows redirects).
const DefaultServer = "https://www.hebridescyber.co.uk"

// InventoryPath is the endpoint, relative to the server origin.
const InventoryPath = "/api/agent/inventory"

// TokenPattern is the device token format the dashboard issues.
var TokenPattern = regexp.MustCompile(`^hcd_[A-Za-z0-9_-]{43}$`)

// ErrTokenRejected means the server refused the token (revoked or unknown).
var ErrTokenRejected = errors.New("the server rejected this device token (revoked or unknown): issue a new one from the dashboard and run `hebrides-agent enrol` again")

// ValidateServer accepts only https:// origins with no path, query or
// credentials. Plain http is allowed for localhost only, and only when
// allowInsecureLocalhost is set (development against `npm run dev`).
func ValidateServer(raw string, allowInsecureLocalhost bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return nil, fmt.Errorf("server URL: %w", err)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("server URL must be an origin like https://www.hebridescyber.co.uk, with no path, query or credentials")
	}
	if u.Host == "" {
		return nil, errors.New("server URL has no host")
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		host := u.Hostname()
		if allowInsecureLocalhost && (host == "localhost" || net.ParseIP(host).IsLoopback()) {
			return u, nil
		}
		return nil, errors.New("server URL must use https (plain http is only allowed for localhost with --allow-insecure-localhost)")
	default:
		return nil, fmt.Errorf("server URL scheme %q is not https", u.Scheme)
	}
}

// Client posts inventories.
type Client struct {
	Server    *url.URL
	Token     string
	UserAgent string
	HTTP      *http.Client
	// Sleep is replaceable in tests.
	Sleep func(time.Duration)
	// MaxAttempts bounds retries on 429/5xx/network errors.
	MaxAttempts int
}

// NewHTTPClient refuses redirects (a redirect could carry the token to
// another host) and requires TLS 1.2 or later.
func NewHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("refusing to follow a redirect: set --server to the exact API origin")
		},
	}
}

// Response is the server's answer to a successful upload.
type Response struct {
	DeviceID    string `json:"device_id"`
	PatchStatus string `json:"patch_status"`
	Summary     string `json:"summary"`
}

// EncodeWithinLimit serialises inv, dropping software from the end until the
// body fits the server's limit, so a huge machine still reports.
func EncodeWithinLimit(inv inventory.Inventory) ([]byte, error) {
	for {
		body, err := json.Marshal(inv)
		if err != nil {
			return nil, err
		}
		if len(body) <= inventory.MaxBodyBytes {
			return body, nil
		}
		if len(inv.Software) == 0 {
			return nil, fmt.Errorf("inventory is %d bytes even with no software listed", len(body))
		}
		drop := len(inv.Software) / 10
		if drop < 1 {
			drop = 1
		}
		inv.Software = inv.Software[:len(inv.Software)-drop]
		inv.Truncated = true
	}
}

// Send uploads inv once, retrying transient failures with backoff.
func (c *Client) Send(ctx context.Context, inv inventory.Inventory) (*Response, error) {
	if !TokenPattern.MatchString(c.Token) {
		return nil, errors.New("device token is missing or malformed: run `hebrides-agent enrol --token <token>`")
	}
	body, err := EncodeWithinLimit(inv)
	if err != nil {
		return nil, err
	}
	endpoint := c.Server.JoinPath(InventoryPath).String()
	attempts := c.MaxAttempts
	if attempts < 1 {
		attempts = 4
	}
	sleep := c.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		resp, retryAfter, err := c.post(ctx, endpoint, body)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		var perm permanentError
		if errors.As(err, &perm) || attempt == attempts {
			break
		}
		wait := retryAfter
		if wait <= 0 {
			wait = time.Duration(1<<(attempt-1)) * 5 * time.Second
		}
		if wait > 10*time.Minute {
			wait = 10 * time.Minute
		}
		sleep(wait)
	}
	var perm permanentError
	if errors.As(lastErr, &perm) {
		return nil, perm.err
	}
	return nil, lastErr
}

type permanentError struct{ err error }

func (p permanentError) Error() string { return p.err.Error() }

func (c *Client) post(ctx context.Context, endpoint string, body []byte) (*Response, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, permanentError{err}
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = NewHTTPClient()
	}
	res, err := httpClient.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "refusing to follow a redirect") {
			return nil, 0, permanentError{err}
		}
		return nil, 0, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64*1024))

	switch {
	case res.StatusCode == http.StatusOK || res.StatusCode == http.StatusAccepted:
		var out Response
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, 0, permanentError{fmt.Errorf("server answered %d with unreadable JSON", res.StatusCode)}
		}
		return &out, 0, nil
	case res.StatusCode == http.StatusUnauthorized:
		return nil, 0, permanentError{ErrTokenRejected}
	case res.StatusCode == http.StatusForbidden:
		// The token is valid but the account can't use device reporting.
		return nil, 0, permanentError{fmt.Errorf("the server refused the report (403): %s", serverError(raw))}
	case res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500:
		return nil, retryAfterOf(res.Header.Get("Retry-After")), fmt.Errorf("server answered %d: %s", res.StatusCode, serverError(raw))
	default:
		return nil, 0, permanentError{fmt.Errorf("server refused the inventory (%d): %s", res.StatusCode, serverError(raw))}
	}
}

func retryAfterOf(h string) time.Duration {
	if secs, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}

func serverError(raw []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error != "" {
		return inventory.Clip(e.Error, 300)
	}
	return inventory.Clip(strings.TrimSpace(string(raw)), 300)
}
