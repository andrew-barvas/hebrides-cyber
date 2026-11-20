package upload

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andrew-barvas/hebrides-cyber/agent/internal/inventory"
)

const goodToken = "hcd_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"

func TestTokenPattern(t *testing.T) {
	if len(goodToken) != 47 || !TokenPattern.MatchString(goodToken) {
		t.Fatal("fixture token should match")
	}
	for _, bad := range []string{"", "hc_live_x", goodToken + "x", "hcd_" + strings.Repeat("!", 43)} {
		if TokenPattern.MatchString(bad) {
			t.Errorf("%q should not match", bad)
		}
	}
}

func TestValidateServer(t *testing.T) {
	ok := []string{"https://www.hebridescyber.co.uk", "https://www.hebridescyber.co.uk/", "https://staging.example.test:8443"}
	for _, s := range ok {
		if _, err := ValidateServer(s, false); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := []string{"http://www.hebridescyber.co.uk", "ftp://x", "https://u:p@host", "https://host/api", "https://host?x=1", "https://", "http://localhost:3000", "::nope"}
	for _, s := range bad {
		if _, err := ValidateServer(s, false); err == nil {
			t.Errorf("%s should be refused", s)
		}
	}
	if _, err := ValidateServer("http://localhost:3000", true); err != nil {
		t.Errorf("localhost with the flag: %v", err)
	}
	if _, err := ValidateServer("http://127.0.0.1:3000", true); err != nil {
		t.Errorf("loopback with the flag: %v", err)
	}
	if _, err := ValidateServer("http://example.com", true); err == nil {
		t.Error("the flag only covers localhost")
	}
}

func sample() inventory.Inventory {
	inv := inventory.Inventory{SchemaVersion: 1, AgentVersion: "1.0.0", OS: inventory.OS{Family: "linux", Version: "22.04"}}
	inv.Normalise()
	return inv
}

func newClient(t *testing.T, srv *httptest.Server) (*Client, *[]time.Duration) {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	var slept []time.Duration
	return &Client{Server: u, Token: goodToken, UserAgent: "hebrides-agent/test", HTTP: srv.Client(), MaxAttempts: 3, Sleep: func(d time.Duration) { slept = append(slept, d) }}, &slept
}

func TestSendPostsInventoryWithToken(t *testing.T) {
	var gotAuth, gotUA, gotPath, gotType string
	var gotBody inventory.Inventory
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotUA, gotPath, gotType = r.Header.Get("Authorization"), r.Header.Get("User-Agent"), r.URL.Path, r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = io.WriteString(w, `{"device_id":"d1","patch_status":"passes","summary":"Up to date."}`)
	}))
	defer srv.Close()
	c, _ := newClient(t, srv)
	res, err := c.Send(context.Background(), sample())
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer "+goodToken || gotUA != "hebrides-agent/test" || gotPath != InventoryPath || gotType != "application/json" {
		t.Errorf("request wrong: %q %q %q %q", gotAuth, gotUA, gotPath, gotType)
	}
	if gotBody.OS.Version != "22.04" || res.PatchStatus != "passes" || res.Summary != "Up to date." {
		t.Errorf("round trip wrong: %#v %#v", gotBody, res)
	}
}

func TestSendRefusesMalformedToken(t *testing.T) {
	c := &Client{Server: &url.URL{Scheme: "https", Host: "x"}, Token: "nope"}
	if _, err := c.Send(context.Background(), sample()); err == nil {
		t.Fatal("malformed token must be refused before any request")
	}
}

func TestSendRetriesServerErrorsHonouringRetryAfter(t *testing.T) {
	var n int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch atomic.AddInt32(&n, 1) {
		case 1:
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"slow down"}`)
		case 2:
			w.WriteHeader(http.StatusBadGateway)
		default:
			_, _ = io.WriteString(w, `{"device_id":"d1","patch_status":"fails","summary":"2 overdue."}`)
		}
	}))
	defer srv.Close()
	c, slept := newClient(t, srv)
	res, err := c.Send(context.Background(), sample())
	if err != nil || res.PatchStatus != "fails" {
		t.Fatalf("want success on third attempt: %v %#v", err, res)
	}
	if len(*slept) != 2 || (*slept)[0] != 30*time.Second || (*slept)[1] != 10*time.Second {
		t.Errorf("backoff wrong: %v", *slept)
	}
}

func TestSendGivesUpAfterMaxAttempts(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c, slept := newClient(t, srv)
	if _, err := c.Send(context.Background(), sample()); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("want a 503 error, got %v", err)
	}
	if len(*slept) != 2 {
		t.Errorf("3 attempts means 2 sleeps, got %v", *slept)
	}
}

func TestSendTokenRejectedIsPermanent(t *testing.T) {
	var n int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c, _ := newClient(t, srv)
	_, err := c.Send(context.Background(), sample())
	if !errors.Is(err, ErrTokenRejected) || n != 1 {
		t.Fatalf("want one attempt and ErrTokenRejected, got %d %v", n, err)
	}
}

func TestSendPlanRefusalIsNotATokenRejection(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"This account's plan doesn't include device patch reporting."}`)
	}))
	defer srv.Close()
	c, slept := newClient(t, srv)
	_, err := c.Send(context.Background(), sample())
	if err == nil || errors.Is(err, ErrTokenRejected) || !strings.Contains(err.Error(), "plan") || len(*slept) != 0 {
		t.Fatalf("got %v, slept %v", err, *slept)
	}
}

func TestSendValidationErrorIsPermanentAndShowsMessage(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"software.0.name: too long"}`)
	}))
	defer srv.Close()
	c, slept := newClient(t, srv)
	_, err := c.Send(context.Background(), sample())
	if err == nil || !strings.Contains(err.Error(), "software.0.name: too long") || len(*slept) != 0 {
		t.Fatalf("got %v, slept %v", err, *slept)
	}
}

func TestSendRefusesRedirects(t *testing.T) {
	var hits int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+InventoryPath, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c, _ := newClient(t, srv)
	hc := NewHTTPClient()
	hc.Transport = srv.Client().Transport
	c.HTTP = hc
	if _, err := c.Send(context.Background(), sample()); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("want a redirect refusal, got %v", err)
	}
	if hits != 0 {
		t.Error("the token must never reach the redirect target")
	}
}

func TestSendUnreadableSuccessBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<html>")
	}))
	defer srv.Close()
	c, _ := newClient(t, srv)
	if _, err := c.Send(context.Background(), sample()); err == nil {
		t.Fatal("unreadable JSON must be an error")
	}
}

func TestEncodeWithinLimitDropsSoftware(t *testing.T) {
	inv := sample()
	for i := 0; i < 20000; i++ {
		inv.Software = append(inv.Software, inventory.Software{Name: strings.Repeat("p", 150), Version: "1.0.0", Source: "dpkg"})
	}
	body, err := EncodeWithinLimit(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > inventory.MaxBodyBytes {
		t.Fatalf("body %d over limit", len(body))
	}
	var back inventory.Inventory
	_ = json.Unmarshal(body, &back)
	if !back.Truncated || len(back.Software) >= 20000 || len(back.Software) == 0 {
		t.Errorf("want a truncated but non-empty list, got %d truncated=%v", len(back.Software), back.Truncated)
	}
}

func TestRetryAfterOf(t *testing.T) {
	if retryAfterOf("12") != 12*time.Second || retryAfterOf("") != 0 || retryAfterOf("Wed, 21 Oct 2026 07:28:00 GMT") != 0 {
		t.Fatal("Retry-After parsing wrong")
	}
}
