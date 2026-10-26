// Labeled fixture set for the AI-triage accuracy benchmark (bench/triage/run.ts).
//
// Each case is a tiny fixture site plus one finding that site's response
// either genuinely confirms, genuinely clears, or leaves ambiguous. The
// benchmark runs the real triageFinding() pipeline (real prompts, real
// replayProbe allowlist, real model) against each one and scores the
// model's verdict against `expected`.
//
// This is a *model* benchmark, not a code benchmark — aiTriage.test.ts
// already covers buildRecord()/parseProbeProposal() deterministically with a
// fake ChatFn. This set exists to catch prompt regressions and measure
// precision/recall of the model's judgement, which only a real model call
// can do. Needs AZURE_OPENAI_* configured; see docs/AI-TRIAGE-DESIGN.md.
//
// Deliberately small to start (CLAUDE.md-style seed set). Grow this toward
// 30-50 cases as real false positives/negatives turn up in production
// triage — add the finding + a minimal fixture that reproduces it, labeled
// with the verdict a careful human reviewer would reach.
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Finding } from "../../src/lib/scanners";
import type { TriageVerdict } from "../../src/lib/scanners/aiTriage";

export type SiteHandler = (req: IncomingMessage, res: ServerResponse) => void;

export type TriageCase = {
  name: string;
  /** What the response actually shows — the ground truth a human reviewer would reach. */
  expected: TriageVerdict;
  finding: Finding;
  site: SiteHandler;
};

function send(res: ServerResponse, status: number, contentType: string, body: string): void {
  res.writeHead(status, { "content-type": contentType, "content-length": String(Buffer.byteLength(body)) });
  res.end(body);
}

function pathOf(req: IncomingMessage): string {
  return new URL(req.url ?? "/", "http://fixture.invalid").pathname;
}

export const CASES: TriageCase[] = [
  {
    name: "reflected-xss-confirmed",
    expected: "confirmed",
    finding: {
      checkId: "reflectedParams.unescaped-reflection",
      severity: "high",
      title: "Search parameter reflected without encoding",
      detail: "The 'q' query parameter is echoed into the page without HTML-encoding.",
      metadata: { url: "/search", parameter: "q" },
    },
    site: (req, res) => {
      const u = new URL(req.url ?? "/", "http://fixture.invalid");
      if (pathOf(req) === "/search") {
        const q = u.searchParams.get("q") ?? "";
        return send(res, 200, "text/html; charset=utf-8", `<!doctype html><title>Results</title><body>You searched for: ${q}</body>`);
      }
      return send(res, 404, "text/html", "<!doctype html><title>Not found</title>");
    },
  },
  {
    name: "reflected-xss-actually-encoded",
    // Same finding shape, but the site HTML-encodes the reflection — a careful reviewer clears it.
    expected: "not_confirmed",
    finding: {
      checkId: "reflectedParams.unescaped-reflection",
      severity: "high",
      title: "Search parameter reflected without encoding",
      detail: "The 'q' query parameter is echoed into the page without HTML-encoding.",
      metadata: { url: "/search", parameter: "q" },
    },
    site: (req, res) => {
      const u = new URL(req.url ?? "/", "http://fixture.invalid");
      if (pathOf(req) === "/search") {
        const q = (u.searchParams.get("q") ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        return send(res, 200, "text/html; charset=utf-8", `<!doctype html><title>Results</title><body>You searched for: ${q}</body>`);
      }
      return send(res, 404, "text/html", "<!doctype html><title>Not found</title>");
    },
  },
  {
    name: "exposed-debug-endpoint-confirmed",
    expected: "confirmed",
    finding: {
      checkId: "exposure.exposed-file:/debug/vars",
      severity: "high",
      title: "Debug endpoint accessible at /debug/vars",
      detail: "A Go expvar-style debug endpoint is reachable without authentication and dumps internal state.",
      metadata: { path: "/debug/vars" },
    },
    site: (req, res) => {
      if (pathOf(req) === "/debug/vars") {
        return send(res, 200, "application/json", JSON.stringify({ cmdline: ["/app/server", "-env=production"], memstats: { Alloc: 1234567 } }));
      }
      return send(res, 404, "text/html", "<!doctype html><title>Not found</title>");
    },
  },
  {
    name: "exposed-debug-endpoint-spa-catchall-trap",
    // Same finding, but the path is actually caught by the SPA's catch-all shell — the classic
    // false-positive trap the AI triage step exists to catch (and buildRecord's catchAll guard).
    expected: "inconclusive",
    finding: {
      checkId: "exposure.exposed-file:/debug/vars",
      severity: "high",
      title: "Debug endpoint accessible at /debug/vars",
      detail: "A Go expvar-style debug endpoint is reachable without authentication and dumps internal state.",
      metadata: { path: "/debug/vars" },
    },
    site: (req, res) => send(res, 200, "text/html; charset=utf-8", `<!doctype html><title>App</title><body><div id="root">Loading…</div></body>`),
  },
  {
    name: "open-redirect-confirmed",
    expected: "confirmed",
    finding: {
      checkId: "openRedirect.unvalidated-target",
      severity: "medium",
      title: "Open redirect via 'next' parameter",
      detail: "The 'next' parameter controls the redirect target with no allowlist check.",
      metadata: { url: "/login", parameter: "next" },
    },
    site: (req, res) => {
      const u = new URL(req.url ?? "/", "http://fixture.invalid");
      if (pathOf(req) === "/login") {
        const next = u.searchParams.get("next");
        if (next && /^https?:\/\//.test(next)) {
          res.writeHead(302, { location: next });
          return res.end();
        }
        return send(res, 200, "text/html", "<!doctype html><title>Login</title>");
      }
      return send(res, 404, "text/html", "<!doctype html><title>Not found</title>");
    },
  },
  {
    name: "open-redirect-allowlisted",
    expected: "not_confirmed",
    finding: {
      checkId: "openRedirect.unvalidated-target",
      severity: "medium",
      title: "Open redirect via 'next' parameter",
      detail: "The 'next' parameter controls the redirect target with no allowlist check.",
      metadata: { url: "/login", parameter: "next" },
    },
    site: (req, res) => {
      if (pathOf(req) === "/login") {
        // Redirect target is always same-origin regardless of what was asked for.
        res.writeHead(302, { location: "/dashboard" });
        return res.end();
      }
      return send(res, 404, "text/html", "<!doctype html><title>Not found</title>");
    },
  },
  {
    name: "verbose-error-confirmed",
    expected: "confirmed",
    finding: {
      checkId: "errorHandling.stack-trace-leak",
      severity: "medium",
      title: "Unhandled exception leaks a stack trace",
      detail: "Requesting an unexpected content type on /api/profile returns a full server stack trace.",
      metadata: { url: "/api/profile" },
    },
    site: (req, res) => {
      if (pathOf(req) === "/api/profile") {
        return send(
          res,
          500,
          "text/plain",
          "TypeError: Cannot read properties of undefined (reading 'id')\n    at ProfileHandler (/app/src/handlers/profile.js:42:18)\n    at Layer.handle (/app/node_modules/express/lib/router/layer.js:95:5)"
        );
      }
      return send(res, 404, "text/html", "<!doctype html><title>Not found</title>");
    },
  },
  {
    name: "verbose-error-generic-page",
    expected: "not_confirmed",
    finding: {
      checkId: "errorHandling.stack-trace-leak",
      severity: "medium",
      title: "Unhandled exception leaks a stack trace",
      detail: "Requesting an unexpected content type on /api/profile returns a full server stack trace.",
      metadata: { url: "/api/profile" },
    },
    site: (req, res) => {
      if (pathOf(req) === "/api/profile") {
        return send(res, 500, "application/json", JSON.stringify({ error: "internal_server_error", requestId: "a1b2c3" }));
      }
      return send(res, 404, "text/html", "<!doctype html><title>Not found</title>");
    },
  },
];
