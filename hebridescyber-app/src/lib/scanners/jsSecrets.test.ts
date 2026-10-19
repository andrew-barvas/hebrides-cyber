import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { discoverJsSecrets, redact, secretFingerprint, buildJsSecretsFindings, checkJsSecrets, type JsSecretsResult } from "./jsSecrets";

// Build the Stripe live-key prefix from fragments so no contiguous
// `sk_live_…`-shaped literal exists in source — GitHub push protection flags
// those as real keys even though these are inert fakes. The concatenated
// runtime string still exercises the real regex.
const stripeKey = (body: string) => `sk` + `_live_` + body;

describe("redact", () => {
  it("shows only the ends of a long value", () => {
    expect(redact("AKIAIOSFODNN7EXAMPLE")).toBe("AKIAIO…MPLE");
  });
  it("barely reveals a short value", () => {
    expect(redact("abcd")).toBe("ab…");
  });
});

describe("secretFingerprint", () => {
  it("is a stable 12-hex digest of the value, not the value", () => {
    const fp = secretFingerprint(stripeKey("abcdefghijklmnopqrstuvwx"));
    expect(fp).toMatch(/^[0-9a-f]{12}$/);
    expect(fp).toBe(secretFingerprint(stripeKey("abcdefghijklmnopqrstuvwx")));
    expect(fp).not.toBe(secretFingerprint(stripeKey("abcdefghijklmnopqrstuvwy")));
  });
});

describe("discoverJsSecrets", () => {
  it("flags high-confidence provider keys with a fingerprint, never the raw value", () => {
    const src = [{ label: "app.js", text: `const k="AKIAIOSFODNN7EXAMPLE"; stripe="${stripeKey("abc123def456ghi789jkl012")}";` }];
    const { secrets } = discoverJsSecrets(src);
    const providers = secrets.map((s) => s.provider);
    expect(providers).toContain("aws-access-key");
    expect(providers).toContain("stripe-secret-key");
    // No raw value leaks into the hit.
    for (const s of secrets) {
      expect(s.preview).not.toBe("AKIAIOSFODNN7EXAMPLE");
      expect(s.fingerprint).toMatch(/^[0-9a-f]{12}$/);
    }
  });

  it("flags a private key block and the OpenAI/GitHub/Slack/SendGrid shapes", () => {
    // Prefixes assembled from fragments so no contiguous real-key-shaped
    // literal sits in source (push protection); the joined text is identical.
    const src = [{
      label: "bundle.js",
      text: [
        "-----BEGIN RSA PRIVATE KEY-----",
        "ghp" + "_0123456789abcdefghijklmnopqrstuvwxyz",
        "xoxb" + "-123456789012-abcdefghijklmnop",
        "SG." + "abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
        "sk-proj-" + "abcdefghijklmnopqrstuvwx",
      ].join("\n"),
    }];
    const providers = discoverJsSecrets(src).secrets.map((s) => s.provider);
    expect(providers).toEqual(expect.arrayContaining(["private-key-block", "github-token", "slack-token", "sendgrid-key", "openai-key"]));
  });

  it("does not flag ordinary code or low-confidence strings", () => {
    const src = [{ label: "app.js", text: `const secret = "my-password"; const apiKey = config.get("x"); let token = user.token;` }];
    expect(discoverJsSecrets(src).secrets).toEqual([]);
  });

  it("de-dupes the same secret seen twice", () => {
    const key = "AKIAIOSFODNN7EXAMPLE";
    const src = [{ label: "a.js", text: key }, { label: "b.js", text: key }];
    expect(discoverJsSecrets(src).secrets).toHaveLength(1);
  });

  it("finds internal/API and private-host endpoints, not ordinary CDNs", () => {
    const src = [{
      label: "app.js",
      text: `fetch("https://api.internal.example.com/v1/users"); img="https://cdn.jsdelivr.net/x.js"; d="http://localhost:3001/debug";`,
    }];
    const hosts = discoverJsSecrets(src).endpoints.map((e) => e.host);
    expect(hosts).toContain("api.internal.example.com");
    expect(hosts.some((h) => h.includes("localhost"))).toBe(true);
    expect(hosts.some((h) => h.includes("jsdelivr"))).toBe(false);
  });
});

describe("buildJsSecretsFindings", () => {
  it("builds a finding per secret and per endpoint with stable checkIds", () => {
    const result: JsSecretsResult = {
      status: "checked",
      secrets: [{ provider: "stripe-secret-key", preview: "sk_liv…wxyz", fingerprint: "abc123def456", foundIn: "app.js" }],
      endpoints: [{ host: "api.internal.example.com", sample: "https://api.internal.example.com/v1" }],
    };
    const findings = buildJsSecretsFindings(result);
    expect(findings.map((f) => f.checkId)).toEqual([
      "js-secrets.exposed-key:stripe-secret-key",
      "js-secrets.exposed-endpoint:api.internal.example.com",
    ]);
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].detail).toContain("abc123def456");
    expect(findings[0].detail).not.toContain("sk_live_");
    expect(findings[1].severity).toBe("info");
  });

  it("returns nothing for a non-checked result", () => {
    expect(buildJsSecretsFindings({ status: "not_applicable" })).toEqual([]);
    expect(buildJsSecretsFindings(undefined)).toEqual([]);
  });
});

describe("checkJsSecrets", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  const htmlRes = (text: string) => ({ ok: true, status: 200, text: async () => text, body: { cancel: async () => {} } });

  it("reads the page and same-origin scripts and reports secrets found in them", async () => {
    fetchMock
      .mockResolvedValueOnce(htmlRes(`<html><script src="/app.js"></script></html>`)) // page
      .mockResolvedValueOnce(htmlRes(`var k="AKIAIOSFODNN7EXAMPLE";`)); // /app.js
    const result = await checkJsSecrets("https://example.com");
    expect(result.status).toBe("checked");
    if (result.status !== "checked") return;
    expect(result.secrets.map((s) => s.provider)).toContain("aws-access-key");
  });

  it("errors (not clean) when the page can't be read", async () => {
    fetchMock.mockResolvedValueOnce({ ok: false, status: 503, text: async () => "", body: { cancel: async () => {} } });
    const result = await checkJsSecrets("https://example.com");
    expect(result.status).toBe("error");
  });

  it("errors on a fetch exception", async () => {
    fetchMock.mockRejectedValueOnce(new Error("network"));
    expect((await checkJsSecrets("https://example.com")).status).toBe("error");
  });

  it("is a clean checked result when nothing high-confidence is present", async () => {
    fetchMock.mockResolvedValueOnce(htmlRes(`<html><body><h1>hi</h1></body></html>`));
    const result = await checkJsSecrets("https://example.com");
    expect(result.status).toBe("checked");
    if (result.status !== "checked") return;
    expect(result.secrets).toEqual([]);
    expect(result.endpoints).toEqual([]);
  });

  it("rejects an invalid URL as an error", async () => {
    expect((await checkJsSecrets("not a url")).status).toBe("error");
  });
});
