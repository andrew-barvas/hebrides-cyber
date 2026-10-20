import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  discoverJsSecrets,
  redact,
  secretFingerprint,
  buildJsSecretsFindings,
  checkJsSecrets,
  parseSourcemap,
  sourcemapCandidateUrls,
  type JsSecretsResult,
} from "./jsSecrets";

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

  describe("expanded provider catalogue", () => {
    it("flags an npm token (distinctive prefix, no co-occurrence needed)", () => {
      const src = [{ label: "app.js", text: `const t = "npm_${"a".repeat(36)}";` }];
      expect(discoverJsSecrets(src).secrets.map((s) => s.provider)).toContain("npm-token");
    });

    it("flags a GCP service-account key only when both markers co-occur", () => {
      const withEmail = [{ label: "a.js", text: `{"type": "service_account", "client_email": "x@y.iam.gserviceaccount.com"}` }];
      expect(discoverJsSecrets(withEmail).secrets.map((s) => s.provider)).toContain("gcp-service-account");
      // The type marker alone (no client_email) is not enough — stays silent.
      const typeOnly = [{ label: "b.js", text: `const kind = {"type": "service_account"};` }];
      expect(discoverJsSecrets(typeOnly).secrets.map((s) => s.provider)).not.toContain("gcp-service-account");
    });

    it("flags an Azure storage key only inside a storage connection string", () => {
      const key = "AccountKey=" + "A".repeat(86) + "==";
      const withContext = [{ label: "a.js", text: `DefaultEndpointsProtocol=https;AccountName=acme;${key};EndpointSuffix=core.windows.net` }];
      expect(discoverJsSecrets(withContext).secrets.map((s) => s.provider)).toContain("azure-storage-key");
      // The same 88-char base64 with no storage context is not flagged.
      const noContext = [{ label: "b.js", text: `const blob = "${key}";` }];
      expect(discoverJsSecrets(noContext).secrets.map((s) => s.provider)).not.toContain("azure-storage-key");
    });

    it("flags a Twilio Account SID only alongside an auth-token marker", () => {
      const sid = "AC" + "0".repeat(32);
      const withToken = [{ label: "a.js", text: `const sid="${sid}"; const auth_token="${"f".repeat(32)}";` }];
      expect(discoverJsSecrets(withToken).secrets.map((s) => s.provider)).toContain("twilio-account-sid");
      // A bare Account SID (semi-public) with no auth-token context is not flagged.
      const sidOnly = [{ label: "b.js", text: `const accountSid = "${sid}";` }];
      expect(discoverJsSecrets(sidOnly).secrets.map((s) => s.provider)).not.toContain("twilio-account-sid");
    });
  });
});

describe("sourcemapCandidateUrls", () => {
  it("prefers the sourceMappingURL comment, then the .map sibling", () => {
    const urls = sourcemapCandidateUrls("https://x.com/a/app.js", "code()\n//# sourceMappingURL=app.min.js.map\n");
    expect(urls[0]).toBe("https://x.com/a/app.min.js.map");
    expect(urls).toContain("https://x.com/a/app.js.map");
  });

  it("uses only the .map sibling when there's no comment", () => {
    expect(sourcemapCandidateUrls("https://x.com/app.js", "code();")).toEqual(["https://x.com/app.js.map"]);
  });

  it("skips an inline data: sourcemap (already in the body, not an exposure)", () => {
    const urls = sourcemapCandidateUrls("https://x.com/app.js", "//# sourceMappingURL=data:application/json;base64,eyJ9");
    expect(urls).toEqual(["https://x.com/app.js.map"]);
  });
});

describe("parseSourcemap", () => {
  it("recognises a real source map by its sources array and reports inlined content", () => {
    const parsed = parseSourcemap(JSON.stringify({ version: 3, sources: ["a.ts", "b.ts"], sourcesContent: ["export const x=1", ""] }));
    expect(parsed).toMatchObject({ sourceCount: 2, hasSourcesContent: true });
    expect(parsed?.inlinedSources).toEqual(["export const x=1"]);
  });

  it("accepts a map with no sourcesContent (sourceCount only)", () => {
    const parsed = parseSourcemap(JSON.stringify({ version: 3, sources: ["a.ts"] }));
    expect(parsed).toMatchObject({ sourceCount: 1, hasSourcesContent: false });
  });

  it("returns null for non-JSON or JSON that isn't a source map", () => {
    expect(parseSourcemap("not json")).toBeNull();
    expect(parseSourcemap(JSON.stringify({ foo: "bar" }))).toBeNull();
    expect(parseSourcemap(JSON.stringify({ sources: "not-an-array" }))).toBeNull();
  });
});

describe("buildJsSecretsFindings", () => {
  it("builds a finding per secret, endpoint and sourcemap with stable checkIds", () => {
    const result: JsSecretsResult = {
      status: "checked",
      secrets: [{ provider: "stripe-secret-key", preview: "sk_liv…wxyz", fingerprint: "abc123def456", foundIn: "app.js" }],
      endpoints: [{ host: "api.internal.example.com", sample: "https://api.internal.example.com/v1" }],
      sourcemaps: [
        { url: "https://example.com/static/app.js.map", scriptUrl: "https://example.com/static/app.js", hasSourcesContent: true, sourceCount: 3 },
        { url: "https://example.com/static/vendor.js.map", scriptUrl: "https://example.com/static/vendor.js", hasSourcesContent: false, sourceCount: 1 },
      ],
    };
    const findings = buildJsSecretsFindings(result);
    expect(findings.map((f) => f.checkId)).toEqual([
      "js-secrets.exposed-key:stripe-secret-key",
      "js-secrets.exposed-endpoint:api.internal.example.com",
      "js-secrets.exposed-sourcemap:/static/app.js.map",
      "js-secrets.exposed-sourcemap:/static/vendor.js.map",
    ]);
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].detail).toContain("abc123def456");
    expect(findings[0].detail).not.toContain("sk_live_");
    expect(findings[1].severity).toBe("info");
    // Inlined source (sourcesContent) is medium; a plain map is low.
    expect(findings[2].severity).toBe("medium");
    expect(findings[3].severity).toBe("low");
  });

  it("falls back to the raw map url when it isn't a parseable URL", () => {
    const findings = buildJsSecretsFindings({
      status: "checked",
      secrets: [],
      endpoints: [],
      sourcemaps: [{ url: "not a url", scriptUrl: "not a url either", hasSourcesContent: false, sourceCount: 1 }],
    });
    expect(findings.map((f) => f.checkId)).toEqual(["js-secrets.exposed-sourcemap:not a url"]);
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

  const jsRes = (text: string) => ({ ok: true, status: 200, text: async () => text, body: { cancel: async () => {} } });
  const notFound = () => ({ ok: false, status: 404, text: async () => "", body: { cancel: async () => {} } });

  it("reports an exposed sourcemap and runs the secret catalogue over its inlined source", async () => {
    const npmToken = "npm_" + "a".repeat(36);
    const map = JSON.stringify({ version: 3, sources: ["src/config.ts"], sourcesContent: [`const T="${npmToken}";`] });
    fetchMock
      .mockResolvedValueOnce(jsRes(`<html><script src="/app.js"></script></html>`)) // page
      .mockResolvedValueOnce(jsRes(`console.log(1)\n//# sourceMappingURL=app.js.map`)) // /app.js
      .mockResolvedValueOnce(jsRes(map)); // /app.js.map
    const result = await checkJsSecrets("https://example.com");
    expect(result.status).toBe("checked");
    if (result.status !== "checked") return;
    expect(result.sourcemaps).toHaveLength(1);
    expect(result.sourcemaps[0]).toMatchObject({ url: "https://example.com/app.js.map", hasSourcesContent: true });
    // The npm token lived only in the sourcesContent, not the bundle.
    expect(result.secrets.map((s) => s.provider)).toContain("npm-token");
  });

  it("reports nothing for a 404 sourcemap (evidence discipline)", async () => {
    fetchMock
      .mockResolvedValueOnce(jsRes(`<html><script src="/app.js"></script></html>`)) // page
      .mockResolvedValueOnce(jsRes(`console.log(1)`)) // /app.js (no sourceMappingURL comment)
      .mockResolvedValueOnce(notFound()); // /app.js.map sibling probe → 404
    const result = await checkJsSecrets("https://example.com");
    expect(result.status).toBe("checked");
    if (result.status !== "checked") return;
    expect(result.sourcemaps).toEqual([]);
  });

  it("ignores a 200 .map that isn't actually a source map", async () => {
    fetchMock
      .mockResolvedValueOnce(jsRes(`<html><script src="/app.js"></script></html>`))
      .mockResolvedValueOnce(jsRes(`console.log(1)`))
      .mockResolvedValueOnce(jsRes(`<!doctype html><title>SPA shell</title>`)); // catch-all 200, not JSON
    const result = await checkJsSecrets("https://example.com");
    if (result.status !== "checked") throw new Error("expected checked");
    expect(result.sourcemaps).toEqual([]);
  });
});
