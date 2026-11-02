import { describe, it, expect } from "vitest";
import { buildHttpEvidence, redactEvidenceText, evidenceSummary, readEvidence, EXCERPT_MAX, REDACTED, SECURITY_HEADERS } from "./findingEvidence";

const now = new Date("2026-10-30T12:00:00Z");

describe("redactEvidenceText", () => {
  it("keeps .env keys but masks every value", () => {
    const out = redactEvidenceText("APP_ENV=production\nDB_PASSWORD=hunter2\nexport STRIPE_KEY='sk_live_abc'\n# comment\n");
    expect(out).toBe(`APP_ENV=${REDACTED}\nDB_PASSWORD=${REDACTED}\nexport STRIPE_KEY=${REDACTED}\n# comment\n`);
    expect(out).not.toContain("hunter2");
    expect(out).not.toContain("sk_live");
  });

  it("masks htpasswd hashes, keeping the user name", () => {
    const out = redactEvidenceText("admin:$apr1$abcd1234$Zm9vYmFyYmF6\nbob:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=");
    expect(out).not.toMatch(/apr1|W6ph5/);
    expect(out.startsWith("admin:")).toBe(true);
  });

  it("masks private keys, JWTs, AWS keys, bearer tokens, URL credentials and emails", () => {
    const text = [
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
      "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
      "id AKIAIOSFODNN7EXAMPLE",
      "Authorization Bearer abc.def-123",
      "dsn postgres://user:s3cret@db.example.com/app",
      "[2026-10-01 10:00:00] login by jane.doe@example.com",
    ].join("\n");
    const out = redactEvidenceText(text);
    for (const secret of ["MIIEow", "eyJhbGci", "AKIAIOSFODNN7EXAMPLE", "abc.def-123", "s3cret", "jane.doe@example.com"]) {
      expect(out).not.toContain(secret);
    }
    expect(out).toContain("postgres://[redacted]@db.example.com/app");
  });

  it("masks long token-shaped strings", () => {
    expect(redactEvidenceText("key 0123456789abcdef0123456789abcdef01")).toBe(`key ${REDACTED}`);
  });

  it("is idempotent", () => {
    const once = redactEvidenceText("SECRET=abc\nmail a@b.co");
    expect(redactEvidenceText(once)).toBe(once);
  });
});

describe("buildHttpEvidence", () => {
  it("records the request, status and only allowlisted headers", () => {
    const headers = new Headers({ "content-type": "text/plain", "set-cookie": "sid=1", server: "nginx", authorization: "x" });
    const e = buildHttpEvidence({ url: "https://example.com/.env", status: 200, headers, body: "A=1", matched: "A=", now });
    expect(e).toEqual({
      request: { method: "GET", url: "https://example.com/.env" },
      response: { status: 200, headers: { "content-type": "text/plain", server: "nginx" }, bodyExcerpt: `A=${REDACTED}` },
      matched: "A=",
      capturedAt: "2026-10-30T12:00:00.000Z",
    });
  });

  it("caps the excerpt after redaction and says so", () => {
    const e = buildHttpEvidence({ url: "https://example.com/log", status: 200, headers: {}, body: "x ".repeat(EXCERPT_MAX), now });
    expect(e.response.bodyExcerpt!.length).toBe(EXCERPT_MAX);
    expect(e.response.truncated).toBe(true);
  });

  it("omits the excerpt when the body was never read", () => {
    const e = buildHttpEvidence({ url: "https://example.com/backup.zip", status: 200, headers: { "content-type": "application/zip" }, now });
    expect(e.response.bodyExcerpt).toBeUndefined();
    expect(e.response.truncated).toBeUndefined();
  });

  it("redacts the matched text too", () => {
    const e = buildHttpEvidence({ url: "u", status: 200, headers: {}, matched: "admin:$2y$10$abcdefghijklmnop", now });
    expect(e.matched).not.toContain("$2y$");
  });
});

describe("evidenceSummary and readEvidence", () => {
  it("summarises in one line, and is empty without evidence", () => {
    const e = buildHttpEvidence({ url: "https://example.com/.git/config", status: 200, headers: { "content-type": "text/plain" }, matched: "[core]", now });
    expect(evidenceSummary(e)).toBe("GET https://example.com/.git/config → 200 (text/plain); matched: [core]");
    expect(evidenceSummary(undefined)).toBe("");
  });

  it("accepts stored evidence and rejects anything malformed", () => {
    const e = buildHttpEvidence({ url: "u", status: 200, headers: {}, now });
    expect(readEvidence(JSON.parse(JSON.stringify(e)))).toEqual(e);
    expect(readEvidence(undefined)).toBeUndefined();
    expect(readEvidence({ request: {} })).toBeUndefined();
    expect(readEvidence({ request: { url: "u" }, response: { status: "200" } })).toBeUndefined();
  });
});

describe("buildHttpEvidence extraHeaders", () => {
  it("records only the named headers, and never a session or credential header", () => {
    const headers = new Headers({
      "x-frame-options": "DENY",
      "set-cookie": "sid=secret",
      authorization: "Basic abc",
      "x-unlisted": "nope",
    });
    const e = buildHttpEvidence({ url: "u", status: 200, headers, extraHeaders: [...SECURITY_HEADERS, "set-cookie", "Authorization"], now });
    expect(e.response.headers).toEqual({ "x-frame-options": "DENY" });
  });

  it("keeps policy values intact instead of applying the key=value rule", () => {
    const e = buildHttpEvidence({
      url: "u",
      status: 200,
      headers: { "strict-transport-security": "max-age=31536000; includeSubDomains", "cache-control": "no-store" },
      extraHeaders: SECURITY_HEADERS,
      now,
    });
    expect(e.response.headers["strict-transport-security"]).toBe("max-age=31536000; includeSubDomains");
    expect(e.response.headers["cache-control"]).toBe("no-store");
  });

  it("masks URL credentials, query strings, JWTs and bearer tokens in header values", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const e = buildHttpEvidence({
      url: "u",
      status: 200,
      headers: {
        "content-security-policy": `report-uri https://user:pass@r.example.com/csp?key=k1; script-src 'nonce-${jwt}'`,
        "access-control-allow-origin": "Bearer abc.def",
      },
      extraHeaders: SECURITY_HEADERS,
      now,
    });
    const csp = e.response.headers["content-security-policy"];
    expect(csp).not.toContain("pass");
    expect(csp).not.toContain("k1");
    expect(csp).not.toContain(jwt);
    expect(e.response.headers["access-control-allow-origin"]).toBe(`Bearer ${REDACTED}`);
  });

  it("allows a longer CSP than other headers", () => {
    const long = "a".repeat(1500);
    const e = buildHttpEvidence({
      url: "u",
      status: 200,
      headers: { "content-security-policy": long, "permissions-policy": long },
      extraHeaders: SECURITY_HEADERS,
      now,
    });
    expect(e.response.headers["content-security-policy"]).toHaveLength(1000);
    expect(e.response.headers["permissions-policy"]).toHaveLength(200);
  });
});
