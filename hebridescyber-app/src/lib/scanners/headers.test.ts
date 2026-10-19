import { describe, it, expect, vi, afterEach } from "vitest";
import { buildHeaderAnalysis, checkHeaders } from "./headers";

function makeResponse(headers: Record<string, string> = {}, status = 200): Response {
  return new Response(null, { status, headers });
}

describe("buildHeaderAnalysis", () => {
  it("reports every OWASP header missing and scores 0 for a bare response", () => {
    const result = buildHeaderAnalysis(makeResponse());
    expect(result.owasp.missingCount).toBe(10);
    expect(result.owasp.score).toBe(0);
    expect(result.owasp.headers.every((h) => !h.present)).toBe(true);
  });

  it("scores 100 when every OWASP header is present", () => {
    const result = buildHeaderAnalysis(
      makeResponse({
        "strict-transport-security": "max-age=63072000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
        "cross-origin-embedder-policy": "require-corp",
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-resource-policy": "same-origin",
        "cache-control": "no-store",
      })
    );
    expect(result.owasp.missingCount).toBe(0);
    expect(result.owasp.score).toBe(100);
  });

  describe("CSP analysis", () => {
    it("grades F and flags missing when there is no CSP header", () => {
      const result = buildHeaderAnalysis(makeResponse());
      expect(result.csp.present).toBe(false);
      expect(result.csp.grade).toBe("F");
    });

    it("grades A for a modern policy: nonce + strict-dynamic and all three framing directives", () => {
      const result = buildHeaderAnalysis(
        makeResponse({
          "content-security-policy":
            "default-src 'self'; script-src 'nonce-r4nd0m' 'strict-dynamic' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        })
      );
      // 'unsafe-inline' here is a legacy fallback a modern browser ignores
      // because the nonce/strict-dynamic is present — so it must NOT count.
      expect(result.csp.grade).toBe("A");
      expect(result.csp.issues).toEqual([]);
    });

    it("downgrades 'unsafe-inline' with no nonce/hash/strict-dynamic to a serious weakness", () => {
      const result = buildHeaderAnalysis(
        makeResponse({
          "content-security-policy":
            "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        })
      );
      // One serious weakness, no gaps → weak (C), not absent (F) and not A/B.
      expect(result.csp.grade).toBe("C");
      expect(result.csp.issues.some((i) => i.includes("'unsafe-inline'") && i.includes("script-src"))).toBe(true);
    });

    it("flags 'unsafe-eval' and names the directive", () => {
      const result = buildHeaderAnalysis(
        makeResponse({ "content-security-policy": "script-src 'self' 'unsafe-eval'" })
      );
      expect(result.csp.issues.some((i) => i.includes("'unsafe-eval'") && i.includes("script-src"))).toBe(true);
    });

    it("flags a wildcard script-src with the offending token", () => {
      const result = buildHeaderAnalysis(makeResponse({ "content-security-policy": "script-src *" }));
      expect(result.csp.issues.some((i) => i.includes("Wildcard source '*'"))).toBe(true);
    });

    it("flags a missing frame-ancestors as a graded gap", () => {
      // Strong script-src but no framing control: a hardening gap, not a bypass.
      const result = buildHeaderAnalysis(
        makeResponse({ "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'" })
      );
      expect(result.csp.issues.some((i) => i.includes("frame-ancestors"))).toBe(true);
      // One gap, no serious weakness → still a strong policy (grade B).
      expect(result.csp.grade).toBe("B");
    });

    it("flags missing base-uri and form-action, both without a default-src fallback", () => {
      const result = buildHeaderAnalysis(
        makeResponse({ "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'" })
      );
      expect(result.csp.issues.some((i) => i.includes("base-uri"))).toBe(true);
      expect(result.csp.issues.some((i) => i.includes("form-action"))).toBe(true);
    });

    // Regression test: the object-src pattern used to be
    // /object-src[^;']*(?!none)/i, a negative-lookahead-after-star bug that
    // matched "object-src 'none'" too (backtracking always finds a position
    // where "none" isn't immediately next), so a correctly locked-down
    // policy got falsely flagged as "Missing object-src 'none'".
    it("does not flag object-src 'none' as missing", () => {
      const result = buildHeaderAnalysis(
        makeResponse({ "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'" })
      );
      expect(result.csp.issues.some((i) => i.includes("object-src"))).toBe(false);
    });

    it("does flag object-src set to something other than 'none'", () => {
      const result = buildHeaderAnalysis(
        makeResponse({ "content-security-policy": "default-src 'self'; object-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'" })
      );
      expect(result.csp.issues.some((i) => i.includes("object-src"))).toBe(true);
    });

    it("grades F for a policy with several serious weaknesses at once", () => {
      const result = buildHeaderAnalysis(
        makeResponse({ "content-security-policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval' data:" })
      );
      expect(result.csp.grade).toBe("F");
    });

    it("credits a hash as mitigation for 'unsafe-inline', like a nonce", () => {
      const result = buildHeaderAnalysis(
        makeResponse({
          "content-security-policy":
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'sha256-abc123'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        })
      );
      expect(result.csp.issues.some((i) => i.includes("'unsafe-inline'"))).toBe(false);
      expect(result.csp.grade).toBe("A");
    });

    it("falls back to default-src for the script directive when script-src is absent", () => {
      const result = buildHeaderAnalysis(
        makeResponse({ "content-security-policy": "default-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'" })
      );
      expect(result.csp.issues.some((i) => i.includes("'unsafe-inline'") && i.includes("default-src"))).toBe(true);
    });
  });

  describe("cookie analysis", () => {
    it("flags every missing security attribute on a bare cookie", () => {
      const result = buildHeaderAnalysis(makeResponse({ "set-cookie": "session=abc123" }));
      expect(result.cookies).toHaveLength(1);
      expect(result.cookies[0].secure).toBe(false);
      expect(result.cookies[0].httpOnly).toBe(false);
      expect(result.cookies[0].issues).toHaveLength(3);
    });

    it("reports no issues for a fully-locked-down cookie", () => {
      const result = buildHeaderAnalysis(
        makeResponse({ "set-cookie": "session=abc123; Secure; HttpOnly; SameSite=Strict" })
      );
      expect(result.cookies[0].secure).toBe(true);
      expect(result.cookies[0].httpOnly).toBe(true);
      expect(result.cookies[0].sameSite).toBe("strict");
      expect(result.cookies[0].issues).toEqual([]);
    });

    it("recognises the __Host- and __Secure- name prefixes", () => {
      const result = buildHeaderAnalysis(
        makeResponse({ "set-cookie": "__Host-session=abc; Secure; HttpOnly; SameSite=Strict; Path=/" })
      );
      expect(result.cookies[0].hasHostPrefix).toBe(true);
    });

    it("returns an empty array when there is no Set-Cookie header at all", () => {
      const result = buildHeaderAnalysis(makeResponse());
      expect(result.cookies).toEqual([]);
    });
  });

  describe("CORS analysis", () => {
    it("flags a wildcard Access-Control-Allow-Origin", () => {
      const result = buildHeaderAnalysis(makeResponse({ "access-control-allow-origin": "*" }));
      expect(result.cors.wildcardOrigin).toBe(true);
      expect(result.cors.issues.length).toBeGreaterThan(0);
    });

    it("flags wildcard origin combined with allow-credentials as a misconfiguration signal", () => {
      const result = buildHeaderAnalysis(
        makeResponse({ "access-control-allow-origin": "*", "access-control-allow-credentials": "true" })
      );
      expect(result.cors.allowCredentialsWithWildcard).toBe(true);
    });

    it("does not flag a specific, non-wildcard origin", () => {
      const result = buildHeaderAnalysis(makeResponse({ "access-control-allow-origin": "https://trusted.example.com" }));
      expect(result.cors.wildcardOrigin).toBe(false);
      expect(result.cors.issues).toEqual([]);
    });
  });

  describe("information disclosure", () => {
    it("flags a Server header containing a version number", () => {
      const result = buildHeaderAnalysis(makeResponse({ server: "nginx/1.18.0" }));
      expect(result.infoDisclosure.issues.some((i) => i.includes("Server header"))).toBe(true);
    });

    it("does not flag a Server header with no version digits", () => {
      const result = buildHeaderAnalysis(makeResponse({ server: "nginx" }));
      expect(result.infoDisclosure.issues).toEqual([]);
    });

    it("flags X-Powered-By and X-Generator", () => {
      const result = buildHeaderAnalysis(makeResponse({ "x-powered-by": "PHP/8.1", "x-generator": "WordPress" }));
      expect(result.infoDisclosure.issues).toHaveLength(2);
    });
  });

  it("carries through the response's HTTP status", () => {
    const result = buildHeaderAnalysis(makeResponse({}, 403));
    expect(result.httpStatus).toBe(403);
  });

  describe("request smuggling surface", () => {
    it("flags a response carrying both Content-Length and Transfer-Encoding", () => {
      const result = buildHeaderAnalysis(makeResponse({ "content-length": "42", "transfer-encoding": "chunked" }));
      expect(result.smugglingSurface.issues).toHaveLength(1);
      expect(result.smugglingSurface.issues[0]).toContain("Content-Length (42)");
      expect(result.smugglingSurface.issues[0]).toContain("Transfer-Encoding (chunked)");
      expect(result.smugglingSurface.contentLength).toBe("42");
      expect(result.smugglingSurface.transferEncoding).toBe("chunked");
    });

    it("does not flag a response with only Content-Length", () => {
      const result = buildHeaderAnalysis(makeResponse({ "content-length": "42" }));
      expect(result.smugglingSurface.issues).toEqual([]);
    });

    it("does not flag a response with only Transfer-Encoding", () => {
      const result = buildHeaderAnalysis(makeResponse({ "transfer-encoding": "chunked" }));
      expect(result.smugglingSurface.issues).toEqual([]);
    });

    it("does not flag a response with neither header", () => {
      const result = buildHeaderAnalysis(makeResponse({}));
      expect(result.smugglingSurface.issues).toEqual([]);
      expect(result.smugglingSurface.contentLength).toBeNull();
      expect(result.smugglingSurface.transferEncoding).toBeNull();
    });
  });
});

describe("checkHeaders", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("fetches the target and returns a checked result", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(null, { status: 200, headers: { "x-frame-options": "DENY" } }))
    );

    const result = await checkHeaders("https://example.com");

    expect(result.status).toBe("checked");
    if (result.status === "checked") {
      expect(result.httpStatus).toBe(200);
      expect(result.owasp.headers.find((h) => h.name === "x-frame-options")?.present).toBe(true);
    }
  });

  it("returns a status: error result when the fetch fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("getaddrinfo ENOTFOUND")));

    const result = await checkHeaders("https://does-not-resolve.invalid");

    expect(result.status).toBe("error");
    if (result.status === "error") {
      expect(result.note).toContain("ENOTFOUND");
    }
  });
});

describe("cookie analysis — platform cookies and SameSite", () => {
  it("leaves out Azure's ARR affinity cookies but still analyses the app's own", () => {
    const result = buildHeaderAnalysis(
      makeResponse({
        "set-cookie":
          "ARRAffinity=abc; path=/; secure; httponly, ARRAffinitySameSite=abc; path=/; secure; samesite=none; httponly, session=xyz; path=/",
      })
    );
    // Regression: the filter set once held "arraaffinity" (typo), so nothing matched.
    expect(result.cookies.map((c) => c.name)).toEqual(["session"]);
    expect(result.cookies[0].issues.length).toBeGreaterThan(0);
  });

  it("accepts SameSite=None when Secure is set (RFC 6265bis) but flags it without Secure", () => {
    const withSecure = buildHeaderAnalysis(makeResponse({ "set-cookie": "embed=1; path=/; secure; httponly; samesite=none" }));
    expect(withSecure.cookies[0].issues).toEqual([]);

    const withoutSecure = buildHeaderAnalysis(makeResponse({ "set-cookie": "embed=1; path=/; httponly; samesite=none" }));
    expect(withoutSecure.cookies[0].issues).toContain("SameSite not set to Strict/Lax — CSRF risk");
  });
});
