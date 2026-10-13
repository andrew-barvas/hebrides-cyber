import { describe, it, expect, vi, afterEach } from "vitest";
import {
  analyseSightings,
  decodeJwt,
  extractJwts,
  findWeakJwtSecret,
  jwtFingerprint,
  runJwtAnalysis,
  COMMON_WEAK_JWT_SECRETS,
} from "./jwtAnalysis";

// Real tokens, generated and verified against Node's own crypto (see the
// task's dev notes) — never hand-typed base64.

// HS256, secret "secret" (in COMMON_WEAK_JWT_SECRETS), has exp.
const WEAK_WITH_EXP =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyNDI2MjJ9.YfN586aSuxahl9U7Gr5kT1amwFDrsW-XAAgUMXO4gF0";
// HS256, a long random secret NOT in the list, no exp claim.
const STRONG_NO_EXP =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEiLCJpYXQiOjE1MTYyMzkwMjJ9.JkEPEbKvfdHRyXRCjjjK3qa_VRUbCm7ZqUr8pRpClUU";
// alg: none, empty signature segment.
const NONE_ALG = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.";
// jwt.io's own real playground default — HS256, secret "your-256-bit-secret", has exp.
const JWTIO_DEFAULT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

describe("decodeJwt", () => {
  it("decodes a well-formed token's header and payload", () => {
    const d = decodeJwt(WEAK_WITH_EXP);
    expect(d).not.toBeNull();
    expect(d!.header).toEqual({ alg: "HS256", typ: "JWT" });
    expect(d!.payload).toMatchObject({ sub: "1234567890", exp: 1516242622 });
  });

  it("returns null for non-JWT input", () => {
    expect(decodeJwt("not.a.jwt.at.all")).toBeNull();
    expect(decodeJwt("onlyonesegment")).toBeNull();
    expect(decodeJwt("a.b")).toBeNull();
    expect(decodeJwt("not-base64.not-base64.sig")).toBeNull();
  });

  it("decodes an alg:none token with an empty signature segment", () => {
    const d = decodeJwt(NONE_ALG);
    expect(d).not.toBeNull();
    expect(d!.header.alg).toBe("none");
    expect(d!.signatureSegment).toBe("");
  });
});

describe("extractJwts", () => {
  it("finds a JWT embedded in surrounding text", () => {
    expect(extractJwts(`Authorization: Bearer ${WEAK_WITH_EXP}`)).toEqual([WEAK_WITH_EXP]);
  });

  it("dedupes repeated occurrences", () => {
    expect(extractJwts(`${WEAK_WITH_EXP} ... ${WEAK_WITH_EXP}`)).toEqual([WEAK_WITH_EXP]);
  });

  it("never matches ordinary base64 or random text (requires the eyJ header fingerprint)", () => {
    expect(extractJwts("dGhpcyBpcyBqdXN0IHJhbmRvbSBiYXNlNjQgdGV4dA==")).toEqual([]);
    expect(extractJwts("hello world, nothing JWT-shaped here")).toEqual([]);
  });

  it("finds multiple distinct tokens", () => {
    expect(extractJwts(`${WEAK_WITH_EXP} ${STRONG_NO_EXP}`).sort()).toEqual([STRONG_NO_EXP, WEAK_WITH_EXP].sort());
  });
});

describe("findWeakJwtSecret", () => {
  it("finds a token signed with a common weak secret, by local recomputation only", () => {
    expect(findWeakJwtSecret(decodeJwt(WEAK_WITH_EXP)!)).toBe("secret");
    expect(findWeakJwtSecret(decodeJwt(JWTIO_DEFAULT)!)).toBe("your-256-bit-secret");
  });

  it("returns null for a token signed with a secret not on the list", () => {
    expect(findWeakJwtSecret(decodeJwt(STRONG_NO_EXP)!)).toBeNull();
  });

  it("returns null for alg:none (no HMAC to recompute)", () => {
    expect(findWeakJwtSecret(decodeJwt(NONE_ALG)!)).toBeNull();
  });

  it("every curated secret is a plain string, never empty", () => {
    for (const s of COMMON_WEAK_JWT_SECRETS) expect(s.length).toBeGreaterThan(0);
  });
});

describe("jwtFingerprint", () => {
  it("is stable, deterministic and never contains the raw token", () => {
    const fp = jwtFingerprint(WEAK_WITH_EXP);
    expect(fp).toBe(jwtFingerprint(WEAK_WITH_EXP));
    expect(fp).toMatch(/^[0-9a-f]{12}$/);
    expect(WEAK_WITH_EXP).not.toContain(fp);
  });

  it("differs for different tokens", () => {
    expect(jwtFingerprint(WEAK_WITH_EXP)).not.toBe(jwtFingerprint(STRONG_NO_EXP));
  });
});

describe("analyseSightings", () => {
  function sighting(token: string, surfaces: Array<"cookie" | "body" | "url">) {
    return { token, decoded: decodeJwt(token)!, surfaces: new Set(surfaces) };
  }

  it("flags alg:none", () => {
    const findings = analyseSightings([sighting(NONE_ALG, ["cookie"])], "https://example.com");
    expect(findings.map((f) => f.type)).toContain("none-algorithm");
  });

  it("flags a missing exp claim", () => {
    const findings = analyseSightings([sighting(STRONG_NO_EXP, ["cookie"])], "https://example.com");
    expect(findings.map((f) => f.type)).toContain("no-expiration");
  });

  it("does not flag a token that has both exp and a strong secret", () => {
    const d = decodeJwt(STRONG_NO_EXP)!;
    d.payload.exp = 9999999999;
    const findings = analyseSightings([{ token: STRONG_NO_EXP, decoded: d, surfaces: new Set(["cookie"]) }], "https://example.com");
    expect(findings).toEqual([]);
  });

  it("flags a weak secret, naming it in the detail", () => {
    const findings = analyseSightings([sighting(WEAK_WITH_EXP, ["cookie"])], "https://example.com");
    const f = findings.find((x) => x.type === "weak-secret");
    expect(f).toBeDefined();
    expect(f!.detail).toContain('"secret"');
  });

  it("flags a token found in a URL, regardless of its other properties", () => {
    const d = decodeJwt(STRONG_NO_EXP)!;
    d.payload.exp = 9999999999;
    const findings = analyseSightings([{ token: STRONG_NO_EXP, decoded: d, surfaces: new Set(["url"]) }], "https://example.com");
    expect(findings.map((f) => f.type)).toEqual(["exposed-in-url"]);
  });

  it("flags sent-over-http exactly once per scan, only when a token was actually seen over http", () => {
    const httpFindings = analyseSightings([sighting(NONE_ALG, ["cookie"])], "http://example.com");
    expect(httpFindings.filter((f) => f.type === "sent-over-http")).toHaveLength(1);

    const httpsFindings = analyseSightings([sighting(NONE_ALG, ["cookie"])], "https://example.com");
    expect(httpsFindings.some((f) => f.type === "sent-over-http")).toBe(false);

    const noTokenFindings = analyseSightings([], "http://example.com");
    expect(noTokenFindings).toEqual([]);
  });

  it("gives each finding a stable, token-specific url containing a fingerprint, never the raw token", () => {
    const findings = analyseSightings([sighting(NONE_ALG, ["cookie"])], "https://example.com");
    for (const f of findings) {
      if (f.type === "sent-over-http") continue;
      expect(f.url).toBe(`https://example.com#${jwtFingerprint(NONE_ALG)}`);
      expect(f.url).not.toContain(NONE_ALG);
    }
  });
});

describe("runJwtAnalysis", () => {
  afterEach(() => vi.unstubAllGlobals());

  function mockFetch(opts: { cookies?: string[]; body?: string; url?: string } = {}) {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        url: opts.url ?? "https://example.com/",
        headers: { getSetCookie: () => opts.cookies ?? [] },
        text: async () => opts.body ?? "",
      })
    );
  }

  it("returns not_applicable for an invalid URL, without fetching", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const result = await runJwtAnalysis("not a url");
    expect(result).toMatchObject({ status: "not_applicable" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("completes with no findings when no JWT is observed", async () => {
    mockFetch({ body: "<html>nothing here</html>" });
    const result = await runJwtAnalysis("https://example.com/");
    expect(result).toEqual({ status: "completed", findings: [] });
  });

  it("finds a JWT in a Set-Cookie header and reports its real issues", async () => {
    mockFetch({ cookies: [`session=${WEAK_WITH_EXP}; Path=/; HttpOnly`] });
    const result = await runJwtAnalysis("https://example.com/");
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.findings.map((f) => f.type)).toEqual(["weak-secret"]);
  });

  it("finds a JWT embedded in the response body", async () => {
    mockFetch({ body: `<script>const t = "${NONE_ALG}";</script>` });
    const result = await runJwtAnalysis("https://example.com/");
    if (result.status !== "completed") throw new Error("expected completed");
    expect(result.findings.map((f) => f.type)).toEqual(["none-algorithm"]);
  });

  it("finds a JWT in the target URL's own query string and flags exposure", async () => {
    const d = decodeJwt(STRONG_NO_EXP)!;
    d.payload.exp = 9999999999;
    mockFetch({});
    const result = await runJwtAnalysis(`https://example.com/callback?token=${STRONG_NO_EXP}`);
    if (result.status !== "completed") throw new Error("expected completed");
    expect(result.findings.map((f) => f.type)).toContain("exposed-in-url");
  });

  it("reports a fetch failure as an error, never an empty completed result", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));
    const result = await runJwtAnalysis("https://example.com/");
    expect(result).toMatchObject({ status: "error", note: expect.stringContaining("ECONNREFUSED") });
  });
});
