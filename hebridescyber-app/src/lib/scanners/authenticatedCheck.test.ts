import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Stub the signed-in crawl so no real browser launches; checkAuthenticated
// only needs its return value threaded through.
const { crawlMock, crawlFindingsMock } = vi.hoisted(() => ({
  crawlMock: vi.fn(),
  crawlFindingsMock: vi.fn(),
}));
vi.mock("./authenticatedCrawl", () => ({
  checkAuthenticatedCrawl: crawlMock,
  buildAuthenticatedCrawlFindings: crawlFindingsMock,
}));

import {
  resolveAuthCredential,
  checkAuthenticated,
  buildAuthenticatedFindings,
  type AuthenticatedCheckResult,
  type StoredAuthCredential,
} from "./authenticatedCheck";
import { buildHeaderAnalysis } from "./headers";

function storedRow(overrides: Partial<StoredAuthCredential> = {}): StoredAuthCredential {
  return { auth_type: null, cookie_value: null, basic_username: null, basic_password: null, ...overrides };
}

describe("resolveAuthCredential", () => {
  it("returns no credential (but decrypted) for a null row", () => {
    expect(resolveAuthCredential(null)).toEqual({ credential: null, decrypted: true });
  });

  it("reads a plaintext cookie credential", () => {
    const r = resolveAuthCredential(storedRow({ auth_type: "cookie", cookie_value: "session=abc" }));
    expect(r).toEqual({ credential: { type: "cookie", cookieValue: "session=abc" }, decrypted: true });
  });

  it("reads a plaintext basic credential", () => {
    const r = resolveAuthCredential(storedRow({ auth_type: "basic", basic_username: "u", basic_password: "p" }));
    expect(r).toEqual({ credential: { type: "basic", username: "u", password: "p" }, decrypted: true });
  });

  it("yields no credential when the row's type/fields don't line up", () => {
    expect(resolveAuthCredential(storedRow({ auth_type: "cookie", cookie_value: null })).credential).toBeNull();
    expect(resolveAuthCredential(storedRow({ auth_type: "basic", basic_username: "u", basic_password: null })).credential).toBeNull();
    expect(resolveAuthCredential(storedRow({ auth_type: "unknown" })).credential).toBeNull();
  });

  it("reports decrypted:false (never ciphertext) when a sealed secret can't be decrypted", () => {
    // A malformed enc:v1: value makes decryptSecret throw → revealSecrets null.
    const r = resolveAuthCredential(storedRow({ auth_type: "cookie", cookie_value: "enc:v1:bad" }));
    expect(r).toEqual({ credential: null, decrypted: false });
  });
});

describe("checkAuthenticated", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    crawlMock.mockReset().mockResolvedValue({ status: "not_applicable", note: "x" });
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("is not_applicable with no credential, and never calls the network", async () => {
    const result = await checkAuthenticated("https://example.com", null);
    expect(result.status).toBe("not_applicable");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("attaches a Cookie header for a cookie credential and returns the header analysis + crawl", async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 200, headers: { "x-frame-options": "DENY" } }));
    const result = await checkAuthenticated("https://example.com", { type: "cookie", cookieValue: "session=abc" });
    expect(result.status).toBe("checked");
    const req = fetchMock.mock.calls[0];
    expect((req[1] as RequestInit).headers).toMatchObject({ Cookie: "session=abc" });
    if (result.status !== "checked") return;
    expect(result.crawl).toEqual({ status: "not_applicable", note: "x" });
    expect(result.owasp).toBeDefined();
  });

  it("attaches a Basic Authorization header for a basic credential", async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 200 }));
    await checkAuthenticated("https://example.com", { type: "basic", username: "u", password: "p" });
    const headers = (fetchMock.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Basic ${Buffer.from("u:p").toString("base64")}`);
  });

  it("returns a status:error result (never throws) when the fetch fails", async () => {
    fetchMock.mockRejectedValue(new Error("ECONNREFUSED"));
    const result = await checkAuthenticated("https://example.com", { type: "cookie", cookieValue: "x" });
    expect(result.status).toBe("error");
    if (result.status === "error") expect(result.note).toContain("ECONNREFUSED");
  });
});

describe("buildAuthenticatedFindings", () => {
  beforeEach(() => crawlFindingsMock.mockReset().mockReturnValue([]));

  function checked(headers: Record<string, string>): AuthenticatedCheckResult {
    return { status: "checked", ...buildHeaderAnalysis(new Response(null, { status: 200, headers })) };
  }

  it("returns nothing for a non-checked result", () => {
    expect(buildAuthenticatedFindings({ status: "not_applicable", note: "x" })).toEqual([]);
    expect(buildAuthenticatedFindings({ status: "error", note: "x" })).toEqual([]);
  });

  it("reports missing security headers under the auth-check namespace", () => {
    const findings = buildAuthenticatedFindings(checked({}));
    const missing = findings.find((f) => f.checkId === "auth-check.missing-headers");
    expect(missing).toBeDefined();
    expect(missing!.severity).toBe("medium");
    expect(missing!.detail).toContain("saved authentication credential");
  });

  it("grades an insecure authenticated session cookie as high, distinct from headers.*", () => {
    const findings = buildAuthenticatedFindings(checked({ "set-cookie": "SID=abc123; Path=/" }));
    const cookie = findings.find((f) => f.checkId === "auth-check.session-cookie-insecure:SID");
    expect(cookie).toBeDefined();
    expect(cookie!.severity).toBe("high");
    expect(cookie!.detail).toContain("only observed after authenticating");
  });

  it("flags a CORS wildcard on an authenticated response as critical", () => {
    const findings = buildAuthenticatedFindings(checked({ "access-control-allow-origin": "*" }));
    const cors = findings.find((f) => f.checkId === "auth-check.cors-wildcard");
    expect(cors).toBeDefined();
    expect(cors!.severity).toBe("critical");
  });

  it("flags an absent CSP (grade F) on the authenticated page", () => {
    // No CSP header at all → grade F.
    const findings = buildAuthenticatedFindings(checked({}));
    expect(findings.some((f) => f.checkId === "auth-check.csp-absent" && f.severity === "high")).toBe(true);
  });

  it("appends the signed-in crawl's findings", () => {
    crawlFindingsMock.mockReturnValue([{ checkId: "crawl.auth.header-gap:x", severity: "medium", title: "t", detail: "d" }]);
    const findings = buildAuthenticatedFindings(checked({ "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'" }));
    expect(findings.some((f) => f.checkId === "crawl.auth.header-gap:x")).toBe(true);
  });
});
