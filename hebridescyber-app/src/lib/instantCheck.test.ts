import { describe, it, expect, vi } from "vitest";

vi.mock("@/lib/scanners/tls", () => ({
  checkTls: vi.fn(async () => ({ status: "checked", isHttps: false, note: "Target is not served over HTTPS at all." })),
}));
vi.mock("@/lib/scanners/dns", () => ({ checkDns: vi.fn(async () => ({ status: "error", note: "lookup failed" })) }));

import { FINDINGS_SHOWN, InstantCheckError, MAX_REDIRECTS, fetchFollowingSafely, normaliseTarget, runInstantCheck } from "./instantCheck";

const ok = (headers: Record<string, string> = {}, status = 200) => new Response("<html></html>", { status, headers });
const redirect = (to: string) => new Response(null, { status: 302, headers: { location: to } });
const allow = async (u: string) => new URL(u).origin;

describe("normaliseTarget", () => {
  it.each([
    ["example.com", "https://example.com"],
    ["  Example.com/path?x=1 ", "https://example.com"],
    ["http://example.com:80/a", "http://example.com"],
    ["https://sub.example.co.uk:443", "https://sub.example.co.uk"],
  ])("accepts %s", (input, origin) => expect(normaliseTarget(input)).toBe(origin));

  it.each(["", "   ", "localhost", "ftp://example.com", "https://user:pw@example.com", "example.com:8080", "http://[::1]/", "a".repeat(300)])(
    "rejects %j",
    (input) => expect(() => normaliseTarget(input)).toThrow(InstantCheckError)
  );
});

describe("fetchFollowingSafely", () => {
  it("validates every hop, not only the first", async () => {
    const validate = vi.fn(allow);
    const fetchImpl = vi.fn().mockResolvedValueOnce(redirect("https://www.example.com/")).mockResolvedValueOnce(ok());
    const { origin } = await fetchFollowingSafely("https://example.com", fetchImpl as never, validate);
    expect(origin).toBe("https://www.example.com");
    expect(validate.mock.calls.map((c) => c[0])).toEqual(["https://example.com", "https://www.example.com/"]);
  });

  it("never fetches a hop that fails validation", async () => {
    const validate = vi.fn(async (u: string) => {
      if (u.includes("internal")) throw new Error("resolves to restricted IP address 10.0.0.5");
      return new URL(u).origin;
    });
    const fetchImpl = vi.fn().mockResolvedValueOnce(redirect("http://internal.example.com/admin"));
    await expect(fetchFollowingSafely("https://example.com", fetchImpl as never, validate)).rejects.toThrow("restricted");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("resolves relative redirects and refuses non-http schemes", async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(redirect("/home")).mockResolvedValueOnce(ok());
    await fetchFollowingSafely("https://example.com", fetchImpl as never, allow);
    expect(fetchImpl.mock.calls[1][0]).toBe("https://example.com/home");
    await expect(fetchFollowingSafely("https://example.com", vi.fn().mockResolvedValue(redirect("file:///etc/passwd")) as never, allow)).rejects.toBeInstanceOf(InstantCheckError);
  });

  it("gives up after too many redirects", async () => {
    const fetchImpl = vi.fn().mockImplementation(async () => redirect("https://example.com/again"));
    await expect(fetchFollowingSafely("https://example.com", fetchImpl as never, allow)).rejects.toThrow(/too many/);
    expect(fetchImpl).toHaveBeenCalledTimes(MAX_REDIRECTS + 1);
  });
});

describe("runInstantCheck", () => {
  it("reports TLS/headers/DNS findings only, worst first, without remediation", async () => {
    const r = await runInstantCheck("example.com", { fetchImpl: (async () => ok()) as never, validate: allow });
    expect(r.target).toBe("https://example.com");
    expect(r.findings[0].severity).toBe("critical");
    expect(r.findings[0].title).toMatch(/not served over HTTPS/);
    expect(r.findings.length).toBeLessThanOrEqual(FINDINGS_SHOWN);
    expect(r.findings.length + r.hidden).toBe(r.total);
    for (const f of r.findings) expect(Object.keys(f).sort()).toEqual(["detail", "severity", "title"]);
    expect(r.score).toBeGreaterThanOrEqual(0);
    expect(r.score).toBeLessThan(100);
  });

  it("keeps internal-range detail from the validator away from the visitor", async () => {
    const validate = async () => {
      throw new Error("example.com resolves to restricted IP address 10.1.2.3");
    };
    const err = await runInstantCheck("example.com", { fetchImpl: (async () => ok()) as never, validate }).catch((e) => e);
    expect(err).toBeInstanceOf(InstantCheckError);
    expect(err.message).not.toMatch(/10\.1\.2\.3|restricted/);
  });
});
