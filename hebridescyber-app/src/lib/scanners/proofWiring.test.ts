import { describe, it, expect, vi, afterEach } from "vitest";
import { summariseResults, type ScanResults } from "./index";
import { enrichWithProofOfExploit, isReflectedXss, validateExploit } from "./proofOfExploit";
import { confirmedProof } from "../proofEvidence";
import type { Finding } from "./index";

afterEach(() => vi.unstubAllGlobals());

const err = { status: "error", note: "x" };
function results(over: Record<string, unknown>): ScanResults {
  return {
    target_url: "https://shop.example", checked_at: "2026-10-05T00:00:00Z",
    tls: err, headers: err, dns: err, exposure: err, directoryListing: err, cloudMisconfig: err, fingerprint: err, ports: err,
    playwright: err, recon: err, webapp: err, safeBrowsing: err, waybackDiscovery: err, hibp: err, wpVulnDb: err, softwareCveDb: err,
    businessLogic: err, apiSpec: err, zap: err, backendExposure: err, ...over,
  } as unknown as ScanResults;
}

describe("findings carry what the proof needs", () => {
  it("open redirect findings record the endpoint and parameter", () => {
    const { findings } = summariseResults(results({
      businessLogic: { status: "checked", csrf: { formsFound: 0, formsWithToken: 0, formsWithoutToken: 0, formsWithoutTokenDetails: [] }, externalForms: [], autocompleteIssues: [], sequentialUrls: [], predictableIds: [], rateLimiting: { checked: false, rateLimited: false, endpoint: null, requestsSent: 0 }, openRedirects: [{ parameter: "next", endpoint: "/login", redirectedTo: "https://evil.example.com" }] },
    }));
    expect(findings.find((f) => f.checkId === "business-logic.open-redirect:next")?.metadata).toEqual({ url: "/login", parameter: "next" });
  });

  it("exposed-file findings record the path", () => {
    const { findings } = summariseResults(results({ exposure: { status: "checked", exposed: [{ path: "/.env", name: ".env file", severity: "critical", hint: "h" }], securityTxt: true } }));
    expect(findings.find((f) => f.checkId === "exposure.exposed-file:/.env")?.metadata).toEqual({ path: "/.env" });
  });
});

describe("open-redirect proof uses the finding's own endpoint", () => {
  it("re-asks the endpoint (path resolved against the target) with the external URL", async () => {
    const fetchMock = vi.fn(async (_url: string) => new Response(null, { status: 302, headers: { location: "https://evil.example.com/x" } }));
    vi.stubGlobal("fetch", fetchMock);
    const finding: Finding = { severity: "medium", title: "t", detail: "d", checkId: "business-logic.open-redirect:next", metadata: { url: "/login?lang=en", parameter: "next" } };
    const out = await validateExploit("https://shop.example/", finding);
    expect(confirmedProof(out)).not.toBeNull();
    expect(fetchMock.mock.calls[0][0]).toBe("https://shop.example/login?lang=en&next=https%3A%2F%2Fevil.example.com");
  });

  it("is unconfirmed when the URL cannot be built", async () => {
    vi.stubGlobal("fetch", vi.fn());
    const finding: Finding = { severity: "medium", title: "t", detail: "d", checkId: "business-logic.open-redirect:next", metadata: { url: "http://[bad", parameter: "next" } };
    expect(await validateExploit("https://shop.example/", finding)).toBe(finding);
  });
});

describe("ZAP reflected XSS", () => {
  it("is recognised by its alert name", () => {
    expect(isReflectedXss({ severity: "high", title: "t", detail: "d", checkId: "zap.alert:Cross Site Scripting (Reflected)" })).toBe(true);
    expect(isReflectedXss({ severity: "high", title: "t", detail: "d", checkId: "zap.alert:Cross Site Scripting (Persistent)" })).toBe(false);
    expect(isReflectedXss({ severity: "high", title: "t", detail: "d" })).toBe(false);
  });

  it("is confirmed from the alert's URL and parameter", async () => {
    vi.stubGlobal("fetch", vi.fn(async (u: string) => new Response(`<p>${new URL(u).searchParams.get("q")}</p>`, { headers: { "content-type": "text/html" } })));
    const finding: Finding = { severity: "high", title: "t", detail: "d", checkId: "zap.alert:Cross Site Scripting (Reflected)", metadata: { url: "https://shop.example/search?q=a", parameter: "q" } };
    expect(confirmedProof(await validateExploit("https://shop.example/", finding))).not.toBeNull();
  });
});

describe("enrichWithProofOfExploit cap", () => {
  it("attempts at most maxProofs findings per scan", async () => {
    const fetchMock = vi.fn(async () => new Response("", { headers: { "access-control-allow-origin": "https://evil.example.com", "access-control-allow-credentials": "true" } }));
    vi.stubGlobal("fetch", fetchMock);
    const many: Finding[] = Array.from({ length: 5 }, (_, i) => ({ severity: "high", title: `c${i}`, detail: "d", checkId: `headers.cors-reflected:${i}` }));
    const out = await enrichWithProofOfExploit("https://shop.example", many, { maxProofs: 2 });
    expect(out.filter((f) => confirmedProof(f))).toHaveLength(2);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("defaults to a sane cap", async () => {
    const fetchMock = vi.fn(async () => new Response(""));
    vi.stubGlobal("fetch", fetchMock);
    const many: Finding[] = Array.from({ length: 30 }, (_, i) => ({ severity: "high", title: `c${i}`, detail: "d", checkId: `headers.cors-reflected:${i}` }));
    await enrichWithProofOfExploit("https://shop.example", many);
    expect(fetchMock).toHaveBeenCalledTimes(20);
  });
});
