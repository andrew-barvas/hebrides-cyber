import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const { resolveTxtMock, resolve4Mock, resolve6Mock } = vi.hoisted(() => ({
  resolveTxtMock: vi.fn(),
  resolve4Mock: vi.fn(),
  resolve6Mock: vi.fn(),
}));

vi.mock("node:dns/promises", () => {
  const mod = { resolveTxt: resolveTxtMock, resolve4: resolve4Mock, resolve6: resolve6Mock };
  return { ...mod, default: mod };
});

import { checkDnsTxt, checkFileVerification, inspectDnsTxt, inspectFile, verificationHints, verifyDomain, validateNoSsrf, mappedIpv4, hostnameFromUrl } from "./ownership";

const TOKEN = "0123456789abcdef0123456789abcdef";
const FILE_URL = "https://example.com/.well-known/hebridescyber-verify.txt";

beforeEach(() => {
  resolveTxtMock.mockReset();
  resolve4Mock.mockReset().mockResolvedValue(["93.184.216.34"]);
  resolve6Mock.mockReset().mockRejectedValue(new Error("ENODATA"));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function stubFetch(response: () => Response | Promise<Response>) {
  const fetchMock = vi.fn(async () => response());
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("inspectDnsTxt", () => {
  it("matches our record, even split into chunks by DNS", async () => {
    resolveTxtMock.mockResolvedValue([["v=spf1 -all"], ["hebridescyber-verify=0123456789abcdef", "0123456789abcdef"]]);
    expect(await inspectDnsTxt("example.com", TOKEN)).toBe("match");
    expect(await checkDnsTxt("example.com", TOKEN)).toBe(true);
  });

  it("tells 'other TXT records' from 'none at all'", async () => {
    resolveTxtMock.mockResolvedValue([["v=spf1 -all"], ["hebridescyber-verify=wrong"]]);
    expect(await inspectDnsTxt("example.com", TOKEN)).toBe("other_txt");
    resolveTxtMock.mockResolvedValue([]);
    expect(await inspectDnsTxt("example.com", TOKEN)).toBe("no_txt");
    resolveTxtMock.mockRejectedValue(Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }));
    expect(await inspectDnsTxt("example.com", TOKEN)).toBe("no_txt");
    expect(await checkDnsTxt("example.com", TOKEN)).toBe(false);
  });
});

describe("inspectFile", () => {
  it("matches a file containing only the token, without following redirects", async () => {
    const fetchMock = stubFetch(() => new Response(`  ${TOKEN}\n`));
    expect(await inspectFile("example.com", TOKEN)).toBe("match");
    expect(fetchMock).toHaveBeenCalledWith(FILE_URL, expect.objectContaining({ redirect: "manual" }));
    expect(await checkFileVerification("example.com", TOKEN)).toBe(true);
  });

  it("names what went wrong: wrong content, redirect, missing, other errors, no connection", async () => {
    stubFetch(() => new Response("something else"));
    expect(await inspectFile("example.com", TOKEN)).toBe("wrong_content");
    stubFetch(() => new Response(null, { status: 301, headers: { location: "https://www.example.com/" } }));
    expect(await inspectFile("example.com", TOKEN)).toBe("redirect");
    stubFetch(() => new Response("not found", { status: 404 }));
    expect(await inspectFile("example.com", TOKEN)).toBe("missing");
    stubFetch(() => new Response("oops", { status: 503 }));
    expect(await inspectFile("example.com", TOKEN)).toBe("http_error");
    stubFetch(() => Promise.reject(new Error("ECONNREFUSED")));
    expect(await inspectFile("example.com", TOKEN)).toBe("unreachable");
  });

  it("never fetches a domain that resolves to a private address, or doesn't resolve", async () => {
    const fetchMock = stubFetch(() => new Response(TOKEN));
    resolve4Mock.mockResolvedValue(["10.0.0.5"]);
    expect(await inspectFile("intranet.example.com", TOKEN)).toBe("unreachable");
    resolve4Mock.mockRejectedValue(new Error("ENOTFOUND"));
    expect(await inspectFile("nowhere.example", TOKEN)).toBe("unreachable");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("verifyDomain", () => {
  it("prefers DNS and doesn't fetch the file once DNS matches", async () => {
    resolveTxtMock.mockResolvedValue([[`hebridescyber-verify=${TOKEN}`]]);
    const fetchMock = stubFetch(() => new Response(TOKEN));
    expect(await verifyDomain("example.com", TOKEN)).toEqual({ verified: true, method: "dns", dns: "match" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("falls back to the file, and reports both reasons when neither matches", async () => {
    resolveTxtMock.mockResolvedValue([]);
    stubFetch(() => new Response(TOKEN));
    expect(await verifyDomain("example.com", TOKEN)).toEqual({ verified: true, method: "file", dns: "no_txt", file: "match" });
    stubFetch(() => new Response("nope", { status: 404 }));
    expect(await verifyDomain("example.com", TOKEN)).toEqual({ verified: false, method: null, dns: "no_txt", file: "missing" });
  });
});

describe("verificationHints", () => {
  it("gives one plain next step per method that failed", () => {
    expect(verificationHints("example.com", TOKEN, { dns: "other_txt", file: "wrong_content" })).toEqual([
      "DNS: example.com has TXT records, but not the hebridescyber-verify one. Check the value was copied exactly, without extra quotes, and is on example.com itself.",
      `File: ${FILE_URL} exists but doesn't contain the token. It should contain only: ${TOKEN}`,
    ]);
    for (const file of ["missing", "http_error", "redirect", "unreachable"] as const) {
      const [, hint] = verificationHints("example.com", TOKEN, { dns: "no_txt", file });
      expect(hint).toMatch(/^File: /);
    }
    expect(verificationHints("example.com", TOKEN, { dns: "no_txt" })).toHaveLength(1);
    expect(verificationHints("example.com", TOKEN, { dns: "match", file: "match" })).toEqual([]);
  });
});

// SSRF guard. These inputs are all rejected by the bare-IP checks *before* any
// DNS resolution, so the mocked resolver above is never reached for them.
describe("validateNoSsrf — blocked ranges", () => {
  it.each([
    "http://127.0.0.1",
    "http://10.0.0.1",
    "http://172.16.5.4",
    "http://192.168.1.1",
    "http://169.254.169.254", // cloud metadata service
    "http://100.64.0.1", // RFC 6598 shared space
    "http://0.0.0.0",
  ])("rejects private/reserved IPv4 %s", async (url) => {
    await expect(validateNoSsrf(url)).rejects.toThrow(/restricted/i);
  });

  it.each([
    "http://[::1]", // loopback
    "http://[fe80::1]", // link-local (already caught)
    "http://[fe9f::1]", // link-local — PREVIOUSLY LEAKED (only fe8 was blocked)
    "http://[fea0::dead]", // link-local — previously leaked
    "http://[febf::1]", // link-local — previously leaked
    "http://[fc00::1]", // unique-local
    "http://[fd12:3456::1]", // unique-local
  ])("rejects private/reserved IPv6 %s", async (url) => {
    await expect(validateNoSsrf(url)).rejects.toThrow(/restricted/i);
  });

  it.each([
    "http://[::ffff:127.0.0.1]", // IPv4-mapped loopback — PREVIOUSLY LEAKED
    "http://[::ffff:169.254.169.254]", // IPv4-mapped metadata — PREVIOUSLY LEAKED
    "http://[::ffff:10.0.0.1]",
  ])("rejects IPv4-mapped IPv6 %s", async (url) => {
    await expect(validateNoSsrf(url)).rejects.toThrow(/restricted/i);
  });

  it("normalises alternate IPv4 encodings before blocking", async () => {
    await expect(validateNoSsrf("http://2130706433")).rejects.toThrow(/restricted/i); // decimal 127.0.0.1
    await expect(validateNoSsrf("http://0x7f000001")).rejects.toThrow(/restricted/i); // hex 127.0.0.1
  });

  it("rejects non-http(s) schemes and malformed URLs", async () => {
    await expect(validateNoSsrf("ftp://example.com")).rejects.toThrow(/permitted/i);
    await expect(validateNoSsrf("file:///etc/passwd")).rejects.toThrow(/permitted/i);
    await expect(validateNoSsrf("not a url")).rejects.toThrow(/Invalid URL/i);
  });
});

describe("mappedIpv4", () => {
  it("extracts dotted and hex-compressed IPv4-mapped addresses", () => {
    expect(mappedIpv4("::ffff:127.0.0.1")).toBe("127.0.0.1");
    expect(mappedIpv4("::ffff:7f00:1")).toBe("127.0.0.1");
    expect(mappedIpv4("::ffff:a9fe:a9fe")).toBe("169.254.169.254");
  });
  it("returns null for ordinary IPv6", () => {
    expect(mappedIpv4("::1")).toBeNull();
    expect(mappedIpv4("fe80::1")).toBeNull();
    expect(mappedIpv4("2001:db8::1")).toBeNull();
  });
});

describe("hostnameFromUrl", () => {
  it("extracts the hostname", () => {
    expect(hostnameFromUrl("https://example.com/path?q=1")).toBe("example.com");
  });
});
