import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";

const { connectMock } = vi.hoisted(() => ({ connectMock: vi.fn() }));

// Static factory only — no `importOriginal` — see dns.test.ts's comment on
// its own "node:dns/promises" mock for why: importOriginal resolves the
// built-in a second time that never unifies with the instance the module
// under test imports, so overrides silently never intercept.
vi.mock("node:tls", () => {
  const exports = { connect: connectMock, TLSSocket: class {} };
  return { ...exports, default: exports };
});

import { checkTls, classifyTrustError, readCertificate } from "./tls";

type MockSocketOptions = {
  cert?: Record<string, unknown>;
  protocol?: string | null;
  cipher?: { name: string } | null;
  /** What Node puts in socket.authorizationError for a certificate it
   *  wouldn't trust (the handshake still completes: rejectUnauthorized is off). */
  authorizationError?: string;
};

// A fake TLSSocket: a plain EventEmitter with just the methods checkTls()
// actually calls. connect()'s success callback runs on a microtask so the
// real code's `const socket = tlsConnect(...)` has already completed and
// `socket.on("timeout"/"error", ...)` listeners are attached first — the
// same ordering a real async TLS handshake would have.
function mockConnectSucceeds(opts: MockSocketOptions) {
  connectMock.mockImplementation((_options: unknown, onSecureConnect: () => void) => {
    const socket = new EventEmitter() as EventEmitter & Record<string, unknown>;
    socket.getPeerCertificate = () => opts.cert ?? {};
    socket.getProtocol = () => opts.protocol ?? "TLSv1.3";
    socket.getCipher = () => opts.cipher ?? { name: "TLS_AES_256_GCM_SHA384" };
    socket.authorizationError = opts.authorizationError ? Object.assign(new Error(opts.authorizationError), { code: opts.authorizationError }) : null;
    socket.end = vi.fn();
    socket.destroy = vi.fn();
    queueMicrotask(() => onSecureConnect.call(socket));
    return socket;
  });
}

function mockConnectEmits(event: "timeout" | "error", error?: Error) {
  connectMock.mockImplementation(() => {
    const socket = new EventEmitter() as EventEmitter & Record<string, unknown>;
    socket.destroy = vi.fn();
    socket.end = vi.fn();
    queueMicrotask(() => socket.emit(event, error));
    return socket;
  });
}

const VALID_CERT = {
  valid_to: new Date(Date.now() + 60 * 86_400_000).toUTCString(),
  valid_from: new Date(Date.now() - 30 * 86_400_000).toUTCString(),
  subject: { CN: "example.com" },
  issuer: { O: "Trusted CA" },
  fingerprint: "AA:BB",
};

describe("checkTls", () => {
  beforeEach(() => {
    connectMock.mockReset();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 200, headers: {} })));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns isHttps:false without connecting when the target isn't HTTPS", async () => {
    const result = await checkTls("http://example.com");
    expect(result.status).toBe("checked");
    if (result.status === "checked" && "isHttps" in result) expect(result.isHttps).toBe(false);
    expect(connectMock).not.toHaveBeenCalled();
  });

  it("reports certificate and connection details for a healthy HTTPS target", async () => {
    mockConnectSucceeds({ cert: VALID_CERT, protocol: "TLSv1.3", cipher: { name: "TLS_AES_256_GCM_SHA384" } });

    const result = await checkTls("https://example.com");

    expect(result.status).toBe("checked");
    if (result.status !== "checked" || !("protocol" in result)) throw new Error("expected full checked result");
    expect(result.isHttps).toBe(true);
    expect(result.protocol).toBe("TLSv1.3");
    expect(result.subject).toBe("example.com");
    expect(result.issuer).toBe("Trusted CA");
    expect(result.selfSigned).toBe(false);
    expect(result.weakProtocol).toBe(false);
    expect(result.weakCipher).toBe(false);
    expect(result.daysUntilExpiry).toBeGreaterThan(0);
  });

  it("flags TLSv1.1 as a weak protocol", async () => {
    mockConnectSucceeds({ cert: VALID_CERT, protocol: "TLSv1.1" });
    const result = await checkTls("https://example.com");
    if (result.status !== "checked" || !("weakProtocol" in result)) throw new Error("expected full checked result");
    expect(result.weakProtocol).toBe(true);
  });

  it("flags a known-weak cipher by name", async () => {
    mockConnectSucceeds({ cert: VALID_CERT, cipher: { name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA" } });
    const result = await checkTls("https://example.com");
    if (result.status !== "checked" || !("weakCipher" in result)) throw new Error("expected full checked result");
    expect(result.weakCipher).toBe(true);
  });

  // Regression: with Node's default rejectUnauthorized, every one of these
  // failed the handshake and came back as a generic "TLS connection error",
  // so none ever became a finding (verified against badssl.com).
  it.each([
    ["CERT_HAS_EXPIRED", "expired"],
    ["DEPTH_ZERO_SELF_SIGNED_CERT", "self-signed"],
    ["ERR_TLS_CERT_ALTNAME_INVALID", "hostname-mismatch"],
    ["UNABLE_TO_VERIFY_LEAF_SIGNATURE", "incomplete-chain"],
    ["SELF_SIGNED_CERT_IN_CHAIN", "untrusted"],
  ])("reads the certificate Node rejects with %s and reports it as %s", async (code, problem) => {
    mockConnectSucceeds({ cert: VALID_CERT, authorizationError: code });
    const result = await checkTls("https://example.com");
    if (result.status !== "checked" || !("trustProblem" in result)) throw new Error("expected full checked result");
    expect(result.trustProblem).toBe(problem);
    expect(result.trustErrorCode).toBe(code);
    expect(result.selfSigned).toBe(problem === "self-signed");
  });

  it("connects without rejecting, so a bad certificate can be read", async () => {
    mockConnectSucceeds({ cert: VALID_CERT });
    await checkTls("https://example.com");
    expect(connectMock.mock.calls[0][0]).toMatchObject({ host: "example.com", servername: "example.com", rejectUnauthorized: false });
  });

  // Regression: a subject-equals-issuer guess called any certificate with two
  // unreadable names self-signed.
  it("trusts Node's verdict over matching names", async () => {
    mockConnectSucceeds({ cert: { ...VALID_CERT, subject: { CN: "self.example.com" }, issuer: { CN: "self.example.com" } } });
    const result = await checkTls("https://example.com");
    if (result.status !== "checked" || !("selfSigned" in result)) throw new Error("expected full checked result");
    expect(result.selfSigned).toBe(false);
    expect(result.trustProblem).toBeNull();
  });

  it("extracts subjectAltNames from the raw subjectaltname string", async () => {
    mockConnectSucceeds({ cert: { ...VALID_CERT, subjectaltname: "DNS:example.com, DNS:www.example.com" } });
    const result = await checkTls("https://example.com");
    if (result.status !== "checked" || !("subjectAltNames" in result)) throw new Error("expected full checked result");
    expect(result.subjectAltNames).toEqual(["example.com", "www.example.com"]);
  });

  it("captures a negative daysUntilExpiry for an already-expired certificate", async () => {
    mockConnectSucceeds({
      cert: { ...VALID_CERT, valid_to: new Date(Date.now() - 5 * 86_400_000).toUTCString() },
    });
    const result = await checkTls("https://example.com");
    if (result.status !== "checked" || !("daysUntilExpiry" in result)) throw new Error("expected full checked result");
    expect(result.daysUntilExpiry).toBeLessThan(0);
  });

  it("parses a present, adequate HSTS header", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(null, { status: 200, headers: { "strict-transport-security": "max-age=63072000; includeSubDomains; preload" } })
      )
    );
    mockConnectSucceeds({ cert: VALID_CERT });
    const result = await checkTls("https://example.com");
    if (result.status !== "checked" || !("hsts" in result)) throw new Error("expected full checked result");
    expect(result.hsts).toEqual({ present: true, maxAge: 63072000, includeSubDomains: true, preload: true, adequate: true });
  });

  it("marks a short max-age HSTS header as not adequate", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 200, headers: { "strict-transport-security": "max-age=3600" } })));
    mockConnectSucceeds({ cert: VALID_CERT });
    const result = await checkTls("https://example.com");
    if (result.status !== "checked" || !("hsts" in result)) throw new Error("expected full checked result");
    expect(result.hsts.adequate).toBe(false);
  });

  it("reports HSTS absent when the fetch for headers fails, without failing the whole check", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network error")));
    mockConnectSucceeds({ cert: VALID_CERT });
    const result = await checkTls("https://example.com");
    if (result.status !== "checked" || !("hsts" in result)) throw new Error("expected full checked result");
    expect(result.hsts.present).toBe(false);
  });

  it("returns status: error when the TLS connection times out", async () => {
    mockConnectEmits("timeout");
    const result = await checkTls("https://example.com");
    expect(result.status).toBe("error");
    if (result.status === "error") expect(result.note).toContain("timed out");
  });

  it("returns status: error when the TLS connection errors", async () => {
    mockConnectEmits("error", new Error("ECONNREFUSED"));
    const result = await checkTls("https://example.com");
    expect(result.status).toBe("error");
    if (result.status === "error") expect(result.note).toContain("ECONNREFUSED");
  });
});

describe("classifyTrustError", () => {
  it("maps no error to no problem, and anything unrecognised to untrusted", () => {
    expect(classifyTrustError(null)).toBeNull();
    expect(classifyTrustError("CERT_REVOKED")).toBe("untrusted");
  });
});

describe("readCertificate", () => {
  beforeEach(() => connectMock.mockReset());

  it("returns the certificate a host serves, with its expiry and fingerprint", async () => {
    mockConnectSucceeds({
      cert: { ...VALID_CERT, fingerprint256: "AB:CD", subjectaltname: "DNS:api.example.com" },
      authorizationError: "CERT_HAS_EXPIRED",
    });
    const cert = await readCertificate("api.example.com");
    expect(cert).toMatchObject({
      host: "api.example.com",
      subject: "example.com",
      subjectAltNames: ["api.example.com"],
      issuer: "Trusted CA",
      fingerprint: "AB:CD",
      trustProblem: "expired",
    });
    expect(cert?.daysUntilExpiry).toBe(60);
  });

  it("is null when no handshake completes — no evidence either way", async () => {
    mockConnectEmits("error", new Error("ECONNREFUSED"));
    expect(await readCertificate("old.example.com")).toBeNull();
    mockConnectEmits("timeout");
    expect(await readCertificate("slow.example.com")).toBeNull();
  });
});
