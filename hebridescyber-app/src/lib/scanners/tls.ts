// TLS scanner — connects to port 443, inspects the negotiated session and
// certificate in detail. No external tools required; uses Node's built-in
// tls module. Cannot probe TLS 1.0/1.1 server-support because Node 18+
// has those versions disabled at the OpenSSL level.
//
// The handshake runs with rejectUnauthorized: false and reads Node's own
// verdict from socket.authorizationError instead. With Node's default
// (reject), every broken certificate — expired, self-signed, wrong
// hostname, missing intermediate — failed the handshake before it could be
// read, so the scan reported a generic connection error and none of those
// problems ever became a finding. Nothing is sent over this connection; it
// only reads the certificate.
import { connect as tlsConnect, type PeerCertificate } from "node:tls";

export type CertTrustProblem = "expired" | "self-signed" | "hostname-mismatch" | "incomplete-chain" | "untrusted";

export type TlsResult =
  | {
      status: "checked";
      isHttps: boolean;
      protocol: string | null;
      cipher: string | null;
      cipherBits: number | null;
      certificateExpiresAt: string;
      certificateIssuedAt: string;
      daysUntilExpiry: number | null;
      daysOld: number | null;
      subject: string;
      issuer: string;
      subjectAltNames: string[];
      selfSigned: boolean;
      weakProtocol: boolean;
      weakCipher: boolean;
      hsts: HstsAnalysis;
      /** Why a browser would refuse this certificate, or null if it would
       *  accept it. Optional: results stored before this existed lack it. */
      trustProblem?: CertTrustProblem | null;
      /** Node's own verification code behind trustProblem. */
      trustErrorCode?: string | null;
      /** SHA-256 fingerprint, so other checks can recognise the same certificate. */
      certFingerprint?: string | null;
    }
  | { status: "checked"; isHttps: false; note: string }
  | { status: "error"; isHttps: boolean; note: string };

type HstsAnalysis = {
  present: boolean;
  maxAge: number | null;
  includeSubDomains: boolean;
  preload: boolean;
  adequate: boolean; // max-age >= 180 days
};

// Cipher suites considered weak by current NIST/BSI guidance.
const WEAK_CIPHERS = new Set([
  "RC4",
  "DES",
  "3DES",
  "NULL",
  "EXPORT",
  "MD5",
  "aNULL",
  "eNULL",
]);

function parseHsts(value: string | null): HstsAnalysis {
  if (!value) return { present: false, maxAge: null, includeSubDomains: false, preload: false, adequate: false };
  const maxAgeMatch = value.match(/max-age=(\d+)/i);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : null;
  const includeSubDomains = /includesubdomains/i.test(value);
  const preload = /preload/i.test(value);
  const adequate = maxAge !== null && maxAge >= 15_552_000; // 180 days
  return { present: true, maxAge, includeSubDomains, preload, adequate };
}

function extractSANs(cert: PeerCertificate): string[] {
  const raw = (cert as unknown as Record<string, unknown>).subjectaltname as string | undefined;
  if (!raw) return [];
  return raw.split(",").map((s) => s.trim().replace(/^DNS:/, ""));
}

/**
 * Node's verification codes, as a site owner would describe them. Only the
 * first problem is reported: Node checks the hostname only once the chain
 * itself verified.
 */
export function classifyTrustError(code: string | null | undefined): CertTrustProblem | null {
  if (!code) return null;
  switch (code) {
    case "CERT_HAS_EXPIRED":
      return "expired";
    case "DEPTH_ZERO_SELF_SIGNED_CERT":
      return "self-signed";
    case "ERR_TLS_CERT_ALTNAME_INVALID":
      return "hostname-mismatch";
    // "unable to verify the first certificate": the server didn't send its
    // intermediate. Chrome and Edge fetch it themselves; Firefox, curl,
    // Android apps and most API clients fail.
    case "UNABLE_TO_VERIFY_LEAF_SIGNATURE":
      return "incomplete-chain";
    default:
      return "untrusted"; // private CA, revoked, not yet valid, …
  }
}

const DAY_MS = 86_400_000;

function daysUntil(date: string | undefined, now = Date.now()): number | null {
  if (!date) return null;
  const t = new Date(date).getTime();
  return Number.isNaN(t) ? null : Math.round((t - now) / DAY_MS);
}

function firstName(field: string | string[] | undefined): string | undefined {
  return Array.isArray(field) ? field[0] : field;
}

type Handshake =
  | { ok: true; cert: PeerCertificate; protocol: string | null; cipherName: string; trustErrorCode: string | null }
  | { ok: false; note: string };

/** One TLS handshake to host:443, reading whatever certificate it presents. */
function handshake(host: string, timeoutMs: number): Promise<Handshake> {
  return new Promise<Handshake>((resolve) => {
    const socket = tlsConnect({ host, port: 443, servername: host, timeout: timeoutMs, rejectUnauthorized: false }, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipherName = socket.getCipher()?.name ?? "";
        const authError = socket.authorizationError as unknown;
        socket.end();
        resolve({
          ok: true,
          cert,
          protocol,
          cipherName,
          trustErrorCode: authError ? String((authError as { code?: string }).code ?? authError) : null,
        });
      } catch (err) {
        socket.destroy();
        resolve({ ok: false, note: `TLS inspection failed: ${(err as Error).message}` });
      }
    });
    socket.on("timeout", () => {
      socket.destroy();
      resolve({ ok: false, note: "TLS connection timed out" });
    });
    socket.on("error", (err) => {
      resolve({ ok: false, note: `TLS connection error: ${err.message}` });
    });
  });
}

export type CertificateRead = {
  host: string;
  subject: string;
  subjectAltNames: string[];
  issuer: string;
  validTo: string | null;
  daysUntilExpiry: number | null;
  fingerprint: string | null;
  trustProblem: CertTrustProblem | null;
};

/**
 * The certificate a host serves on 443, or null when no handshake completed
 * (nothing listening, DNS failure, timeout) — which is no evidence either way.
 */
export async function readCertificate(host: string, timeoutMs = 6_000): Promise<CertificateRead | null> {
  const hs = await handshake(host, timeoutMs);
  if (!hs.ok || !hs.cert?.valid_to) return null;
  return {
    host,
    subject: firstName(hs.cert.subject?.CN) ?? host,
    subjectAltNames: extractSANs(hs.cert),
    issuer: firstName(hs.cert.issuer?.O) ?? firstName(hs.cert.issuer?.CN) ?? "unknown",
    validTo: hs.cert.valid_to,
    daysUntilExpiry: daysUntil(hs.cert.valid_to),
    fingerprint: hs.cert.fingerprint256 ?? null,
    trustProblem: classifyTrustError(hs.trustErrorCode),
  };
}

export async function checkTls(targetUrl: string): Promise<TlsResult> {
  const parsed = new URL(targetUrl);
  const host = parsed.hostname;
  const isHttps = parsed.protocol === "https:";

  if (!isHttps) {
    return { status: "checked", isHttps: false, note: "Target is not served over HTTPS at all." };
  }

  // Fetch the URL to capture HSTS header alongside TLS details.
  let hstsHeader: string | null = null;
  try {
    const res = await fetch(targetUrl, { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(8000) });
    hstsHeader = res.headers.get("strict-transport-security");
  } catch {
    // Non-fatal — continue without HSTS header info. (An invalid certificate
    // also lands here: fetch does verify.)
  }

  const hs = await handshake(host, 10_000);
  if (!hs.ok) return { status: "error", isHttps: true, note: hs.note };

  try {
    const { cert, protocol, cipherName, trustErrorCode } = hs;
    const validTo = cert?.valid_to ?? "unknown";
    const validFrom = cert?.valid_from ?? "unknown";
    const daysUntilExpiry = validTo === "unknown" ? null : daysUntil(validTo);
    const daysOld =
      validFrom === "unknown" ? null : Math.round((Date.now() - new Date(validFrom).getTime()) / DAY_MS);

    const subject = firstName(cert?.subject?.CN) ?? firstName(cert?.subject?.O) ?? "unknown";
    const issuer = firstName(cert?.issuer?.O) ?? firstName(cert?.issuer?.CN) ?? "unknown";
    const trustProblem = classifyTrustError(trustErrorCode);

    const weakProtocol = protocol !== null && ["TLSv1", "TLSv1.1"].includes(protocol);
    const weakCipher = Array.from(WEAK_CIPHERS).some((w) => cipherName.includes(w));

    return {
      status: "checked",
      isHttps: true,
      protocol,
      cipher: cipherName || null,
      cipherBits: null, // getCipher() does not expose key bits; left for future tls.getCipherInfo()
      certificateExpiresAt: validTo,
      certificateIssuedAt: validFrom,
      daysUntilExpiry,
      daysOld,
      subject,
      issuer,
      subjectAltNames: extractSANs(cert),
      // Node's verdict, not a subject-equals-issuer guess: that heuristic
      // also matched any certificate whose names were both unreadable.
      selfSigned: trustProblem === "self-signed",
      weakProtocol,
      weakCipher,
      hsts: parseHsts(hstsHeader),
      trustProblem,
      trustErrorCode,
      certFingerprint: cert?.fingerprint256 ?? null,
    };
  } catch (err) {
    return { status: "error", isHttps: true, note: `TLS inspection failed: ${(err as Error).message}` };
  }
}
