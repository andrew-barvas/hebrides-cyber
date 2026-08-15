// TLS scanner — connects to port 443, inspects the negotiated session and
// certificate in detail. No external tools required; uses Node's built-in
// tls module. Cannot probe TLS 1.0/1.1 server-support because Node 18+
// has those versions disabled at the OpenSSL level.
import { connect as tlsConnect, TLSSocket } from "node:tls";

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

function extractSANs(cert: ReturnType<TLSSocket["getPeerCertificate"]>): string[] {
  const raw = (cert as Record<string, unknown>).subjectaltname as string | undefined;
  if (!raw) return [];
  return raw.split(",").map((s) => s.trim().replace(/^DNS:/, ""));
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
    // Non-fatal — continue without HSTS header info.
  }

  return new Promise<TlsResult>((resolve) => {
    const socket = tlsConnect({ host, port: 443, servername: host, timeout: 10_000 }, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipherInfo = socket.getCipher();
        socket.end();

        const validTo = cert?.valid_to ?? "unknown";
        const validFrom = cert?.valid_from ?? "unknown";
        const daysUntilExpiry =
          validTo === "unknown" ? null : Math.round((new Date(validTo).getTime() - Date.now()) / 86_400_000);
        const daysOld =
          validFrom === "unknown" ? null : Math.round((Date.now() - new Date(validFrom).getTime()) / 86_400_000);

        const subject = cert?.subject?.CN ?? cert?.subject?.O ?? "unknown";
        const issuer = cert?.issuer?.O ?? cert?.issuer?.CN ?? "unknown";
        const subjectAltNames = extractSANs(cert);

        // A cert is self-signed if its issuer fingerprint matches its own fingerprint.
        const selfSigned = Boolean(
          cert && cert.fingerprint && cert.fingerprint === (cert as Record<string, unknown>).issuerCertificate
            ? ((cert as Record<string, unknown>).issuerCertificate as Record<string, unknown>)?.fingerprint
            : subject === issuer
        );

        const weakProtocol = protocol !== null && ["TLSv1", "TLSv1.1"].includes(protocol);
        const cipherName = cipherInfo?.name ?? "";
        const weakCipher = WEAK_CIPHERS.has(cipherName) || WEAK_CIPHERS.has((cipherInfo as Record<string, unknown>)?.version as string ?? "");

        resolve({
          status: "checked",
          isHttps: true,
          protocol,
          cipher: cipherName || null,
          cipherBits: cipherInfo ? (cipherInfo as Record<string, unknown>).bits as number ?? null : null,
          certificateExpiresAt: validTo,
          certificateIssuedAt: validFrom,
          daysUntilExpiry,
          daysOld,
          subject,
          issuer,
          subjectAltNames,
          selfSigned,
          weakProtocol,
          weakCipher,
          hsts: parseHsts(hstsHeader),
        });
      } catch (err) {
        socket.destroy();
        resolve({ status: "error", isHttps: true, note: `TLS inspection failed: ${(err as Error).message}` });
      }
    });
    socket.on("timeout", () => {
      socket.destroy();
      resolve({ status: "error", isHttps: true, note: "TLS connection timed out" });
    });
    socket.on("error", (err) => {
      resolve({ status: "error", isHttps: true, note: `TLS connection error: ${err.message}` });
    });
  });
}
