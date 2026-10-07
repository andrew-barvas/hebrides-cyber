// Deep TLS/SSL analysis via testssl.sh.
//
// This is the *extended*, binary-backed TLS check. It is deliberately NOT a
// replacement for src/lib/scanners/tls.ts — that module runs everywhere (a
// plain node:tls handshake, no binaries) and answers "what did we negotiate,
// and is the certificate about to expire?". This module answers the questions
// a single handshake structurally cannot: which protocol versions the server
// still *offers* (node 18+ refuses to negotiate TLS 1.0/1.1 at the OpenSSL
// level, so tls.ts can never observe them), which weak cipher *categories* are
// still accepted, whether forward secrecy is available, and whether the server
// is vulnerable to the named TLS attacks (ROBOT, Heartbleed, POODLE, DROWN,
// FREAK, LOGJAM, SWEET32, CCS, Ticketbleed, CRIME, insecure renegotiation).
//
// Anything tls.ts already reports is suppressed here — see SUPPRESSED_IDS.
// Two findings for one defect in a single report is a visible quality bug.
//
// Like every other extended tool (src/worker/tools/*.ts) this degrades to
// { status: "not_configured" } when the binary is absent, so it is inert
// outside the GitHub Actions queue worker and never throws.
//
// Wire-up: called from runExtendedTools() in src/lib/scanExecution.ts, which
// only runs when executeScan() is passed { runExtendedTools: true }.

import { execTool } from "../execTool";
import { readFile, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "./index";
import * as FIX from "./remediationText";

const execFileAsync = execTool;

/**
 * Hard ceiling on the whole testssl.sh run. Sits between nmap/nuclei (120s)
 * and ZAP's active scan (300s). A scoped run against a responsive host lands
 * at roughly 60-120s; see TESTSSL_ARGS for why it isn't the 5-15 minutes a
 * default `testssl.sh <host>` invocation costs.
 */
const TESTSSL_TIMEOUT_MS = 180_000;

/**
 * testssl.sh prints its full human-readable report to stdout even with
 * --quiet, and we only care about the JSON file. Raise the buffer so a chatty
 * run is not killed for the wrong reason (and if it is, the partial-JSON
 * salvage path below still recovers the findings).
 */
const TESTSSL_MAX_BUFFER = 10 * 1024 * 1024;

/**
 * testssl.sh is verbose. Cap what reaches the report so one badly-configured
 * host cannot bury every other scanner's findings. Selection is deterministic
 * (severity, then checkId) so the same server always yields the same set —
 * findings are diffed New/Fixed by checkId and a non-deterministic cut would
 * make them flap.
 */
const MAX_FINDINGS = 15;

/**
 * The scoping flags. A bare `testssl.sh <host>` runs every check it has,
 * including --each-cipher / --cipher-per-proto, which probe several hundred
 * cipher suites one connection at a time — routinely 5-15 minutes. That is not
 * acceptable inside a scan job, so we ask only for the checks that produce
 * findings this product actually reports:
 *
 *   --protocols        SSLv2/SSLv3/TLS 1.0-1.3 support (tls.ts's blind spot)
 *   --std              cipher strength by *category* (NULL, aNULL, EXPORT,
 *                      LOW, 3DES/IDEA, obsoleted CBC). This is the grouped
 *                      check — deliberately NOT --each-cipher.
 *   --fs               forward secrecy, ECDHE curves, DH group strength
 *   --server-defaults  certificate chain of trust, SANs, signature algorithm,
 *                      key size, OCSP stapling
 *   plus the individual vulnerability probes listed below.
 *
 * Deliberately excluded, and why:
 *   --each-cipher / --cipher-per-proto / --full  the slow per-cipher sweeps
 *   --headers          HSTS, cookies, server banner, security headers — all
 *                      already covered by headers.ts and tls.ts
 *   --rc4              subsumed by --std's LOW category, and enumerates every
 *                      RC4 suite individually
 *   --beast --lucky13  client-side-mitigated, testssl rates them LOW, and both
 *                      walk the CBC cipher list per protocol
 *   --breach           HTTP-layer, needs --headers context, high false-positive
 *                      rate against any host that gzips
 *   --client-simulation --grease --winshock --starttls-injection
 *                      not applicable to an HTTPS endpoint / not reportable
 *
 * Output/behaviour flags:
 *   --severity LOW     only write findings rated LOW or above to the JSON.
 *                      Everything left in the file is a rated defect, which is
 *                      what lets this module honour "never report a finding you
 *                      cannot evidence" (docs/SCANNER-CONVENTIONS.md).
 *   --disable-rating   suppresses the overall_grade entry, which would
 *                      double-count every other finding as one more CRITICAL.
 *   --ip one           test the first resolved address only, not every A record
 *   --warnings batch   never block waiting for a keypress
 *   --quiet --color 0  no banner, no ANSI escapes
 *   --connect-timeout / --openssl-timeout  bound individual hung connections,
 *                      so the hard timeout above is a backstop, not the plan
 *
 * Note --phone-out is *not* passed, so testssl.sh makes no outbound CRL/OCSP
 * fetches to third parties on the customer's behalf.
 */
const TESTSSL_SCOPE_ARGS = [
  "--protocols",
  "--std",
  "--fs",
  "--server-defaults",
  "--heartbleed",
  "--ccs-injection",
  "--ticketbleed",
  "--robot",
  "--renegotiation",
  "--crime",
  "--poodle",
  "--tls-fallback",
  "--sweet32",
  "--freak",
  "--logjam",
  "--drown",
];

const TESTSSL_OUTPUT_ARGS = [
  "--severity", "LOW",
  "--disable-rating",
  "--ip", "one",
  "--warnings", "batch",
  "--connect-timeout", "10",
  "--openssl-timeout", "10",
  "--quiet",
  "--color", "0",
];

/**
 * One flat-JSON entry as testssl.sh writes it with --jsonfile. Shape confirmed
 * against fileout_json_finding() in testssl.sh 3.2: every key is a string, and
 * `cve`/`cwe` are omitted entirely when empty.
 */
export type TestsslEntry = {
  id: string;
  ip?: string;
  port?: string;
  severity: string;
  cve?: string;
  cwe?: string;
  finding: string;
};

export type DeepTlsResult =
  | {
      status: "completed";
      host: string;
      /** Entries testssl.sh reported at LOW or above, before dedupe/cap. */
      entryCount: number;
      /** True when MAX_FINDINGS clipped the list. */
      truncated: boolean;
      findings: Finding[];
      note?: string;
    }
  | { status: "not_configured"; host: string; findings: [] }
  | { status: "skipped"; host: string; findings: []; note: string }
  | { status: "error"; host: string; findings: []; note: string };

// ---- Severity mapping -------------------------------------------------------

/**
 * testssl.sh's own scale is DEBUG < INFO < OK < LOW < MEDIUM < HIGH <
 * CRITICAL, plus WARN and FATAL. It is an evidence-based tool — it rates a
 * finding by what it actually negotiated with the server — so the honest
 * mapping is one-to-one with no escalation. Nothing gets promoted to
 * "critical" that testssl.sh did not itself call CRITICAL.
 *
 * WARN is deliberately absent: per testssl.sh's own man page it means "a
 * client-side scanning error or problem", i.e. a statement about our scanner,
 * not about the target. Those are counted into the result note instead of
 * being emitted as findings about the customer's server.
 */
const SEVERITY_MAP: Record<string, Finding["severity"]> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
};

const SEVERITY_RANK: Record<Finding["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

// ---- Overlap suppression ----------------------------------------------------

/**
 * testssl.sh check ids that another module in this suite already reports. Most
 * of these cannot even be produced by TESTSSL_SCOPE_ARGS (we never ask for
 * --headers), but the list is the durable guard: if the scope flags are ever
 * widened, these still will not turn into a second copy of an existing
 * finding.
 *
 *   cert_expirationStatus / cert_notAfter / cert_notBefore -> tls.cert-expiring
 *   HSTS*                                                  -> tls.hsts-missing / tls.hsts-short
 *   DNS_CAArecord                                          -> dns.caa-missing
 *   security_headers / banner_* / cookie_*                 -> headers.*
 *   HTTP_status_code / http_get / insecure_redirect        -> playwright.unhealthy-status
 *   overall_grade / service / scanTime / scanProblem       -> meta, not a defect
 */
const SUPPRESSED_IDS = new Set([
  "cert_expirationStatus",
  "cert_notAfter",
  "cert_notBefore",
  "HSTS",
  "HSTS_time",
  "HSTS_subdomains",
  "HSTS_preload",
  "DNS_CAArecord",
  "security_headers",
  "banner_server",
  "banner_application",
  "banner_reverseproxy",
  "cookie_bigip_f5",
  "HTTP_status_code",
  "HTTP_headerAge",
  "HTTP_clock_skew",
  "http_get",
  "insecure_redirect",
  "overall_grade",
  "service",
  "scanTime",
  "scanProblem",
]);

const SUPPRESSED_PREFIXES = ["cookie_", "overall_grade"];

/**
 * testssl.sh check ids that represent Azure Static Web Apps / CDN platform
 * configuration that the app operator cannot change. When — and only when —
 * the target is detected as served by Azure's platform (PLATFORM_TLS_TECHNOLOGIES
 * in the fingerprint), these are demoted to "info": still in the report for
 * transparency, but not penalising a score for something the customer can't
 * fix.
 *
 * Never demoted for other targets. On a self-hosted nginx, obsolete CBC
 * suites or SHA-1 signature algorithms are the operator's own configuration
 * and a real, actionable finding.
 */
export const PLATFORM_TLS_TECHNOLOGIES = ["Azure CDN", "Azure App Service"] as const;

export type DeepTlsOptions = { platformManagedTls?: boolean };

const PLATFORM_INFRA_IDS = new Set([
  "cert_trust_wildcard",  // Azure CDN shares a wildcard cert across customers on the platform
  "FS_KEMs",              // Post-quantum key encapsulation — future-proofing concern, not a current threat
  "FS_TLS12_sig_algs",    // RSA+SHA1 in TLS 1.2 signature algorithms — Azure platform TLS config
  "cipherlist_OBSOLETED", // CBC cipher suites in TLS 1.2 — Azure SWA platform; TLS 1.3 is available to modern clients
]);

/**
 * tls.ts already reports a self-signed certificate as `tls.self-signed`.
 * testssl.sh surfaces that same verdict in two places — `cert_caIssuers` with
 * the literal finding "selfsigned", and `cert_chain_of_trust` as
 * "failed (self signed). ..." — and both of those checks also carry genuinely
 * additive verdicts (issuer removed from a root store, incomplete chain,
 * untrusted root). So we drop only the self-signed verdict itself and keep the
 * rest of each check, rather than dropping the whole check.
 */
const SELF_SIGNED_RE = /self[\s-]?signed/i;

// ---- Human-readable titles --------------------------------------------------

/**
 * testssl.sh ids are machine identifiers. Anything not listed falls back to
 * the raw id, which is still stable and searchable — the id is never invented
 * here, so an unmapped check degrades to a slightly uglier title rather than
 * to a wrong one.
 */
const TITLES: Record<string, string> = {
  SSLv2: "SSL 2.0 is still offered by the server",
  SSLv3: "SSL 3.0 is still offered by the server",
  TLS1: "TLS 1.0 is still offered by the server",
  TLS1_1: "TLS 1.1 is still offered by the server",
  TLS1_2: "TLS 1.2 support problem",
  TLS1_3: "TLS 1.3 is not offered",
  heartbleed: "Heartbleed (CVE-2014-0160)",
  CCS: "OpenSSL CCS injection (CVE-2014-0224)",
  ticketbleed: "Ticketbleed (CVE-2016-9244)",
  ROBOT: "ROBOT — Return of Bleichenbacher's Oracle Threat",
  secure_renego: "Insecure TLS renegotiation supported",
  secure_client_renego: "Client-initiated TLS renegotiation supported (DoS risk)",
  insecure_client_renego: "Insecure client-initiated renegotiation supported",
  CRIME_TLS: "CRIME — TLS compression enabled",
  POODLE_SSL: "POODLE over SSL 3.0 (CVE-2014-3566)",
  fallback_SCSV: "TLS_FALLBACK_SCSV downgrade protection missing",
  SWEET32: "SWEET32 — 64-bit block ciphers offered (CVE-2016-2183)",
  FREAK: "FREAK — export RSA ciphers offered (CVE-2015-0204)",
  LOGJAM: "LOGJAM — export DH ciphers offered (CVE-2015-4000)",
  "LOGJAM-common_primes": "LOGJAM — common/well-known DH prime in use",
  DROWN: "DROWN — SSL 2.0 reachable (CVE-2016-0800)",
  FS: "No forward secrecy",
  FS_ciphers: "Weak forward-secrecy cipher selection",
  FS_ECDHE_curves: "Weak elliptic curves offered for key exchange",
  DH_groups: "Weak Diffie-Hellman group",
  cert_chain_of_trust: "Certificate chain of trust problem",
  cert_trust: "Certificate trust problem",
  cert_keySize: "Weak certificate key size",
  cert_signatureAlgorithm: "Weak certificate signature algorithm",
  cert_subjectAltName: "Certificate subject alternative name problem",
  cert_commonName: "Certificate common name problem",
  cert_extlifeSpan: "Certificate lifetime exceeds CA/Browser Forum limits",
  cert_revocation: "Certificate revocation information problem",
  cert_serialNumberLen: "Certificate serial number too short",
  cert_ocspRevoked: "Certificate has been revoked (OCSP)",
  cert_crlRevoked: "Certificate has been revoked (CRL)",
  OCSP_stapling: "OCSP stapling not enabled",
  certificate_transparency: "No Certificate Transparency information",
  cipher_order: "Server does not enforce its own cipher order",
};

/**
 * Label for each weak cipher category testssl.sh reports under --std, used to
 * build the single grouped finding.
 */
const CIPHER_CATEGORY_LABELS: Record<string, string> = {
  NULL: "NULL ciphers (no encryption)",
  aNULL: "anonymous ciphers (no authentication)",
  EXPORT: "export-grade ciphers",
  LOW: "LOW-strength ciphers (64-bit, DES, RC2, RC4, MD5)",
  "3DES_IDEA": "Triple DES / IDEA ciphers",
  OBSOLETED: "obsoleted CBC ciphers",
  STRONG_NOFS: "strong ciphers without forward secrecy",
  STRONG_FS: "strong forward-secrecy ciphers",
};

// ---- Remediation ------------------------------------------------------------
// Prose lives in remediationText.ts (DEEP_TLS_*), same convention as every
// other scanner module — see that file's header comment.

function remediationFor(id: string): string {
  if (id.startsWith("cipherlist_") || id.startsWith("cipher-")) return FIX.DEEP_TLS_CIPHERS;
  if (id.startsWith("cert_") || id.startsWith("intermediate_cert") || id === "OCSP_stapling") {
    return FIX.DEEP_TLS_CERTIFICATE;
  }
  if (["SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"].includes(id)) return FIX.DEEP_TLS_PROTOCOL;
  if (["FS", "FS_ciphers", "FS_ECDHE_curves", "DH_groups"].includes(id)) return FIX.DEEP_TLS_FORWARD_SECRECY;
  return FIX.DEEP_TLS_VULNERABILITY;
}

// ---- Parsing ----------------------------------------------------------------

/**
 * Normalises a testssl.sh check id into something stable enough to key a
 * checkId on. When a host serves more than one certificate (RSA + ECDSA)
 * testssl.sh suffixes the id with " <hostCert#1>", " <hostCert#2>", ... —
 * which would otherwise make a checkId depend on the certificate ordering and
 * flap between New and Fixed on every scan. Stripping it also means the two
 * certificates collapse into one finding, which is handled by the dedupe in
 * buildFindings().
 */
export function normaliseCheckId(rawId: string): string {
  return rawId.replace(/\s*<[^>]*>\s*$/, "").trim();
}

function isTestsslEntry(value: unknown): value is TestsslEntry {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return typeof record.id === "string" && typeof record.severity === "string" && typeof record.finding === "string";
}

/**
 * Parses the flat JSON array testssl.sh writes with --jsonfile.
 *
 * Includes a repair step for one specific real case: when the run is killed by
 * TESTSSL_TIMEOUT_MS the closing "]" is never written, so the file is a valid
 * list of findings inside a truncated array. Rather than throw away a run that
 * had already probed most of the checks, we close the array and keep what was
 * written. Anything still unparseable yields an empty list — never a throw.
 */
export function parseTestsslJson(raw: string): TestsslEntry[] {
  const trimmed = raw.trim();
  if (!trimmed) return [];

  const candidates = [trimmed];
  if (!trimmed.endsWith("]")) {
    // Drop a dangling partial object / trailing comma, then close the array.
    const lastClose = trimmed.lastIndexOf("}");
    if (lastClose !== -1) candidates.push(`${trimmed.slice(0, lastClose + 1)}]`);
  }

  for (const candidate of candidates) {
    try {
      const parsed: unknown = JSON.parse(candidate);
      if (!Array.isArray(parsed)) continue;
      return parsed.filter(isTestsslEntry);
    } catch {
      // try the next candidate
    }
  }
  return [];
}

function shouldSuppress(id: string, finding: string): boolean {
  if (SUPPRESSED_IDS.has(id)) return true;
  if (SUPPRESSED_PREFIXES.some((prefix) => id.startsWith(prefix))) return true;
  // tls.self-signed already covers this exact verdict.
  if ((id === "cert_chain_of_trust" || id === "cert_caIssuers") && SELF_SIGNED_RE.test(finding)) return true;
  return false;
}

function cveIdsFrom(entry: TestsslEntry): string[] {
  if (!entry.cve) return [];
  return entry.cve
    .split(/\s+/)
    .map((c) => c.trim())
    .filter((c) => /^CVE-\d{4}-\d+$/i.test(c));
}

/**
 * True for the two id shapes that describe cipher suites:
 *   cipherlist_LOW, cipherlist_3DES_IDEA, ...   (--std, one per category)
 *   cipher-tls1_2_xc028, cipher-tls1_x35, ...   (--each-cipher, one per suite)
 *
 * We never ask for --each-cipher, but a single run of it emits dozens of LOW
 * entries — the real baseline output shipped with testssl.sh has 14 in one
 * scan — so the grouping covers that shape too rather than trusting the flag
 * list to stay put forever.
 *
 * Deliberately not matched: cipher_order / cipherorder_TLSv1_2, which are
 * about ordering, not strength, and get their own finding.
 */
function isCipherSuiteId(id: string): boolean {
  return id.startsWith("cipherlist_") || id.startsWith("cipher-");
}

/**
 * Collapses everything testssl.sh said about cipher strength into one finding.
 * The remediation for all of it is the same single cipher-suite list, and the
 * checkId is fixed so that fixing three of five categories reads as
 * "unchanged, less severe" rather than as five findings churning in and out of
 * the New/Fixed diff.
 */
function buildCipherFinding(entries: TestsslEntry[], platformManagedTls: boolean): Finding | null {
  if (entries.length === 0) return null;

  let worst: Finding["severity"] | null = null;
  const categoryParts: string[] = [];
  const suiteNames: string[] = [];
  const cves = new Set<string>();

  // Sort for determinism — the JSON order is testssl.sh's execution order.
  const sorted = [...entries].sort((a, b) => a.id.localeCompare(b.id));

  for (const entry of sorted) {
    const severity = SEVERITY_MAP[entry.severity.toUpperCase()];
    if (!severity) continue;
    const effectiveSeverity: Finding["severity"] = platformManagedTls && PLATFORM_INFRA_IDS.has(entry.id) ? "info" : severity;
    if (worst === null || SEVERITY_RANK[effectiveSeverity] < SEVERITY_RANK[worst]) worst = effectiveSeverity;
    for (const cve of cveIdsFrom(entry)) cves.add(cve);

    if (entry.id.startsWith("cipherlist_")) {
      const category = entry.id.slice("cipherlist_".length);
      categoryParts.push(`${CIPHER_CATEGORY_LABELS[category] ?? category}: ${entry.finding}`);
    } else {
      // "TLSv1.2   xc028   ECDHE-RSA-AES256-SHA384   ECDH 253 ..." — the
      // OpenSSL suite name is the third whitespace-separated column.
      const columns = entry.finding.trim().split(/\s+/);
      suiteNames.push(columns[2] ?? entry.id);
    }
  }

  if (worst === null) return null;

  const details: string[] = [];
  if (categoryParts.length > 0) details.push(categoryParts.join("; "));
  if (suiteNames.length > 0) {
    const shown = suiteNames.slice(0, 8).join(", ");
    details.push(
      `${suiteNames.length} individual weak suite(s) offered: ${shown}` +
        (suiteNames.length > 8 ? ` (+${suiteNames.length - 8} more)` : "")
    );
  }

  const groupCount = categoryParts.length + (suiteNames.length > 0 ? 1 : 0);
  const finding: Finding = {
    checkId: "deep-tls.weak-cipher-suites",
    severity: worst,
    title: `[testssl] Weak cipher suites accepted (${groupCount} group${groupCount === 1 ? "" : "s"})`,
    detail: details.join(". "),
    remediation: FIX.DEEP_TLS_CIPHERS,
  };
  if (cves.size > 0) finding.cveIds = [...cves].sort();
  return finding;
}

/**
 * Maps testssl.sh's flat JSON entries onto this codebase's Finding[]. Exported
 * so it can be exercised against captured testssl.sh output without needing
 * the binary.
 */
export function buildFindings(
  entries: TestsslEntry[],
  options: DeepTlsOptions = {}
): { findings: Finding[]; truncated: boolean; warnCount: number } {
  const platformManagedTls = options.platformManagedTls ?? false;
  const cipherEntries: TestsslEntry[] = [];
  const byCheckId = new Map<string, Finding>();
  let warnCount = 0;

  for (const entry of entries) {
    const id = normaliseCheckId(entry.id);
    const rawSeverity = entry.severity.toUpperCase();

    if (rawSeverity === "WARN" || rawSeverity === "FATAL") {
      warnCount++;
      continue;
    }

    const severity = SEVERITY_MAP[rawSeverity];
    if (!severity) continue; // OK / INFO / DEBUG — not a defect
    if (shouldSuppress(id, entry.finding)) continue;

    if (isCipherSuiteId(id)) {
      cipherEntries.push({ ...entry, id });
      continue;
    }

    const effectiveSeverity: Finding["severity"] = platformManagedTls && PLATFORM_INFRA_IDS.has(id) ? "info" : severity;
    const cwe = entry.cwe?.trim();
    const checkId = `deep-tls.finding:${id}`;
    const finding: Finding = {
      checkId,
      severity: effectiveSeverity,
      title: `[testssl] ${TITLES[id] ?? id}`,
      // The `finding` string is testssl.sh's own verbatim observation
      // ("offered (NOT ok)", "VULNERABLE, uses 64 bit block ciphers", ...) —
      // i.e. the evidence, carried through unedited.
      detail: cwe ? `${entry.finding} (${cwe})` : entry.finding,
      remediation: remediationFor(id),
    };
    const cves = cveIdsFrom(entry);
    if (cves.length > 0) finding.cveIds = cves;

    // Multiple certificates can normalise onto one id; keep the worst.
    const existing = byCheckId.get(checkId);
    if (!existing || SEVERITY_RANK[finding.severity] < SEVERITY_RANK[existing.severity]) {
      byCheckId.set(checkId, finding);
    }
  }

  const cipherFinding = buildCipherFinding(cipherEntries, platformManagedTls);
  if (cipherFinding?.checkId) byCheckId.set(cipherFinding.checkId, cipherFinding);

  const all = [...byCheckId.values()].sort((a, b) => {
    const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (bySeverity !== 0) return bySeverity;
    return (a.checkId ?? "").localeCompare(b.checkId ?? "");
  });

  return { findings: all.slice(0, MAX_FINDINGS), truncated: all.length > MAX_FINDINGS, warnCount };
}

// ---- Runner -----------------------------------------------------------------

/**
 * Runs testssl.sh against the target's TLS endpoint and returns unified
 * Finding[].
 *
 * Never throws. Returns:
 *   - "skipped"        target is not HTTPS (tls.no-https already covers that)
 *   - "not_configured" the testssl.sh binary is absent (any environment other
 *                      than the GitHub Actions queue worker)
 *   - "error"          the binary ran but produced nothing usable
 *   - "completed"      including the partial-result case after a timeout
 *
 * Set TESTSSL_PATH to point at a testssl.sh outside $PATH.
 */
export async function runDeepTls(targetUrl: string, options: DeepTlsOptions = {}): Promise<DeepTlsResult> {
  let host: string;
  let port: string;
  try {
    const parsed = new URL(targetUrl);
    host = parsed.hostname;
    port = parsed.port || "443";
    if (parsed.protocol !== "https:") {
      return {
        status: "skipped",
        host,
        findings: [],
        note: "Target is not served over HTTPS — deep TLS analysis does not apply.",
      };
    }
  } catch {
    return { status: "error", host: targetUrl, findings: [], note: "Invalid URL" };
  }

  const binary = process.env.TESTSSL_PATH || "testssl.sh";
  const jsonFile = join(tmpdir(), `testssl-${randomUUID()}.json`);
  const uri = `${host}:${port}`;

  const args = [...TESTSSL_OUTPUT_ARGS, "--jsonfile", jsonFile, ...TESTSSL_SCOPE_ARGS, uri];

  const readEntries = async (): Promise<TestsslEntry[]> => {
    try {
      return parseTestsslJson(await readFile(jsonFile, "utf8"));
    } catch {
      return [];
    }
  };

  try {
    await execFileAsync(binary, args, {
      timeout: TESTSSL_TIMEOUT_MS,
      maxBuffer: TESTSSL_MAX_BUFFER,
    });

    const entries = await readEntries();
    const { findings, truncated, warnCount } = buildFindings(entries, options);
    return {
      status: "completed",
      host,
      entryCount: entries.length,
      truncated,
      findings,
      note: warnCount > 0 ? `testssl.sh reported ${warnCount} scanner-side warning(s), not emitted as findings.` : undefined,
    };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") {
      return { status: "not_configured", host, findings: [] };
    }

    // testssl.sh exits non-zero for its own error conditions, and is killed
    // outright when it hits TESTSSL_TIMEOUT_MS. In both cases the JSON file
    // may already hold everything it managed to probe, so salvage it rather
    // than discarding a mostly-complete run.
    const entries = await readEntries();
    if (entries.length > 0) {
      const { findings, truncated, warnCount } = buildFindings(entries, options);
      return {
        status: "completed",
        host,
        entryCount: entries.length,
        truncated,
        findings,
        note:
          `testssl.sh did not exit cleanly (${error.message}); reporting the ${entries.length} check(s) it completed` +
          (warnCount > 0 ? `, excluding ${warnCount} scanner-side warning(s)` : "") +
          ".",
      };
    }

    return { status: "error", host, findings: [], note: `testssl.sh exited: ${error.message}` };
  } finally {
    unlink(jsonFile).catch(() => undefined);
  }
}
