// DNS security scanner — checks email authentication records (SPF, DMARC),
// certificate authority authorisation (CAA), and DNSSEC deployment signals.
// Uses Node's built-in dns/promises — no external tools or API keys needed.
import { resolveTxt, resolveCaa, resolve6, resolveMx, resolve } from "node:dns/promises";
import type { CaaRecord } from "node:dns";

export type DnsResult =
  | {
      status: "checked";
      spf: SpfAnalysis;
      dkim: DkimAnalysis;
      dmarc: DmarcAnalysis;
      caa: CaaAnalysis;
      dnssec: DnssecAnalysis;
      ipv6: boolean;
      mxCount: number;
    }
  | { status: "error"; note: string };

// ---- SPF -------------------------------------------------------------------

type SpfAnalysis = {
  present: boolean;
  record: string | null;
  issues: string[];
};

function analyseSpf(records: string[][]): SpfAnalysis {
  const flat = records.flat();
  const spfRecords = flat.filter((r) => r.startsWith("v=spf1"));

  if (spfRecords.length === 0) {
    return { present: false, record: null, issues: ["No SPF record found — domain is vulnerable to email spoofing"] };
  }

  const record = spfRecords[0];
  const issues: string[] = [];

  if (spfRecords.length > 1) {
    issues.push("Multiple SPF records found — only one is permitted; receivers will reject or ignore extras");
  }
  if (record.includes("+all") || record.endsWith(" all") || record.endsWith("\tall")) {
    issues.push("SPF ends with '+all' or 'all' — any server can send as this domain; use '-all' to reject unauthorised senders");
  }
  if (record.includes("?all")) {
    issues.push("SPF uses '?all' (neutral) — unauthorised senders are not rejected; use '-all'");
  }
  if (record.includes("~all")) {
    issues.push("SPF uses '~all' (softfail) — unauthorised senders are flagged but not rejected; upgrade to '-all'");
  }
  const includeLookups = (record.match(/include:/g) ?? []).length;
  const aLookups = (record.match(/\ba\b/g) ?? []).length;
  const mxLookups = (record.match(/\bmx\b/g) ?? []).length;
  if (includeLookups + aLookups + mxLookups > 10) {
    issues.push("SPF record exceeds 10 DNS lookup limit — some receivers will fail to evaluate it (permerror)");
  }

  return { present: true, record, issues };
}

// ---- DKIM ------------------------------------------------------------------

// Unlike SPF and DMARC, DKIM has no fixed record name. The key lives at
// <selector>._domainkey.<domain>, and the selector is chosen freely by whoever
// set it up — it is not discoverable from DNS. The only black-box approach is
// to probe the defaults that common providers use.
//
// This has an important consequence for how we report: finding a key is real
// evidence DKIM is configured, but NOT finding one proves nothing — the domain
// may well sign with a custom selector we never guessed. So absence is reported
// as info-level and worded as "not detected", never "DKIM missing". Claiming
// otherwise would violate the rule that we never report a finding we cannot
// evidence, and would be a false positive on a correctly configured domain.
const COMMON_DKIM_SELECTORS = [
  "google", // Google Workspace
  "selector1", // Microsoft 365
  "selector2", // Microsoft 365 (rotation pair)
  "k1", // Mailchimp / Mandrill
  "k2",
  "s1", // SendGrid, various
  "s2",
  "mail", // common self-hosted default
  "dkim", // common self-hosted default
  "default", // OpenDKIM default
  "mandrill",
  "zoho",
];

type DkimAnalysis = {
  found: boolean;
  selector: string | null;
  record: string | null;
  selectorsTried: number;
  issues: string[];
};

// A DKIM key record is a TXT value containing a p= public key tag. The v=DKIM1
// tag is recommended but genuinely optional per RFC 6376, so we key off p=
// and treat v= as a bonus signal rather than requiring it.
function looksLikeDkimRecord(value: string): boolean {
  return /(^|;)\s*p\s*=/.test(value) && (/v\s*=\s*DKIM1/i.test(value) || /(^|;)\s*k\s*=/.test(value));
}

// Estimates RSA key size from the base64 SubjectPublicKeyInfo in the p= tag.
// A 1024-bit key decodes to roughly 160 bytes of DER, a 2048-bit key to roughly
// 290. We only flag the clearly-weak case and stay quiet in the ambiguous
// middle rather than guessing at a boundary.
function rsaKeyTooShort(record: string): boolean {
  const pMatch = record.match(/(?:^|;)\s*p\s*=\s*([A-Za-z0-9+/=]+)/);
  if (!pMatch) return false;
  const derBytes = Buffer.from(pMatch[1], "base64").length;
  return derBytes > 0 && derBytes < 200;
}

async function checkDkim(domain: string): Promise<DkimAnalysis> {
  const probes = await Promise.allSettled(
    COMMON_DKIM_SELECTORS.map(async (selector) => {
      const records = await resolveTxt(`${selector}._domainkey.${domain}`);
      // Long TXT values arrive split into 255-byte chunks that must be
      // rejoined before parsing — DKIM keys are almost always long enough to
      // be split, so skipping this would break nearly every real lookup.
      const joined = records.map((chunks) => chunks.join(""));
      const hit = joined.find(looksLikeDkimRecord);
      if (!hit) throw new Error("no dkim record");
      return { selector, record: hit };
    })
  );

  const found = probes.find((p) => p.status === "fulfilled");
  if (!found || found.status !== "fulfilled") {
    return {
      found: false,
      selector: null,
      record: null,
      selectorsTried: COMMON_DKIM_SELECTORS.length,
      issues: [],
    };
  }

  const { selector, record } = found.value;
  const issues: string[] = [];

  // An empty p= is the RFC-defined way to revoke a key. If that is the only
  // selector publishing, mail signed with it will fail verification.
  if (/(^|;)\s*p\s*=\s*(;|$)/.test(record)) {
    issues.push(`DKIM key at selector '${selector}' is revoked (empty p= tag) — signatures using it will fail`);
  } else if (rsaKeyTooShort(record)) {
    issues.push(`DKIM key at selector '${selector}' appears to be 1024-bit or smaller — upgrade to 2048-bit`);
  }

  if (/(^|;)\s*t\s*=\s*[^;]*y/.test(record)) {
    issues.push(`DKIM record at selector '${selector}' is in testing mode (t=y) — receivers will ignore failures`);
  }

  return { found: true, selector, record, selectorsTried: COMMON_DKIM_SELECTORS.length, issues };
}

// ---- DMARC -----------------------------------------------------------------

type DmarcAnalysis = {
  present: boolean;
  record: string | null;
  policy: string | null;
  pct: number | null;
  issues: string[];
};

function analyseDmarc(records: string[][]): DmarcAnalysis {
  const flat = records.flat();
  const dmarcRecord = flat.find((r) => r.startsWith("v=DMARC1"));

  if (!dmarcRecord) {
    return {
      present: false,
      record: null,
      policy: null,
      pct: null,
      issues: ["No DMARC record found — no policy for email authentication failures"],
    };
  }

  const pMatch = dmarcRecord.match(/p=(\w+)/i);
  const policy = pMatch?.[1]?.toLowerCase() ?? null;
  const pctMatch = dmarcRecord.match(/pct=(\d+)/i);
  const pct = pctMatch ? parseInt(pctMatch[1], 10) : 100;
  const issues: string[] = [];

  if (policy === "none") {
    issues.push("DMARC policy is 'none' — no enforcement; spoofed emails are not rejected");
  }
  if (pct !== null && pct < 100) {
    issues.push(`DMARC pct=${pct}% — policy only applies to ${pct}% of failing messages`);
  }
  if (!dmarcRecord.includes("rua=")) {
    issues.push("No DMARC reporting address (rua) — authentication failures won't be reported");
  }

  return { present: true, record: dmarcRecord, policy, pct, issues };
}

// ---- CAA -------------------------------------------------------------------

type CaaAnalysis = {
  present: boolean;
  records: string[];
  issues: string[];
};

function analyseCaa(caaRecords: CaaRecord[]): CaaAnalysis {
  if (caaRecords.length === 0) {
    return {
      present: false,
      records: [],
      issues: ["No CAA records — any certificate authority can issue certificates for this domain"],
    };
  }

  const records: string[] = [];
  for (const r of caaRecords) {
    if (r.issue) records.push(`issue "${r.issue}"`);
    if (r.issuewild) records.push(`issuewild "${r.issuewild}"`);
    if (r.iodef) records.push(`iodef "${r.iodef}"`);
  }

  const issues: string[] = [];
  const hasIssue = caaRecords.some((r) => r.issue !== undefined);
  const hasIssuewild = caaRecords.some((r) => r.issuewild !== undefined);

  if (!hasIssue && !hasIssuewild) {
    issues.push("CAA records exist but have no 'issue' or 'issuewild' entries");
  }

  return { present: true, records, issues };
}

// ---- DNSSEC ----------------------------------------------------------------

type DnssecAnalysis = {
  likelySigned: boolean;
  note: string;
};

async function checkDnssec(domain: string): Promise<DnssecAnalysis> {
  // Node's dns module doesn't support DNSSEC validation directly. We probe
  // for DS records (the parent-zone delegation signer) as a signal that the
  // zone is likely DNSSEC-signed. A missing DS record does not prove the
  // zone is unsigned — it may just mean the parent hasn't published it yet.
  try {
    const ds = await resolve(domain, "DS").catch(() => []);
    if (Array.isArray(ds) && ds.length > 0) {
      return { likelySigned: true, note: `DS record present — domain appears to be DNSSEC-signed` };
    }
    return {
      likelySigned: false,
      note: "No DS record found — domain does not appear to be DNSSEC-signed",
    };
  } catch {
    return { likelySigned: false, note: "DNSSEC check inconclusive — DS lookup failed" };
  }
}

// ---- Main ------------------------------------------------------------------

export async function checkDns(targetUrl: string): Promise<DnsResult> {
  const domain = new URL(targetUrl).hostname;

  try {
    const [txtRecords, dmarcRecords, caaRecords, ipv6Records, mxRecords, dnssec, dkimResult] = await Promise.allSettled([
      resolveTxt(domain),
      resolveTxt(`_dmarc.${domain}`),
      resolveCaa(domain),
      resolve6(domain),
      resolveMx(domain),
      checkDnssec(domain),
      checkDkim(domain),
    ]);

    const spf = analyseSpf(txtRecords.status === "fulfilled" ? txtRecords.value : []);
    const dkim: DkimAnalysis =
      dkimResult.status === "fulfilled"
        ? dkimResult.value
        : { found: false, selector: null, record: null, selectorsTried: 0, issues: [] };
    const dmarc = analyseDmarc(dmarcRecords.status === "fulfilled" ? dmarcRecords.value : []);
    const caa = analyseCaa(caaRecords.status === "fulfilled" ? caaRecords.value : []);
    const ipv6 = ipv6Records.status === "fulfilled" && ipv6Records.value.length > 0;
    const mxCount = mxRecords.status === "fulfilled" ? mxRecords.value.length : 0;
    const dnssecResult = dnssec.status === "fulfilled" ? dnssec.value : { likelySigned: false, note: "DNSSEC check failed" };

    return { status: "checked", spf, dkim, dmarc, caa, dnssec: dnssecResult, ipv6, mxCount };
  } catch (err) {
    return { status: "error", note: `DNS check failed: ${(err as Error).message}` };
  }
}
