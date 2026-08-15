// DNS security scanner — checks email authentication records (SPF, DMARC),
// certificate authority authorisation (CAA), and DNSSEC deployment signals.
// Uses Node's built-in dns/promises — no external tools or API keys needed.
import { resolveTxt, resolveCaa, resolve4, resolve6, resolveMx, resolve } from "node:dns/promises";

export type DnsResult =
  | {
      status: "checked";
      spf: SpfAnalysis;
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

function analyseCaa(caaRecords: { critical: number; issue: string; value: string }[]): CaaAnalysis {
  if (caaRecords.length === 0) {
    return {
      present: false,
      records: [],
      issues: ["No CAA records — any certificate authority can issue certificates for this domain"],
    };
  }

  const records = caaRecords.map((r) => `${r.issue} "${r.value}"`);
  const issues: string[] = [];
  const hasIssuewild = caaRecords.some((r) => r.issue === "issuewild");
  const hasIssue = caaRecords.some((r) => r.issue === "issue");

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
    const [txtRecords, dmarcRecords, caaRecords, ipv6Records, mxRecords, dnssec] = await Promise.allSettled([
      resolveTxt(domain),
      resolveTxt(`_dmarc.${domain}`),
      resolveCaa(domain),
      resolve6(domain),
      resolveMx(domain),
      checkDnssec(domain),
    ]);

    const spf = analyseSpf(txtRecords.status === "fulfilled" ? txtRecords.value : []);
    const dmarc = analyseDmarc(dmarcRecords.status === "fulfilled" ? dmarcRecords.value : []);
    const caa = analyseCaa(caaRecords.status === "fulfilled" ? caaRecords.value : []);
    const ipv6 = ipv6Records.status === "fulfilled" && ipv6Records.value.length > 0;
    const mxCount = mxRecords.status === "fulfilled" ? mxRecords.value.length : 0;
    const dnssecResult = dnssec.status === "fulfilled" ? dnssec.value : { likelySigned: false, note: "DNSSEC check failed" };

    return { status: "checked", spf, dmarc, caa, dnssec: dnssecResult, ipv6, mxCount };
  } catch (err) {
    return { status: "error", note: `DNS check failed: ${(err as Error).message}` };
  }
}
