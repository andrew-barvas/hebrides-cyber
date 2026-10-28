// E-66: DMARC aggregate (RUA) report parsing.
//
// DMARC aggregate reports are the one half of the retired NCSC Mail Check that
// the passive `dns.ts` DMARC check can't replace: `dns.ts` tells you a DMARC
// record exists and what its policy is, but only the mailbox named in the
// record's `rua=` tag receives the daily XML reports that reveal who is
// actually sending mail as your domain and whether it passes SPF/DKIM. This
// module parses one of those reports into a per-source summary a customer can
// read without wading through XML.
//
// Reports arrive as RFC 7489 §7.2.1.1 XML, usually gzip'd (and historically
// zip'd) as an email attachment. This module takes the already-decompressed
// XML string — the ingest route (`/api/dmarc/ingest`) handles gunzip, since
// that's an I/O concern. Parsing is hand-rolled regex over the known-shaped
// `<record>` elements, matching the house style (newsletter.ts RSS,
// lockfileSyntax.ts) — no XML dependency, and resilient to the namespace
// prefixes and attribute noise real reporters (Google, Microsoft, Yahoo) add.
//
// Evidence discipline: a report that can't be parsed into at least an org +
// one record returns null (the caller rejects it) rather than a misleading
// empty-but-valid summary.

export type DmarcAuthResult = "pass" | "fail";

export type DmarcReportRow = {
  sourceIp: string;
  count: number;
  /** The DMARC-level disposition the receiver applied: none/quarantine/reject. */
  disposition: string;
  dkim: DmarcAuthResult;
  spf: DmarcAuthResult;
  /** Envelope-from / header-from domain the message claimed, when present. */
  headerFrom: string | null;
};

export type DmarcAggregateReport = {
  /** The reporting organisation (e.g. "google.com"). */
  orgName: string;
  reportId: string | null;
  /** The domain the report is about (the published DMARC record's domain). */
  domain: string | null;
  dateBegin: number | null; // unix seconds
  dateEnd: number | null;
  rows: DmarcReportRow[];
  // Derived rollups the UI and storage use:
  totalMessages: number;
  passingMessages: number; // DMARC-aligned (SPF or DKIM pass)
  failingMessages: number;
};

function firstTag(xml: string, tag: string): string | null {
  // Matches <tag>…</tag> and <ns:tag …>…</ns:tag>, non-greedy, dot-matches-newline.
  const m = xml.match(new RegExp(`<(?:[\\w-]+:)?${tag}\\b[^>]*>([\\s\\S]*?)</(?:[\\w-]+:)?${tag}>`, "i"));
  return m ? m[1].trim() : null;
}

function allBlocks(xml: string, tag: string): string[] {
  const re = new RegExp(`<(?:[\\w-]+:)?${tag}\\b[^>]*>([\\s\\S]*?)</(?:[\\w-]+:)?${tag}>`, "gi");
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) out.push(m[1]);
  return out;
}

function authResult(value: string | null): DmarcAuthResult {
  return value && value.trim().toLowerCase() === "pass" ? "pass" : "fail";
}

/**
 * Parses one decompressed DMARC aggregate-report XML string. Returns null when
 * it isn't a recognisable report (no org name, or no parseable records) —
 * never a half-empty summary.
 */
export function parseDmarcAggregateReport(xml: string): DmarcAggregateReport | null {
  if (!xml || !/<(?:[\w-]+:)?feedback\b/i.test(xml)) {
    // Not a DMARC feedback document.
    if (!/<(?:[\w-]+:)?record\b/i.test(xml)) return null;
  }

  const metadata = firstTag(xml, "report_metadata") ?? xml;
  const orgName = firstTag(metadata, "org_name");
  if (!orgName) return null;

  const reportId = firstTag(metadata, "report_id");
  const dateRange = firstTag(metadata, "date_range") ?? "";
  const dateBegin = toInt(firstTag(dateRange, "begin"));
  const dateEnd = toInt(firstTag(dateRange, "end"));

  const policy = firstTag(xml, "policy_published") ?? "";
  const domain = firstTag(policy, "domain");

  const rows: DmarcReportRow[] = [];
  for (const block of allBlocks(xml, "record")) {
    const row = firstTag(block, "row") ?? block;
    const sourceIp = firstTag(row, "source_ip");
    if (!sourceIp) continue;
    const count = toInt(firstTag(row, "count")) ?? 0;
    const policyEvaluated = firstTag(row, "policy_evaluated") ?? row;
    const disposition = (firstTag(policyEvaluated, "disposition") ?? "none").toLowerCase();
    const dkim = authResult(firstTag(policyEvaluated, "dkim"));
    const spf = authResult(firstTag(policyEvaluated, "spf"));
    const identifiers = firstTag(block, "identifiers") ?? "";
    const headerFrom = firstTag(identifiers, "header_from");
    rows.push({ sourceIp, count, disposition, dkim, spf, headerFrom });
  }

  if (rows.length === 0) return null;

  let total = 0;
  let passing = 0;
  for (const r of rows) {
    total += r.count;
    // DMARC passes when SPF or DKIM is aligned+pass (receiver-evaluated here).
    if (r.dkim === "pass" || r.spf === "pass") passing += r.count;
  }

  return {
    orgName,
    reportId,
    domain,
    dateBegin,
    dateEnd,
    rows,
    totalMessages: total,
    passingMessages: passing,
    failingMessages: total - passing,
  };
}

function toInt(value: string | null): number | null {
  if (value == null) return null;
  const n = parseInt(value.trim(), 10);
  return Number.isFinite(n) ? n : null;
}
