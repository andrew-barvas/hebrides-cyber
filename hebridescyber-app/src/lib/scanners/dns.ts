// DNS security scanner — checks email authentication records (SPF, DMARC,
// DKIM), mail transport security (MTA-STS, TLS-RPT), certificate authority
// authorisation (CAA), and DNSSEC deployment signals. Uses Node's built-in
// dns/promises for DNS lookups — no external tools or API keys needed. The
// MTA-STS policy-file fetch is the one exception, a plain HTTPS GET.
import { resolveTxt, resolveCaa, resolve6, resolveMx, resolve } from "node:dns/promises";
import type { CaaRecord } from "node:dns";
import { registrableDomain } from "./registrableDomain";

export type DnsResult =
  | {
      status: "checked";
      spf: SpfAnalysis;
      dkim: DkimAnalysis;
      dmarc: DmarcAnalysis;
      caa: CaaAnalysis;
      dnssec: DnssecAnalysis;
      mtaSts: MtaStsAnalysis;
      tlsRpt: TlsRptAnalysis;
      ipv6: boolean;
      mxCount: number;
    }
  | { status: "error"; note: string };

// ---- SPF -------------------------------------------------------------------

type SpfAnalysis = {
  present: boolean;
  record: string | null;
  issues: string[];
  /** The recursive DNS-lookup count across the whole include/redirect chain,
   *  per RFC 7208 §4.6.4 (null when it couldn't be computed — see lookupError). */
  lookupCount: number | null;
  /** Set when a record in the chain couldn't be resolved, so the count is a
   *  floor, not the real total — reported as "could not evaluate", never "exceeds". */
  lookupError: boolean;
};

// RFC 7208 §4.6.4: the mechanisms that each cost one DNS lookup, capped at 10
// in total across the whole (recursively-evaluated) record. `redirect=` also
// costs a lookup and continues evaluation at the target.
const SPF_LOOKUP_MECHANISMS = ["include", "a", "mx", "ptr", "exists"] as const;

// Hard ceilings so a hostile or circular record can't hang (or balloon) a
// scan: stop resolving once this many SPF records have been fetched. 12 > the
// RFC's own 10-lookup limit, so a compliant record is always fully evaluated
// and only an over-limit (or malicious) one is cut short.
const SPF_MAX_RESOLUTIONS = 12;

/** Fetches the SPF (v=spf1) TXT record for a name, or null when there's none.
 *  Injected so the recursion is unit-testable without live DNS. */
export type SpfLookup = (name: string) => Promise<string | null>;

/** The individual lookup-costing terms in one SPF record (not counting
 *  `all`/`redirect`): used both to tally and to find the names to recurse into. */
function spfTokens(record: string): string[] {
  return record.split(/\s+/).filter(Boolean);
}

/** Count the lookup-costing mechanisms in a single record (no recursion). */
function countLocalLookups(record: string): number {
  let count = 0;
  for (const token of spfTokens(record)) {
    // Strip a leading qualifier (+/-/~/?) then read the mechanism name.
    const mech = token.replace(/^[+\-~?]/, "").split(/[:/=]/)[0].toLowerCase();
    if ((SPF_LOOKUP_MECHANISMS as readonly string[]).includes(mech)) count += 1;
  }
  return count;
}

type SpfRecursionResult = { count: number; chain: string[]; error: boolean };

/**
 * The real RFC 7208 §4.6.4 lookup total: this record's own costing mechanisms
 * plus, recursively, those inside every `include:`/`redirect=` target. Bounded
 * by SPF_MAX_RESOLUTIONS and a visited-set so a circular or deliberately-deep
 * chain terminates. A target that can't be resolved sets `error` (the count is
 * then a floor), so the caller reports "could not evaluate", not "exceeds".
 */
async function countSpfLookups(
  rootDomain: string,
  rootRecord: string,
  lookup: SpfLookup
): Promise<SpfRecursionResult> {
  const visited = new Set<string>([rootDomain.toLowerCase()]);
  let resolutions = 0;
  let error = false;
  const chain: string[] = [];

  // Each queued item is a record whose own lookups we still need to count,
  // plus the target names it refers out to.
  async function walk(record: string): Promise<number> {
    let total = countLocalLookups(record);

    const targets: string[] = [];
    for (const token of spfTokens(record)) {
      const bare = token.replace(/^[+\-~?]/, "");
      const inc = bare.match(/^include:(.+)$/i);
      const red = bare.match(/^redirect=(.+)$/i);
      if (inc) targets.push(inc[1].toLowerCase());
      else if (red) targets.push(red[1].toLowerCase());
    }

    for (const target of targets) {
      if (visited.has(target)) continue; // cycle guard
      visited.add(target);
      if (resolutions >= SPF_MAX_RESOLUTIONS) {
        // Can't be sure we've seen the whole chain — treat as unevaluable
        // rather than claiming a definitive total.
        error = true;
        continue;
      }
      resolutions += 1;
      let targetRecord: string | null;
      try {
        targetRecord = await lookup(target);
      } catch {
        targetRecord = null;
        error = true;
      }
      if (targetRecord === null) {
        // A missing/failed include target can't be counted — the real total is
        // unknown. (An include: pointing at a name with no SPF record is itself
        // a permerror, but either way we can't assert "exceeds".)
        error = true;
        continue;
      }
      chain.push(target);
      total += await walk(targetRecord);
    }
    return total;
  }

  const count = await walk(rootRecord);
  return { count, chain, error };
}

// Per-lookup bound so a slow or hanging authoritative server for one include
// target can't stall the whole chain (the convention's "a hung third party
// must not hang a scan"). DNS has its own retry/timeout, but a Promise.race
// gives a hard ceiling regardless of resolver config.
const SPF_LOOKUP_TIMEOUT_MS = 5_000;

/** The default live SPF lookup: the first v=spf1 TXT record at `name`, or null.
 *  Rejects (so the caller records a lookup error) on timeout or DNS failure. */
async function liveSpfLookup(name: string): Promise<string | null> {
  let timer: NodeJS.Timeout | undefined;
  try {
    const records = await Promise.race([
      resolveTxt(name),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("SPF lookup timed out")), SPF_LOOKUP_TIMEOUT_MS);
      }),
    ]);
    const flat = records.map((chunks) => chunks.join(""));
    return flat.find((r) => r.trim().toLowerCase().startsWith("v=spf1")) ?? null;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Pure SPF record analysis (qualifier/multiplicity checks). The recursive
 * lookup count is attached separately by analyseSpfWithLookups so this stays
 * synchronous and the DNS recursion is injectable.
 */
function analyseSpf(records: string[][]): SpfAnalysis {
  const flat = records.flat();
  const spfRecords = flat.filter((r) => r.startsWith("v=spf1"));

  if (spfRecords.length === 0) {
    return { present: false, record: null, issues: ["No SPF record found — domain is vulnerable to email spoofing"], lookupCount: null, lookupError: false };
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

  return { present: true, record, issues, lookupCount: null, lookupError: false };
}

/**
 * analyseSpf plus the recursive lookup count. Replaces the old literal-token
 * tally (which only counted include/a/mx in the top-level record and so missed
 * the nested lookups that cause the real >10 permerror). When the computed
 * total exceeds 10 the issue states the count and chain; when a record in the
 * chain couldn't be resolved it says "could not evaluate" rather than asserting
 * the limit was breached — evidence discipline.
 */
async function analyseSpfWithLookups(records: string[][], lookup: SpfLookup, domain: string): Promise<SpfAnalysis> {
  const base = analyseSpf(records);
  if (!base.present || base.record === null) return base;

  const { count, chain, error } = await countSpfLookups(domain, base.record, lookup);
  const chainNote = chain.length > 0 ? ` (chain: ${[domain, ...chain].join(" → ")})` : "";

  if (error) {
    base.lookupError = true;
    base.lookupCount = count;
    base.issues.push(
      `SPF DNS-lookup count could not be fully evaluated — at least ${count} lookup${count === 1 ? "" : "s"} so far, but a record in the include/redirect chain could not be resolved${chainNote}. Confirm the chain resolves and stays within the RFC 7208 limit of 10.`
    );
  } else {
    base.lookupCount = count;
    if (count > 10) {
      base.issues.push(
        `SPF requires ${count} DNS lookups across its include/redirect chain — over the RFC 7208 limit of 10, so some receivers fail evaluation with a permerror and ignore the record entirely${chainNote}. Flatten or remove includes to get back under 10.`
      );
    }
  }

  return base;
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
  /** An enforcing policy (quarantine/reject) weakened by pct<100 — so only a
   *  fraction of failing mail is actually acted on. */
  partialEnforcement: boolean;
  /** An enforcing policy with no rua= aggregate-report address configured. */
  noReporting: boolean;
};

/** An enforcing DMARC policy: quarantine or reject (not none/absent). */
function isEnforcingPolicy(policy: string | null): boolean {
  return policy === "quarantine" || policy === "reject";
}

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
      partialEnforcement: false,
      noReporting: false,
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

  // Both are only meaningful on an enforcing policy: a p=none record is
  // already covered by dns.dmarc-none, so reporting "partial enforcement" or
  // "no reporting" on top of it would be noise. pct only weakens enforcement
  // when the policy is actually enforcing something.
  const partialEnforcement = isEnforcingPolicy(policy) && pct !== null && pct < 100;
  const noReporting = isEnforcingPolicy(policy) && !dmarcRecord.includes("rua=");

  return { present: true, record: dmarcRecord, policy, pct, issues, partialEnforcement, noReporting };
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

// ---- MTA-STS (RFC 8461) -----------------------------------------------------
//
// Two independent parts, both required for MTA-STS to actually do anything:
// a `_mta-sts.<domain>` TXT record announcing a policy exists, and a policy
// file served over HTTPS at `https://mta-sts.<domain>/.well-known/mta-sts.txt`
// declaring the enforcement mode. A domain can publish the DNS record and
// never serve the file (or serve it with mode: testing, which enforces
// nothing) — both are real, evidenced gaps this checks for separately rather
// than treating "the TXT record exists" as "MTA-STS is protecting this mail."
//
// Only meaningful for domains that receive mail at all, so the caller only
// invokes this when mxCount > 0 — a domain with no MX records has no inbound
// mail transport to protect, and reporting "no MTA-STS" on it would be noise
// dressed up as a finding.

type MtaStsAnalysis = {
  dnsRecordPresent: boolean;
  policyFetched: boolean;
  mode: string | null; // "enforce" | "testing" | "none" | null (unfetched/unparseable)
  issues: string[];
};

const HTTP_TIMEOUT_MS = 8_000;

async function checkMtaSts(domain: string): Promise<MtaStsAnalysis> {
  const txt = await resolveTxt(`_mta-sts.${domain}`).catch(() => [] as string[][]);
  const flat = txt.flat();
  const dnsRecordPresent = flat.some((r) => r.startsWith("v=STSv1"));

  if (!dnsRecordPresent) {
    return { dnsRecordPresent: false, policyFetched: false, mode: null, issues: [] };
  }

  try {
    const res = await fetch(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, {
      redirect: "follow",
      signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
    });
    if (!res.ok) {
      return {
        dnsRecordPresent: true,
        policyFetched: false,
        mode: null,
        issues: [`_mta-sts DNS record exists but the policy file returned HTTP ${res.status} — the record is a dangling pointer`],
      };
    }
    const body = await res.text();
    const modeMatch = body.match(/^\s*mode:\s*(\w+)/im);
    const mode = modeMatch?.[1]?.toLowerCase() ?? null;
    const issues: string[] = [];
    if (!mode) {
      issues.push("MTA-STS policy file fetched but has no parseable 'mode:' line");
    } else if (mode === "none") {
      issues.push("MTA-STS mode is 'none' — the policy is published but not enforced");
    } else if (mode === "testing") {
      issues.push("MTA-STS mode is 'testing' — failures are reported but mail is not rejected; upgrade to 'enforce' once confident");
    }
    return { dnsRecordPresent: true, policyFetched: true, mode, issues };
  } catch (err) {
    return {
      dnsRecordPresent: true,
      policyFetched: false,
      mode: null,
      issues: [`_mta-sts DNS record exists but the policy file could not be fetched: ${(err as Error).message}`],
    };
  }
}

// ---- TLS-RPT (RFC 8460) ------------------------------------------------------
//
// A `_smtp._tls.<domain>` TXT record telling other mail servers where to send
// reports about failed opportunistic-TLS/MTA-STS connections. Pure reporting,
// no enforcement of its own — but it's the only visibility a domain owner has
// into whether inbound mail delivery is silently being downgraded to
// plaintext by a receiving server that doesn't honour STARTTLS.

type TlsRptAnalysis = {
  present: boolean;
  record: string | null;
  issues: string[];
};

async function checkTlsRpt(domain: string): Promise<TlsRptAnalysis> {
  const txt = await resolveTxt(`_smtp._tls.${domain}`).catch(() => [] as string[][]);
  const flat = txt.flat();
  const record = flat.find((r) => r.startsWith("v=TLSRPTv1")) ?? null;

  if (!record) return { present: false, record: null, issues: [] };

  const issues: string[] = [];
  if (!record.includes("rua=")) {
    issues.push("TLS-RPT record has no rua= reporting address — reports have nowhere to go");
  }
  return { present: true, record, issues };
}

// ---- Main ------------------------------------------------------------------

/**
 * CAA as a certificate authority sees it for `hostname`: CAs walk up the
 * tree from the certificate's name (RFC 8659 §3), so the host's own CAA set
 * wins, else its registered domain's. The walk stops there — the parent of
 * a registered domain (e.g. co.uk) is never the customer's to set.
 */
async function resolveCaaForHost(hostname: string, domain: string): Promise<CaaRecord[]> {
  const own = await resolveCaa(hostname).catch(() => [] as CaaRecord[]);
  if (own.length > 0 || hostname === domain) return own;
  return resolveCaa(domain);
}

export type CheckDnsOptions = {
  /** Override the SPF include/redirect resolver — tests inject a fake chain
   *  so the recursive lookup counting runs without live DNS. */
  spfLookup?: SpfLookup;
};

export async function checkDns(targetUrl: string, options: CheckDnsOptions = {}): Promise<DnsResult> {
  const hostname = new URL(targetUrl).hostname;
  // Email authentication (SPF, DMARC, DKIM, MX → MTA-STS/TLS-RPT) and the
  // zone's DNSSEC status belong to the registered domain, not to whichever
  // host serves the website. Scanning https://www.example.co.uk used to look
  // them all up on www.example.co.uk — normally a CNAME to a hosting
  // provider, with no TXT records at all — and reported "No SPF record" and
  // "No DMARC record" for domains that had both (found on our own site:
  // SPF, DMARC and Microsoft 365 DKIM all present on the apex). IPv6 stays on
  // the web host, since that's about the website being reachable.
  const domain = registrableDomain(hostname) ?? hostname;

  try {
    const [txtRecords, dmarcRecords, caaRecords, ipv6Records, mxRecords, dnssec, dkimResult] = await Promise.allSettled([
      resolveTxt(domain),
      resolveTxt(`_dmarc.${domain}`),
      resolveCaaForHost(hostname, domain),
      resolve6(hostname),
      resolveMx(domain),
      checkDnssec(domain),
      checkDkim(domain),
    ]);

    const spf = await analyseSpfWithLookups(
      txtRecords.status === "fulfilled" ? txtRecords.value : [],
      options.spfLookup ?? liveSpfLookup,
      domain
    );
    const dkim: DkimAnalysis =
      dkimResult.status === "fulfilled"
        ? dkimResult.value
        : { found: false, selector: null, record: null, selectorsTried: 0, issues: [] };
    const dmarc = analyseDmarc(dmarcRecords.status === "fulfilled" ? dmarcRecords.value : []);
    const caa = analyseCaa(caaRecords.status === "fulfilled" ? caaRecords.value : []);
    const ipv6 = ipv6Records.status === "fulfilled" && ipv6Records.value.length > 0;
    const mxCount = mxRecords.status === "fulfilled" ? mxRecords.value.length : 0;
    const dnssecResult = dnssec.status === "fulfilled" ? dnssec.value : { likelySigned: false, note: "DNSSEC check failed" };

    // Only meaningful for a domain that actually receives mail — see
    // checkMtaSts's header comment. Run after mxCount is known rather than
    // joining the Promise.allSettled batch above, since whether to check at
    // all depends on that result.
    const [mtaSts, tlsRpt] =
      mxCount > 0
        ? await Promise.all([checkMtaSts(domain), checkTlsRpt(domain)])
        : [
            { dnsRecordPresent: false, policyFetched: false, mode: null, issues: [] } as MtaStsAnalysis,
            { present: false, record: null, issues: [] } as TlsRptAnalysis,
          ];

    return { status: "checked", spf, dkim, dmarc, caa, dnssec: dnssecResult, mtaSts, tlsRpt, ipv6, mxCount };
  } catch (err) {
    return { status: "error", note: `DNS check failed: ${(err as Error).message}` };
  }
}
