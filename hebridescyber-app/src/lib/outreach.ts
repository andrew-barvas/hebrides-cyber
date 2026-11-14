// Outreach snapshots: a one-page summary of a local business's website and
// email setup, plus a draft email, for the owner to review and send by hand.
// Used by src/scripts/outreach-snapshot.ts. NOTHING HERE SENDS ANYTHING.
//
// Two rules are built in rather than left to whoever runs it:
//
//   1. Only passive checks. Each snapshot is runInstantCheck (instantCheck.ts),
//      exactly what the public /check page does for any visitor: one GET per
//      redirect hop, a TLS handshake and DNS lookups. No ports, paths or
//      inputs are probed, because the business hasn't asked for a scan or
//      verified its domain.
//
//   2. PECR. Unsolicited marketing email is only allowed to "corporate
//      subscribers" (limited companies, PLCs, LLPs and similar bodies), with
//      the sender identified and a simple way to opt out. Sole traders and
//      ordinary partnerships count as individuals and need prior consent, so
//      they are excluded, and so is anyone whose type isn't stated. This is
//      a guard, not legal advice: OT-35 asks for the wording to be checked.
//
// Pure: CSV text in, records and text out.
import { csvCell } from "./csv";

export type CompanyType = "ltd" | "plc" | "llp" | "cic" | "charity_company" | "sole_trader" | "partnership" | "unknown";

/** Corporate subscribers under PECR. */
const CORPORATE: ReadonlySet<CompanyType> = new Set<CompanyType>(["ltd", "plc", "llp", "cic", "charity_company"]);

export type Prospect = { name: string; website: string; email: string; companyType: CompanyType; companyNumber: string | null };

export type Eligibility = { ok: true } | { ok: false; reason: string };

export type SnapshotFindings = { severity: string; title: string; detail: string }[];

export type SnapshotInput = {
  prospect: Prospect;
  result: { target: string; score: number; total: number; findings: SnapshotFindings; checkedAt: string };
  sender: { name: string; business: string; postalAddress: string; replyTo: string };
};

const TYPE_ALIASES: Record<string, CompanyType> = {
  ltd: "ltd",
  limited: "ltd",
  "private limited company": "ltd",
  plc: "plc",
  llp: "llp",
  cic: "cic",
  "community interest company": "cic",
  "charitable company": "charity_company",
  charity_company: "charity_company",
  "sole trader": "sole_trader",
  sole_trader: "sole_trader",
  partnership: "partnership",
};

export function parseCompanyType(value: string | undefined): CompanyType {
  return TYPE_ALIASES[(value ?? "").trim().toLowerCase()] ?? "unknown";
}

/** Minimal CSV reader: header row, quoted fields, doubled quotes. */
export function parseCsv(text: string): Record<string, string>[] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else field += ch;
  }
  if (field !== "" || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  const [header, ...body] = rows.filter((r) => r.some((c) => c.trim() !== ""));
  if (!header) return [];
  const keys = header.map((h) => h.trim().toLowerCase());
  return body.map((r) => Object.fromEntries(keys.map((k, i) => [k, (r[i] ?? "").trim()])));
}

/** Expected columns: name, website, email, company_type, and optionally company_number. */
export function parseProspects(csv: string): Prospect[] {
  return parseCsv(csv).map((r) => ({
    name: r.name ?? "",
    website: r.website ?? "",
    email: (r.email ?? "").toLowerCase(),
    companyType: parseCompanyType(r.company_type),
    companyNumber: r.company_number || null,
  }));
}

export function domainOf(website: string): string | null {
  try {
    const url = new URL(/^https?:\/\//i.test(website) ? website : `https://${website}`);
    return url.hostname.toLowerCase().replace(/^www\./, "") || null;
  } catch {
    return null;
  }
}

export function eligibility(p: Prospect, suppressed: ReadonlySet<string>): Eligibility {
  if (!p.name) return { ok: false, reason: "no business name" };
  const domain = domainOf(p.website);
  if (!domain) return { ok: false, reason: "no usable website address" };
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(p.email)) return { ok: false, reason: "no usable email address" };
  if (suppressed.has(p.email) || suppressed.has(domain) || suppressed.has(p.email.split("@")[1])) return { ok: false, reason: "opted out or on the do-not-contact list" };
  if (p.companyType === "sole_trader" || p.companyType === "partnership") {
    return { ok: false, reason: `${p.companyType === "sole_trader" ? "sole trader" : "partnership"}: PECR needs prior consent, so contact by phone, post or in person instead` };
  }
  if (!CORPORATE.has(p.companyType)) return { ok: false, reason: "company type not stated: check Companies House before emailing" };
  return { ok: true };
}

/** Eligible prospects, one per website domain, in input order, plus why the rest were left out. */
export function selectProspects(
  prospects: Prospect[],
  suppressed: ReadonlySet<string>,
  limit: number
): { selected: Prospect[]; excluded: Array<{ prospect: Prospect; reason: string }> } {
  const selected: Prospect[] = [];
  const excluded: Array<{ prospect: Prospect; reason: string }> = [];
  const seen = new Set<string>();
  for (const p of prospects) {
    const verdict = eligibility(p, suppressed);
    if (!verdict.ok) {
      excluded.push({ prospect: p, reason: verdict.reason });
      continue;
    }
    const domain = domainOf(p.website)!;
    if (seen.has(domain)) {
      excluded.push({ prospect: p, reason: "same website as an earlier row" });
      continue;
    }
    if (selected.length >= limit) {
      excluded.push({ prospect: p, reason: `over this run's limit of ${limit}; run again another day` });
      continue;
    }
    seen.add(domain);
    selected.push(p);
  }
  return { selected, excluded };
}

export function slug(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60) || "business";
}

/** The one-page snapshot, in Markdown, to attach or paste. */
export function renderSnapshot({ prospect, result }: Pick<SnapshotInput, "prospect" | "result">): string {
  const lines = [
    `# Website and email check: ${prospect.name}`,
    "",
    `Checked ${result.target} on ${result.checkedAt.slice(0, 10)}, using the same free check anyone can run at https://www.hebridescyber.co.uk/check.`,
    "It looked only at what any visitor or mail server sees: the HTTPS certificate, the security headers on the home page, and the email-authentication records in DNS. Nothing was tested or probed.",
    "",
    `**Score: ${result.score}/100.** ${result.total === 0 ? "No problems found in these checks." : `${result.total} thing${result.total === 1 ? "" : "s"} worth fixing.`}`,
    "",
  ];
  for (const f of result.findings) lines.push(`- **${f.severity.toUpperCase()}: ${f.title}.** ${f.detail}`);
  if (result.findings.length > 0) lines.push("");
  lines.push(
    "This is a light outside view, not a security assessment. A full scan, after you confirm you own the site, also looks for exposed files, outdated software and open services, with step-by-step fixes."
  );
  return lines.join("\n");
}

/** A draft for the owner to read, edit and send personally. Identifies the sender and says how to opt out (PECR). */
export function renderDraftEmail({ prospect, result, sender }: SnapshotInput): { subject: string; body: string } {
  const top = result.findings[0];
  const subject = top ? `${prospect.name}: one thing on your website worth fixing` : `${prospect.name}: your website and email check came back clean`;
  const opening = top
    ? `I ran the free website check on our site against ${result.target}, and one result stood out: ${top.title.charAt(0).toLowerCase()}${top.title.slice(1)}. ${top.detail}`
    : `I ran the free website check on our site against ${result.target}, and it came back clean, which is rarer than you'd think.`;
  const body = [
    "Hello,",
    "",
    opening,
    "",
    "The one-page summary is attached. The check only looks at what any visitor or mail server can see, so nothing on your systems was tested.",
    "",
    top
      ? "If it's useful, you can run it again yourself at https://www.hebridescyber.co.uk/check, or reply and I'll talk you through the fix. No obligation either way."
      : "You can run it again yourself any time at https://www.hebridescyber.co.uk/check, or reply if you'd like a fuller check of the site. No obligation either way.",
    "",
    sender.name,
    sender.business,
    sender.postalAddress,
    "",
    `You're getting this because ${prospect.name} is a local business. If you'd rather not hear from us again, reply "stop" to ${sender.replyTo} and we won't contact you again.`,
  ].join("\n");
  return { subject, body };
}

/** One manifest row per input row, for the owner's records (and to build the next do-not-contact list). */
export function manifestCsv(rows: Array<{ prospect: Prospect; status: string; detail: string; file: string }>): string {
  // csvCell quotes and neutralises spreadsheet formulas: names and websites come from scraped lists.
  const cell = (v: string) => csvCell(v);
  const header = ["name", "website", "email", "company_type", "status", "detail", "file"];
  return [header, ...rows.map((r) => [r.prospect.name, r.prospect.website, r.prospect.email, r.prospect.companyType, r.status, r.detail, r.file])]
    .map((r) => r.map((v) => cell(String(v))).join(","))
    .join("\r\n");
}
