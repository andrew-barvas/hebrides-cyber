// Outreach snapshots for local businesses (src/lib/outreach.ts says what is
// and isn't allowed). Reads a prospect CSV, runs the same passive check as
// the public /check page against each eligible business, and writes a
// one-page summary and a draft email per business for the owner to review
// and send personally. IT NEVER SENDS EMAIL.
//
//   npm run outreach:snapshot -- --in prospects.csv --out outreach/2026-11-14 \
//     [--suppress do-not-contact.txt] [--limit 15] [--delay-ms 5000]
//
// prospects.csv columns: name, website, email, company_type, company_number
// (company_type: ltd, plc, llp, cic, charitable company; sole traders and
// partnerships are skipped). do-not-contact.txt: one email address or domain
// per line, for everyone who has asked not to be contacted.
//
// Sender details come from OUTREACH_SENDER_NAME, OUTREACH_BUSINESS,
// OUTREACH_POSTAL_ADDRESS and OUTREACH_REPLY_TO, so the draft identifies the
// sender as PECR requires. The script refuses to run without them.
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { runInstantCheck } from "../lib/instantCheck";
import { manifestCsv, parseProspects, renderDraftEmail, renderSnapshot, selectProspects, slug, type Prospect } from "../lib/outreach";

const DEFAULT_LIMIT = 15;
const MAX_LIMIT = 30;
const DEFAULT_DELAY_MS = 5_000;

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main() {
  const input = arg("in");
  const out = arg("out");
  if (!input || !out) throw new Error("Usage: --in prospects.csv --out <folder> [--suppress file] [--limit n] [--delay-ms n]");
  const limit = Math.min(MAX_LIMIT, Math.max(1, Number(arg("limit") ?? DEFAULT_LIMIT) || DEFAULT_LIMIT));
  const delayMs = Math.max(1_000, Number(arg("delay-ms") ?? DEFAULT_DELAY_MS) || DEFAULT_DELAY_MS);

  const sender = {
    name: process.env.OUTREACH_SENDER_NAME ?? "",
    business: process.env.OUTREACH_BUSINESS ?? "",
    postalAddress: process.env.OUTREACH_POSTAL_ADDRESS ?? "",
    replyTo: process.env.OUTREACH_REPLY_TO ?? "",
  };
  const missing = Object.entries(sender).filter(([, v]) => !v.trim()).map(([k]) => k);
  if (missing.length > 0) throw new Error(`Set the sender details first (PECR requires the sender to be identified): missing ${missing.join(", ")}`);

  const suppressFile = arg("suppress");
  const suppressed = new Set(
    suppressFile && existsSync(suppressFile)
      ? readFileSync(suppressFile, "utf8").split(/\r?\n/).map((l) => l.trim().toLowerCase()).filter(Boolean)
      : []
  );

  const prospects = parseProspects(readFileSync(input, "utf8"));
  const { selected, excluded } = selectProspects(prospects, suppressed, limit);
  mkdirSync(out, { recursive: true });

  const manifest: Array<{ prospect: Prospect; status: string; detail: string; file: string }> = excluded.map((e) => ({ prospect: e.prospect, status: "skipped", detail: e.reason, file: "" }));
  for (const [i, prospect] of selected.entries()) {
    if (i > 0) await new Promise((r) => setTimeout(r, delayMs));
    const name = slug(prospect.name);
    try {
      const result = await runInstantCheck(prospect.website);
      const draft = renderDraftEmail({ prospect, result, sender });
      writeFileSync(join(out, `${name}.snapshot.md`), renderSnapshot({ prospect, result }) + "\n");
      writeFileSync(join(out, `${name}.draft.txt`), `To: ${prospect.email}\nSubject: ${draft.subject}\n\n${draft.body}\n`);
      manifest.push({ prospect, status: "ready to review", detail: `score ${result.score}, ${result.total} issue(s)`, file: name });
      console.log(`ready   ${prospect.name} (${result.target}): score ${result.score}`);
    } catch (err) {
      manifest.push({ prospect, status: "check failed", detail: (err as Error).message, file: "" });
      console.log(`failed  ${prospect.name}: ${(err as Error).message}`);
    }
  }
  writeFileSync(join(out, "manifest.csv"), manifestCsv(manifest) + "\r\n");
  console.log(`\n${selected.length} checked, ${excluded.length} skipped. Nothing was sent: review the drafts in ${out} and send them yourself.`);
}

main().catch((err) => {
  console.error("outreach-snapshot failed:", (err as Error).message);
  process.exit(1);
});
