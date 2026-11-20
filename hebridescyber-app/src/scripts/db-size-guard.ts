// Daily database size check (src/lib/dbSize.ts), run by
// .github/workflows/db-size-guard.yml. Prints the size and the largest
// tables to the job summary; emails a warning from 70% of the Free plan's
// limit; exits non-zero from 85%, so the failed run alerts the owner too.
//
// Run locally with: DATABASE_URL=... npx tsx src/scripts/db-size-guard.ts
import { Client } from "pg";
import { appendFile } from "node:fs/promises";
import { assessDbSize, sizeReport, type TableSize } from "../lib/dbSize";
import { sendEmail } from "../lib/email";

async function main() {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error("DATABASE_URL is not set.");
    process.exit(1);
  }
  const db = new Client({ connectionString: url, ssl: url.includes("localhost") || url.includes("127.0.0.1") ? undefined : { rejectUnauthorized: false } });
  await db.connect();
  let total: number;
  let tables: TableSize[];
  try {
    const size = await db.query<{ bytes: string }>("select pg_database_size(current_database())::bigint as bytes");
    total = Number(size.rows[0].bytes);
    const rows = await db.query<{ schema: string; table: string; total: string; data: string; indexes: string; rows: string }>(`
      select n.nspname as schema, c.relname as table,
             pg_total_relation_size(c.oid)::bigint as total,
             pg_relation_size(c.oid)::bigint as data,
             pg_indexes_size(c.oid)::bigint as indexes,
             greatest(c.reltuples, 0)::bigint as rows
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where c.relkind = 'r' and n.nspname not in ('pg_catalog', 'information_schema')
      order by pg_total_relation_size(c.oid) desc
      limit 25`);
    tables = rows.rows.map((r) => ({ schema: r.schema, table: r.table, totalBytes: Number(r.total), dataBytes: Number(r.data), indexBytes: Number(r.indexes), rows: Number(r.rows) }));
  } finally {
    await db.end();
  }

  const assessment = assessDbSize(total);
  const report = sizeReport(assessment, tables);
  console.log(report);
  if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, `${report}\n`);

  if (assessment.level !== "ok") {
    const to = process.env.ALERT_EMAIL ?? "hello@hebridescyber.co.uk";
    const sent = await sendEmail({
      to,
      subject: `Database at ${assessment.percent}% of the Supabase Free limit`,
      html: `<p>The Hebrides Cyber database is ${assessment.usedMb} MB of ${assessment.limitMb} MB (${assessment.percent}%). Over the limit, Supabase can make the project read-only.</p><pre style="font-size:12px">${report.replace(/</g, "&lt;")}</pre><p>See the "DB size guard" workflow run in GitHub Actions.</p>`,
    });
    if (!sent.ok) console.error(`Warning email not sent: ${sent.error}`);
  }
  if (assessment.level === "fail") process.exit(1);
}

main().catch((err) => {
  console.error("db-size-guard failed:", (err as Error).message);
  process.exit(1);
});
