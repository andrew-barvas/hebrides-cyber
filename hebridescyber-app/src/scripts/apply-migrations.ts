// CLI for the migration runner (src/lib/migrationRunner.ts).
//
//   tsx src/scripts/apply-migrations.ts status            read-only report; exit 1 on drift or unknown history
//   tsx src/scripts/apply-migrations.ts apply             apply pending migrations in order
//   tsx src/scripts/apply-migrations.ts baseline 047      record files up to 047 as already applied (no SQL is run)
//
// DATABASE_URL is the direct Postgres connection string (Supabase → Settings →
// Database). Without it every command exits 0 after saying so, so a workflow
// can call this safely before the secret exists.
import { Client } from "pg";
import path from "node:path";
import { applyPending, listMigrations, recordBaseline, RunnerError, statusReport } from "../lib/migrationRunner";

const MIGRATIONS_DIR = path.resolve(__dirname, "../../sql/migrations");

async function main(argv: string[]): Promise<number> {
  const [command, arg] = argv;
  if (!["status", "apply", "baseline"].includes(command ?? "")) {
    console.error("usage: apply-migrations <status | apply | baseline NNN>");
    return 2;
  }
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.log("DATABASE_URL is not set — nothing to do.");
    return 0;
  }

  const files = listMigrations(MIGRATIONS_DIR);
  const db = new Client({ connectionString: url, ssl: url.includes("localhost") || url.includes("127.0.0.1") ? undefined : { rejectUnauthorized: false } });
  await db.connect();
  try {
    if (command === "status") {
      const report = await statusReport(db, files);
      console.log(`${report.applied.length} applied, ${report.pending.length} pending${report.pending.length ? `: ${report.pending.map((f) => f.name).join(", ")}` : ""}`);
      for (const d of report.drifted) console.log(`::error::${d.name} was edited after it was applied`);
      for (const name of report.orphaned) console.log(`::warning::${name} is recorded as applied but its file is gone`);
      if (report.existingDatabaseWithoutLedger) {
        console.log("::error::This database has tables but no migration history. Record it with `baseline <last-applied-number>` first.");
        return 1;
      }
      return report.drifted.length > 0 ? 1 : 0;
    }
    if (command === "baseline") {
      const recorded = await recordBaseline(db, files, arg ?? "");
      console.log(`Recorded ${recorded.length} migration(s) as already applied${recorded.length ? ` (${recorded[0]} … ${recorded[recorded.length - 1]})` : ""}.`);
      return 0;
    }
    const { applied } = await applyPending(db, files, (line) => console.log(line));
    console.log(applied.length ? `Applied ${applied.length} migration(s).` : "Nothing to apply — the database is up to date.");
    return 0;
  } catch (err) {
    if (err instanceof RunnerError) {
      console.log(`::error::${err.message}`);
      return 1;
    }
    throw err;
  } finally {
    await db.end();
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err) => {
    console.error(err);
    process.exit(1);
  }
);
