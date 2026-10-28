// One-off: encrypt the secrets that were saved before they were stored
// encrypted. New saves are encrypted by the API routes (credentialEncryption.ts);
// legacy rows stay readable as plaintext until they are re-saved, which a
// customer who never touches their integration never does. This rewrites them.
//
// Idempotent and safe to re-run: a value that is already encrypted is left
// alone, and a row is only written when something in it actually changes. Run by
// `npm run secrets:encrypt-existing` (dry run unless --confirm) and by the
// "Encrypt stored secrets" workflow.
import type { SupabaseClient } from "@supabase/supabase-js";
import { encryptCredentials, encryptSecret, isEncryptedBlob, isEncryptedSecret } from "./credentialEncryption";
import { isMissingSchemaError } from "./dbErrors";

/** Tables whose live secrets sit in plain `text` columns. */
export const STRING_SECRET_TARGETS: ReadonlyArray<{ table: string; fields: readonly string[] }> = [
  {
    table: "ticket_integrations",
    fields: ["jira_api_token", "linear_api_key", "servicenow_password", "github_token", "pagerduty_routing_key", "opsgenie_api_key"],
  },
  { table: "target_auth_credentials", fields: ["cookie_value", "basic_password"] },
  { table: "uptime_integrations", fields: ["api_key"] },
];

const PAGE_SIZE = 500;

export type TableOutcome = {
  table: string;
  /** Rows read. */
  scanned: number;
  /** Rows that held at least one plaintext secret (written unless dryRun). */
  rewritten: number;
  /** Rows with nothing left to encrypt. */
  alreadySecure: number;
  /** Rows that could not be updated. */
  failed: number;
  /** The table doesn't exist yet (its migration isn't applied). */
  missing?: boolean;
};

type Row = Record<string, unknown> & { id: string };

async function forEachRow(
  db: SupabaseClient,
  table: string,
  visit: (row: Row) => Promise<void>
): Promise<{ missing: boolean }> {
  for (let from = 0; ; from += PAGE_SIZE) {
    const { data, error } = await db
      .from(table)
      .select("*")
      .order("id", { ascending: true })
      .range(from, from + PAGE_SIZE - 1);
    if (error) {
      if (isMissingSchemaError(error)) return { missing: true };
      throw new Error(`${table}: ${error.message}`);
    }
    const rows = (data ?? []) as Row[];
    for (const row of rows) await visit(row);
    if (rows.length < PAGE_SIZE) return { missing: false };
  }
}

async function rewriteStringSecrets(db: SupabaseClient, table: string, fields: readonly string[], dryRun: boolean): Promise<TableOutcome> {
  const out: TableOutcome = { table, scanned: 0, rewritten: 0, alreadySecure: 0, failed: 0 };
  const { missing } = await forEachRow(db, table, async (row) => {
    out.scanned++;
    const patch: Record<string, string> = {};
    for (const f of fields) {
      const v = row[f];
      if (typeof v === "string" && v !== "" && !isEncryptedSecret(v)) patch[f] = dryRun ? v : encryptSecret(v);
    }
    if (Object.keys(patch).length === 0) {
      out.alreadySecure++;
      return;
    }
    if (dryRun) {
      out.rewritten++;
      return;
    }
    const { error } = await db.from(table).update(patch).eq("id", row.id);
    if (error) out.failed++;
    else out.rewritten++;
  });
  if (missing) out.missing = true;
  return out;
}

async function rewriteCloudCredentials(db: SupabaseClient, dryRun: boolean): Promise<TableOutcome> {
  const out: TableOutcome = { table: "cloud_credentials", scanned: 0, rewritten: 0, alreadySecure: 0, failed: 0 };
  const { missing } = await forEachRow(db, "cloud_credentials", async (row) => {
    out.scanned++;
    const value = row.credentials_encrypted;
    if (isEncryptedBlob(value) || value === null || typeof value !== "object") {
      out.alreadySecure++;
      return;
    }
    if (dryRun) {
      out.rewritten++;
      return;
    }
    const { error } = await db
      .from("cloud_credentials")
      .update({ credentials_encrypted: encryptCredentials(value as Record<string, unknown>) })
      .eq("id", row.id);
    if (error) out.failed++;
    else out.rewritten++;
  });
  if (missing) out.missing = true;
  return out;
}

/** Encrypts every legacy plaintext secret. With `dryRun`, only reports what it would change. */
export async function encryptExistingSecrets(db: SupabaseClient, opts: { dryRun: boolean }): Promise<TableOutcome[]> {
  const results: TableOutcome[] = [];
  for (const target of STRING_SECRET_TARGETS) {
    results.push(await rewriteStringSecrets(db, target.table, target.fields, opts.dryRun));
  }
  results.push(await rewriteCloudCredentials(db, opts.dryRun));
  return results;
}
