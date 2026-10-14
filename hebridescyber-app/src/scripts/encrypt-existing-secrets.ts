// Encrypts customer secrets that were saved as plaintext before encryption at
// rest existed (ticket-tracker and on-call tokens, authenticated-scan cookies
// and passwords, cloud credentials). The logic is src/lib/secretMigration.ts.
//
// Dry run by default: it reports what it would rewrite and changes nothing.
// Pass --confirm to write. Idempotent: re-running skips what is already
// encrypted. Exits 1 if any row could not be rewritten.
//
// Run with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... CREDENTIALS_ENC_KEY=... npm run secrets:encrypt-existing [-- --confirm]
// or from GitHub: Actions -> "Encrypt stored secrets" -> Run workflow.

import { createClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";
import { isCredentialEncryptionConfigured } from "../lib/credentialEncryption";
import { encryptExistingSecrets } from "../lib/secretMigration";

async function main() {
  const dryRun = !process.argv.includes("--confirm");
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !serviceRoleKey) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }
  if (!dryRun && !isCredentialEncryptionConfigured()) {
    console.error("CREDENTIALS_ENC_KEY is not set (or is not a 32-byte key) — refusing to write. Set it and re-run.");
    process.exit(1);
  }

  const db = createClient(supabaseUrl, serviceRoleKey, {
    realtime: { transport: ws as unknown as WebSocketLikeConstructor },
  });
  console.log(dryRun ? "DRY RUN — nothing will be changed. Pass --confirm to encrypt." : "Encrypting legacy plaintext secrets…");

  const results = await encryptExistingSecrets(db, { dryRun });
  let failed = 0;
  for (const r of results) {
    if (r.missing) {
      console.log(`${r.table}: table doesn't exist yet — skipped`);
      continue;
    }
    failed += r.failed;
    const verb = dryRun ? "would rewrite" : "rewrote";
    console.log(`${r.table}: ${r.scanned} rows, ${verb} ${r.rewritten}, already secure ${r.alreadySecure}${r.failed ? `, FAILED ${r.failed}` : ""}`);
  }
  if (failed > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
