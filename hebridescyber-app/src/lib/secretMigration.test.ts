import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { decryptCredentials, decryptSecret, encryptCredentials, encryptSecret, isEncryptedBlob, isEncryptedSecret } from "./credentialEncryption";
import { encryptExistingSecrets } from "./secretMigration";

const TEST_KEY = Buffer.alloc(32, 7).toString("base64");

type Row = Record<string, unknown> & { id: string };

/** A tiny in-memory stand-in for the three calls the migration makes. */
function fakeDb(tables: Record<string, Row[]>, opts: { failUpdatesFor?: string[]; missing?: string[] } = {}) {
  const updates: Array<{ table: string; id: string; patch: Record<string, unknown> }> = [];
  const db = {
    from(table: string) {
      return {
        select() {
          let from = 0;
          let to = Infinity;
          const q = {
            order: () => q,
            range: (f: number, t: number) => {
              from = f;
              to = t;
              return q;
            },
            then: (resolve: (v: unknown) => void) => {
              if (opts.missing?.includes(table)) return resolve({ data: null, error: { code: "42P01", message: "no such table" } });
              resolve({ data: (tables[table] ?? []).slice(from, to + 1), error: null });
            },
          };
          return q;
        },
        update(patch: Record<string, unknown>) {
          return {
            eq: (_col: string, id: string) =>
              Promise.resolve().then(() => {
                if (opts.failUpdatesFor?.includes(id)) return { error: { message: "boom" } };
                const row = tables[table].find((r) => r.id === id)!;
                Object.assign(row, patch);
                updates.push({ table, id, patch });
                return { error: null };
              }),
          };
        },
      };
    },
  };
  return { db: db as unknown as SupabaseClient, updates };
}

describe("encryptExistingSecrets", () => {
  const original = process.env.CREDENTIALS_ENC_KEY;
  beforeEach(() => {
    process.env.CREDENTIALS_ENC_KEY = TEST_KEY;
  });
  afterEach(() => {
    if (original === undefined) delete process.env.CREDENTIALS_ENC_KEY;
    else process.env.CREDENTIALS_ENC_KEY = original;
  });

  function seed() {
    return {
      ticket_integrations: [
        { id: "t1", provider: "github", github_token: "ghp_plain", github_owner: "acme" },
        { id: "t2", provider: "jira", jira_api_token: encryptSecret("already"), jira_email: "a@acme.test" },
        { id: "t3", provider: "pagerduty", pagerduty_routing_key: "pd-plain", opsgenie_api_key: null },
      ] as Row[],
      target_auth_credentials: [
        { id: "a1", auth_type: "cookie", cookie_value: "session=1", basic_password: null },
        { id: "a2", auth_type: "basic", cookie_value: null, basic_password: "pw", basic_username: "svc" },
      ] as Row[],
      uptime_integrations: [{ id: "u1", provider: "uptimerobot", api_key: "ur-plain" }] as Row[],
      cloud_credentials: [
        { id: "c1", provider: "aws", credentials_encrypted: { accessKeyId: "AKIA", secretAccessKey: "s" } },
        { id: "c2", provider: "azure", credentials_encrypted: encryptCredentials({ clientSecret: "x" }) },
      ] as Row[],
    };
  }

  it("encrypts every legacy plaintext secret, leaving non-secret columns and already-encrypted values alone", async () => {
    const tables = seed();
    const { db } = fakeDb(tables);
    const report = await encryptExistingSecrets(db, { dryRun: false });

    expect(report).toEqual([
      { table: "ticket_integrations", scanned: 3, rewritten: 2, alreadySecure: 1, failed: 0 },
      { table: "target_auth_credentials", scanned: 2, rewritten: 2, alreadySecure: 0, failed: 0 },
      { table: "uptime_integrations", scanned: 1, rewritten: 1, alreadySecure: 0, failed: 0 },
      { table: "cloud_credentials", scanned: 2, rewritten: 1, alreadySecure: 1, failed: 0 },
    ]);
    expect(decryptSecret(tables.uptime_integrations[0].api_key as string)).toBe("ur-plain");

    expect(isEncryptedSecret(tables.ticket_integrations[0].github_token)).toBe(true);
    expect(decryptSecret(tables.ticket_integrations[0].github_token as string)).toBe("ghp_plain");
    expect(tables.ticket_integrations[0].github_owner).toBe("acme");
    expect(decryptSecret(tables.ticket_integrations[1].jira_api_token as string)).toBe("already");
    expect(decryptSecret(tables.ticket_integrations[2].pagerduty_routing_key as string)).toBe("pd-plain");
    expect(tables.ticket_integrations[2].opsgenie_api_key).toBeNull();
    expect(decryptSecret(tables.target_auth_credentials[0].cookie_value as string)).toBe("session=1");
    expect(tables.target_auth_credentials[0].basic_password).toBeNull();
    expect(decryptSecret(tables.target_auth_credentials[1].basic_password as string)).toBe("pw");
    expect(tables.target_auth_credentials[1].basic_username).toBe("svc");
    expect(isEncryptedBlob(tables.cloud_credentials[0].credentials_encrypted)).toBe(true);
    expect(decryptCredentials(tables.cloud_credentials[0].credentials_encrypted)).toEqual({ accessKeyId: "AKIA", secretAccessKey: "s" });
  });

  it("is idempotent: a second run changes nothing", async () => {
    const tables = seed();
    const { db } = fakeDb(tables);
    await encryptExistingSecrets(db, { dryRun: false });
    const snapshot = JSON.stringify(tables);
    const second = fakeDb(tables);
    const report = await encryptExistingSecrets(second.db, { dryRun: false });
    expect(second.updates).toHaveLength(0);
    expect(report.every((r) => r.rewritten === 0 && r.failed === 0)).toBe(true);
    expect(JSON.stringify(tables)).toBe(snapshot);
  });

  it("a dry run reports what it would rewrite and writes nothing", async () => {
    const tables = seed();
    const before = JSON.stringify(tables);
    const { db, updates } = fakeDb(tables);
    const report = await encryptExistingSecrets(db, { dryRun: true });
    expect(updates).toHaveLength(0);
    expect(JSON.stringify(tables)).toBe(before);
    expect(report.map((r) => r.rewritten)).toEqual([2, 2, 1, 1]);
  });

  it("keeps going past a row it cannot update and counts it as failed", async () => {
    const tables = seed();
    const { db } = fakeDb(tables, { failUpdatesFor: ["t1"] });
    const report = await encryptExistingSecrets(db, { dryRun: false });
    expect(report[0]).toMatchObject({ table: "ticket_integrations", rewritten: 1, failed: 1 });
    expect(tables.ticket_integrations[0].github_token).toBe("ghp_plain");
    expect(isEncryptedSecret(tables.ticket_integrations[2].pagerduty_routing_key)).toBe(true);
  });

  it("skips a table whose migration hasn't been applied yet", async () => {
    const { db } = fakeDb(seed(), { missing: ["cloud_credentials"] });
    const report = await encryptExistingSecrets(db, { dryRun: false });
    expect(report[3]).toMatchObject({ table: "cloud_credentials", missing: true, scanned: 0 });
    expect(report[0].rewritten).toBe(2);
  });

  it("pages through more rows than one request returns", async () => {
    const many: Row[] = Array.from({ length: 1203 }, (_, i) => ({ id: `r${String(i).padStart(5, "0")}`, provider: "github", github_token: `tok-${i}` }));
    const tables = { ticket_integrations: many, target_auth_credentials: [] as Row[], cloud_credentials: [] as Row[] };
    const { db } = fakeDb(tables);
    const report = await encryptExistingSecrets(db, { dryRun: false });
    expect(report[0]).toMatchObject({ scanned: 1203, rewritten: 1203, failed: 0 });
    expect(decryptSecret(many[1202].github_token as string)).toBe("tok-1202");
  });
});
