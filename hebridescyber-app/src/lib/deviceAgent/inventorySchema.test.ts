import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { inventorySchema, LIMITS } from "./inventorySchema";
import { ubuntuInventory } from "./testFixtures";

// The Go agent's own golden payloads (agent/internal/collect/testdata), so a
// field renamed on either side fails here or in `go test`.
const GOLDEN_DIR = join(process.cwd(), "..", "agent", "internal", "collect", "testdata");
const golden = (os: string) => JSON.parse(readFileSync(join(GOLDEN_DIR, `inventory-${os}.golden.json`), "utf8")) as unknown;

function issueOf(body: unknown): string {
  const r = inventorySchema.safeParse(body);
  if (r.success) return "ok";
  const i = r.error.issues[0];
  return `${i.path.join(".")}: ${i.message}`;
}

describe("inventorySchema", () => {
  it.each(["linux", "macos", "windows"])("accepts the Go agent's %s payload", (os) => {
    const r = inventorySchema.safeParse(golden(os));
    expect(r.success, r.success ? "" : JSON.stringify(r.error.issues[0])).toBe(true);
  });

  it("fills omitted optional fields with defaults, as the agent omits empty ones", () => {
    const r = inventorySchema.parse(golden("windows"));
    expect(r.os.distro_id).toBe("");
    expect(r.software[1].installed_at).toBe("");
    expect(r.pending_updates.some((p) => p.security)).toBe(true);
  });

  it("strips unknown keys rather than storing them", () => {
    const r = inventorySchema.parse({ ...ubuntuInventory(), extra: "x", os: { ...ubuntuInventory().os, injected: "<script>" } });
    expect(r).not.toHaveProperty("extra");
    expect(r.os).not.toHaveProperty("injected");
  });

  it("refuses another schema version", () => {
    expect(issueOf({ ...ubuntuInventory(), schema_version: 2 })).toMatch(/^schema_version:/);
  });

  it("refuses oversized lists and strings", () => {
    const sw = ubuntuInventory().software[0];
    expect(issueOf({ ...ubuntuInventory(), software: Array.from({ length: LIMITS.software + 1 }, () => sw) })).toMatch(/^software:/);
    expect(issueOf({ ...ubuntuInventory(), software: [{ ...sw, name: "x".repeat(LIMITS.name + 1) }] })).toMatch(/^software\.0\.name: must be 200/);
    expect(issueOf({ ...ubuntuInventory(), hostname: "h".repeat(LIMITS.name + 1) })).toMatch(/^hostname:/);
    expect(issueOf({ ...ubuntuInventory(), errors: Array.from({ length: LIMITS.errors + 1 }, () => "e") })).toMatch(/^errors:/);
  });

  it("refuses control characters, bad enums, bad dates and wrong types", () => {
    const base = ubuntuInventory();
    expect(issueOf({ ...base, hostname: "web\u0000-01" })).toMatch(/control characters/);
    expect(issueOf({ ...base, os: { ...base.os, family: "plan9" } })).toMatch(/^os\.family:/);
    expect(issueOf({ ...base, software: [{ ...base.software[0], source: "npm" }] })).toMatch(/^software\.0\.source:/);
    expect(issueOf({ ...base, pending_updates: [{ ...base.pending_updates[0], released_at: "last week" }] })).toMatch(/YYYY-MM-DD/);
    expect(issueOf({ ...base, pending_updates: [{ ...base.pending_updates[0], severity: "urgent" }] })).toMatch(/severity/);
    expect(issueOf({ ...base, pending_updates_checked: "yes" })).toMatch(/^pending_updates_checked:/);
    expect(issueOf({ ...base, collected_at: "not a time" })).toMatch(/RFC 3339/);
    expect(issueOf({ ...base, software: [{ ...base.software[0], name: "" }] })).toMatch(/required/);
  });

  it("refuses a body that isn't an object", () => {
    for (const body of [null, "[]", [], 42]) expect(inventorySchema.safeParse(body).success).toBe(false);
  });

  it("keeps tab and newline-free text but allows ordinary punctuation and unicode", () => {
    expect(issueOf({ ...ubuntuInventory(), hostname: "Café-PC (Ünïcode) #2" })).toBe("ok");
  });
});
