import { describe, it, expect } from "vitest";
import { hasPermission, type OrgRole, type RbacAction } from "./rbac";

describe("hasPermission", () => {
  it("owner has access to everything", () => {
    expect(hasPermission("owner", "scans", "create")).toBe(true);
    expect(hasPermission("owner", "members", "delete")).toBe(true);
    expect(hasPermission("owner", "anything", "execute")).toBe(true);
  });

  it("admin can manage scans and members", () => {
    expect(hasPermission("admin", "scans", "create")).toBe(true);
    expect(hasPermission("admin", "scans", "read")).toBe(true);
    expect(hasPermission("admin", "scans", "execute")).toBe(true);
    expect(hasPermission("admin", "members", "create")).toBe(true);
    expect(hasPermission("admin", "members", "delete")).toBe(true);
  });

  it("admin can manage integrations", () => {
    expect(hasPermission("admin", "integrations", "create")).toBe(true);
    expect(hasPermission("admin", "integrations", "delete")).toBe(true);
  });

  it("analyst can create and read scans but not delete", () => {
    expect(hasPermission("analyst", "scans", "create")).toBe(true);
    expect(hasPermission("analyst", "scans", "read")).toBe(true);
    expect(hasPermission("analyst", "scans", "execute")).toBe(true);
    expect(hasPermission("analyst", "scans", "delete")).toBe(false);
  });

  it("analyst can read and update findings", () => {
    expect(hasPermission("analyst", "findings", "read")).toBe(true);
    expect(hasPermission("analyst", "findings", "update")).toBe(true);
    expect(hasPermission("analyst", "findings", "delete")).toBe(false);
  });

  it("viewer is read-only", () => {
    expect(hasPermission("viewer", "scans", "read")).toBe(true);
    expect(hasPermission("viewer", "scans", "create")).toBe(false);
    expect(hasPermission("viewer", "reports", "read")).toBe(true);
    expect(hasPermission("viewer", "reports", "create")).toBe(false);
    expect(hasPermission("viewer", "members", "read")).toBe(false);
  });

  it("member has minimal access", () => {
    expect(hasPermission("member", "scans", "read")).toBe(true);
    expect(hasPermission("member", "scans", "create")).toBe(false);
    expect(hasPermission("member", "integrations", "read")).toBe(false);
  });

  it("denies access to unknown resources", () => {
    expect(hasPermission("admin", "billing", "update")).toBe(false);
    expect(hasPermission("analyst", "unknown", "read")).toBe(false);
  });

  const roles: OrgRole[] = ["owner", "admin", "analyst", "viewer", "member"];
  const actions: RbacAction[] = ["create", "read", "update", "delete", "execute"];

  it("never throws for any role/resource/action combination", () => {
    for (const role of roles) {
      for (const action of actions) {
        expect(() => hasPermission(role, "scans", action)).not.toThrow();
        expect(() => hasPermission(role, "unknown", action)).not.toThrow();
      }
    }
  });
});
