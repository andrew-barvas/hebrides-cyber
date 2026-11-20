import { describe, it, expect } from "vitest";
import { displayStatus, evaluatePatchRule, isInScopeUpdate, nextPendingFirstSeen } from "./patchRule";
import type { DeviceCve, DeviceMatch } from "./matching";
import { ubuntuInventory, windowsInventory } from "./testFixtures";

const NOW = new Date("2026-11-20T09:00:00Z");

function match(overrides: Partial<DeviceMatch> = {}): DeviceMatch {
  return { status: "checked", matchedAt: NOW.toISOString(), cves: [], osEol: null, notes: [], coverage: { softwareTotal: 3, softwareChecked: 2 }, ...overrides };
}

function cve(overrides: Partial<DeviceCve> = {}): DeviceCve {
  return {
    id: "CVE-2026-1000",
    advisoryId: "CVE-2026-1000",
    source: "nvd",
    software: "Google Chrome",
    version: "123.0.6312.122",
    cvssScore: 8.8,
    severity: "high",
    fixAvailable: true,
    fixedVersion: "124.0.6367.60",
    publishedAt: "2026-10-01T10:00:00Z",
    summary: "Use after free",
    ...overrides,
  };
}

describe("isInScopeUpdate", () => {
  it("counts security updates and vendor critical/important ratings only", () => {
    expect(isInScopeUpdate({ security: true, severity: "" })).toBe(true);
    expect(isInScopeUpdate({ security: false, severity: "important" })).toBe(true);
    expect(isInScopeUpdate({ security: false, severity: "critical" })).toBe(true);
    expect(isInScopeUpdate({ security: false, severity: "moderate" })).toBe(false);
    expect(isInScopeUpdate({ security: false, severity: "" })).toBe(false);
  });
});

describe("nextPendingFirstSeen", () => {
  const pending = ubuntuInventory().pending_updates;
  it("keeps the first-reported date of updates still pending and adds today for new ones", () => {
    const next = nextPendingFirstSeen({ "apt:openssl": "2026-11-01", "apt:gone": "2026-10-01" }, pending, NOW);
    expect(next).toEqual({ "apt:openssl": "2026-11-01", "apt:tzdata": "2026-11-20" });
  });
  it("ignores stored dates that are malformed or in the future", () => {
    expect(nextPendingFirstSeen({ "apt:openssl": "soon", "apt:tzdata": "2027-01-01" }, pending, NOW)).toEqual({ "apt:openssl": "2026-11-20", "apt:tzdata": "2026-11-20" });
  });
});

describe("evaluatePatchRule", () => {
  it("passes a fully checked device with nothing outstanding", () => {
    const ev = evaluatePatchRule({ inventory: windowsInventory({ pending_updates: [] }), previousFirstSeen: {}, match: match(), now: NOW });
    expect(ev.status).toBe("passes");
    expect(ev.summary).toMatch(/Meets the 14-day rule/);
    expect(ev.gaps).toEqual([]);
  });

  it("is at risk while a critical update is inside its 14 days, with the due date", () => {
    const ev = evaluatePatchRule({ inventory: windowsInventory(), previousFirstSeen: {}, match: match(), now: NOW });
    expect(ev.status).toBe("at_risk");
    expect(ev.dueSoon).toHaveLength(1);
    expect(ev.dueSoon[0]).toMatchObject({ since: "2026-11-11", sinceBasis: "vendor_release", dueBy: "2026-11-25", overdue: false, severity: "critical" });
    expect(ev.summary).toBe("1 security update to install by 2026-11-25.");
  });

  it("fails once the vendor release is more than 14 days old", () => {
    const inv = windowsInventory();
    inv.pending_updates[0].released_at = "2026-11-05";
    const ev = evaluatePatchRule({ inventory: inv, previousFirstSeen: {}, match: match(), now: NOW });
    expect(ev.status).toBe("fails");
    expect(ev.overdue[0]).toMatchObject({ dueBy: "2026-11-19", overdue: true });
    expect(ev.summary).toBe("Misses the 14-day rule: 1 item overdue.");
  });

  it("day 14 itself is still inside the window", () => {
    const inv = windowsInventory();
    inv.pending_updates[0].released_at = "2026-11-06";
    expect(evaluatePatchRule({ inventory: inv, previousFirstSeen: {}, match: match(), now: NOW }).status).toBe("at_risk");
  });

  it("ages an undated pending update from the day the device first reported it", () => {
    const fresh = evaluatePatchRule({ inventory: ubuntuInventory(), previousFirstSeen: {}, match: match(), now: NOW });
    expect(fresh.status).toBe("at_risk");
    expect(fresh.dueSoon[0]).toMatchObject({ key: "apt:openssl", sinceBasis: "first_reported", since: "2026-11-20" });
    // tzdata isn't a security update, so it's not in scope.
    expect(fresh.dueSoon).toHaveLength(1);
    expect(fresh.pendingFirstSeen).toEqual({ "apt:openssl": "2026-11-20", "apt:tzdata": "2026-11-20" });

    const later = evaluatePatchRule({ inventory: ubuntuInventory(), previousFirstSeen: { "apt:openssl": "2026-11-01" }, match: match(), now: NOW });
    expect(later.status).toBe("fails");
  });

  it("is unknown, never passes, when the update source couldn't be read", () => {
    const ev = evaluatePatchRule({ inventory: windowsInventory({ pending_updates: [], pending_updates_checked: false }), previousFirstSeen: {}, match: match(), now: NOW });
    expect(ev.status).toBe("unknown");
    expect(ev.gaps.join(" ")).toMatch(/couldn't read its update source/);
    expect(ev.summary).toMatch(/Not enough evidence/);
  });

  it("is unknown until a CVE match has run, and lists that as a gap", () => {
    const ev = evaluatePatchRule({ inventory: windowsInventory({ pending_updates: [] }), previousFirstSeen: {}, match: null, now: NOW });
    expect(ev.status).toBe("unknown");
    expect(ev.gaps).toContain("CVE and end-of-life matching hasn't run on this report yet.");
  });

  it("is unknown when the match was partial and nothing is outstanding", () => {
    const ev = evaluatePatchRule({ inventory: windowsInventory({ pending_updates: [] }), previousFirstSeen: {}, match: match({ status: "partial", notes: ["OSV.dev lookup failed"] }), now: NOW });
    expect(ev.status).toBe("unknown");
    expect(ev.gaps).toContain("OSV.dev lookup failed");
  });

  it("still fails on overdue evidence even when another source is missing", () => {
    const inv = windowsInventory({ pending_updates_checked: false, software_checked: false, truncated: true });
    const ev = evaluatePatchRule({ inventory: inv, previousFirstSeen: {}, match: match({ cves: [cve()] }), now: NOW });
    expect(ev.status).toBe("fails");
    expect(ev.gaps).toHaveLength(3);
  });

  it("counts a high CVE with a fix published over 14 days ago as overdue", () => {
    const ev = evaluatePatchRule({ inventory: windowsInventory({ pending_updates: [] }), previousFirstSeen: {}, match: match({ cves: [cve()] }), now: NOW });
    expect(ev.status).toBe("fails");
    expect(ev.overdue[0]).toMatchObject({ kind: "cve", title: "CVE-2026-1000 in Google Chrome 123.0.6312.122", severity: "CVSS 8.8", detail: "Fixed in 124.0.6367.60", sinceBasis: "cve_published" });
  });

  it("ignores CVEs below 7, without a known fix, and treats a vendor high rating as in scope", () => {
    const cves = [
      cve({ id: "CVE-low", cvssScore: 5.3, severity: "medium" }),
      cve({ id: "CVE-nofix", fixAvailable: false }),
      cve({ id: "CVE-unknownfix", fixAvailable: null }),
      cve({ id: "CVE-rated", cvssScore: null, severity: "high", fixedVersion: null, publishedAt: "2026-11-15T00:00:00Z", summary: "rated high by the distro" }),
    ];
    const ev = evaluatePatchRule({ inventory: windowsInventory({ pending_updates: [] }), previousFirstSeen: {}, match: match({ cves }), now: NOW });
    expect(ev.overdue).toEqual([]);
    expect(ev.dueSoon.map((i) => i.key)).toEqual(["CVE-rated:Google Chrome"]);
    expect(ev.dueSoon[0]).toMatchObject({ severity: "high", detail: "rated high by the distro" });
    expect(ev.status).toBe("at_risk");
    expect(ev.counts.cves).toBe(4);
  });

  it("a CVE with no publication date has no window and is listed, not failed", () => {
    const ev = evaluatePatchRule({ inventory: windowsInventory({ pending_updates: [] }), previousFirstSeen: {}, match: match({ cves: [cve({ publishedAt: null })] }), now: NOW });
    expect(ev.dueSoon[0]).toMatchObject({ since: null, dueBy: null, overdue: false });
    expect(ev.summary).toBe("1 security update to install.");
  });

  it("fails an unsupported operating system", () => {
    const ev = evaluatePatchRule({
      inventory: windowsInventory({ pending_updates: [] }),
      previousFirstSeen: {},
      match: match({ osEol: { product: "windows", cycle: "11-23h2-w", state: "unsupported", eolDate: "2025-11-11" } }),
      now: NOW,
    });
    expect(ev.status).toBe("fails");
    expect(ev.overdue[0]).toMatchObject({ kind: "unsupported_os", title: "Microsoft Windows 11 Pro 11-23h2-w is no longer supported", sinceBasis: "end_of_life" });
  });

  it("an unsupported OS with no end date still fails", () => {
    const inv = ubuntuInventory({ pending_updates: [] });
    inv.os.name = "";
    const ev = evaluatePatchRule({ inventory: inv, previousFirstSeen: {}, match: match({ osEol: { product: "ubuntu", cycle: "14.04", state: "unsupported", eolDate: null } }), now: NOW });
    expect(ev.overdue[0]).toMatchObject({ title: "linux 14.04 is no longer supported", sinceBasis: null });
  });

  it("reports counts for the dashboard", () => {
    const ev = evaluatePatchRule({ inventory: ubuntuInventory(), previousFirstSeen: {}, match: null, now: NOW });
    expect(ev.counts).toEqual({ software: 3, pendingUpdates: 2, securityUpdates: 1, cves: 0 });
    expect(ev.evaluatedAt).toBe(NOW.toISOString());
  });

  it("an update flagged only by vendor rating shows the rating, and an id-only title falls back to the id", () => {
    const inv = windowsInventory();
    inv.pending_updates = [{ id: "KB1", title: "", version: "2.0", severity: "important", security: false, released_at: "2026-11-18", source: "windows-update" }];
    const ev = evaluatePatchRule({ inventory: inv, previousFirstSeen: {}, match: match(), now: NOW });
    expect(ev.dueSoon[0]).toMatchObject({ title: "KB1", severity: "important", detail: "Update available: 2.0" });
  });
});

describe("displayStatus", () => {
  it("shows never-reported, stale and stored statuses", () => {
    expect(displayStatus("never_reported", null, NOW)).toBe("never_reported");
    expect(displayStatus("passes", "2026-11-01T00:00:00Z", NOW)).toBe("stale");
    expect(displayStatus("fails", "2026-11-19T00:00:00Z", NOW)).toBe("fails");
    expect(displayStatus("garbage", "2026-11-19T00:00:00Z", NOW)).toBe("unknown");
  });
});
