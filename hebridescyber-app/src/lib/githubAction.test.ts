// The packaged GitHub Action (action/index.js at the repo root) is a plain,
// dependency-free CommonJS script outside this app, so it has no test runner
// of its own. Loaded here through Node's require — it only starts a scan when
// run as the entry point.
import { describe, it, expect } from "vitest";
import { createRequire } from "node:module";
import path from "node:path";
import { readFileSync } from "node:fs";

const require = createRequire(import.meta.url);
const action = require(path.resolve(process.cwd(), "..", "action", "index.js")) as {
  DEFAULT_API_BASE_URL: string;
  isTriaged: (finding: unknown, now?: number) => boolean;
  blockingFindings: (findings: unknown[], failOn: string, now?: number) => Array<{ check_id: string }>;
  lockfilesIn: (paths: string[]) => string[];
  blockingVulnerabilities: (vulns: unknown[], failOn: string) => Array<{ name: string }>;
  buildDependencyComment: (result: unknown, failOn: string) => string;
  LOCKFILE_COMPANIONS: Record<string, string | null>;
};

const NOW = Date.parse("2026-10-01T12:00:00Z");
const finding = (check_id: string, severity: string, extra: Record<string, unknown> = {}) => ({
  check_id, severity, title: check_id, status: "new", ...extra,
});
const triage = (state: string, expires_at: string | null = null) => ({ state, reason: "documented", expires_at, triaged_at: "2026-09-01T00:00:00Z" });

describe("action API base URL", () => {
  // The API key travels to this host as a Bearer token. hebridescyber.com was
  // never registered: the old default failed every run and would have handed
  // customers' keys to whoever registered it.
  const repoRoot = path.resolve(process.cwd(), "..");

  it("defaults to the live domain, the same in index.js and action.yml", () => {
    expect(action.DEFAULT_API_BASE_URL).toBe("https://www.hebridescyber.co.uk");
    const yml = readFileSync(path.join(repoRoot, "action", "action.yml"), "utf8");
    expect(yml).toMatch(/api-base-url:[\s\S]*?default: "https:\/\/www\.hebridescyber\.co\.uk"/);
  });

  it("no shipped file points customers at the unregistered hebridescyber.com", () => {
    const files = [
      "action/index.js", "action/action.yml", "action/README.md",
      "hebridescyber-app/docs/API.md", "hebridescyber-app/public/.well-known/security.txt",
    ];
    for (const f of files) {
      expect(readFileSync(path.join(repoRoot, f), "utf8"), f).not.toMatch(/(?:https?:\/\/(?:www\.)?|@)hebridescyber\.com\b/);
    }
  });
});

describe("action isTriaged", () => {
  it("is true for a triage with no expiry or a future one", () => {
    expect(action.isTriaged(finding("a", "high", { triage: triage("accepted_risk") }), NOW)).toBe(true);
    expect(action.isTriaged(finding("a", "high", { triage: triage("snoozed", "2026-10-05T00:00:00Z") }), NOW)).toBe(true);
  });

  it("is false with no triage, a null triage, or an expired one", () => {
    expect(action.isTriaged(finding("a", "high"), NOW)).toBe(false);
    expect(action.isTriaged(finding("a", "high", { triage: null }), NOW)).toBe(false);
    expect(action.isTriaged(finding("a", "high", { triage: triage("snoozed", "2026-09-30T00:00:00Z") }), NOW)).toBe(false);
    expect(action.isTriaged(finding("a", "high", { triage: triage("snoozed", "not a date") }), NOW)).toBe(false);
  });
});

describe("action blockingFindings", () => {
  const findings = [
    finding("new-high", "high"),
    finding("new-high-fp", "high", { triage: triage("false_positive") }),
    finding("new-crit-snoozed", "critical", { triage: triage("snoozed", "2026-10-31T00:00:00Z") }),
    finding("new-crit-expired", "critical", { triage: triage("snoozed", "2026-09-01T00:00:00Z") }),
    finding("old-crit", "critical", { status: "unchanged" }),
    finding("new-low", "low"),
  ];

  it("ignores actively triaged findings when deciding pass/fail", () => {
    expect(action.blockingFindings(findings, "high", NOW).map((f) => f.check_id)).toEqual(["new-high", "new-crit-expired"]);
  });

  it("passes when every blocking finding is triaged", () => {
    expect(action.blockingFindings([findings[1], findings[2]], "low", NOW)).toEqual([]);
  });

  it("never blocks with fail-on none", () => {
    expect(action.blockingFindings(findings, "none", NOW)).toEqual([]);
  });
});

describe("action dependency check helpers", () => {
  it("picks supported lockfiles out of the changed paths, including monorepo ones", () => {
    expect(action.lockfilesIn(["src/a.ts", "package-lock.json", "web/yarn.lock", "node_modules/x/package-lock.json", "Cargo.lock", "docs/go.mod"])).toEqual([
      "package-lock.json",
      "web/yarn.lock",
      "Cargo.lock",
    ]);
    expect(action.lockfilesIn(undefined as unknown as string[])).toEqual([]);
  });

  it("lists every lockfile the server supports", async () => {
    const { LOCKFILES } = await import("@/lib/scanners/dependencyLockfiles");
    expect(Object.keys(action.LOCKFILE_COMPANIONS).sort()).toEqual(LOCKFILES.map((l) => l.file).sort());
    for (const l of LOCKFILES) expect(action.LOCKFILE_COMPANIONS[l.file] ?? undefined).toBe(l.companion);
  });

  const vuln = (name: string, severity: string, extra: Record<string, unknown> = {}) => ({
    name, version: "1.0.0", severity, direct: true, dev: false, fixed_version: "1.0.1", introduced_via: null,
    advisories: [{ id: "GHSA-1", cve_ids: ["CVE-2021-1234"] }], ...extra,
  });

  it("gates on severity and never on none", () => {
    const vulns = [vuln("a", "critical"), vuln("b", "high"), vuln("c", "low")];
    expect(action.blockingVulnerabilities(vulns, "high").map((v) => v.name)).toEqual(["a", "b"]);
    expect(action.blockingVulnerabilities(vulns, "low")).toHaveLength(3);
    expect(action.blockingVulnerabilities(vulns, "none")).toEqual([]);
    expect(action.blockingVulnerabilities(undefined as unknown as unknown[], "high")).toEqual([]);
  });

  it("writes a clean comment, with the marker the action updates in place", () => {
    const md = action.buildDependencyComment({ complete: true, packages_added: 1, vulnerabilities: [] }, "high");
    expect(md).toContain("<!-- hebrides-cyber-dependency-check -->");
    expect(md).toContain("No known-vulnerable packages introduced");
    expect(md).toContain("(1 package added)");
    expect(action.buildDependencyComment({ complete: true, packages_added: 3, vulnerabilities: [] }, "high")).toContain("(3 packages added)");
  });

  it("tabulates introduced vulnerabilities with fix and route in", () => {
    const md = action.buildDependencyComment(
      {
        complete: true,
        packages_added: 4,
        vulnerabilities: [
          vuln("lo|dash", "high"),
          vuln("deep", "low", { direct: false, dev: true, introduced_via: ["a@1", "b@2"], fixed_version: null, advisories: [{ id: "GHSA-9", cve_ids: [] }] }),
          vuln("plain", "low", { direct: false }),
        ],
      },
      "high"
    );
    expect(md).toContain("introduces **3** known-vulnerable packages — 1 at or above `high`");
    expect(md).toContain("high ⛔");
    expect(md).toContain("`lo\\|dash@1.0.0`");
    expect(md).toContain("`1.0.1`");
    expect(md).toContain("direct dependency");
    expect(md).toContain("no fix named");
    expect(md).toContain("a@1 → b@2");
    expect(md).toContain("(dev)");
    expect(md).toContain("GHSA-9");
    expect(md).toContain("| transitive |");
  });

  it("uses singular wording and omits the gate count when nothing blocks", () => {
    const md = action.buildDependencyComment({ complete: true, packages_added: 1, vulnerabilities: [vuln("a", "low")] }, "high");
    expect(md).toContain("introduces **1** known-vulnerable package.");
  });

  it("says plainly when it couldn't check everything", () => {
    const md = action.buildDependencyComment({ complete: false, notes: ["A lockfile couldn't be read."], files: [{ status: "error", error: "yarn.lock: could not be read" }, { status: "ok" }], packages_added: 0, vulnerabilities: [] }, "high");
    expect(md).toContain("Not everything could be checked");
    expect(md).toContain("- yarn.lock: could not be read");
    expect(md).not.toContain("No known-vulnerable");
    expect(action.buildDependencyComment({ complete: false, packages_added: 0, vulnerabilities: [vuln("a", "low")] }, "none")).toContain("Not everything could be checked");
  });
});
