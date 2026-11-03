import { describe, it, expect } from "vitest";
import { buildFindings, PLATFORM_TLS_TECHNOLOGIES, scanProblemOf, testsslScopeArgs, type TestsslEntry } from "./deepTls";

describe("deepTls scan problems", () => {
  it("treats a file of only WARN/FATAL entries as a failed run", () => {
    expect(
      scanProblemOf([
        { id: "scanProblem", severity: "FATAL", finding: "Can't connect to '127.0.0.1:1'" },
        { id: "engine_problem", severity: "WARN", finding: "No engine or GOST support via engine with your /usr/bin/openssl" },
      ])
    ).toBe("Can't connect to '127.0.0.1:1'");
  });

  it("never treats an empty file as a failure: a healthy server writes nothing at LOW", () => {
    expect(scanProblemOf([])).toBeNull();
  });

  it("never treats a scanner-side WARN on its own as a failure", () => {
    expect(scanProblemOf([{ id: "engine_problem", severity: "WARN", finding: "No engine" }])).toBeNull();
  });

  it("keeps a run that rated at least one check", () => {
    expect(
      scanProblemOf([
        { id: "engine_problem", severity: "WARN", finding: "No engine" },
        { id: "TLS1", severity: "LOW", finding: "offered (deprecated)" },
      ])
    ).toBeNull();
  });
});

describe("deepTls scope under a non-intrusive profile", () => {
  const intrusive = ["--heartbleed", "--ccs-injection", "--ticketbleed", "--robot"];

  it("runs every probe by default", () => {
    expect(testsslScopeArgs()).toEqual(expect.arrayContaining(intrusive));
  });

  it("drops only the probes that send crafted input to trigger a flaw", () => {
    const narrowed = testsslScopeArgs(true);
    for (const flag of intrusive) expect(narrowed).not.toContain(flag);
    expect(narrowed).toEqual(testsslScopeArgs().filter((a) => !intrusive.includes(a)));
    // The configuration checks Lookout sells stay in.
    expect(narrowed).toEqual(expect.arrayContaining(["--protocols", "--std", "--fs", "--server-defaults", "--sweet32", "--drown"]));
  });
});

const platformEntries: TestsslEntry[] = [
  { id: "cipherlist_OBSOLETED", severity: "LOW", finding: "offered" },
  { id: "FS_TLS12_sig_algs", severity: "LOW", finding: "RSA+SHA1 RSA+SHA256" },
];

function severities(entries: TestsslEntry[], platformManagedTls?: boolean) {
  return buildFindings(entries, platformManagedTls === undefined ? undefined : { platformManagedTls }).findings.map((f) => f.severity);
}

describe("deepTls platform demotion", () => {
  it("keeps testssl's severity by default — on a self-hosted server these are the operator's own config", () => {
    const s = severities(platformEntries);
    expect(s.length).toBeGreaterThan(0);
    expect(s).not.toContain("info");
    expect(s).toContain("low");
  });

  it("keeps it when the target is explicitly not platform-managed", () => {
    expect(severities(platformEntries, false)).toContain("low");
  });

  it("demotes to info only when TLS is terminated by Azure's platform", () => {
    const s = severities(platformEntries, true);
    expect(s.length).toBeGreaterThan(0);
    expect(s.every((x) => x === "info")).toBe(true);
  });

  it("never demotes checks outside the platform list, even on Azure", () => {
    const s = severities([{ id: "SSLv3", severity: "HIGH", finding: "offered (NOT ok)" }], true);
    expect(s).toContain("high");
  });

  it("recognises both Azure fingerprints", () => {
    expect([...PLATFORM_TLS_TECHNOLOGIES]).toEqual(["Azure CDN", "Azure App Service"]);
  });
});
