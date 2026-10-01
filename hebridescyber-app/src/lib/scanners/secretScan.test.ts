import { describe, it, expect } from "vitest";
import { buildSecretFindings, looksLikeSamplePath, maskSecretValue, secretCheckId, severityForSecret, type GitleaksReportEntry } from "./secretScan";

describe("looksLikeSamplePath", () => {
  it.each([
    "tests/config.py",
    "src/__tests__/keys.ts",
    "fixtures/aws.json",
    "docs/setup.md",
    "README.md",
    "config.test.ts",
    "test_settings.py",
    "fake-keys.json",
    "example.env",
    ".env.sample",
  ])("treats %s as sample/test content", (path) => {
    expect(looksLikeSamplePath(path)).toBe(true);
  });

  // Regression: plain substring matching downgraded real secrets.
  it.each(["config.latest.json", "src/attestation.ts", "contest/config.js", "inspect.py", ".env.production", "src/config/aws.ts"])(
    "treats %s as real config",
    (path) => {
      expect(looksLikeSamplePath(path)).toBe(false);
    }
  );

  it("normalises Windows separators and case", () => {
    expect(looksLikeSamplePath("SRC\\Tests\\keys.ts")).toBe(true);
  });
});

describe("severityForSecret", () => {
  it("starts structurally unambiguous credentials at critical", () => {
    expect(severityForSecret("aws-access-token", 4.5, "src/config.ts")).toBe("critical");
    expect(severityForSecret("rsa-private-key", 0, "deploy/id_rsa")).toBe("critical");
  });

  it("starts keyword/entropy hits at medium, provider-specific ones at high", () => {
    expect(severityForSecret("generic-api-key", 4.5, "src/config.ts")).toBe("medium");
    expect(severityForSecret("some-provider-token", 4.5, "src/config.ts")).toBe("high");
  });

  it("drops one level for low entropy, but treats 0 as 'not scored'", () => {
    expect(severityForSecret("some-provider-token", 2.1, "src/config.ts")).toBe("medium");
    expect(severityForSecret("some-provider-token", 0, "src/config.ts")).toBe("high");
  });

  it("downgrades two levels in sample paths, but never suppresses", () => {
    expect(severityForSecret("aws-access-token", 4.5, "tests/fixtures/aws.json")).toBe("medium");
    expect(severityForSecret("generic-api-key", 2.0, "docs/README.md")).toBe("info");
  });

  // Regression for the path heuristic above.
  it("keeps a real key in config.latest.json critical", () => {
    expect(severityForSecret("aws-access-token", 4.5, "config.latest.json")).toBe("critical");
  });
});

describe("maskSecretValue", () => {
  it("keeps only a 4-character prefix of a long value", () => {
    expect(maskSecretValue("AKIAIOSFODNN7EXAMPLE")).toBe("AKIA******** (20 chars)");
  });

  it("reveals nothing of a short value", () => {
    expect(maskSecretValue("hunter2")).toBe("[redacted, 7 chars]");
  });

  it("returns null for absent or already-redacted values", () => {
    expect(maskSecretValue(undefined)).toBeNull();
    expect(maskSecretValue("  ")).toBeNull();
    expect(maskSecretValue("REDACTED")).toBeNull();
    expect(maskSecretValue("*****")).toBeNull();
  });
});

describe("secretCheckId", () => {
  it("is stable for the same location and never derived from the secret", () => {
    const a = secretCheckId("aws-access-token", "abc123", "src/a.ts", 10);
    expect(a).toBe(secretCheckId("aws-access-token", "abc123", "src/a.ts", 10));
    expect(a).toMatch(/^secretScan\.exposed-secret:aws-access-token-[0-9a-f]{16}$/);
    expect(a).not.toBe(secretCheckId("aws-access-token", "abc123", "src/a.ts", 11));
  });

  it("sanitises odd rule ids", () => {
    expect(secretCheckId("Weird Rule/ID", "c", "f", 1)).toMatch(/^secretScan\.exposed-secret:weird-rule-id-/);
  });
});

describe("buildSecretFindings", () => {
  const entry = (overrides: Partial<GitleaksReportEntry> = {}): GitleaksReportEntry => ({
    RuleID: "aws-access-token",
    File: "src/config.ts",
    StartLine: 12,
    Commit: "0123456789abcdef",
    Date: "2026-03-04T10:00:00Z",
    Entropy: 4.7,
    Secret: "AKIAIOSFODNN7EXAMPLE",
    Description: "AWS Access Key",
    ...overrides,
  });

  it("builds a finding that never contains the full secret", () => {
    const { findings, truncated } = buildSecretFindings("acme/app", [entry()]);
    expect(truncated).toBe(false);
    const [f] = findings;
    expect(f).toMatchObject({ severity: "critical", title: "[Gitleaks] Secret in repository: AWS Access Key in src/config.ts" });
    expect(f.detail).toContain("commit `01234567` (2026-03-04)");
    expect(f.detail).toContain("AKIA********");
    expect(f.detail).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(f.remediation).toContain("Rotate the credential first");
  });

  it("collapses one secret seen across many commits into one finding", () => {
    const { findings } = buildSecretFindings("acme/app", [entry({ Commit: "c1" }), entry({ Commit: "c2" }), entry({ Commit: "c3" })]);
    expect(findings).toHaveLength(1);
  });

  it("explains a downgrade in sample paths", () => {
    const [f] = buildSecretFindings("acme/app", [entry({ File: "tests/fixtures/aws.json" })]).findings;
    expect(f.severity).toBe("medium");
    expect(f.detail).toContain("Severity was downgraded");
  });

  it("truncates past 100 findings and says so", () => {
    const many = Array.from({ length: 120 }, (_, i) => entry({ File: `src/f${i}.ts`, Secret: `AKIAIOSFODNN7EXAMP${String(i).padStart(3, "0")}` }));
    const { findings, truncated } = buildSecretFindings("acme/app", many);
    expect(findings).toHaveLength(100);
    expect(truncated).toBe(true);
  });

  it("describes a working-tree match without a commit", () => {
    const [f] = buildSecretFindings("acme/app", [entry({ Commit: undefined, Secret: undefined })]).findings;
    expect(f.detail).toContain("the current working tree");
    expect(f.detail).toContain("not stored anywhere in this report by design");
  });
});
