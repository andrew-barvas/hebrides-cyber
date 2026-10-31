import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const { execToolMock, planGateMock } = vi.hoisted(() => ({ execToolMock: vi.fn(), planGateMock: vi.fn() }));
vi.mock("../../lib/execTool", () => ({ execTool: execToolMock }));
vi.mock("../../lib/planAccess", () => ({ planGate: planGateMock }));

process.env.CREDENTIALS_ENC_KEY = Buffer.alloc(32, 7).toString("base64");
import { encryptCredentials } from "../../lib/credentialEncryption";
import { parseProwlerOcsf, prowlerRecordsToFindings, runProwlerIam } from "./prowlerIam";

// Hand-built to Prowler 5.47.0's json-ocsf shape, NOT a real capture; see fixtures/prowler/README.md.
const FIXTURE = readFileSync(`${process.cwd()}/src/worker/tools/fixtures/prowler/iam-ocsf-5.47.0.json`, "utf8");
const ROLE_ARN = "arn:aws:iam::123456789012:role/HebridesCyberAudit";
const EXTERNAL_ID = "hc-0123456789abcdef0123456789abcdef";

describe("parseProwlerOcsf", () => {
  it("reads check id, status, severity and account from each record", () => {
    const recs = parseProwlerOcsf(FIXTURE);
    expect(recs).toHaveLength(6);
    expect(recs[0]).toMatchObject({
      checkId: "iam_inline_policy_allows_privilege_escalation",
      status: "FAIL",
      severity: "high",
      accountId: "123456789012",
      resourceName: "ci-deploy",
    });
    expect(recs[3].severity).toBe("critical");
  });

  it("throws on a report that is not a JSON array or has a record with no check id", () => {
    expect(() => parseProwlerOcsf("{}")).toThrow();
    expect(() => parseProwlerOcsf("not json")).toThrow();
    expect(() => parseProwlerOcsf(JSON.stringify([{ status_code: "FAIL" }]))).toThrow(/missing/);
  });
});

describe("prowlerRecordsToFindings", () => {
  const findings = prowlerRecordsToFindings(parseProwlerOcsf(FIXTURE));

  it("turns only FAIL records into findings, with stable per-resource check ids", () => {
    expect(findings.map((f) => f.checkId)).toEqual([
      "prowler.iam_inline_policy_allows_privilege_escalation:123456789012:arn:aws:iam::123456789012:user/deploy-bot/policy/ci-deploy",
      "prowler.iam_policy_allows_privilege_escalation:123456789012:arn:aws:iam::123456789012:policy/DevPolicy",
      "prowler.iam_user_mfa_enabled_console_access:123456789012:arn:aws:iam::123456789012:user/alice",
    ]);
  });

  it("carries Prowler's own detail, remediation and structured evidence", () => {
    const f = findings[0];
    expect(f.severity).toBe("high");
    expect(f.detail).toContain("iam:PassRole");
    expect(f.remediation).toContain("least privilege");
    expect(f.metadata).toMatchObject({
      prowler: { check: "iam_inline_policy_allows_privilege_escalation", version: "5.47.0", accountId: "123456789012", region: "us-east-1" },
    });
  });

  it("falls back to generic remediation when the record has none", () => {
    expect(findings[1].remediation).toBeTruthy();
    expect(findings[1].remediation).toContain("least privilege");
  });
});

describe("runProwlerIam", () => {
  type Row = { label: string; credentials_encrypted: unknown };
  const supabaseWith = (rows: Row[], error: { message: string } | null = null) =>
    ({ from: () => ({ select: () => ({ eq: () => ({ eq: () => Promise.resolve({ data: rows, error }) }) }) }) }) as never;
  const roleRow: Row = { label: "prod", credentials_encrypted: encryptCredentials({ authMode: "role", externalId: EXTERNAL_ID, roleArn: ROLE_ARN }) };
  const saved = { ...process.env };

  beforeEach(() => {
    execToolMock.mockReset();
    planGateMock.mockReset();
    planGateMock.mockResolvedValue("ok");
    process.env.CREDENTIALS_ENC_KEY = Buffer.alloc(32, 7).toString("base64");
    process.env.PROWLER_AWS_ACCESS_KEY_ID = "AKIAEXAMPLE";
    process.env.PROWLER_AWS_SECRET_ACCESS_KEY = "secret";
  });
  afterEach(() => {
    process.env = { ...saved };
  });

  function writesReport(content: string) {
    execToolMock.mockImplementation(async (_f: string, args: string[]) => {
      writeFileSync(join(args[args.indexOf("--output-directory") + 1], "prowler-iam.ocsf.json"), content);
      return { stdout: "", stderr: "" };
    });
  }

  it("runs only the iam service with the role and external id, and returns the failures", async () => {
    writesReport(FIXTURE);
    const res = await runProwlerIam(supabaseWith([roleRow]), "owner");
    expect(res.status).toBe("completed");
    expect(res.findings).toHaveLength(3);
    const [file, args, opts] = execToolMock.mock.calls[0];
    expect(file).toBe("prowler");
    expect(args).toEqual(expect.arrayContaining(["--service", "iam", "--role", ROLE_ARN, "--external-id", EXTERNAL_ID, "--ignore-exit-code-3"]));
    expect(args).not.toContain("--security-hub");
    expect(opts.env.AWS_ACCESS_KEY_ID).toBe("AKIAEXAMPLE");
    expect(opts.env.SUPABASE_SERVICE_ROLE_KEY).toBeUndefined();
  });

  it("is not_applicable below the Agency tier and does not run", async () => {
    planGateMock.mockResolvedValue("denied");
    const res = await runProwlerIam(supabaseWith([roleRow]), "owner");
    expect(res.status).toBe("not_applicable");
    expect(execToolMock).not.toHaveBeenCalled();
  });

  it("is not_configured with no role connected, including a role still waiting for its ARN", async () => {
    expect((await runProwlerIam(supabaseWith([]), "owner")).status).toBe("not_configured");
    const pending: Row = { label: "p", credentials_encrypted: encryptCredentials({ authMode: "role", externalId: EXTERNAL_ID, roleArn: "" }) };
    expect((await runProwlerIam(supabaseWith([pending]), "owner")).status).toBe("not_configured");
    const legacy: Row = { label: "k", credentials_encrypted: encryptCredentials({ accessKeyId: "AKIA1234567890123456", secretAccessKey: "x" }) };
    expect((await runProwlerIam(supabaseWith([legacy]), "owner")).status).toBe("not_configured");
  });

  it("is an error, never clean, when the credential lookup fails", async () => {
    const res = await runProwlerIam(supabaseWith([], { message: "boom" }), "owner");
    expect(res.status).toBe("error");
  });

  it("is an error when a role is connected but the platform identity is missing", async () => {
    delete process.env.PROWLER_AWS_ACCESS_KEY_ID;
    const res = await runProwlerIam(supabaseWith([roleRow]), "owner");
    expect(res.status).toBe("error");
    expect(execToolMock).not.toHaveBeenCalled();
  });

  it("is an error when prowler is not installed", async () => {
    execToolMock.mockRejectedValue(Object.assign(new Error("spawn prowler ENOENT"), { code: "ENOENT" }));
    const res = await runProwlerIam(supabaseWith([roleRow]), "owner");
    expect(res).toMatchObject({ status: "error" });
    expect((res as { note: string }).note).toContain("not installed");
  });

  it("is an error, with the external id scrubbed, when the role cannot be assumed", async () => {
    execToolMock.mockRejectedValue(Object.assign(new Error(`Command failed: prowler --external-id ${EXTERNAL_ID}`), { stderr: "AccessDenied" }));
    const res = await runProwlerIam(supabaseWith([roleRow]), "owner");
    expect(res.status).toBe("error");
    expect((res as { note: string }).note).not.toContain(EXTERNAL_ID);
  });

  it("is an error when prowler exits cleanly but writes no report", async () => {
    execToolMock.mockResolvedValue({ stdout: "", stderr: "" });
    expect((await runProwlerIam(supabaseWith([roleRow]), "owner")).status).toBe("error");
  });

  it("is an error for an empty report or one about a different account", async () => {
    writesReport("[]");
    expect((await runProwlerIam(supabaseWith([roleRow]), "owner")).status).toBe("error");
    writesReport(FIXTURE.replaceAll("123456789012", "999999999999"));
    expect((await runProwlerIam(supabaseWith([roleRow]), "owner")).status).toBe("error");
  });

  it("is an error for a malformed report, not an empty completed run", async () => {
    writesReport("{not json");
    expect((await runProwlerIam(supabaseWith([roleRow]), "owner")).status).toBe("error");
  });
});

describe("runProwlerIam: partial and gating failures", () => {
  type Row = { label: string; credentials_encrypted: unknown };
  const supabaseWith = (rows: Row[]) =>
    ({ from: () => ({ select: () => ({ eq: () => ({ eq: () => Promise.resolve({ data: rows, error: null }) }) }) }) }) as never;
  const role = (label: string, arn: string): Row => ({ label, credentials_encrypted: encryptCredentials({ authMode: "role", externalId: EXTERNAL_ID, roleArn: arn }) });
  const saved = { ...process.env };

  beforeEach(() => {
    execToolMock.mockReset();
    planGateMock.mockReset();
    planGateMock.mockResolvedValue("ok");
    process.env.PROWLER_AWS_ACCESS_KEY_ID = "AKIAEXAMPLE";
    process.env.PROWLER_AWS_SECRET_ACCESS_KEY = "secret";
  });
  afterEach(() => {
    process.env = { ...saved };
  });

  it("is an error when the plan lookup fails", async () => {
    planGateMock.mockResolvedValue("error");
    expect((await runProwlerIam(supabaseWith([role("a", ROLE_ARN)]), "o")).status).toBe("error");
  });

  it("is an error, not not_configured, when stored credentials cannot be decrypted", async () => {
    const res = await runProwlerIam(supabaseWith([{ label: "x", credentials_encrypted: { v: 1, iv: "x", tag: "x", data: "x" } }]), "o");
    expect(res.status).toBe("error");
  });

  it("is an error for an invalid stored role ARN and never runs prowler", async () => {
    const res = await runProwlerIam(supabaseWith([role("bad", "arn:aws:iam::1:user/x")]), "o");
    expect(res.status).toBe("error");
    expect(execToolMock).not.toHaveBeenCalled();
  });

  it("keeps the findings from the account that worked but reports error when another account fails", async () => {
    const otherArn = "arn:aws:iam::210987654321:role/Other";
    execToolMock.mockImplementation(async (_f: string, args: string[]) => {
      if (args[args.indexOf("--role") + 1] === otherArn) throw new Error("AccessDenied");
      writeFileSync(join(args[args.indexOf("--output-directory") + 1], "prowler-iam.ocsf.json"), FIXTURE);
      return { stdout: "", stderr: "" };
    });
    const res = await runProwlerIam(supabaseWith([role("good", ROLE_ARN), role("bad", otherArn)]), "o");
    expect(res.status).toBe("error");
    expect(res.findings).toHaveLength(3);
    expect(res.status === "error" && res.accounts).toEqual([{ accountId: "123456789012", label: "good", checksEvaluated: 5, failed: 3 }]);
  });

  it("reports each account on a completed run", async () => {
    execToolMock.mockImplementation(async (_f: string, args: string[]) => {
      writeFileSync(join(args[args.indexOf("--output-directory") + 1], "prowler-iam.ocsf.json"), FIXTURE);
      return { stdout: "", stderr: "" };
    });
    const res = await runProwlerIam(supabaseWith([role("good", ROLE_ARN)]), "o");
    expect(res.status === "completed" && res.accounts[0]).toMatchObject({ accountId: "123456789012", failed: 3 });
  });
});

describe("prowlerRecordsToFindings edge cases", () => {
  const base = parseProwlerOcsf(FIXTURE)[0];
  it("dedupes identical resources and maps an unknown severity to info", () => {
    const f = prowlerRecordsToFindings([{ ...base, severity: "info" }, { ...base }]);
    expect(f).toHaveLength(1);
    expect(parseProwlerOcsf(JSON.stringify([{ ...JSON.parse(FIXTURE)[0], severity: "Weird" }]))[0].severity).toBe("info");
  });
  it("ignores MANUAL and MUTED records", () => {
    expect(prowlerRecordsToFindings([{ ...base, status: "MANUAL" }, { ...base, status: "MUTED" }])).toEqual([]);
  });
});
