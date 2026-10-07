import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";

const { execToolMock } = vi.hoisted(() => ({ execToolMock: vi.fn() }));
vi.mock("../../lib/execTool", () => ({ execTool: execToolMock }));

import { parseHydraOutput, buildCredentialSprayFindings, runCredentialSpray } from "./credentialSpray";

// Real THC-Hydra v9.5 -o output; see fixtures/hydra/README.md.
const FOUND = readFileSync(`${process.cwd()}/src/worker/tools/fixtures/hydra/found-9.5.out`, "utf8");
const NONE = readFileSync(`${process.cwd()}/src/worker/tools/fixtures/hydra/none-9.5.out`, "utf8");

describe("parseHydraOutput (real v9.5 -o output)", () => {
  it("extracts login+password from a success line, ignoring the header", () => {
    expect(parseHydraOutput(FOUND)).toEqual([{ login: "admin", password: "secret" }]);
  });
  it("returns [] when nothing was found (header only)", () => {
    expect(parseHydraOutput(NONE)).toEqual([]);
  });
  it("dedupes repeated success lines", () => {
    const dup = FOUND + "\n[8095][http-get] host: 127.0.0.1   login: admin   password: secret";
    expect(parseHydraOutput(dup)).toEqual([{ login: "admin", password: "secret" }]);
  });
});

describe("buildCredentialSprayFindings", () => {
  it("emits a high finding per recovered login, keyed by login", () => {
    const f = buildCredentialSprayFindings([{ login: "svc-test", password: "Summer2024" }]);
    expect(f).toHaveLength(1);
    expect(f[0].checkId).toBe("credential-spray.weak-credential:svc-test");
    expect(f[0].severity).toBe("high");
    expect(f[0].detail).toContain("Summer2024");
    expect(f[0].remediation).toBeTruthy();
  });
  it("returns nothing when no credential was recovered", () => {
    expect(buildCredentialSprayFindings([])).toEqual([]);
  });
});

describe("runCredentialSpray", () => {
  const envKeys = ["CREDENTIAL_SPRAY_LOGIN", "CREDENTIAL_SPRAY_WORDLIST", "CREDENTIAL_SPRAY_FORM"] as const;
  beforeEach(() => {
    execToolMock.mockReset();
    process.env.CREDENTIAL_SPRAY_LOGIN = "svc-test";
    process.env.CREDENTIAL_SPRAY_WORDLIST = "/tmp/pw.txt";
    process.env.CREDENTIAL_SPRAY_FORM = "/login:user=^USER^&pass=^PASS^:F=incorrect";
  });
  afterEach(() => envKeys.forEach((k) => delete process.env[k]));

  it("is not_configured unless ALL of login, wordlist and form are set, without spawning", async () => {
    for (const missing of envKeys) {
      execToolMock.mockReset();
      const saved = process.env[missing];
      delete process.env[missing];
      expect(await runCredentialSpray("https://example.com")).toEqual({ status: "not_configured" });
      expect(execToolMock).not.toHaveBeenCalled();
      process.env[missing] = saved;
    }
  });

  it("runs hydra against ONE login with -f and low parallelism", async () => {
    execToolMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    await runCredentialSpray("https://example.com/login");
    const [bin, args] = execToolMock.mock.calls[0] as [string, string[]];
    expect(bin).toBe("hydra");
    expect(args).toEqual(expect.arrayContaining(["-l", "svc-test", "-P", "/tmp/pw.txt", "-f", "-t", "1", "https-post-form"]));
    // single login, never -L (a user list)
    expect(args).not.toContain("-L");
    expect(args[args.indexOf("-s") + 1]).toBe("443");
  });

  it("not_configured when the binary is absent (ENOENT)", async () => {
    const err = new Error("spawn hydra ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execToolMock.mockRejectedValueOnce(err);
    expect(await runCredentialSpray("https://example.com")).toEqual({ status: "not_configured" });
  });

  it("error on an invalid URL without spawning", async () => {
    expect(await runCredentialSpray("not a url")).toEqual({ status: "error", note: "Invalid URL" });
    expect(execToolMock).not.toHaveBeenCalled();
  });
});
