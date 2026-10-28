import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const execToolMock = vi.fn();
vi.mock("../../lib/execTool", () => ({ execTool: (...args: unknown[]) => execToolMock(...args) }));

import { badsecretsSeverity, buildBadsecretsArgs, buildBadsecretsFindings, parseBadsecretsOutput, runBadsecrets } from "./badsecrets";
import { getComplianceRefs } from "../../lib/scanners/compliance";

const TARGET = "https://shop.example.com/";

// Shape of badsecrets 1.2.0 --json results (badsecrets/base.py carve(),
// carve_all_modules()). Values are placeholders, not real keys or sessions.
const FLASK_HIT = {
  type: "SecretFound",
  detecting_module: "Flask_SignedCookies",
  location: "cookies",
  product: "eyJ1c2VyIjoiYWxpY2UifQ.placeholder.signature",
  secret: "placeholder-known-key",
  details: { hash_algorithm: "SHA1" },
  description: { product: "Flask Signed Cookie", secret: "Flask Password", severity: "HIGH" },
};
const VIEWSTATE_HIT = {
  type: "SecretFound",
  detecting_module: "ASPNET_Viewstate",
  location: "body",
  product: "/wEPDwUJ-placeholder",
  secret: "validationKey: PLACEHOLDER validationAlgo: SHA1",
  description: { product: "ASP.NET Viewstate", secret: "ASP.NET MachineKey", severity: "CRITICAL" },
};
const JWT_IDENTIFIED = {
  type: "IdentifyOnly",
  detecting_module: "Generic_JWT",
  location: "body",
  product: "eyJhbGciOiJIUzI1NiJ9.placeholder.sig",
  hashcat: null,
  description: { product: "JSON Web Token (JWT)", secret: "HMAC/RSA Key", severity: "HIGH" },
};

beforeEach(() => {
  execToolMock.mockReset();
  vi.stubGlobal("fetch", vi.fn(async () => new Response("<html></html>")));
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("buildBadsecretsArgs", () => {
  it("runs passive-only JSON mode against the target with our user agent", () => {
    const args = buildBadsecretsArgs(TARGET);
    expect(args).toEqual(expect.arrayContaining(["--json", "--passive-only", "--no-color", "-u", TARGET]));
    expect(args[args.indexOf("-a") + 1]).toMatch(/^HebridesCyberScanner\//);
  });
});

describe("parseBadsecretsOutput", () => {
  it("reads one JSON array per line and treats empty output as nothing found", () => {
    expect(parseBadsecretsOutput("")).toEqual([]);
    expect(parseBadsecretsOutput(`${JSON.stringify([FLASK_HIT])}\n${JSON.stringify([VIEWSTATE_HIT])}\n`)).toHaveLength(2);
  });

  it("throws on banner text or a non-array", () => {
    expect(() => parseBadsecretsOutput("No secrets found :(")).toThrow();
    expect(() => parseBadsecretsOutput('{"type":"SecretFound"}')).toThrow(/not a JSON array/);
  });
});

describe("badsecretsSeverity", () => {
  it("maps badsecrets' severities, defaulting a confirmed key to high", () => {
    expect(badsecretsSeverity("CRITICAL")).toBe("critical");
    expect(badsecretsSeverity("HIGH")).toBe("high");
    expect(badsecretsSeverity("MEDIUM")).toBe("medium");
    expect(badsecretsSeverity("LOW")).toBe("low");
    expect(badsecretsSeverity("INFO")).toBe("high");
    expect(badsecretsSeverity(undefined)).toBe("high");
  });
});

describe("buildBadsecretsFindings", () => {
  it("reports one finding per module and never the key or the token", () => {
    const { findings, identified } = buildBadsecretsFindings([FLASK_HIT, { ...FLASK_HIT, product: "other-cookie" }, VIEWSTATE_HIT, JWT_IDENTIFIED], TARGET);
    expect(findings.map((f) => [f.checkId, f.severity])).toEqual([
      ["badsecrets.known-secret:Flask_SignedCookies", "high"],
      ["badsecrets.known-secret:ASPNET_Viewstate", "critical"],
    ]);
    expect(identified).toEqual(["JSON Web Token (JWT)"]);

    const flask = findings[0];
    expect(flask.title).toBe("[badsecrets] Flask Signed Cookie uses a publicly known Flask Password");
    expect(flask.detail).toContain("in a cookie");
    expect(flask.metadata).toMatchObject({ module: "Flask_SignedCookies", locations: ["cookies"] });
    expect((flask.metadata as { keyFingerprints: string[] }).keyFingerprints).toEqual([expect.stringMatching(/^[0-9a-f]{12}$/)]);
    expect(flask.remediation).toContain("app.secret_key");

    const serialised = JSON.stringify(findings);
    for (const value of [FLASK_HIT.secret, FLASK_HIT.product, VIEWSTATE_HIT.secret, VIEWSTATE_HIT.product, "other-cookie"]) {
      expect(serialised).not.toContain(value);
    }
  });

  it("falls back to generic wording for a module it has no specific advice for", () => {
    const { findings } = buildBadsecretsFindings([{ type: "SecretFound", detecting_module: "Future Module!", secret: { k: 1 } }], TARGET);
    expect(findings[0].checkId).toBe("badsecrets.known-secret:FutureModule");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].detail).toContain("in the response");
    expect(findings[0].remediation).toContain("wherever your application configures its secret key");
  });

  it("is categorised for compliance", () => {
    const controls = getComplianceRefs("badsecrets.known-secret:Flask_SignedCookies").map((r) => r.control);
    expect(controls).toContain("Secure configuration");
  });
});

describe("runBadsecrets", () => {
  function okExec(stdout: string) {
    execToolMock.mockImplementation(async (_bin: string, args: string[]) => (args.includes("-l") ? { stdout: "modules", stderr: "" } : { stdout, stderr: "" }));
  }

  it("is not_configured when badsecrets isn't installed", async () => {
    execToolMock.mockRejectedValueOnce(Object.assign(new Error("spawn badsecrets ENOENT"), { code: "ENOENT" }));
    expect(await runBadsecrets(TARGET)).toMatchObject({ status: "not_configured" });
  });

  it("is an error when the probe fails for another reason", async () => {
    execToolMock.mockRejectedValueOnce(Object.assign(new Error("ImportError: yara"), { code: 1 }));
    expect(await runBadsecrets(TARGET)).toMatchObject({ status: "error", note: expect.stringContaining("ImportError") });
  });

  it("is an error, not a clean result, when the target is unreachable", async () => {
    okExec("");
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new Error("ECONNREFUSED"))));
    const result = await runBadsecrets(TARGET);
    expect(result).toMatchObject({ status: "error", note: expect.stringContaining("unreachable") });
    expect(execToolMock).toHaveBeenCalledTimes(1); // the scan itself never ran
  });

  it("completes with no findings on empty output from a reachable site", async () => {
    okExec("");
    expect(await runBadsecrets(TARGET)).toEqual({ status: "completed", findings: [], identified: [] });
  });

  it("completes with findings from real-shaped output", async () => {
    okExec(`${JSON.stringify([FLASK_HIT])}\n`);
    const result = await runBadsecrets(TARGET);
    expect(result.status).toBe("completed");
    expect(result.findings.map((f) => f.checkId)).toEqual(["badsecrets.known-secret:Flask_SignedCookies"]);
  });

  it("is an error on a timeout, a crash or unparseable output", async () => {
    execToolMock.mockImplementation(async (_b: string, args: string[]) => {
      if (args.includes("-l")) return { stdout: "", stderr: "" };
      throw Object.assign(new Error("killed"), { killed: true });
    });
    expect(await runBadsecrets(TARGET)).toMatchObject({ status: "error", note: expect.stringContaining("exceeded") });

    execToolMock.mockImplementation(async (_b: string, args: string[]) => {
      if (args.includes("-l")) return { stdout: "", stderr: "" };
      throw Object.assign(new Error("exit 2"), { code: 2, stderr: "error: unrecognized arguments" });
    });
    expect(await runBadsecrets(TARGET)).toMatchObject({ status: "error", note: expect.stringContaining("unrecognized arguments") });

    okExec("Traceback (most recent call last):");
    expect(await runBadsecrets(TARGET)).toMatchObject({ status: "error", note: expect.stringContaining("could not parse") });
  });
});
