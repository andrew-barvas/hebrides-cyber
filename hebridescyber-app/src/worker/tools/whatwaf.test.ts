import { describe, it, expect, vi, beforeEach } from "vitest";

const { execToolMock } = vi.hoisted(() => ({
  execToolMock: vi.fn(),
}));

vi.mock("../../lib/execTool", () => ({ execTool: (...args: unknown[]) => execToolMock(...args) }));

import { parseWhatWafOutput, runWhatWaf } from "./whatwaf";
import { findingSource, isCovered, scanCoverage } from "../../lib/findingLifecycle";

/** A line as WhatWaf v1.9's lib/formatter.py prints it: ANSI-coloured stamp, then the coloured level tag and message. */
function line(tag: string, message: string, color = "\x1b[32m"): string {
  return `\x1b[38m[21:44:15]\x1b[0m${color}[${tag}] ${message}\x1b[0m`;
}

const START = [line("INFO", "loading firewall detection scripts"), line("INFO", "running firewall detection checks")];
const VERIFYING = line("WARN", "no protection identified on target, verifying", "\x1b[33m");
const NO_WAF = [...START, VERIFYING, line("SUCCESS", "no protection identified on target", "\x1b[1m\x1b[32m")].join("\n");
const ONE_WAF = [...START, line("FIREWALL", "detected website protection identified as 'Cloudflare Web Application Firewall (CloudFlare)'", "\x1b[1m\x1b[96m"), line("WARN", "skipping bypass analysis")].join("\n");

beforeEach(() => {
  execToolMock.mockReset();
});

function stdout(text: string) {
  execToolMock.mockResolvedValueOnce({ stdout: text, stderr: "" });
}

describe("runWhatWaf", () => {
  it("returns not_configured when binary is absent", async () => {
    const err = new Error("spawn whatwaf ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execToolMock.mockRejectedValueOnce(err);
    expect(await runWhatWaf("https://example.com")).toEqual({ status: "not_configured" });
  });

  it("returns error for non-ENOENT failures", async () => {
    execToolMock.mockRejectedValueOnce(new Error("timeout"));
    const result = await runWhatWaf("https://example.com");
    expect(result).toMatchObject({ status: "error", note: expect.stringContaining("timeout") });
  });

  it("skips bypass analysis and doesn't pass --json, which writes a file rather than stdout", async () => {
    stdout(NO_WAF);
    await runWhatWaf("https://example.com");
    const [file, args] = execToolMock.mock.calls[0] as [string, string[]];
    expect(file).toBe("whatwaf");
    expect(args).toEqual(["-u", "https://example.com", "--ra", "--throttle", "1", "--skip"]);
    expect(args).not.toContain("--json");
  });

  // WhatWaf prints its verdict, then asks "create an issue?" on stdin (EOF with execTool) and exits non-zero.
  function failedExit(text: string, extra: Record<string, unknown> = {}) {
    execToolMock.mockRejectedValueOnce(Object.assign(new Error("Command failed: whatwaf"), { code: 1, stdout: text, stderr: "EOFError", ...extra }));
  }
  const UNIDENTIFIED = [...START, line("INFO", "target seems to be behind some kind of protection for the following reasons:")].join("\n");

  it("keeps a WAF verdict WhatWaf printed before crashing on its interactive prompt", async () => {
    failedExit(UNIDENTIFIED);
    expect(await runWhatWaf("https://example.com")).toMatchObject({ status: "completed", waf: "Unidentified WAF" });
    failedExit(ONE_WAF);
    expect(await runWhatWaf("https://example.com")).toMatchObject({ status: "completed", waf: "Cloudflare Web Application Firewall (CloudFlare)" });
  });

  it("never reads 'no WAF' from a failed exit", async () => {
    failedExit(NO_WAF);
    expect(await runWhatWaf("https://example.com")).toMatchObject({ status: "error", note: expect.stringContaining("exited with error") });
  });

  it("is an error when a failed exit has no verdict, or the run was killed by the timeout", async () => {
    failedExit("Traceback (most recent call last):\nEOFError");
    expect(await runWhatWaf("https://example.com")).toMatchObject({ status: "error" });
    failedExit(ONE_WAF, { killed: true });
    expect(await runWhatWaf("https://example.com")).toMatchObject({ status: "error" });
  });

  it("returns completed with the detected WAF and no invented confidence", async () => {
    stdout(ONE_WAF);
    const result = await runWhatWaf("https://example.com");
    expect(result).toEqual({
      status: "completed",
      waf: "Cloudflare Web Application Firewall (CloudFlare)",
      vendor: null,
      evidence: `WhatWaf reported: "[FIREWALL] detected website protection identified as 'Cloudflare Web Application Firewall (CloudFlare)'".`,
    });
    expect(result).not.toHaveProperty("confidence");
  });

  it("reports no WAF only on WhatWaf's final 'no protection identified' verdict", async () => {
    stdout(NO_WAF);
    expect(await runWhatWaf("https://example.com")).toEqual({
      status: "completed",
      waf: null,
      vendor: null,
      evidence: 'WhatWaf reported: "[SUCCESS] no protection identified on target".',
    });
  });

  it("is an error, not 'no WAF', for unparseable output", async () => {
    stdout("Traceback (most recent call last):\n  File \"whatwaf\", line 1\nKeyError: 'headers'");
    expect(await runWhatWaf("https://example.com")).toMatchObject({ status: "error", note: expect.stringContaining("no verdict line") });
  });

  it("is an error, not 'no WAF', for empty output", async () => {
    stdout("   \n\x1b[0m\n");
    expect(await runWhatWaf("https://example.com")).toEqual({ status: "error", note: "whatwaf produced no output" });
  });
});

describe("parseWhatWafOutput", () => {
  it("is an error when the run stops at 'no protection identified on target, verifying' (verification never reported)", () => {
    expect(parseWhatWafOutput([...START, VERIFYING].join("\n"))).toMatchObject({ status: "error" });
  });

  it("reports an unidentified WAF when verification finds protection after 'verifying'", () => {
    const text = [...START, VERIFYING, line("INFO", "target seems to be behind some kind of protection for the following reasons:"), "------------------------------", "[1] response code changed"].join("\n");
    expect(parseWhatWafOutput(text)).toEqual({
      status: "completed",
      waf: "Unidentified WAF",
      vendor: null,
      evidence: 'WhatWaf reported: "[INFO] target seems to be behind some kind of protection for the following reasons:".',
    });
  });

  it("lists several WAFs when WhatWaf names more than one", () => {
    const text = [...START, line("FIREWALL", "Akamai Global Host (Akamai Technologies)"), line("FIREWALL", "Cloudflare Web Application Firewall (CloudFlare)")].join("\n");
    expect(parseWhatWafOutput(text)).toMatchObject({
      status: "completed",
      waf: "Akamai Global Host (Akamai Technologies), Cloudflare Web Application Firewall (CloudFlare)",
    });
  });

  // The old wrapper parsed an invented JSON shape (`firewall_name`, `is_protected`). WhatWaf never prints JSON to
  // stdout, so JSON, whatever it says, carries no verdict.
  it("is an error for JSON, including is_protected: false and is_protected missing", () => {
    for (const text of ['{"is_protected":false}', '{"firewall_url":null}', '{"is_protected":true,"firewall_name":"Cloudflare"}']) {
      expect(parseWhatWafOutput(text)).toMatchObject({ status: "error", note: expect.stringContaining("no verdict line") });
    }
  });

  it("is an error for output that names no outcome, such as start-up lines alone", () => {
    expect(parseWhatWafOutput(START.join("\n"))).toMatchObject({ status: "error" });
  });

  it("doesn't take 'no waf' or 'unprotected' text that isn't WhatWaf's verdict line as evidence", () => {
    expect(parseWhatWafOutput("No WAF detected")).toMatchObject({ status: "error" });
    expect(parseWhatWafOutput("site appears unprotected")).toMatchObject({ status: "error" });
  });

  it("is an error when the output contains both a protection and the no-protection verdict", () => {
    expect(parseWhatWafOutput(`${ONE_WAF}\n${NO_WAF}`)).toMatchObject({ status: "error", note: expect.stringContaining("both") });
  });
});

describe("whatwaf and finding lifecycle", () => {
  it("an errored run doesn't resolve last scan's whatwaf findings; a completed one can", () => {
    const keys = ["whatwaf"];
    expect(findingSource("whatwaf.no-waf", true, keys)).toBe("whatwaf");
    expect(isCovered("whatwaf", scanCoverage({ whatwaf: parseWhatWafOutput("") }), "whatwaf.no-waf")).toBe(false);
    expect(isCovered("whatwaf", scanCoverage({ whatwaf: parseWhatWafOutput(NO_WAF) }), "whatwaf.waf-detected")).toBe(true);
  });
});
