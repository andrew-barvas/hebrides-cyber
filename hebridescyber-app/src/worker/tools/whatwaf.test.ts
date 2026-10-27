import { describe, it, expect, vi, beforeEach } from "vitest";

const { execToolMock } = vi.hoisted(() => ({
  execToolMock: vi.fn(),
}));

vi.mock("../../lib/execTool", () => ({ execTool: (...args: unknown[]) => execToolMock(...args) }));

import { parseWhatWafOutput, runWhatWaf } from "./whatwaf";
import { findingSource, isCovered, scanCoverage } from "../../lib/findingLifecycle";

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

  it("returns completed with the detected WAF and no invented confidence", async () => {
    stdout(JSON.stringify({ firewall_name: "Cloudflare", firewall_url: "https://www.cloudflare.com", is_protected: true }));
    const result = await runWhatWaf("https://example.com");
    expect(result).toEqual({
      status: "completed",
      waf: "Cloudflare",
      vendor: "https://www.cloudflare.com",
      evidence: "WhatWaf identified the firewall as Cloudflare.",
    });
    expect(result).not.toHaveProperty("confidence");
  });

  it("reports no WAF only when JSON says is_protected: false", async () => {
    stdout(JSON.stringify({ is_protected: false }));
    expect(await runWhatWaf("https://example.com")).toEqual({
      status: "completed",
      waf: null,
      vendor: null,
      evidence: "WhatWaf reported is_protected: false.",
    });
  });

  it("is an error, not 'no WAF', for unparseable output", async () => {
    stdout("Traceback (most recent call last):\n  File \"whatwaf\", line 1\nKeyError: 'headers'");
    expect(await runWhatWaf("https://example.com")).toMatchObject({ status: "error", note: expect.stringContaining("could not be interpreted") });
  });

  it("is an error, not 'no WAF', for empty output", async () => {
    stdout("   \n");
    expect(await runWhatWaf("https://example.com")).toEqual({ status: "error", note: "whatwaf produced no output" });
  });

  it("is an error, not 'no WAF', when is_protected is missing", async () => {
    stdout(JSON.stringify({ firewall_url: null }));
    expect(await runWhatWaf("https://example.com")).toEqual({
      status: "error",
      note: "whatwaf output had neither is_protected nor firewall_name",
    });
  });
});

describe("parseWhatWafOutput", () => {
  it("reports no WAF from an explicit 'no waf' line, quoting it", () => {
    expect(parseWhatWafOutput("[banner]\n[FAIL] No WAF detected on target\n")).toEqual({
      status: "completed",
      waf: null,
      vendor: null,
      evidence: 'WhatWaf reported: "[FAIL] No WAF detected on target".',
    });
  });

  it("reports no WAF from an explicit 'unprotected' line", () => {
    expect(parseWhatWafOutput("site appears unprotected")).toMatchObject({ status: "completed", waf: null });
  });

  it("is an error for text that names no outcome, such as a banner alone", () => {
    expect(parseWhatWafOutput("WhatWaf v2.1.6 — starting")).toMatchObject({ status: "error" });
  });

  it("is an error for JSON that isn't an object", () => {
    for (const text of ["null", "42", '"no"', "[]"]) {
      expect(parseWhatWafOutput(text)).toMatchObject({ status: "error", note: expect.stringContaining("could not be interpreted") });
    }
  });

  it("treats a named firewall as detected even without is_protected", () => {
    expect(parseWhatWafOutput(JSON.stringify({ firewall_name: "  Akamai  " }))).toEqual({
      status: "completed",
      waf: "Akamai",
      vendor: null,
      evidence: "WhatWaf identified the firewall as Akamai.",
    });
  });

  it("reports an unnamed WAF when is_protected is true without a name", () => {
    expect(parseWhatWafOutput(JSON.stringify({ is_protected: true, firewall_name: "" }))).toMatchObject({
      status: "completed",
      waf: "Unidentified WAF",
      evidence: expect.stringContaining("did not name the firewall"),
    });
  });

  it("is an error when is_protected: false contradicts a named firewall", () => {
    expect(parseWhatWafOutput(JSON.stringify({ is_protected: false, firewall_name: "Cloudflare" }))).toMatchObject({
      status: "error",
      note: expect.stringContaining("Cloudflare"),
    });
  });
});

describe("whatwaf and finding lifecycle", () => {
  it("an errored run doesn't resolve last scan's whatwaf findings; a completed one can", () => {
    const keys = ["whatwaf"];
    expect(findingSource("whatwaf.no-waf", true, keys)).toBe("whatwaf");
    expect(isCovered("whatwaf", scanCoverage({ whatwaf: parseWhatWafOutput("") }), "whatwaf.no-waf")).toBe(false);
    expect(isCovered("whatwaf", scanCoverage({ whatwaf: parseWhatWafOutput('{"is_protected":false}') }), "whatwaf.waf-detected")).toBe(true);
  });
});
