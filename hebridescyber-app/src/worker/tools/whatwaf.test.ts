import { describe, it, expect, vi, beforeEach } from "vitest";

const { execFileMock } = vi.hoisted(() => ({
  execFileMock: vi.fn(),
}));

vi.mock("node:child_process", () => ({
  execFile: (...args: unknown[]) => execFileMock(...args),
  default: { execFile: (...args: unknown[]) => execFileMock(...args) },
}));
vi.mock("node:util", () => ({
  promisify: () => execFileMock,
  default: { promisify: () => execFileMock },
}));

import { runWhatWaf } from "./whatwaf";

beforeEach(() => {
  execFileMock.mockReset();
});

describe("runWhatWaf", () => {
  it("returns not_configured when binary is absent", async () => {
    const err = new Error("spawn whatwaf ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execFileMock.mockRejectedValueOnce(err);
    const result = await runWhatWaf("https://example.com");
    expect(result).toEqual({ status: "not_configured" });
  });

  it("returns completed with detected WAF", async () => {
    execFileMock.mockResolvedValueOnce({
      stdout: JSON.stringify({
        firewall_name: "Cloudflare",
        firewall_url: "https://www.cloudflare.com",
        is_protected: true,
      }),
    });
    const result = await runWhatWaf("https://example.com");
    expect(result).toEqual({
      status: "completed",
      waf: "Cloudflare",
      vendor: "https://www.cloudflare.com",
      confidence: 85,
    });
  });

  it("returns completed with no WAF when is_protected is false", async () => {
    execFileMock.mockResolvedValueOnce({
      stdout: JSON.stringify({ is_protected: false }),
    });
    const result = await runWhatWaf("https://example.com");
    expect(result).toEqual({
      status: "completed",
      waf: null,
      vendor: null,
      confidence: 90,
    });
  });

  it("returns completed with no WAF when stdout says 'no waf'", async () => {
    execFileMock.mockResolvedValueOnce({
      stdout: "No WAF detected",
    });
    const result = await runWhatWaf("https://example.com");
    expect(result).toEqual({
      status: "completed",
      waf: null,
      vendor: null,
      confidence: 90,
    });
  });

  it("returns error for non-ENOENT failures", async () => {
    execFileMock.mockRejectedValueOnce(new Error("timeout"));
    const result = await runWhatWaf("https://example.com");
    expect(result.status).toBe("error");
    expect((result as { note: string }).note).toContain("timeout");
  });
});
