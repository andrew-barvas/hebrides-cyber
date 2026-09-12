import { describe, it, expect, vi, beforeEach } from "vitest";

const { execFileMock, readFileMock, unlinkMock } = vi.hoisted(() => ({
  execFileMock: vi.fn(),
  readFileMock: vi.fn(),
  unlinkMock: vi.fn(),
}));

vi.mock("node:child_process", () => ({
  execFile: (...args: unknown[]) => execFileMock(...args),
  default: { execFile: (...args: unknown[]) => execFileMock(...args) },
}));
vi.mock("node:util", () => ({
  promisify: () => execFileMock,
  default: { promisify: () => execFileMock },
}));
vi.mock("node:fs/promises", () => ({
  readFile: (...args: unknown[]) => readFileMock(...args),
  unlink: (...args: unknown[]) => unlinkMock(...args),
  default: {
    readFile: (...args: unknown[]) => readFileMock(...args),
    unlink: (...args: unknown[]) => unlinkMock(...args),
  },
}));

import { runCmsMap } from "./cmsmap";

beforeEach(() => {
  execFileMock.mockReset();
  readFileMock.mockReset().mockRejectedValue(new Error("no file"));
  unlinkMock.mockReset().mockResolvedValue(undefined);
});

describe("runCmsMap", () => {
  it("returns not_configured when binary is absent", async () => {
    const err = new Error("spawn cmsmap ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execFileMock.mockRejectedValueOnce(err);
    const result = await runCmsMap("https://example.com", "wordpress");
    expect(result).toEqual({ status: "not_configured", findings: [] });
  });

  it("returns not_applicable for unsupported CMS type", async () => {
    const result = await runCmsMap("https://example.com", "ghost");
    expect(result.status).toBe("not_applicable");
  });

  it("parses vulnerability lines from stdout", async () => {
    execFileMock.mockResolvedValueOnce({
      stdout: "[!] Vulnerability found: SQL Injection in admin panel CVE-2023-12345\n",
    });
    const result = await runCmsMap("https://example.com", "wordpress");
    expect(result.status).toBe("completed");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].type).toBe("vulnerability");
    expect(result.findings[0].cveIds).toEqual(["CVE-2023-12345"]);
  });

  it("parses misconfiguration lines from stdout", async () => {
    execFileMock.mockResolvedValueOnce({
      stdout: "[I] 200 config backup found at /wp-config.php.bak\n",
    });
    const result = await runCmsMap("https://example.com", "joomla");
    expect(result.status).toBe("completed");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].type).toBe("misconfiguration");
  });

  it("returns empty findings for clean output", async () => {
    execFileMock.mockResolvedValueOnce({
      stdout: "[I] Starting scan\n[+] Scan complete\n",
    });
    const result = await runCmsMap("https://example.com", "drupal");
    expect(result.status).toBe("completed");
    expect(result.findings).toHaveLength(0);
  });

  it("returns error for non-ENOENT failures", async () => {
    execFileMock.mockRejectedValueOnce(new Error("timeout"));
    const result = await runCmsMap("https://example.com", "wordpress");
    expect(result.status).toBe("error");
  });
});
