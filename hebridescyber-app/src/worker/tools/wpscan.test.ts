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

import { runWpScanCli } from "./wpscan";

beforeEach(() => {
  execFileMock.mockReset();
});

describe("runWpScanCli", () => {
  it("returns not_configured when binary is absent", async () => {
    const err = new Error("spawn wpscan ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    execFileMock.mockRejectedValueOnce(err);
    const result = await runWpScanCli("https://example.com");
    expect(result).toEqual({ status: "not_configured", findings: [] });
  });

  it("parses config backups from JSON output", async () => {
    execFileMock.mockResolvedValueOnce({
      stdout: JSON.stringify({
        config_backups: { "https://example.com/wp-config.php.bak": {} },
      }),
    });
    const result = await runWpScanCli("https://example.com");
    expect(result.status).toBe("completed");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].title).toContain("config backup");
    expect(result.findings[0].severity).toBe("high");
  });

  it("parses database exports", async () => {
    execFileMock.mockResolvedValueOnce({
      stdout: JSON.stringify({
        db_exports: { "https://example.com/dump.sql": {} },
      }),
    });
    const result = await runWpScanCli("https://example.com");
    expect(result.status).toBe("completed");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("critical");
  });

  it("parses theme vulnerabilities with CVEs", async () => {
    execFileMock.mockResolvedValueOnce({
      stdout: JSON.stringify({
        main_theme: {
          slug: "twentytwentyone",
          version: { number: "1.0" },
          vulnerabilities: [
            {
              title: "XSS in theme",
              fixed_in: "1.1",
              references: { cve: ["2021-12345"] },
            },
          ],
        },
      }),
    });
    const result = await runWpScanCli("https://example.com");
    expect(result.status).toBe("completed");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].cveIds).toEqual(["CVE-2021-12345"]);
    expect(result.findings[0].fixedIn).toBe("1.1");
  });

  it("handles non-zero exit with stdout (WPScan behaviour)", async () => {
    const err = new Error("Process exited with code 5") as NodeJS.ErrnoException & { stdout: string };
    err.stdout = JSON.stringify({
      config_backups: { "https://example.com/wp-config.php~": {} },
    });
    execFileMock.mockRejectedValueOnce(err);
    const result = await runWpScanCli("https://example.com");
    expect(result.status).toBe("completed");
    expect(result.findings).toHaveLength(1);
  });

  it("returns empty findings for clean site", async () => {
    execFileMock.mockResolvedValueOnce({
      stdout: JSON.stringify({}),
    });
    const result = await runWpScanCli("https://example.com");
    expect(result).toEqual({ status: "completed", findings: [] });
  });
});
