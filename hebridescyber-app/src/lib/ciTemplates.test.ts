// The CI files customers copy into their repositories (public/ci/) and the
// /docs/ci page that presents them. The script's behaviour is tested by
// running it (ciScanScript.test.ts); these keep the templates honest.
import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { render, screen } from "@testing-library/react";
import CiDocsPage, { metadata } from "@/app/docs/ci/page";
import { CI_SCRIPT, CI_TEMPLATES, ciFileSha256, readCiFile } from "./ciTemplates";

const CI_DIR = path.join(process.cwd(), "public", "ci");
const script = readCiFile(CI_SCRIPT);
const SCRIPT_VARS = new Set([...script.matchAll(/\$\{(HEBRIDES_[A-Z_]+)/g)].map((m) => m[1]));

describe("CI files", () => {
  it("lists every template in public/ci, and nothing there is unlisted", () => {
    const onDisk = readdirSync(CI_DIR).sort();
    expect(onDisk).toEqual([CI_SCRIPT, ...CI_TEMPLATES.map((t) => t.file)].sort());
    expect(new Set(CI_TEMPLATES.map((t) => t.id)).size).toBe(CI_TEMPLATES.length);
  });

  it("knows the settings the script reads", () => {
    expect([...SCRIPT_VARS].sort()).toEqual([
      "HEBRIDES_API_BASE_URL", "HEBRIDES_CYBER_API_KEY", "HEBRIDES_FAIL_ON", "HEBRIDES_JUNIT_FILE",
      "HEBRIDES_POLL_SECONDS", "HEBRIDES_RESULT_FILE", "HEBRIDES_TARGET_URL", "HEBRIDES_TIMEOUT_SECONDS",
    ]);
  });

  describe.each(CI_TEMPLATES.map((t) => [t.name, t] as const))("%s template", (_name, t) => {
    const text = readCiFile(t.file);

    it("runs the script from the repository", () => {
      expect(text).toMatch(/sh ci\/hebrides-scan\.sh/);
    });

    it("sets only settings the script actually reads", () => {
      for (const m of text.matchAll(/\b(HEBRIDES_[A-Z_]+)\b/g)) expect(SCRIPT_VARS, `${t.file}: ${m[1]}`).toContain(m[1]);
    });

    it("takes the API key from a secret, never a literal", () => {
      for (const line of text.split("\n").filter((l) => /HEBRIDES_CYBER_API_KEY\s*[:=]/.test(l) && !/^\s*(#|\/\/)/.test(l))) {
        expect(line, `${t.file}: ${line.trim()}`).toMatch(/credentials\('|\$\(HEBRIDES_CYBER_API_KEY\)|\$\{\{\s*secrets\./);
      }
    });

    it("points only at the live domain", () => {
      expect(text).not.toMatch(/hebridescyber\.com\b/);
      for (const m of text.matchAll(/https:\/\/[a-z0-9.-]*hebridescyber[a-z0-9.-]*/g)) expect(m[0]).toBe("https://www.hebridescyber.co.uk");
    });

    it("keeps the full result and fails the job on the script's exit code", () => {
      expect(text).toContain("hebrides-scan.json");
      expect(text).not.toMatch(/hebrides-scan\.sh[^\n]*\|\|\s*true/);
    });
  });

  it("checksums the file's bytes as served", () => {
    expect(ciFileSha256(CI_SCRIPT)).toBe(createHash("sha256").update(readFileSync(path.join(CI_DIR, CI_SCRIPT))).digest("hex"));
    expect(ciFileSha256(CI_SCRIPT)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("reads only from public/ci, whatever name it is given", () => {
    expect(() => readCiFile("../../package.json")).toThrow();
  });
});

describe("/docs/ci page", () => {
  it("shows every template exactly as served, the script's checksum, and download links", () => {
    const { container } = render(CiDocsPage());
    for (const t of CI_TEMPLATES) {
      expect(screen.getByRole("heading", { level: 3, name: t.name })).toBeTruthy();
      expect([...container.querySelectorAll("pre")].some((pre) => pre.textContent === readCiFile(t.file))).toBe(true);
      expect(container.querySelector(`a[download][href="/ci/${t.file}"]`)).not.toBeNull();
    }
    expect(container.textContent).toContain(`SHA-256: ${ciFileSha256(CI_SCRIPT)}`);
    expect(container.querySelectorAll(`a[download][href="/ci/${CI_SCRIPT}"]`).length).toBeGreaterThan(0);
  });

  it("has its own title and a description that fits a search result", () => {
    expect(String(metadata.title)).toMatch(/CI\/CD/);
    expect(String(metadata.description).length).toBeLessThanOrEqual(160);
  });
});
