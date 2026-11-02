import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  SCANNER_TOOLS,
  applyUpdate,
  checkLicence,
  compareVersions,
  pickUpdate,
  pinnedValue,
  prBody,
  readPins,
  releaseAssetUrl,
  type ReleaseAssetTool,
  type ScannerTool,
} from "./scannerToolUpdates";

const tool = (id: string) => {
  const t = SCANNER_TOOLS.find((x) => x.id === id);
  if (!t) throw new Error(id);
  return t;
};
const now = new Date("2026-11-01T00:00:00Z");
const daysAgo = (d: number) => new Date(now.getTime() - d * 86_400_000).toISOString();
const SHA = "a".repeat(64);

describe("compareVersions", () => {
  it("compares numerically by segment and ignores a leading v", () => {
    expect(compareVersions("v3.11.1", "v3.3.9")).toBeGreaterThan(0);
    expect(compareVersions("1.9", "v1.10")).toBeLessThan(0);
    expect(compareVersions("v2.0", "2.0.0")).toBe(0);
  });
});

describe("pickUpdate", () => {
  it("takes the newest stable release that is old enough and newer than the pin", () => {
    const r = pickUpdate(
      [
        { tag: "v3.12.0", publishedAt: daysAgo(3) },
        { tag: "v3.11.1", publishedAt: daysAgo(20) },
        { tag: "v3.11.0", publishedAt: daysAgo(40) },
        { tag: "v3.13.0-rc1", publishedAt: daysAgo(30) },
        { tag: "v4.0.0", publishedAt: daysAgo(30), prerelease: true },
        { tag: "v4.1.0", publishedAt: daysAgo(30), draft: true },
      ],
      "v3.3.9",
      now,
    );
    expect(r?.tag).toBe("v3.11.1");
  });

  it("never downgrades and returns null when nothing qualifies", () => {
    expect(pickUpdate([{ tag: "v1.0.0", publishedAt: daysAgo(400) }], "v1.2.0", now)).toBeNull();
    expect(pickUpdate([{ tag: "v1.3.0", publishedAt: daysAgo(2) }], "v1.2.0", now)).toBeNull();
  });

  it("copes with tag styles that changed over time", () => {
    expect(pickUpdate([{ tag: "1.8", publishedAt: daysAgo(900) }, { tag: "v1.9", publishedAt: daysAgo(800) }], "v1.9", now)).toBeNull();
  });
});

describe("checkLicence", () => {
  it("holds an update whose upstream licence changed or could not be read", () => {
    expect(checkLicence(tool("nuclei"), "MIT")).toBeNull();
    expect(checkLicence(tool("nuclei"), "BUSL-1.1")).toMatch(/licence changed from MIT to BUSL-1.1/);
    expect(checkLicence(tool("nuclei"), null)).toMatch(/could not read/);
  });
});

describe("release-asset pins", () => {
  const yml = [
    "        env:",
    "          NUCLEI_VERSION: v3.3.9",
    `          NUCLEI_SHA256: ${"d".repeat(64)}`,
    "          NUCLEI_TEMPLATES_VERSION: v10.5.1",
    "          DALFOX_VERSION: 3.2.4",
  ].join("\r\n");

  it("reads and rewrites the version and checksum, leaving lookalike env names alone", () => {
    expect(readPins(tool("nuclei"), yml)).toEqual(["v3.3.9"]);
    const out = applyUpdate(tool("nuclei"), yml, { version: "v3.11.1", sha256: SHA });
    expect(out).toContain("NUCLEI_VERSION: v3.11.1\r\n");
    expect(out).toContain(`NUCLEI_SHA256: ${SHA}\r\n`);
    expect(out).toContain("NUCLEI_TEMPLATES_VERSION: v10.5.1");
    expect(out).toContain("DALFOX_VERSION: 3.2.4");
  });

  it("refuses to move a checksum pin without a valid SHA-256", () => {
    expect(() => applyUpdate(tool("nuclei"), yml, { version: "v3.11.1" })).toThrow(/SHA-256 is required/);
    expect(() => applyUpdate(tool("nuclei"), yml, { version: "v3.11.1", sha256: "abc" })).toThrow(/SHA-256 is required/);
  });

  it("builds the download URL the workflow uses, with or without the tag's v", () => {
    expect(releaseAssetUrl(tool("nuclei") as ReleaseAssetTool, "v3.11.1")).toBe(
      "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip",
    );
    expect(releaseAssetUrl(tool("dalfox") as ReleaseAssetTool, "3.2.4")).toBe(
      "https://github.com/hahwul/dalfox/releases/download/v3.2.4/dalfox-v3.2.4-linux-x86_64.tar.gz",
    );
    expect(pinnedValue(tool("dalfox"), "v3.3.0")).toBe("3.3.0");
    expect(pinnedValue(tool("nuclei"), "v3.11.1")).toBe("v3.11.1");
  });

  it("rewrites the URL template when upstream renamed the asset", () => {
    const pg = [
      "          POSTGREST_VERSION: v12.2.3",
      `          POSTGREST_SHA256: ${"9".repeat(64)}`,
      '          curl -fsSL -o /tmp/p.tar.xz "https://github.com/PostgREST/postgrest/releases/download/${POSTGREST_VERSION}/postgrest-${POSTGREST_VERSION}-linux-static-x64.tar.xz"',
    ].join("\n");
    const out = applyUpdate(tool("postgrest"), pg, { version: "v16.4", sha256: SHA });
    expect(out).toContain("postgrest-${POSTGREST_VERSION}-linux-static-x86-64.tar.xz");
    expect(out).toContain("POSTGREST_VERSION: v16.4");
  });
});

describe("git-tag pins", () => {
  const yml = [
    "          sudo git clone --depth 1 --branch v3.2.4 https://github.com/testssl/testssl.sh.git /opt/testssl.sh",
    '          test "$(sudo git -C /opt/testssl.sh describe --tags --exact-match)" = "v3.2.4"',
    "          git clone --depth 1 --branch v4.1 https://github.com/commixproject/commix.git /opt/commix",
  ].join("\n");

  it("moves the clone tag and the check that asserts it, and nothing else", () => {
    expect(readPins(tool("testssl"), yml)).toEqual(["v3.2.4"]);
    const out = applyUpdate(tool("testssl"), yml, { version: "v3.2.5" });
    expect(out).toContain("--branch v3.2.5 https://github.com/testssl/testssl.sh.git");
    expect(out).toContain('--exact-match)" = "v3.2.5"');
    expect(out).toContain("--branch v4.1 https://github.com/commixproject/commix.git");
  });

  it("handles a tag held in an env var and cloned through it", () => {
    const t = ['          NUCLEI_TEMPLATES_VERSION: v10.5.1', '          git clone --depth 1 --branch "${NUCLEI_TEMPLATES_VERSION}" \\', "            https://github.com/projectdiscovery/nuclei-templates.git"].join("\n");
    expect(readPins(tool("nuclei-templates"), t)).toEqual(["v10.5.1"]);
    const out = applyUpdate(tool("nuclei-templates"), t, { version: "v10.6.0" });
    expect(out).toContain("NUCLEI_TEMPLATES_VERSION: v10.6.0");
    expect(out).toContain('--branch "${NUCLEI_TEMPLATES_VERSION}"');
  });
});

describe("pip pins", () => {
  it("rewrites pkg==version wherever it appears, and not other packages", () => {
    const yml = "pip3 install --break-system-packages zizmor==1.30.1 \\\n sudo /opt/badsecrets/bin/pip install --quiet badsecrets==1.2.0";
    expect(readPins(tool("zizmor"), yml)).toEqual(["1.30.1"]);
    const out = applyUpdate(tool("zizmor"), yml, { version: "1.31.1" });
    expect(out).toContain("zizmor==1.31.1 \\");
    expect(out).toContain("badsecrets==1.2.0");
  });

  it("moves a wheel pin's version, checksum and content-addressed URL, keeping the placeholder", () => {
    const yml = [
      "          PROWLER_VERSION: 5.47.0",
      `          PROWLER_SHA256: ${"8".repeat(64)}`,
      '          curl -fsSL             "https://files.pythonhosted.org/packages/23/fa/abc/prowler-${PROWLER_VERSION}-py3-none-any.whl"             -o "/tmp/x"',
    ].join("\n");
    const out = applyUpdate(tool("prowler"), yml, {
      version: "5.48.0",
      sha256: SHA,
      wheelUrl: "https://files.pythonhosted.org/packages/9a/bc/def/prowler-5.48.0-py3-none-any.whl",
    });
    expect(out).toContain('"https://files.pythonhosted.org/packages/9a/bc/def/prowler-${PROWLER_VERSION}-py3-none-any.whl"');
    expect(out).toContain("PROWLER_VERSION: 5.48.0");
    expect(() => applyUpdate(tool("prowler"), yml, { version: "5.48.0", sha256: SHA })).toThrow(/wheel URL/);
  });
});

describe("the real workflows", () => {
  const dir = resolve(__dirname, "../../../.github/workflows");
  const texts = readdirSync(dir)
    .filter((f) => f.endsWith(".yml"))
    .map((f) => readFileSync(join(dir, f), "utf8"));

  it.each(SCANNER_TOOLS.map((t) => [t.id, t] as [string, ScannerTool]))("%s is pinned, to one version, somewhere", (_id, t) => {
    const pins = new Set(texts.flatMap((x) => readPins(t, x)));
    expect(pins.size).toBe(1);
  });
});

describe("prBody", () => {
  it("names the versions, release and checksum", () => {
    const body = prBody(tool("ffuf"), "2.1.0", "2.3.0", { tag: "v2.3.0", publishedAt: "2026-09-09T00:00:00Z" }, SHA);
    expect(body).toContain("from `2.1.0` to `2.3.0`");
    expect(body).toContain("https://github.com/ffuf/ffuf/releases/tag/v2.3.0");
    expect(body).toContain(SHA);
  });
});
