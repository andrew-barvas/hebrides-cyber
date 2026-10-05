import { describe, it, expect, vi, afterEach } from "vitest";
import { collectDependencyPackages, scanDependencyManifest, type DependencyManifestResult } from "./dependencyManifest";

afterEach(() => {
  vi.unstubAllGlobals();
});

let n = 0;
/** Unique advisory ids per test, so osv.ts's module-level detail cache never crosses tests. */
const advisory = (label: string) => `GHSA-${label}-${++n}`;

type Vuln = { id: string; aliases?: string[]; withdrawn?: string; database_specific?: { severity: string }; severity?: Array<{ type: string; score: string }>; affected?: unknown[] };

/**
 * One fake world: a GitHub repo root holding `files`, and OSV.dev knowing
 * `vulns` (keyed "ecosystem:name@version" → advisories). Anything else 404s.
 */
function world(opts: {
  files: Record<string, string>;
  vulns?: Record<string, Vuln[]>;
  listing?: number;
  batchStatus?: number;
  detailFails?: string[];
}) {
  const vulnsById = new Map<string, Vuln>();
  for (const list of Object.values(opts.vulns ?? {})) for (const v of list) vulnsById.set(v.id, v);
  const calls: string[] = [];

  const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
    const url = String(input);
    calls.push(url);
    if (url === "https://api.github.com/repos/acme/demo/contents/") {
      if (opts.listing) return new Response("{}", { status: opts.listing });
      return new Response(JSON.stringify(Object.keys(opts.files).map((name) => ({ name, type: "file", size: opts.files[name].length }))));
    }
    const file = /^https:\/\/api\.github\.com\/repos\/acme\/demo\/contents\/(.+)$/.exec(url);
    if (file) {
      const name = decodeURIComponent(file[1]);
      return name in opts.files ? new Response(opts.files[name]) : new Response("{}", { status: 404 });
    }
    if (url === "https://api.osv.dev/v1/querybatch") {
      if (opts.batchStatus) return new Response("{}", { status: opts.batchStatus });
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
      return new Response(
        JSON.stringify({
          results: queries.map((q) => {
            const list = opts.vulns?.[`${q.package.ecosystem}:${q.package.name}@${q.version}`] ?? [];
            return list.length ? { vulns: list.map((v) => ({ id: v.id, modified: "2026-01-01T00:00:00Z" })) } : {};
          }),
        })
      );
    }
    const vuln = /^https:\/\/api\.osv\.dev\/v1\/vulns\/(.+)$/.exec(url);
    if (vuln) {
      const id = decodeURIComponent(vuln[1]);
      if (opts.detailFails?.includes(id) || !vulnsById.has(id)) return new Response("{}", { status: 500 });
      return new Response(JSON.stringify(vulnsById.get(id)));
    }
    return new Response("{}", { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return { fetchMock, calls };
}

const scan = () => scanDependencyManifest({ githubRepo: "acme/demo", githubToken: "test-token" });
const completed = (r: DependencyManifestResult) => {
  if (r.status !== "completed") throw new Error(`expected completed, got ${r.status}: ${"note" in r ? r.note : ""}`);
  return r;
};

const semverRange = (name: string, eco: string, introduced: string, fixed: string) => [
  { package: { name, ecosystem: eco }, ranges: [{ type: "SEMVER", events: [{ introduced }, { fixed }] }] },
];

const PACKAGE_JSON = JSON.stringify({ dependencies: { "web-frame": "^4.0.0" }, devDependencies: { "test-runner": "^2.0.0" } });
const PACKAGE_LOCK = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    "": { dependencies: { "web-frame": "^4.0.0" }, devDependencies: { "test-runner": "^2.0.0" } },
    "node_modules/web-frame": { version: "4.1.0", dependencies: { "body-reader": "^1.0.0" } },
    "node_modules/body-reader": { version: "1.2.0", dependencies: { "deep-merge": "^1.0.0" } },
    "node_modules/deep-merge": { version: "1.0.5" },
    "node_modules/test-runner": { version: "2.2.0", dev: true },
  },
});

describe("scanDependencyManifest — lockfile path", () => {
  it("reports a transitive vulnerability, lockfile-exact, with the route in and the fix", async () => {
    const id = advisory("merge");
    world({
      files: { "package.json": PACKAGE_JSON, "package-lock.json": PACKAGE_LOCK, "README.md": "# demo" },
      vulns: {
        "npm:deep-merge@1.0.5": [
          {
            id,
            aliases: ["CVE-2099-1001"],
            database_specific: { severity: "HIGH" },
            severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }],
            affected: semverRange("deep-merge", "npm", "0", "1.0.6"),
          },
        ],
      },
    });
    const r = completed(await scan());
    expect(r.manifestsScanned).toEqual(["package-lock.json"]);
    expect(r.lockfilesScanned).toEqual(["package-lock.json"]);
    expect(r.dependenciesChecked).toBe(4);
    expect(r.findings).toHaveLength(1);

    const f = r.findings[0];
    expect(f.checkId).toBe("dependency-manifest.npm:deep-merge");
    expect(f.title).toBe("Vulnerable dependency: deep-merge@1.0.5");
    expect(f.severity).toBe("high");
    expect(f.cveIds).toEqual(["CVE-2099-1001"]);
    expect(f.cvssScore).toBe(7.5);
    expect(f.detail).toContain("lockfile-exact");
    expect(f.detail).toContain("introduced via web-frame@4.1.0 > body-reader@1.2.0 > deep-merge@1.0.5");
    expect(f.detail).toContain("Fixed in 1.0.6");
    expect(f.remediation).toContain("1.0.6");
    expect(f.remediation).toContain('"overrides"');
    expect(f.metadata).toMatchObject({ ecosystem: "npm", packageName: "deep-merge", versionSource: "lockfile", osvIds: [id] });
  });

  it("stores the full inventory, not just vulnerable packages", async () => {
    const id = advisory("inv");
    world({
      files: { "package.json": PACKAGE_JSON, "package-lock.json": PACKAGE_LOCK },
      vulns: { "npm:deep-merge@1.0.5": [{ id, affected: semverRange("deep-merge", "npm", "0", "1.0.6") }] },
    });
    const inv = completed(await scan()).inventory!;
    expect(inv.vulnerabilityLookup).toBe("completed");
    expect(inv.files).toEqual([{ file: "package-lock.json", ecosystem: "npm", kind: "lockfile", graph: true }]);
    expect(inv.packages.map((p) => `${p.name}@${p.version}`)).toEqual(["test-runner@2.2.0", "web-frame@4.1.0", "body-reader@1.2.0", "deep-merge@1.0.5"]);
    const webFrame = inv.packages.find((p) => p.name === "web-frame")!;
    expect(inv.packages[webFrame.dependsOn![0]].name).toBe("body-reader");
    expect(inv.packages.find((p) => p.name === "test-runner")).toMatchObject({ direct: true, scope: "optional" });
    expect(inv.packages.find((p) => p.name === "deep-merge")).toMatchObject({ direct: false, scope: "required", vulnIds: [id], fixedVersion: "1.0.6" });
    expect(inv.advisories).toEqual([{ id, cveIds: [] }]);
  });

  it("ignores a withdrawn advisory", async () => {
    const id = advisory("withdrawn");
    world({
      files: { "package-lock.json": PACKAGE_LOCK },
      vulns: { "npm:deep-merge@1.0.5": [{ id, withdrawn: "2026-01-01T00:00:00Z" }] },
    });
    expect(completed(await scan()).findings).toEqual([]);
  });

  it("still reports a package whose advisory detail couldn't be fetched", async () => {
    const id = advisory("nodetail");
    world({ files: { "package-lock.json": PACKAGE_LOCK }, vulns: { "npm:deep-merge@1.0.5": [{ id }] }, detailFails: [id] });
    const r = completed(await scan());
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].detail).toContain(id);
    expect(r.findings[0].severity).toBe("medium");
    expect(r.note).toContain("could not be fetched");
  });

  it("groups several vulnerable versions of one package into one finding", async () => {
    const [a, b] = [advisory("v1"), advisory("v2")];
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { dependencies: { "web-frame": "^4.0.0", "deep-merge": "^2.0.0" } },
        "node_modules/web-frame": { version: "4.1.0", dependencies: { "deep-merge": "^1.0.0" } },
        "node_modules/web-frame/node_modules/deep-merge": { version: "1.0.5" },
        "node_modules/deep-merge": { version: "2.0.0" },
      },
    });
    world({
      files: { "package-lock.json": lock },
      vulns: { "npm:deep-merge@1.0.5": [{ id: a }], "npm:deep-merge@2.0.0": [{ id: b }] },
    });
    const r = completed(await scan());
    expect(r.findings.map((f) => f.checkId)).toEqual(["dependency-manifest.npm:deep-merge"]);
    expect(r.findings[0].title).toBe("Vulnerable dependency: deep-merge@1.0.5, 2.0.0");
    expect(r.findings[0].remediation).not.toContain("isn't declared by your project directly");
  });

  it("covers ecosystems with no manifest fallback (Gemfile.lock, Cargo.lock, packages.lock.json)", async () => {
    const [g, c, nu] = [advisory("gem"), advisory("crate"), advisory("nuget")];
    world({
      files: {
        "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack-lite (2.2.4)\n\nDEPENDENCIES\n  rack-lite\n",
        "Cargo.lock": `version = 3\n\n[[package]]\nname = "byte-tools"\nversion = "1.0.5"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`,
        "packages.lock.json": JSON.stringify({ version: 1, dependencies: { "net8.0": { "Demo.Json": { type: "Direct", resolved: "13.0.1" } } } }),
      },
      vulns: { "RubyGems:rack-lite@2.2.4": [{ id: g }], "crates.io:byte-tools@1.0.5": [{ id: c }], "NuGet:Demo.Json@13.0.1": [{ id: nu }] },
    });
    const r = completed(await scan());
    expect(r.findings.map((f) => f.checkId)).toEqual(["dependency-manifest.ruby:rack-lite", "dependency-manifest.cargo:byte-tools", "dependency-manifest.nuget:Demo.Json"]);
  });

  it("caps listed findings per ecosystem with a summary finding", async () => {
    const packages: Record<string, unknown> = { "": { dependencies: {} } };
    const vulns: Record<string, Vuln[]> = {};
    for (let i = 0; i < 32; i++) {
      const name = `pkg-${String(i).padStart(2, "0")}`;
      packages[`node_modules/${name}`] = { version: "1.0.0" };
      vulns[`npm:${name}@1.0.0`] = [{ id: advisory(name) }];
    }
    world({ files: { "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages }) }, vulns });
    const r = completed(await scan());
    expect(r.findings).toHaveLength(31);
    expect(r.findings[30]).toMatchObject({ checkId: "dependency-manifest.additional-vulnerable:npm", severity: "info" });
    expect(r.findings[30].title).toContain("2 further vulnerable npm dependencies");
  });
});

describe("scanDependencyManifest — manifest fallback", () => {
  it("falls back to declared ranges when there's no lockfile, and says so", async () => {
    const id = advisory("pip");
    world({
      files: { "requirements.txt": "http-client==2.28.0\nunpinned-lib\n" },
      vulns: {
        "PyPI:http-client@2.28.0": [
          { id, aliases: ["CVE-2099-2002"], database_specific: { severity: "CRITICAL" }, affected: [{ package: { name: "http-client", ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.31.0" }] }] }] },
        ],
      },
    });
    const r = completed(await scan());
    expect(r.manifestsScanned).toEqual(["requirements.txt"]);
    expect(r.lockfilesScanned).toEqual([]);
    expect(r.dependenciesDeclared).toBe(2);
    const f = r.findings[0];
    expect(f.checkId).toBe("dependency-manifest.pip:http-client");
    // Manifest ranges aren't evidence of the installed version: no escalation.
    expect(f.severity).toBe("medium");
    expect(f.detail).toContain("manifest-range check, not a lockfile-exact match");
    expect(f.detail).toContain("Fixed in 2.31.0");
    expect(f.remediation).toContain("not a lockfile");
    expect(r.inventory!.files[0]).toEqual({ file: "requirements.txt", ecosystem: "PyPI", kind: "manifest", graph: false });
  });

  it("falls back when the lockfile can't be parsed", async () => {
    world({ files: { "package.json": PACKAGE_JSON, "package-lock.json": "{ broken" } });
    const r = completed(await scan());
    expect(r.manifestsScanned).toEqual(["package.json"]);
    expect(r.note).toContain("package-lock.json could not be parsed");
    expect(r.note).toContain("Fell back to package.json");
  });
});

describe("collectDependencyPackages", () => {
  it("prefers one lockfile per ecosystem and notes the others", () => {
    const c = collectDependencyPackages({
      "package-lock.json": PACKAGE_LOCK,
      "yarn.lock": "# yarn lockfile v1\n\nx@^1.0.0:\n  version \"1.0.0\"\n",
      "package.json": PACKAGE_JSON,
      "go.mod": "module example.com/app\n\nrequire example.com/router v1.8.0\n",
    });
    expect(c.files.map((f) => `${f.file}:${f.kind}`)).toEqual(["package-lock.json:lockfile", "go.mod:manifest"]);
    expect(c.notes.join(" ")).toContain("yarn.lock also present and not read");
    expect(c.packages.find((p) => p.name === "example.com/router")).toMatchObject({ exact: false, direct: true, version: "1.8.0" });
  });

  it("uses go.mod to mark direct modules in go.sum", () => {
    const c = collectDependencyPackages({
      "go.sum": "example.com/router v1.8.0 h1:aaaa=\nexample.com/text v0.3.7 h1:bbbb=\n",
      "go.mod": "module example.com/app\n\nrequire (\n\texample.com/router v1.8.0\n\texample.com/text v0.3.7 // indirect\n)\n",
    });
    expect(c.files.map((f) => f.file)).toEqual(["go.sum"]);
    expect(c.packages.map((p) => [p.name, p.direct, p.exact])).toEqual([
      ["example.com/router", true, true],
      ["example.com/text", false, true],
    ]);
  });
});

describe("scanDependencyManifest — errors and inapplicable cases", () => {
  it("a failed OSV.dev batch is an error, never 'no vulnerabilities'", async () => {
    world({ files: { "package-lock.json": PACKAGE_LOCK }, batchStatus: 503 });
    const r = await scan();
    expect(r.status).toBe("error");
    expect(r.findings).toEqual([]);
    if (r.status !== "error") return;
    expect(r.note).toContain("HTTP 503");
    expect(r.note).toContain("not a clean result");
    expect(r.inventory?.vulnerabilityLookup).toBe("failed");
    expect(r.inventory?.packages).toHaveLength(4);
  });

  it("an unreadable repository root is an error", async () => {
    world({ files: {}, listing: 403 });
    const r = await scan();
    expect(r.status).toBe("error");
    expect(r.status === "error" && r.note).toContain("HTTP 403");
  });

  it("files that exist but can't be read are an error, not 'nothing to scan'", async () => {
    const { fetchMock } = world({ files: { "package-lock.json": PACKAGE_LOCK } });
    const real = fetchMock.getMockImplementation()!;
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) =>
      url.endsWith("/contents/package-lock.json") ? new Response("{}", { status: 502 }) : real(url, init)
    );
    const r = await scan();
    expect(r.status).toBe("error");
    expect(r.status === "error" && r.note).toContain("package-lock.json could not be read (HTTP 502)");
  });

  it("no supported file is not_applicable", async () => {
    world({ files: { "README.md": "# demo", "pyproject.toml": "[project]\nname = 'x'\n" } });
    expect((await scan()).status).toBe("not_applicable");
  });

  it("no repo or an invalid repo name is not_applicable, without any request", async () => {
    const { fetchMock } = world({ files: {} });
    expect((await scanDependencyManifest({ githubRepo: null })).status).toBe("not_applicable");
    expect((await scanDependencyManifest({ githubRepo: "not a repo", githubToken: "t" })).status).toBe("not_applicable");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
