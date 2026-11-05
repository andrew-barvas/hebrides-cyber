import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseNmapXml, type NmapPort } from "./nmap";
import {
  matchServiceCves,
  buildServiceCveFindings,
  incompleteServiceChecks,
  packagedByFrom,
  severityForCvss,
  type ServiceCveResult,
} from "./serviceCve";
import { createCveIndex, memoryCveIndexStore, type CveMatchRow, type CveRecordRow, type CveIndexState, type CveIndex } from "../../lib/cveIndex";
import { applyThreatIntel, type KevIndex, type EpssIndex } from "../../lib/scanners/threatIntel";
import { getComplianceRefs } from "../../lib/scanners/compliance";
import { getFixDifficulty } from "../../lib/scanners/fixDifficulty";
import { getAttackRefs } from "../../lib/scanners/attackMap";
import type { EolEntry } from "../../lib/scanners/endOfLife";

// Real nmap -sV -oX output against tests/fixtures/nmap-banners/ (see the
// fixture's README): OpenSSH 7.4, Ubuntu's OpenSSH 8.9p1, vsftpd 2.3.4,
// Apache httpd 2.4.49 and an Apache that hides its version.
const XML = readFileSync(join(__dirname, "fixtures", "nmap", "banner-services.xml"), "utf8");
const PORTS = parseNmapXml(XML);
const portOf = (product: string, version?: string) =>
  PORTS.find((p) => p.product === product && (version === undefined ? !p.productVersion : p.productVersion?.startsWith(version)))!.port;

const NOW = new Date("2026-11-01T12:00:00Z");
const STATE: CveIndexState = {
  backfill_completed_at: "2026-10-01T00:00:00Z",
  last_success_at: "2026-11-01T03:00:00Z",
  last_modified_through: "2026-11-01T02:50:00Z",
  cve_count: 300_000,
};

function row(cve_id: string, vendor: string, product: string, over: Partial<CveMatchRow>): CveMatchRow {
  return {
    cve_id,
    part: "a",
    vendor,
    product,
    exact_version: null,
    any_update: false,
    start_including: null,
    start_excluding: null,
    end_including: null,
    end_excluding: null,
    conditional: false,
    criteria: `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`,
    ...over,
  };
}

// Criteria shaped like NVD's for each CVE (ranges as NVD records them).
const MATCHES: CveMatchRow[] = [
  // OpenSSH username enumeration, through 7.7.
  row("CVE-2018-15473", "openbsd", "openssh", { end_including: "7.7" }),
  // regreSSHion: 8.6 through 9.8 (9.8p1 fixes it).
  row("CVE-2024-6387", "openbsd", "openssh", { start_including: "8.6", end_including: "9.8" }),
  // Only on a particular appliance: never reported.
  row("CVE-2099-0001", "openbsd", "openssh", { end_including: "9.9", conditional: true }),
  // vsftpd 2.3.4 backdoor: one exact version.
  // NVD files it under vsftpd_project; nmap says vsftpd (cveIndex.ts CPE_ALIASES).
  row("CVE-2011-2523", "vsftpd_project", "vsftpd", { exact_version: "2.3.4", criteria: "cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*" }),
  // Apache path traversal: 2.4.49 exactly.
  row("CVE-2021-41773", "apache", "http_server", { exact_version: "2.4.49", criteria: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" }),
];
const RECORDS: CveRecordRow[] = [
  { cve_id: "CVE-2018-15473", cvss_score: 5.3, cvss_version: "3.1", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", summary: "OpenSSH through 7.7 is prone to a user enumeration vulnerability.", published_at: null, last_modified_at: "2024-01-01T00:00:00Z" },
  { cve_id: "CVE-2024-6387", cvss_score: 8.1, cvss_version: "3.1", cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", summary: "A signal handler race condition in sshd.", published_at: null, last_modified_at: "2025-01-01T00:00:00Z" },
  { cve_id: "CVE-2011-2523", cvss_score: 9.8, cvss_version: "3.1", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", summary: "vsftpd 2.3.4 contains a backdoor.", published_at: null, last_modified_at: "2024-01-01T00:00:00Z" },
  { cve_id: "CVE-2021-41773", cvss_score: 7.5, cvss_version: "2.0", cvss_vector: null, summary: "Path traversal in Apache HTTP Server 2.4.49.", published_at: null, last_modified_at: "2024-01-01T00:00:00Z" },
];

// endoflife.date's Apache HTTP Server cycles: 2.4 still supported.
const APACHE_EOL: EolEntry[] = [
  { cycle: "2.4", eol: false },
  { cycle: "2.2", eol: "2017-07-11" },
];

const index = (matches = MATCHES): CveIndex => createCveIndex(memoryCveIndexStore({ state: STATE, matches, records: RECORDS }), { now: NOW });
const fetchEol = vi.fn(async (product: string) => (product === "apache-http-server" ? APACHE_EOL : null));

async function run(ports: NmapPort[] = PORTS, idx: CveIndex | null = index()): Promise<ServiceCveResult> {
  return matchServiceCves(ports, idx, { now: NOW, fetchEol });
}

describe("the nmap fixture", () => {
  it("parses every banner service with its CPEs", () => {
    expect(PORTS).toHaveLength(5);
    const ssh = PORTS.find((p) => p.productVersion === "7.4")!;
    expect(ssh).toMatchObject({ service: "ssh", product: "OpenSSH", cpes: ["cpe:/a:openbsd:openssh:7.4"] });
    const ubuntu = PORTS.find((p) => p.productVersion?.startsWith("8.9p1"))!;
    expect(ubuntu.cpes).toContain("cpe:/a:openbsd:openssh:8.9p1");
    expect(ubuntu.cpes).toContain("cpe:/o:canonical:ubuntu_linux");
    expect(PORTS.find((p) => p.product === "vsftpd")?.cpes).toEqual(["cpe:/a:vsftpd:vsftpd:2.3.4"]);
    expect(PORTS.find((p) => p.product === "Apache httpd" && !p.productVersion)?.cpes).toEqual(["cpe:/a:apache:http_server"]);
  });
});

describe("matchServiceCves + buildServiceCveFindings", () => {
  it("reports each version-bounded CVE once per port with its matched CPE as evidence", async () => {
    const result = await run();
    expect(result.status).toBe("checked");
    const findings = buildServiceCveFindings(result);
    const ids = findings.map((f) => f.checkId).sort();
    const ssh = portOf("OpenSSH", "7.4");
    const ubuntu = portOf("OpenSSH", "8.9p1");
    const ftp = portOf("vsftpd", "2.3.4");
    const web = portOf("Apache httpd", "2.4.49");
    const hidden = portOf("Apache httpd");
    expect(ids).toEqual(
      [
        `network-exposure.service-cve:${ssh}:CVE-2018-15473`,
        `network-exposure.service-cve:${ubuntu}:CVE-2024-6387`,
        `network-exposure.service-cve:${ftp}:CVE-2011-2523`,
        `network-exposure.service-cve:${web}:CVE-2021-41773`,
        `network-exposure.service-version-unknown:${hidden}`,
      ].sort()
    );

    const backdoor = findings.find((f) => f.checkId?.endsWith("CVE-2011-2523"))!;
    expect(backdoor.severity).toBe("critical");
    expect(backdoor.cveIds).toEqual(["CVE-2011-2523"]);
    expect(backdoor.cvssScore).toBe(9.8);
    expect(backdoor.detail).toContain("cpe:2.3:a:vsftpd_project:vsftpd:2.3.4");
    expect(backdoor.detail).toContain("cpe:/a:vsftpd:vsftpd:2.3.4");
    expect(backdoor.metadata).toMatchObject({ matchedCriteria: "cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*", versionRange: "2.3.4", comparedVersion: "2.3.4", indexedThrough: STATE.last_modified_through });
    expect(backdoor.remediation).toContain("CVE-2011-2523");

    // CVSS 2.0 scores aren't Finding.cvssScore (a v3.1 field); severity still uses it.
    const traversal = findings.find((f) => f.checkId?.endsWith("CVE-2021-41773"))!;
    expect(traversal.severity).toBe("high");
    expect(traversal.cvssScore).toBeUndefined();
    expect(traversal.detail).toContain("CVSS 2.0 base score 7.5");
  });

  it("never reports a conditional criterion, and never a CVE without a version", async () => {
    const findings = buildServiceCveFindings(await run());
    expect(findings.some((f) => f.checkId?.includes("CVE-2099-0001"))).toBe(false);
    const unknown = findings.find((f) => f.checkId?.startsWith("network-exposure.service-version-unknown"))!;
    expect(unknown.severity).toBe("info");
    expect(unknown.title).toContain("version unknown");
    expect(unknown.cveIds).toBeUndefined();
  });

  it("downgrades a distribution-packaged service to info and says why", async () => {
    const findings = buildServiceCveFindings(await run());
    const regresshion = findings.find((f) => f.checkId?.endsWith("CVE-2024-6387"))!;
    expect(regresshion.severity).toBe("info");
    expect(regresshion.detail).toContain("Ubuntu");
    expect(regresshion.metadata?.packagedBy).toBe("Ubuntu");
    expect(regresshion.remediation).toContain("Ubuntu's own package");
  });

  it("carries KEV and EPSS context through threatIntel.ts's final pass", async () => {
    const findings = buildServiceCveFindings(await run());
    const kev: KevIndex = new Map([["CVE-2021-41773", { ransomware: true }]]);
    const epss: EpssIndex = new Map([["CVE-2021-41773", { epss: 0.94, percentile: 0.999 }]]);
    applyThreatIntel(findings, kev, epss);
    expect(findings.find((f) => f.checkId?.endsWith("CVE-2021-41773"))?.threatIntel).toEqual({
      knownExploited: true,
      kevCveIds: ["CVE-2021-41773"],
      ransomware: true,
      epss: 0.94,
      epssPercentile: 0.999,
    });
    expect(findings.find((f) => f.checkId?.endsWith("CVE-2018-15473"))?.threatIntel).toEqual({ knownExploited: false });
  });

  it("has compliance, fix-difficulty and ATT&CK entries for its checkIds", () => {
    for (const id of ["network-exposure.service-cve:22:CVE-2024-6387", "network-exposure.service-eol:443"]) {
      expect(getComplianceRefs(id).length).toBeGreaterThan(0);
      expect(getFixDifficulty(id)).toBe("moderate");
      expect(getAttackRefs(id).map((r) => r.id)).toEqual(["T1190"]);
    }
    expect(getComplianceRefs("network-exposure.service-version-unknown:80")).toEqual([]);
  });

  it("reports a service past end of life, and puts it in the CVE detail", async () => {
    const old = { ...PORTS.find((p) => p.productVersion === "2.4.49")!, productVersion: "2.2.34", cpes: ["cpe:/a:apache:http_server:2.2.34"] };
    const result = await run([old]);
    const findings = buildServiceCveFindings(result);
    const eol = findings.find((f) => f.checkId === `network-exposure.service-eol:${old.port}`)!;
    expect(eol.severity).toBe("high");
    expect(eol.detail).toContain("2.2 release line as end of life since 2017-07-11");
    expect(eol.remediation).toContain("https://endoflife.date/apache-http-server");

    const withCve = await run([old], index([row("CVE-2017-9798", "apache", "http_server", { end_including: "2.2.34" })]));
    expect(buildServiceCveFindings(withCve).find((f) => f.checkId?.endsWith("CVE-2017-9798"))?.detail).toContain("past end of life (2017-07-11)");
  });

  it("mentions an approaching end of life in the CVE detail", async () => {
    const soon: EolEntry[] = [{ cycle: "2.4", eol: "2026-12-01" }];
    const web = PORTS.find((p) => p.productVersion === "2.4.49")!;
    const result = await matchServiceCves([web], index(), { now: NOW, fetchEol: async () => soon });
    expect(buildServiceCveFindings(result)[0].detail).toContain("reaches end of life on 2026-12-01");
  });
});

describe("incompleteServiceChecks (evidence discipline)", () => {
  it("is empty when every service was evaluated", async () => {
    const result = await run(PORTS.filter((p) => p.productVersion === "7.4" || p.product === "vsftpd"));
    expect(incompleteServiceChecks(result)).toEqual([]);
  });

  it("marks the whole check when the index is unavailable, never clean", async () => {
    const stale = createCveIndex(memoryCveIndexStore({ state: null, matches: MATCHES, records: RECORDS }), { now: NOW });
    const result = await run(PORTS, stale);
    expect(result.status).toBe("error");
    expect(buildServiceCveFindings(result).filter((f) => f.checkId?.startsWith("network-exposure.service-cve"))).toEqual([]);
    expect(incompleteServiceChecks(result)).toContain("network-exposure.service-cve");

    const none = await run(PORTS, null);
    expect(none.status).toBe("not_configured");
    expect(incompleteServiceChecks(none)).toContain("network-exposure.service-cve");
  });

  it("marks a port it couldn't look up, a CVE it couldn't place, and a failed EOL read", async () => {
    const noCpe: NmapPort = { port: 9000, protocol: "tcp", state: "open", service: "http", version: "Foo 1.0", product: "Foo", productVersion: "1.0", cpes: [] };
    const partial = { ...PORTS.find((p) => p.productVersion === "7.4")!, port: 2022, productVersion: "7", cpes: ["cpe:/a:openbsd:openssh:7"] };
    const mysql: NmapPort = { port: 3306, protocol: "tcp", state: "open", service: "mysql", version: "MySQL 8.0.35", product: "MySQL", productVersion: "8.0.35", cpes: ["cpe:/a:mysql:mysql:8.0.35"] };
    const hidden = PORTS.find((p) => p.product === "Apache httpd" && !p.productVersion)!;
    const result = await run([noCpe, partial, mysql, hidden], index([...MATCHES, row("CVE-2018-0001", "openbsd", "openssh", { exact_version: "7.4" })]));
    const incomplete = incompleteServiceChecks(result);
    expect(incomplete).toContain("network-exposure.service-cve:9000");
    expect(incomplete).toContain("network-exposure.service-cve:2022:CVE-2018-0001");
    expect(incomplete).toContain("network-exposure.service-eol:3306"); // endoflife.date read failed (mock returns null)
    expect(incomplete).toContain(`network-exposure.service-eol:${hidden.port}`); // EOL needs a version
    expect(incomplete).toContain(`network-exposure.service-cve:${hidden.port}`);
  });

  it("treats an unorderable version as not looked up", async () => {
    const odd: NmapPort = { port: 8443, protocol: "tcp", state: "open", service: "https", version: "nginx r22", product: "nginx", productVersion: "r22", cpes: ["cpe:/a:igor_sysoev:nginx:r22"] };
    const result = await run([odd]);
    expect(result.status === "checked" && result.services[0].state).toBe("unordered_version");
    // The mocked endoflife.date read for nginx fails, so EOL is unevaluated too.
    expect(incompleteServiceChecks(result)).toEqual(["network-exposure.service-cve:8443", "network-exposure.service-eol:8443"]);
  });

  it("reports a product without a CPE or version as version unknown", async () => {
    const bare: NmapPort = { port: 6379, protocol: "tcp", state: "open", service: "redis", version: "Redis key-value store", product: "Redis key-value store", productVersion: null, cpes: [] };
    const findings = buildServiceCveFindings(await run([bare]));
    expect(findings.map((f) => f.checkId)).toEqual(["network-exposure.service-version-unknown:6379"]);
  });

  it("uses nmap's version when the CPE has none", async () => {
    const versionless = { ...PORTS.find((p) => p.productVersion === "7.4")!, cpes: ["cpe:/a:openbsd:openssh"] };
    const findings = buildServiceCveFindings(await run([versionless]));
    expect(findings.map((f) => f.checkId)).toEqual([`network-exposure.service-cve:${versionless.port}:CVE-2018-15473`]);
  });
});

describe("helpers", () => {
  it("recognises distribution packaging from version, extrainfo or OS CPE", () => {
    expect(packagedByFrom({ productVersion: "8.9p1 Ubuntu 3ubuntu0.10", extraInfo: null, cpes: [] })).toBe("Ubuntu");
    expect(packagedByFrom({ productVersion: "9.2p1 Debian 2+deb12u3", extraInfo: null, cpes: [] })).toBe("Debian");
    expect(packagedByFrom({ productVersion: "2.4.37", extraInfo: "(Red Hat Enterprise Linux)", cpes: [] })).toBe("Red Hat");
    expect(packagedByFrom({ productVersion: "8.0", extraInfo: null, cpes: ["cpe:/o:debian:debian_linux"] })).toBe("Debian");
    expect(packagedByFrom({ productVersion: "7.4", extraInfo: "protocol 2.0", cpes: ["cpe:/a:openbsd:openssh:7.4", "cpe:/o:linux:linux_kernel"] })).toBeNull();
    expect(packagedByFrom({})).toBeNull();
  });

  it("maps CVSS to severity, unscored as medium", () => {
    expect([9.8, 7.0, 4.0, 3.9, null].map(severityForCvss)).toEqual(["critical", "high", "medium", "low", "medium"]);
  });
});
