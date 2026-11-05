// Runs the real nmap binary against a local listener. Skipped unless
// RUN_TOOL_INTEGRATION=1, as the tool-integration CI job arranges. nmap runs
// in the default `full` profile but had no real-binary test — this confirms
// what the unit tests can only assume: that the installed nmap's -oX output
// parses, that an open service on one of runNmap's fixed "dangerous" ports is
// discovered, and that a host with none of them open is a clean
// completed-with-no-ports result rather than an error (evidence discipline).
//
// runNmap scans a FIXED port list (DANGEROUS_PORTS in nmap.ts) on the target's
// hostname and ignores the URL's own port, so the listener must bind one of
// those ports for the sweep to reach it.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import { runNmap, parseNmapXml } from "./nmap";
import { execTool } from "../../lib/execTool";
import { matchServiceCves, buildServiceCveFindings } from "./serviceCve";
import { createCveIndex, memoryCveIndexStore, type CveMatchRow } from "../../lib/cveIndex";
import { ALL_BANNERS, startBannerListener, type BannerListener } from "../../../tests/fixtures/nmap-banners/bannerServices";

// A subset of nmap.ts's DANGEROUS_PORTS, all unprivileged and normally free on
// the CI runner. We bind the first one that's available.
const CANDIDATE_PORTS = [3306, 6379, 27017, 9200, 2375, 5432];

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("nmap against a local listener", () => {
  let server: Server | undefined;
  let boundPort: number | null = null;

  beforeAll(async () => {
    for (const p of CANDIDATE_PORTS) {
      try {
        await new Promise<void>((resolve, reject) => {
          const s = createServer((_req, res) => {
            res.writeHead(200, { "content-type": "text/plain" });
            res.end("ok");
          });
          s.once("error", reject);
          s.listen(p, "127.0.0.1", () => {
            server = s;
            boundPort = p;
            resolve();
          });
        });
        break;
      } catch {
        // Port in use — try the next dangerous port.
      }
    }
  });

  afterAll(() => {
    server?.close();
  });

  it("discovers an open service on one of nmap's fixed dangerous ports", async () => {
    if (boundPort === null) throw new Error("could not bind any candidate dangerous port");
    const result = await runNmap(`http://127.0.0.1:${boundPort}/`);
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    const found = result.ports.find((p) => p.port === boundPort);
    expect(found, `nmap should have found the open port ${boundPort}`).toBeTruthy();
    expect(found!.state).toBe("open");
    // -sV always labels the port with some service name; we don't assert which,
    // since nmap's guess for an HTTP server on 3306 varies (mysql?/http/...).
    expect(found!.service.length).toBeGreaterThan(0);
  }, 180_000);

  it("is completed-with-no-ports (not an error) for a host with none of those ports open", async () => {
    // 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — guaranteed unroutable, so nmap
    // finds nothing open. That is a clean, evidenced "nothing open", never an
    // error (CLAUDE.md evidence discipline: a failed lookup is status "error",
    // but a successful scan that finds nothing is "completed" with no ports).
    const result = await runNmap("http://192.0.2.1/");
    expect(result.status).toBe("completed");
    if (result.status === "completed") expect(result.ports).toEqual([]);
  }, 180_000);
});

// The real nmap's -sV against loopback listeners presenting real products'
// banners (tests/fixtures/nmap-banners/): product, version and <cpe> come out
// of the installed binary, and feed the CVE matching end to end. This is the
// same run tests/fixtures/nmap-banners/capture.ts records as
// fixtures/nmap/banner-services.xml.
describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("nmap -sV CPE detection against banner listeners", () => {
  const listeners: BannerListener[] = [];
  let xml = "";

  beforeAll(async () => {
    for (const kind of ALL_BANNERS) listeners.push(await startBannerListener(kind));
    const ports = listeners.map((l) => l.port).join(",");
    ({ stdout: xml } = await execTool("nmap", ["-sV", "--open", "-p", ports, "-oX", "-", "127.0.0.1"], { timeout: 180_000 }));
    // Printed so a fixture refresh can be taken from the CI log.
    console.log(`NMAP_BANNER_XML_BASE64 ${Buffer.from(xml).toString("base64")}`);
  }, 200_000);

  afterAll(async () => {
    await Promise.all(listeners.map((l) => l.close()));
  });

  const portOf = (kind: string) => listeners.find((l) => l.kind === kind)!.port;

  it("parses the CPE nmap emits for each identified product", () => {
    const ports = parseNmapXml(xml);
    const byPort = (kind: string) => ports.find((p) => p.port === portOf(kind));
    expect(byPort("openssh-7.4")?.cpes).toContain("cpe:/a:openbsd:openssh:7.4");
    expect(byPort("openssh-8.9p1-ubuntu")?.cpes).toContain("cpe:/a:openbsd:openssh:8.9p1");
    expect(byPort("vsftpd-2.3.4")?.cpes).toContain("cpe:/a:vsftpd:vsftpd:2.3.4");
    expect(byPort("apache-2.4.49")?.cpes).toContain("cpe:/a:apache:http_server:2.4.49");
    expect(byPort("apache-no-version")?.productVersion ?? null).toBeNull();
  });

  it("turns them into version-bounded service-cve findings, and a hidden version into 'version unknown'", async () => {
    const r = (cve_id: string, vendor: string, product: string, over: Partial<CveMatchRow>): CveMatchRow => ({
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
    });
    const index = createCveIndex(
      memoryCveIndexStore({
        state: { backfill_completed_at: new Date().toISOString(), last_success_at: new Date().toISOString(), last_modified_through: null, cve_count: 4 },
        matches: [
          r("CVE-2018-15473", "openbsd", "openssh", { end_including: "7.7" }),
          r("CVE-2024-6387", "openbsd", "openssh", { start_including: "8.6", end_including: "9.8" }),
          r("CVE-2011-2523", "vsftpd_project", "vsftpd", { exact_version: "2.3.4", any_update: true }),
          r("CVE-2021-41773", "apache", "http_server", { exact_version: "2.4.49", any_update: true }),
        ],
        records: [],
      })
    );
    const result = await matchServiceCves(parseNmapXml(xml), index, { fetchEol: async () => [{ cycle: "2.4", eol: false }] });
    const ids = buildServiceCveFindings(result).map((f) => f.checkId);
    expect(ids).toEqual(
      expect.arrayContaining([
        `network-exposure.service-cve:${portOf("openssh-7.4")}:CVE-2018-15473`,
        `network-exposure.service-cve:${portOf("openssh-8.9p1-ubuntu")}:CVE-2024-6387`,
        `network-exposure.service-cve:${portOf("vsftpd-2.3.4")}:CVE-2011-2523`,
        `network-exposure.service-cve:${portOf("apache-2.4.49")}:CVE-2021-41773`,
        `network-exposure.service-version-unknown:${portOf("apache-no-version")}`,
      ])
    );
    expect(ids.some((id) => id?.startsWith(`network-exposure.service-cve:${portOf("apache-no-version")}`))).toBe(false);
    expect(result.services.find((s) => s.port === portOf("openssh-8.9p1-ubuntu"))?.packagedBy).toBe("Ubuntu");
  });
});
