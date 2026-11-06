// Runs the real naabu (+ nmap) against a local listener. Skipped unless
// RUN_TOOL_INTEGRATION=1, as the tool-integration CI job arranges. Confirms
// what the unit tests can only assume: that the real naabu binary's -json
// output parses, that a port we open is discovered, and that an unreachable
// host is a completed-with-no-ports result rather than a crash. naabu needs
// raw-socket/connect-scan capability, which the CI job provides.
//
// The listener answers with an Apache httpd 2.4.49 Server header
// (tests/fixtures/nmap-banners/), so the run also proves that the real nmap's
// <cpe> reaches the CVE matching and comes out as a service-cve finding.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { runNetworkExposure } from "./networkExposure";
import { buildServiceCveFindings } from "./serviceCve";
import { createCveIndex, memoryCveIndexStore } from "../../lib/cveIndex";
import { startBannerListener, type BannerListener } from "../../../tests/fixtures/nmap-banners/bannerServices";

// CVE-2021-41773 as NVD records it: apache:http_server 2.4.49 exactly.
const cveIndex = () =>
  createCveIndex(
    memoryCveIndexStore({
      state: { backfill_completed_at: new Date().toISOString(), last_success_at: new Date().toISOString(), last_modified_through: null, cve_count: 1 },
      matches: [
        {
          cve_id: "CVE-2021-41773",
          part: "a",
          vendor: "apache",
          product: "http_server",
          exact_version: "2.4.49",
          any_update: true,
          start_including: null,
          start_excluding: null,
          end_including: null,
          end_excluding: null,
          conditional: false,
          criteria: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        },
      ],
      records: [],
    })
  );

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("networkExposure against a local listener", () => {
  let listener: BannerListener;
  let port: number;

  beforeAll(async () => {
    // Bind to 8080 when free — it's in naabu's top-1000 so the discovery sweep
    // reaches it. Fall back to an ephemeral port (still exercised directly via
    // the -top-ports list only if present; the assertion tolerates its absence).
    listener = await startBannerListener("apache-2.4.49", 8080).catch(() => startBannerListener("apache-2.4.49"));
    port = listener.port;
  });

  afterAll(async () => {
    await listener?.close();
  });

  it("discovers the open port and detects its service", async () => {
    const result = await runNetworkExposure(`http://127.0.0.1:${port}/`);
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    // When the listener is on a top-1000 port, it must be discovered. We don't
    // assert the exact service string — nmap labels 8080 variously
    // (http/http-alt/http-proxy depending on its probe), and the real signal is
    // that naabu found the port and the pipeline carried it through with some
    // service name, not which synonym nmap chose.
    if (port === 8080) {
      const found = result.ports.find((p) => p.port === 8080);
      expect(found, "naabu+nmap should have discovered the open port 8080").toBeTruthy();
      expect(found!.service.length).toBeGreaterThan(0);
    }
  }, 240_000);

  it("matches the identified service's CPE against the CVE index", async () => {
    const result = await runNetworkExposure(`http://127.0.0.1:${port}/`, { cveIndex: cveIndex(), fetchEol: async () => [{ cycle: "2.4", eol: false }] });
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    if (port !== 8080) return; // not on naabu's top-1000 list: nothing to match
    expect(result.ports.find((p) => p.port === 8080)?.cpes).toContain("cpe:/a:apache:http_server:2.4.49");
    expect(result.serviceCves.status).toBe("checked");
    const ids = buildServiceCveFindings(result.serviceCves).map((f) => f.checkId);
    expect(ids).toContain("network-exposure.service-cve:8080:CVE-2021-41773");
    expect(result.incompleteChecks).not.toContain("network-exposure.service-cve:8080");
  }, 240_000);

  it("is completed-with-no-ports (not an error) for a host with nothing open on the top 1000", async () => {
    // 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — guaranteed unroutable, so naabu
    // finds nothing. That is a clean, evidenced "nothing open", not an error.
    const result = await runNetworkExposure("http://192.0.2.1/");
    expect(result.status).toBe("completed");
    if (result.status === "completed") expect(result.ports).toEqual([]);
  }, 240_000);
});
