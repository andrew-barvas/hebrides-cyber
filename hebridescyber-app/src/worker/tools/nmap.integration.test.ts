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
import { runNmap } from "./nmap";

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
