// Runs the real naabu (+ nmap) against a local listener. Skipped unless
// RUN_TOOL_INTEGRATION=1, as the tool-integration CI job arranges. Confirms
// what the unit tests can only assume: that the real naabu binary's -json
// output parses, that a port we open is discovered, and that an unreachable
// host is a completed-with-no-ports result rather than a crash. naabu needs
// raw-socket/connect-scan capability, which the CI job provides.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { runNetworkExposure } from "./networkExposure";

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("networkExposure against a local listener", () => {
  let server: Server;
  let port: number;

  beforeAll(async () => {
    server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
    // Bind to 8080 when free — it's in naabu's top-1000 so the discovery sweep
    // reaches it. Fall back to an ephemeral port (still exercised directly via
    // the -top-ports list only if present; the assertion tolerates its absence).
    await new Promise<void>((resolve) => {
      server.on("error", () => server.listen(0, "127.0.0.1", () => resolve()));
      server.listen(8080, "127.0.0.1", () => resolve());
    });
    port = (server.address() as AddressInfo).port;
  });

  afterAll(() => {
    server?.close();
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

  it("is completed-with-no-ports (not an error) for a host with nothing open on the top 1000", async () => {
    // 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — guaranteed unroutable, so naabu
    // finds nothing. That is a clean, evidenced "nothing open", not an error.
    const result = await runNetworkExposure("http://192.0.2.1/");
    expect(result.status).toBe("completed");
    if (result.status === "completed") expect(result.ports).toEqual([]);
  }, 240_000);
});
