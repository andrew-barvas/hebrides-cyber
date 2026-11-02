// Runs the real testssl.sh against a local TLS listener. Skipped unless
// RUN_TOOL_INTEGRATION=1, as the tool-integration CI job arranges (it installs
// the pinned testssl.sh and sets TESTSSL_PATH). This is the real-binary test
// CLAUDE.md rule 15 asks for before deepTls may run under the `exposure`
// profile: it confirms that the pinned release accepts our flags, that its
// --jsonfile output parses, that a server still offering TLS 1.0/1.1 is
// reported, that the non-intrusive scope still finds it, and that an
// unreachable host is an error rather than a clean result (rule 7).
//
// The listener is Node's own TLS server with a throwaway self-signed
// certificate made by the openssl CLI. SECLEVEL=0 lets OpenSSL 3 offer the
// old protocols at all.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:tls";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { runDeepTls } from "./deepTls";

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("testssl.sh against a local TLS listener", () => {
  let server: Server | undefined;
  let port = 0;
  let dir = "";

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "deeptls-"));
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
      "-subj", "/CN=localhost",
      "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"),
    ], { stdio: "ignore" });
    server = createServer({
      key: readFileSync(join(dir, "key.pem")),
      cert: readFileSync(join(dir, "cert.pem")),
      minVersion: "TLSv1",
      ciphers: "DEFAULT@SECLEVEL=0",
    }, (socket) => {
      socket.end("HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
  });

  afterAll(() => {
    server?.close();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  const legacyProtocolIds = (ids: string[]) => ids.filter((id) => id === "deep-tls.finding:TLS1" || id === "deep-tls.finding:TLS1_1");

  it("reports the legacy protocols the server still offers", async () => {
    const result = await runDeepTls(`https://127.0.0.1:${port}/`);
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    const ids = result.findings.map((f) => f.checkId ?? "");
    expect(legacyProtocolIds(ids), `findings were ${JSON.stringify(ids)}`).not.toEqual([]);
  }, 240_000);

  it("still reports them with the intrusive probes left out", async () => {
    const result = await runDeepTls(`https://127.0.0.1:${port}/`, { nonIntrusive: true });
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    const ids = result.findings.map((f) => f.checkId ?? "");
    expect(legacyProtocolIds(ids), `findings were ${JSON.stringify(ids)}`).not.toEqual([]);
    for (const probe of ["heartbleed", "CCS", "ticketbleed", "ROBOT"]) {
      expect(ids).not.toContain(`deep-tls.finding:${probe}`);
    }
  }, 240_000);

  it("reports an error, never a clean result, when nothing is listening", async () => {
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", resolve));
    const deadPort = (closed.address() as AddressInfo).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));

    const result = await runDeepTls(`https://127.0.0.1:${deadPort}/`, { nonIntrusive: true });
    expect(result.status, JSON.stringify(result)).toBe("error");
    expect(result.findings).toEqual([]);
  }, 240_000);
});
