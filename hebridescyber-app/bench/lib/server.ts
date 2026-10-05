// Starts a fixture site on an ephemeral loopback port.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { SiteHandler } from "../fixtures/sites";

export type RunningSite = { url: string; close: () => Promise<void> };

export function startSite(handler: SiteHandler): Promise<RunningSite> {
  return new Promise((resolve, reject) => {
    const server: Server = createServer((req, res) => {
      try {
        handler(req, res);
      } catch {
        res.statusCode = 500;
        res.end();
      }
    });
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        url: `http://127.0.0.1:${port}`,
        close: () =>
          new Promise<void>((done) => {
            server.closeAllConnections();
            server.close(() => done());
          }),
      });
    });
  });
}
