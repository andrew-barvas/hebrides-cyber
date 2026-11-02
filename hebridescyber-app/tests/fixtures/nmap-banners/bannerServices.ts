// Loopback listeners that present real products' banners, so the real nmap
// binary identifies them (product, version and <cpe>) without any vulnerable
// software being installed. Used by the nmap/networkExposure integration
// tests and by capture.ts, which recorded
// src/worker/tools/fixtures/nmap/banner-services.xml. Each listener only
// writes a greeting; none parses or acts on what nmap sends.
import { createServer as createTcpServer, type Server as TcpServer, type AddressInfo } from "node:net";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";

export type BannerKind =
  /** Upstream OpenSSH 7.4: nmap → cpe:/a:openbsd:openssh:7.4 */
  | "openssh-7.4"
  /** Ubuntu's OpenSSH 8.9p1 package: distribution-packaged. */
  | "openssh-8.9p1-ubuntu"
  /** vsftpd 2.3.4 */
  | "vsftpd-2.3.4"
  /** Apache httpd 2.4.49, Server header only */
  | "apache-2.4.49"
  /** Apache httpd with ServerTokens Prod: product, no version */
  | "apache-no-version";

const TCP_BANNERS: Partial<Record<BannerKind, string>> = {
  "openssh-7.4": "SSH-2.0-OpenSSH_7.4\r\n",
  "openssh-8.9p1-ubuntu": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n",
  "vsftpd-2.3.4": "220 (vsFTPd 2.3.4)\r\n",
};

const HTTP_SERVER_HEADERS: Partial<Record<BannerKind, string>> = {
  "apache-2.4.49": "Apache/2.4.49 (Unix)",
  "apache-no-version": "Apache",
};

export type BannerListener = { kind: BannerKind; port: number; close: () => Promise<void> };

/** Starts one listener on 127.0.0.1:`port` (0 = ephemeral). Rejects if the port is taken. */
export function startBannerListener(kind: BannerKind, port = 0): Promise<BannerListener> {
  return new Promise((resolve, reject) => {
    let server: TcpServer | HttpServer;
    const banner = TCP_BANNERS[kind];
    if (banner !== undefined) {
      server = createTcpServer((socket) => {
        socket.on("error", () => {});
        socket.on("data", () => {}); // read and ignore whatever the probe sends
        socket.write(banner);
        socket.setTimeout(10_000, () => socket.destroy());
      });
    } else {
      const header = HTTP_SERVER_HEADERS[kind]!;
      server = createHttpServer((_req, res) => {
        res.setHeader("Server", header);
        res.setHeader("Content-Type", "text/html");
        res.end("<html><body>It works!</body></html>");
      });
    }
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      const bound = (server.address() as AddressInfo).port;
      resolve({
        kind,
        port: bound,
        close: () =>
          new Promise<void>((done) => {
            if ("closeAllConnections" in server) server.closeAllConnections();
            server.close(() => done());
          }),
      });
    });
  });
}

export const ALL_BANNERS: BannerKind[] = ["openssh-7.4", "openssh-8.9p1-ubuntu", "vsftpd-2.3.4", "apache-2.4.49", "apache-no-version"];
