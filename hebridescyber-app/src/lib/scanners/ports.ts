// TCP port scanner — pure Node.js net.createConnection, no nmap binary
// required. Checks the 30 most security-relevant ports with a short timeout
// per connection. Runs all probes in parallel for speed.
import { createConnection } from "node:net";
import { PORT_TARGETS, type PortRisk } from "./portRisk";

export type PortsResult =
  | { status: "checked"; openPorts: OpenPort[]; riskyPorts: OpenPort[] }
  | { status: "error"; note: string };

// The port, service, risk and reason classification lives in portRisk.ts, so
// networkExposure.ts (naabu+nmap discovery) classifies a discovered port the
// same way this base check does.
export type OpenPort = PortRisk;

const CONNECT_TIMEOUT_MS = 2_000;

function probePort(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = createConnection({ host, port }, () => {
      socket.destroy();
      resolve(true);
    });
    socket.setTimeout(CONNECT_TIMEOUT_MS);
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.on("error", () => resolve(false));
  });
}

export async function checkOpenPorts(targetUrl: string): Promise<PortsResult> {
  const host = new URL(targetUrl).hostname;

  try {
    const results = await Promise.allSettled(
      PORT_TARGETS.map(async (t) => {
        const open = await probePort(host, t.port);
        return open ? t : null;
      })
    );

    const openPorts: OpenPort[] = results
      .filter((r): r is PromiseFulfilledResult<PortRisk> => r.status === "fulfilled" && r.value !== null)
      .map((r) => r.value);

    const riskyPorts = openPorts.filter((p) => p.risk === "critical" || p.risk === "high");

    return { status: "checked", openPorts, riskyPorts };
  } catch (err) {
    return { status: "error", note: `Port scan failed: ${(err as Error).message}` };
  }
}
