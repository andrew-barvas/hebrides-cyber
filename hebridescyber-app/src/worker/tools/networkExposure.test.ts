import { describe, it, expect, vi, beforeEach } from "vitest";

// networkExposure.ts shells out via execTool (promisified execFile with stdin
// closed), so mock the same two modules every other tool wrapper's test mocks.
const { execFileMock } = vi.hoisted(() => ({ execFileMock: vi.fn() }));
vi.mock("node:child_process", () => ({
  execFile: (...args: unknown[]) => execFileMock(...args),
  default: { execFile: (...args: unknown[]) => execFileMock(...args) },
}));
vi.mock("node:util", () => ({
  promisify: () => execFileMock,
  default: { promisify: () => execFileMock },
}));

import { parseNaabuJson, classifyPort, runNetworkExposure } from "./networkExposure";

// Real naabu `-json` output: one object per line, plus a progress line on
// stderr that never reaches stdout. Port 3306 (MySQL) and 6379 (Redis) are
// risky; 443 is expected/info. A duplicate 3306 must collapse.
const NAABU_JSON = [
  '{"ip":"93.184.216.34","port":443,"host":"example.com"}',
  '{"ip":"93.184.216.34","port":3306,"host":"example.com"}',
  '{"ip":"93.184.216.34","port":6379,"host":"example.com"}',
  '{"ip":"93.184.216.34","port":3306,"host":"example.com"}',
  "",
].join("\n");

// nmap -sV -oX - over the discovered ports.
const NMAP_XML = `<?xml version="1.0"?>
<nmaprun><host><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24.0"/></port>
<port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MySQL" version="8.0.35"/></port>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis"/></port>
</ports></host></nmaprun>`;

beforeEach(() => execFileMock.mockReset());

describe("parseNaabuJson", () => {
  it("extracts unique, sorted ports from the JSON lines", () => {
    expect(parseNaabuJson(NAABU_JSON)).toEqual([443, 3306, 6379]);
  });

  it("ignores non-JSON lines, banners and out-of-range ports", () => {
    const raw = ['[INF] Running SYN scan', '{"port":22}', '{"port":99999}', '{"port":0}', "not json"].join("\n");
    expect(parseNaabuJson(raw)).toEqual([22]);
  });

  it("returns an empty list for empty output", () => {
    expect(parseNaabuJson("")).toEqual([]);
  });
});

describe("classifyPort", () => {
  it("reuses ports.ts's risk/reason for a known dangerous port", () => {
    const c = classifyPort({ port: 6379, protocol: "tcp", state: "open", service: "redis", version: null });
    expect(c.risk).toBe("critical");
    expect(c.reason).toContain("Redis");
  });

  it("falls back to info with a generic reason for an unknown port", () => {
    const c = classifyPort({ port: 5000, protocol: "tcp", state: "open", service: "upnp", version: "1.0" });
    expect(c.risk).toBe("info");
    expect(c.reason).toContain("5000");
  });

  it("prefers nmap's detected service over the table's label", () => {
    const c = classifyPort({ port: 3306, protocol: "tcp", state: "open", service: "mysql", version: "8.0.35" });
    expect(c.service).toBe("mysql");
    expect(c.version).toBe("8.0.35");
  });
});

describe("runNetworkExposure", () => {
  it("runs naabu then nmap and classifies every discovered port", async () => {
    execFileMock
      .mockResolvedValueOnce({ stdout: NAABU_JSON, stderr: "" }) // naabu
      .mockResolvedValueOnce({ stdout: NMAP_XML, stderr: "" }); // nmap
    const result = await runNetworkExposure("https://example.com");
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.ports.map((p) => p.port)).toEqual([443, 3306, 6379]);
    expect(result.ports.find((p) => p.port === 6379)?.risk).toBe("critical");
    // parseNmapXml joins product + version ("MySQL" + "8.0.35").
    expect(result.ports.find((p) => p.port === 3306)?.version).toBe("MySQL 8.0.35");
    // First invocation is naabu with the host and top-ports.
    expect(execFileMock.mock.calls[0][0]).toBe("naabu");
    expect(execFileMock.mock.calls[1][0]).toBe("nmap");
  });

  it("reports not_configured when naabu is missing (ENOENT), never a clean result", async () => {
    const enoent = Object.assign(new Error("not found"), { code: "ENOENT" });
    execFileMock.mockRejectedValueOnce(enoent);
    const result = await runNetworkExposure("https://example.com");
    expect(result.status).toBe("not_configured");
    expect(result.ports).toEqual([]);
  });

  it("reports an error (not clean) when naabu fails for another reason", async () => {
    execFileMock.mockRejectedValueOnce(new Error("boom"));
    const result = await runNetworkExposure("https://example.com");
    expect(result.status).toBe("error");
  });

  it("treats no open ports as a genuine completed result", async () => {
    execFileMock.mockResolvedValueOnce({ stdout: "", stderr: "" });
    const result = await runNetworkExposure("https://example.com");
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.ports).toEqual([]);
  });

  it("falls back to the discovered ports with no service when nmap fails", async () => {
    execFileMock
      .mockResolvedValueOnce({ stdout: '{"port":6379}', stderr: "" }) // naabu
      .mockRejectedValueOnce(Object.assign(new Error("nmap gone"), { code: "ENOENT" })); // nmap
    const result = await runNetworkExposure("https://example.com");
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.ports).toHaveLength(1);
    expect(result.ports[0]).toMatchObject({ port: 6379, risk: "critical", version: null });
  });

  it("carries through a naabu port nmap reports closed on its own connect", async () => {
    execFileMock
      .mockResolvedValueOnce({ stdout: '{"port":3306}\n{"port":6379}', stderr: "" }) // naabu found two
      .mockResolvedValueOnce({ stdout: `<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" portid="3306"><state state="open"/><service name="mysql"/></port></ports></host></nmaprun>`, stderr: "" });
    const result = await runNetworkExposure("https://example.com");
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.ports.map((p) => p.port)).toEqual([3306, 6379]);
  });

  it("rejects an invalid URL", async () => {
    const result = await runNetworkExposure("not a url");
    expect(result.status).toBe("error");
  });
});
