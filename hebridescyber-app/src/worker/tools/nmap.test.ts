import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseNmapXml } from "./nmap";

describe("parseNmapXml", () => {
  it("reads product, version, extrainfo and every <cpe> from real -sV output", () => {
    const ports = parseNmapXml(readFileSync(join(__dirname, "fixtures", "nmap", "banner-services.xml"), "utf8"));
    const ubuntu = ports.find((p) => p.productVersion?.startsWith("8.9p1"));
    expect(ubuntu).toMatchObject({
      service: "ssh",
      product: "OpenSSH",
      version: `OpenSSH ${ubuntu?.productVersion}`,
      extraInfo: expect.stringContaining("Ubuntu"),
    });
    expect(ubuntu?.cpes?.[0]).toBe("cpe:/a:openbsd:openssh:8.9p1");
    expect(ports.every((p) => Array.isArray(p.cpes))).toBe(true);
  });

  it("gives a self-closing <service/> no CPEs and never borrows the next port's", () => {
    const xml = `<nmaprun><host><ports>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="7.4" extrainfo="protocol 2.0"><cpe>cpe:/a:openbsd:openssh:7.4</cpe></service></port>
<port protocol="tcp" portid="80"><state state="closed"/><service name="http"><cpe>cpe:/a:apache:http_server</cpe></service></port>
</ports></host></nmaprun>`;
    const ports = parseNmapXml(xml);
    expect(ports).toEqual([
      { port: 6379, protocol: "tcp", state: "open", service: "redis", version: null, product: null, productVersion: null, extraInfo: null, cpes: [] },
      { port: 22, protocol: "tcp", state: "open", service: "ssh", version: "OpenSSH 7.4", product: "OpenSSH", productVersion: "7.4", extraInfo: "protocol 2.0", cpes: ["cpe:/a:openbsd:openssh:7.4"] },
    ]);
  });

  it("unescapes XML entities in CPEs", () => {
    const xml = `<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="A&amp;B"><cpe>cpe:/a:a%26b:x&amp;y</cpe></service></port>`;
    expect(parseNmapXml(xml)[0]).toMatchObject({ product: "A&B", cpes: ["cpe:/a:a%26b:x&y"] });
  });
});
