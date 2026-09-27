import { describe, it, expect, vi, afterEach } from "vitest";
import {
  RDAP_BOOTSTRAP_URL,
  checkDomainRegistration,
  parseBootstrap,
  parseRdapDomain,
  resetRdapBootstrapCache,
} from "./domainRegistration";

afterEach(() => {
  vi.unstubAllGlobals();
  resetRdapBootstrapCache();
});

const NOW = new Date("2026-09-27T12:00:00Z");

const BOOTSTRAP = {
  services: [
    [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
    [["uk"], ["https://rdap.nominet.uk/uk/"]],
    [["io"], ["http://insecure.example/"]],
  ],
};

const rdap = (expiration: string | null, status: string[] = [], registrar = "Example Registrar Ltd") => ({
  events: expiration ? [{ eventAction: "registration", eventDate: "2015-01-01T00:00:00Z" }, { eventAction: "expiration", eventDate: expiration }] : [],
  status,
  entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", registrar]]] }],
});

describe("parseBootstrap", () => {
  it("maps each TLD to its HTTPS RDAP base, ignoring http-only services", () => {
    const map = parseBootstrap(BOOTSTRAP);
    expect(map.get("net")).toBe("https://rdap.verisign.com/com/v1/");
    expect(map.get("uk")).toBe("https://rdap.nominet.uk/uk/");
    expect(map.has("io")).toBe(false);
    expect(parseBootstrap({}).size).toBe(0);
  });
});

describe("parseRdapDomain", () => {
  it("reads expiry, registrar and statuses", () => {
    expect(parseRdapDomain("example.com", rdap("2026-10-07T12:00:00Z", ["client transfer prohibited", "active"]), NOW)).toEqual({
      status: "checked",
      domain: "example.com",
      expiresAt: "2026-10-07T12:00:00.000Z",
      daysUntilExpiry: 10,
      registrar: "Example Registrar Ltd",
      statuses: ["client transfer prohibited", "active"],
      transferLocked: true,
    });
  });

  it("reports a missing transfer lock only on generic TLDs", () => {
    expect(parseRdapDomain("example.com", rdap("2027-01-01T00:00:00Z", ["active"]), NOW).transferLocked).toBe(false);
    expect(parseRdapDomain("example.co.uk", rdap("2027-01-01T00:00:00Z", ["active"]), NOW).transferLocked).toBeNull();
  });

  // Seen live: hebridescyber.co.uk's Nominet record carries this status.
  it("recognises a lock that's present even on a ccTLD", () => {
    expect(parseRdapDomain("example.co.uk", rdap("2027-01-01T00:00:00Z", ["client transfer prohibited"]), NOW).transferLocked).toBe(true);
  });

  it("accepts a server-side lock as a lock", () => {
    expect(parseRdapDomain("example.com", rdap(null, ["server transfer prohibited"]), NOW).transferLocked).toBe(true);
  });

  it("goes negative once expired, and null without an expiration event", () => {
    expect(parseRdapDomain("example.com", rdap("2026-09-20T12:00:00Z"), NOW).daysUntilExpiry).toBe(-7);
    expect(parseRdapDomain("example.com", rdap(null), NOW)).toMatchObject({ expiresAt: null, daysUntilExpiry: null });
  });
});

describe("checkDomainRegistration", () => {
  function stub(rdapResponse: Response | Error) {
    const fetchMock = vi.fn(async (url: string) => {
      if (url === RDAP_BOOTSTRAP_URL) return new Response(JSON.stringify(BOOTSTRAP));
      if (rdapResponse instanceof Error) throw rdapResponse;
      return rdapResponse.clone();
    });
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("queries the registry for the registrable domain, not the subdomain", async () => {
    const fetchMock = stub(new Response(JSON.stringify(rdap("2027-03-01T00:00:00Z"))));
    const result = await checkDomainRegistration("https://shop.example.co.uk/basket", NOW);
    expect(fetchMock).toHaveBeenLastCalledWith("https://rdap.nominet.uk/uk/domain/example.co.uk", expect.anything());
    expect(result).toMatchObject({ status: "checked", domain: "example.co.uk", transferLocked: null });
  });

  it("caches the bootstrap file between scans", async () => {
    const fetchMock = stub(new Response(JSON.stringify(rdap("2027-03-01T00:00:00Z"))));
    await checkDomainRegistration("https://example.com", NOW);
    await checkDomainRegistration("https://example.net", NOW);
    expect(fetchMock.mock.calls.filter(([u]) => u === RDAP_BOOTSTRAP_URL)).toHaveLength(1);
  });

  it("is not applicable when the registry has no record", async () => {
    stub(new Response("", { status: 404 }));
    expect((await checkDomainRegistration("https://example.com", NOW)).status).toBe("not_applicable");
  });

  it("is not applicable for a TLD without RDAP, or a bare IP", async () => {
    stub(new Response("{}"));
    expect((await checkDomainRegistration("https://example.io", NOW)).status).toBe("not_applicable");
    expect((await checkDomainRegistration("https://203.0.113.7", NOW)).status).toBe("not_applicable");
  });

  it("reports an error, not a finding, when the registry is unreachable", async () => {
    stub(new Error("ECONNRESET"));
    expect(await checkDomainRegistration("https://example.com", NOW)).toMatchObject({ status: "error" });
  });
});
