import { describe, expect, it } from "vitest";
import { buildLookalikeResponse, emailResponseSteps, registrarLookupUrl, NCSC_EMAIL_REPORT_ADDRESS } from "./lookalikeResponse";

const input = { domain: "examp1e.co.uk", targetDomain: "example.co.uk", how: "a character swapped for a lookalike", spottedAt: "2026-11-03T10:00:00Z" };

describe("buildLookalikeResponse", () => {
  it("names both domains and stays hedged: it may be unrelated", () => {
    const r = buildLookalikeResponse(input);
    expect(r.summary).toContain("examp1e.co.uk looks like example.co.uk");
    expect(r.summary).toContain("may be unrelated");
  });

  it("gives blocking steps for both mail platforms, naming the domain", () => {
    const block = buildLookalikeResponse(input).steps.find((s) => s.title === "Block it in your email");
    expect(block?.body).toContain("Tenant Allow/Block Lists");
    expect(block?.body).toContain("Blocked senders");
    expect(block?.body).toContain("examp1e.co.uk");
  });

  it("links to a registrar lookup and the NCSC", () => {
    const r = buildLookalikeResponse(input);
    expect(r.steps.map((s) => s.link?.href).filter(Boolean)).toEqual([registrarLookupUrl("examp1e.co.uk"), "https://www.ncsc.gov.uk/section/about-this-website/report-scam-website"]);
    expect(r.steps.some((s) => s.body.includes(NCSC_EMAIL_REPORT_ADDRESS))).toBe(true);
  });

  it("writes an abuse report that asks for investigation, with placeholders for evidence and the sender", () => {
    const { subject, body } = buildLookalikeResponse(input).abuseReport;
    expect(subject).toBe("Abuse report: examp1e.co.uk may be impersonating example.co.uk");
    expect(body).toContain("(a character swapped for a lookalike)");
    expect(body).toContain("we first saw it on 3 November 2026");
    expect(body).toContain("[Add any evidence here");
    expect(body).toContain("[Your name]");
  });

  it("leaves the date out when unknown or invalid", () => {
    expect(buildLookalikeResponse({ ...input, spottedAt: null }).abuseReport.body).not.toContain("first saw");
    expect(buildLookalikeResponse({ ...input, spottedAt: "nope" }).abuseReport.body).not.toContain("first saw");
  });
});

describe("registrarLookupUrl", () => {
  it("encodes the domain", () => {
    expect(registrarLookupUrl("a b.com")).toBe("https://lookup.icann.org/en/lookup?name=a%20b.com");
  });
});

describe("emailResponseSteps", () => {
  it("is three short steps", () => {
    expect(emailResponseSteps()).toHaveLength(3);
  });
});
