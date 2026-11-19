import { describe, it, expect } from "vitest";
import { domainOf, eligibility, manifestCsv, parseCompanyType, parseProspects, renderDraftEmail, renderSnapshot, selectProspects, type Prospect } from "./outreach";

const CSV = [
  "name,website,email,company_type,company_number",
  'Harbour Cafe Ltd,harbourcafe.example,Info@HarbourCafe.example,Ltd,SC123456',
  "Island Joinery,islandjoinery.example,hello@islandjoinery.example,sole trader,",
  "Croft Partners,croftpartners.example,office@croftpartners.example,partnership,",
  "Mystery Co,mystery.example,a@mystery.example,,",
  "Harbour Cafe (dup),https://www.harbourcafe.example/menu,other@harbourcafe.example,ltd,",
  "Opted Out Ltd,optedout.example,me@optedout.example,ltd,",
  '"Quotes, Commas LLP",quotes.example,q@quotes.example,LLP,',
].join("\r\n");

const result = {
  target: "https://harbourcafe.example",
  score: 72,
  total: 2,
  findings: [{ severity: "medium", title: "No DMARC record", detail: "Anyone can send email that looks like it came from this domain." }],
  checkedAt: "2026-11-14T10:00:00Z",
};
const sender = { name: "Andrew", business: "Hebrides Cyber", postalAddress: "Inverness, Scotland", replyTo: "hello@hebridescyber.co.uk" };

describe("prospect parsing and PECR eligibility", () => {
  it("parses quoted fields and normalises company types and emails", () => {
    const ps = parseProspects(CSV);
    expect(ps).toHaveLength(7);
    expect(ps[0]).toMatchObject({ name: "Harbour Cafe Ltd", email: "info@harbourcafe.example", companyType: "ltd", companyNumber: "SC123456" });
    expect(ps[6]).toMatchObject({ name: "Quotes, Commas LLP", companyType: "llp" });
    expect(parseCompanyType("Community Interest Company")).toBe("cic");
    expect(parseCompanyType("??")).toBe("unknown");
    expect(domainOf("https://www.Example.com/x")).toBe("example.com");
  });

  it("emails only corporate subscribers, never sole traders, partnerships or unknown types", () => {
    const [ltd, sole, partners, unknown] = parseProspects(CSV);
    const none = new Set<string>();
    expect(eligibility(ltd, none)).toEqual({ ok: true });
    expect(eligibility(sole, none)).toMatchObject({ ok: false, reason: expect.stringContaining("PECR") });
    expect(eligibility(partners, none)).toMatchObject({ ok: false, reason: expect.stringContaining("PECR") });
    expect(eligibility(unknown, none)).toMatchObject({ ok: false, reason: expect.stringContaining("Companies House") });
  });

  it("drops opted-out contacts, duplicate websites and anything over the limit", () => {
    const { selected, excluded } = selectProspects(parseProspects(CSV), new Set(["optedout.example"]), 1);
    expect(selected.map((p) => p.name)).toEqual(["Harbour Cafe Ltd"]);
    const reasons = Object.fromEntries(excluded.map((e) => [e.prospect.name, e.reason]));
    expect(reasons["Harbour Cafe (dup)"]).toBe("same website as an earlier row");
    expect(reasons["Opted Out Ltd"]).toContain("opted out");
    expect(reasons["Quotes, Commas LLP"]).toContain("limit");
  });
});

describe("snapshot and draft", () => {
  const prospect: Prospect = { name: "Harbour Cafe Ltd", website: "harbourcafe.example", email: "info@harbourcafe.example", companyType: "ltd", companyNumber: null };

  it("says the check was passive and names the finding", () => {
    const md = renderSnapshot({ prospect, result });
    expect(md).toContain("Score: 72/100");
    expect(md).toContain("Nothing was tested or probed");
    expect(md).toContain("No DMARC record");
  });

  it("identifies the sender and gives a way to opt out", () => {
    const { subject, body } = renderDraftEmail({ prospect, result, sender });
    expect(subject).toBe("Harbour Cafe Ltd: one thing on your website worth fixing");
    expect(body).toContain("no DMARC record");
    expect(body).toContain("Hebrides Cyber");
    expect(body).toContain("Inverness, Scotland");
    expect(body).toContain('reply "stop" to hello@hebridescyber.co.uk');
  });

  it("doesn't offer to fix anything when the check was clean", () => {
    const { subject, body } = renderDraftEmail({ prospect, result: { ...result, total: 0, findings: [] }, sender });
    expect(subject).toContain("came back clean");
    expect(body).not.toContain("the fix");
  });

  it("writes a formula-safe manifest", () => {
    const csv = manifestCsv([{ prospect: { ...prospect, name: "=HYPERLINK(1)" }, status: "skipped", detail: "x, y", file: "" }]);
    expect(csv.split("\r\n")[1]).toBe("'=HYPERLINK(1),harbourcafe.example,info@harbourcafe.example,ltd,skipped,\"x, y\",");
  });
});
