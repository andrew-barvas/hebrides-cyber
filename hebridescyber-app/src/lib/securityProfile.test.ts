import { describe, it, expect } from "vitest";
import type { Finding } from "./scanners";
import { buildPublicProfile, isProfileSlug, newProfileSlug, renderBadgeSvg } from "./securityProfile";

const NOW = new Date("2026-11-14T12:00:00Z");
const f = (checkId: string): Finding => ({ checkId, severity: "high", title: "t", detail: "d" });
const all = { tls: true, dns: true, headers: true };

describe("buildPublicProfile", () => {
  it("lists only the practices that pass, and nothing about open problems", () => {
    const p = buildPublicProfile({ host: "shop.example", scan: { score: 82, checkedAt: "2026-11-10T00:00:00Z", findings: [f("dns.dmarc-missing"), f("exposure.env-file")], evaluated: all }, now: NOW });
    expect(p.passes.map((x) => x.key)).toEqual(["https", "modern-tls", "headers"]);
    expect(p.stale).toBe(false);
    expect(JSON.stringify(p)).not.toMatch(/dmarc|env-file|high/);
  });

  it("never claims a practice for an area the scan couldn't evaluate", () => {
    const p = buildPublicProfile({ host: "a.example", scan: { score: 90, checkedAt: "2026-11-13T00:00:00Z", findings: [], evaluated: { tls: true, dns: false } }, now: NOW });
    expect(p.passes.map((x) => x.key)).toEqual(["https", "modern-tls"]);
  });

  it("marks an old or missing scan as stale rather than showing it as current", () => {
    expect(buildPublicProfile({ host: "a.example", scan: { score: 90, checkedAt: "2026-09-01T00:00:00Z", findings: [], evaluated: all }, now: NOW }).stale).toBe(true);
    expect(buildPublicProfile({ host: "a.example", scan: null, now: NOW })).toMatchObject({ stale: true, score: null, passes: [] });
  });
});

describe("slugs and badge", () => {
  it("makes unguessable slugs the database will accept, and rejects anything else", () => {
    const s = newProfileSlug();
    expect(isProfileSlug(s)).toBe(true);
    expect(newProfileSlug()).not.toBe(s);
    for (const bad of ["short", "UPPERCASE12345", "../../etc/passwd", "a".repeat(40), 42]) expect(isProfileSlug(bad)).toBe(false);
  });

  it("shows the rating and score when current, and 'not checked recently' when stale", () => {
    const rating = { label: "Good", colour: "#4d7c0f" };
    expect(renderBadgeSvg({ score: 82, stale: false }, rating)).toContain("Good · 82/100");
    expect(renderBadgeSvg({ score: 82, stale: false }, rating)).toContain("#4d7c0f");
    const stale = renderBadgeSvg({ score: 82, stale: true }, rating);
    expect(stale).toContain("not checked recently");
    expect(stale).not.toContain("82");
  });
});
