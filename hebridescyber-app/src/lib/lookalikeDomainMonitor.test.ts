import { describe, it, expect, vi, beforeEach } from "vitest";

const { sendEmailMock } = vi.hoisted(() => ({ sendEmailMock: vi.fn() }));
vi.mock("./email", async (orig) => ({ ...(await orig<typeof import("./email")>()), sendEmail: sendEmailMock }));

import {
  generateLookalikeCandidates,
  checkCandidateDomain,
  sendLookalikeDomainAlerts,
  noticeTitle,
  noticeLines,
  buildLookalikeDomainEmail,
  MAX_CANDIDATES,
  SWEEP_INTERVAL_DAYS,
  type CandidateCheckResult,
  type LookalikeFinding,
} from "./lookalikeDomainMonitor";

describe("generateLookalikeCandidates", () => {
  it("generates omission, doubling, transposition, hyphenation, substitution and tld-swap candidates", () => {
    const candidates = generateLookalikeCandidates("example.com");
    const byTechnique = new Map<string, string[]>();
    for (const c of candidates) byTechnique.set(c.technique, [...(byTechnique.get(c.technique) ?? []), c.domain]);

    expect(byTechnique.get("omission")).toContain("xample.com");
    expect(byTechnique.get("doubling")).toContain("eexample.com");
    expect(byTechnique.get("transposition")).toContain("xeample.com");
    expect(byTechnique.get("hyphenation")).toContain("e-xample.com");
    expect(byTechnique.get("substitution")).toContain("exampl3.com");
    expect(byTechnique.get("tld-swap")).toContain("example.net");
  });

  it("never includes the original domain itself", () => {
    const candidates = generateLookalikeCandidates("example.com");
    expect(candidates.some((c) => c.domain === "example.com")).toBe(false);
  });

  it("deduplicates candidates reachable by more than one technique", () => {
    const candidates = generateLookalikeCandidates("example.com");
    const domains = candidates.map((c) => c.domain);
    expect(new Set(domains).size).toBe(domains.length);
  });

  it("skips labels shorter than 4 characters", () => {
    expect(generateLookalikeCandidates("abc.com")).toEqual([]);
  });

  it("returns an empty list for an unparseable domain (IP, bare suffix)", () => {
    expect(generateLookalikeCandidates("com")).toEqual([]);
    expect(generateLookalikeCandidates("192.0.2.1")).toEqual([]);
  });

  it("does not swap the TLD for a multi-label suffix (co.uk)", () => {
    const candidates = generateLookalikeCandidates("example.co.uk");
    expect(candidates.some((c) => c.technique === "tld-swap")).toBe(false);
  });

  it("caps the result at MAX_CANDIDATES", () => {
    // A longer label generates far more than MAX_CANDIDATES raw permutations.
    const candidates = generateLookalikeCandidates("averylongexamplelabelindeed.com");
    expect(candidates.length).toBeLessThanOrEqual(MAX_CANDIDATES);
  });

  it("is pure and deterministic — same input, same output", () => {
    expect(generateLookalikeCandidates("example.com")).toEqual(generateLookalikeCandidates("example.com"));
  });
});

function crtShResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

describe("checkCandidateDomain", () => {
  it("reports exists with the earliest certificate date for a matching exact domain", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        crtShResponse([
          { name_value: "exarnple.com", not_before: "2024-03-01T00:00:00" },
          { name_value: "*.exarnple.com", not_before: "2024-01-01T00:00:00" },
        ])
      )
    );
    const result = await checkCandidateDomain("exarnple.com");
    expect(result).toEqual({ status: "exists", firstSeen: "2024-01-01T00:00:00" });
    vi.unstubAllGlobals();
  });

  it("reports not_found when no returned certificate names the exact candidate", async () => {
    // A loose server-side match returning an unrelated/longer name must not count.
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(crtShResponse([{ name_value: "sub.exarnple.com" }])));
    const result = await checkCandidateDomain("exarnple.com");
    expect(result).toEqual({ status: "not_found" });
    vi.unstubAllGlobals();
  });

  it("reports not_found for an empty result array", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(crtShResponse([])));
    const result = await checkCandidateDomain("exarnple.com");
    expect(result).toEqual({ status: "not_found" });
    vi.unstubAllGlobals();
  });

  it("reports error on a non-ok response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(crtShResponse({}, 500)));
    const result = await checkCandidateDomain("exarnple.com");
    expect(result.status).toBe("error");
    vi.unstubAllGlobals();
  });

  it("reports error when the fetch itself throws", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network down")));
    const result = await checkCandidateDomain("exarnple.com");
    expect(result).toEqual({ status: "error", reason: "network down" });
    vi.unstubAllGlobals();
  });

  it("matches a wildcard certificate against its base name", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(crtShResponse([{ name_value: "*.exarnple.com", not_before: "2024-01-01T00:00:00" }])));
    const result = await checkCandidateDomain("exarnple.com");
    expect(result).toEqual({ status: "exists", firstSeen: "2024-01-01T00:00:00" });
    vi.unstubAllGlobals();
  });
});

describe("message building", () => {
  const findings: LookalikeFinding[] = [
    { domain: "exarnple.com", technique: "substitution", firstSeen: "2024-01-01T00:00:00" },
    { domain: "example-login.com", technique: "hyphenation", firstSeen: "2024-06-01T00:00:00" },
  ];

  it("titles with the count and target domain", () => {
    expect(noticeTitle("example.com", findings)).toBe("2 lookalike domains found for example.com");
    expect(noticeTitle("example.com", findings.slice(0, 1))).toBe("1 lookalike domain found for example.com");
  });

  it("lists every finding up to the cap, with an overflow count", () => {
    const many = Array.from({ length: 15 }, (_, i) => ({ domain: `evil${i}.com`, technique: "omission", firstSeen: "2024-01-01T00:00:00" }));
    const lines = noticeLines("example.com", many);
    expect(lines[0]).toContain("evil0.com");
    expect(lines.some((l) => l.includes("more on the Assets page"))).toBe(true);
  });

  it("includes the why-it-matters line", () => {
    const lines = noticeLines("example.com", findings);
    expect(lines.at(-1)).toContain("phishing");
  });

  it("builds an email with the domain, findings and a dashboard link", () => {
    const { subject, html } = buildLookalikeDomainEmail("example.com", findings, "https://app.example.com");
    expect(subject).toBe(noticeTitle("example.com", findings));
    expect(html).toContain("exarnple.com");
    expect(html).toContain("example-login.com");
    expect(html).toContain("https://app.example.com/dashboard/assets");
  });

  it("escapes HTML in the email body", () => {
    const malicious: LookalikeFinding[] = [{ domain: "<img src=x>.com", technique: "omission", firstSeen: "2024-01-01T00:00:00" }];
    const { html } = buildLookalikeDomainEmail("example.com", malicious, "https://app.example.com");
    expect(html).not.toContain("<img src=x>.com");
    expect(html).toContain("&lt;img");
  });
});

// ---- sendLookalikeDomainAlerts orchestration -------------------------------

type Row = Record<string, unknown>;

function fakeSupabase(opts: {
  subscription?: Row | null;
  user?: Row | null;
  sweepRow?: Row | null;
  sweepTableMissing?: boolean;
  existingLookalikeDomains?: Set<string>;
  insertFails?: boolean;
  claimFails?: boolean;
}) {
  const sweptUpserts: Row[] = [];
  const insertedRows: Row[][] = [];
  const claimedUpdates: Array<{ notified_at: string | null; candidateDomains: string[] }> = [];
  const known = new Set(opts.existingLookalikeDomains ?? []);
  const notifiedState = new Map<string, string | null>();

  const supabase = {
    from(table: string) {
      if (table === "subscriptions") {
        return { select: () => ({ eq: () => ({ maybeSingle: async () => ({ data: opts.subscription ?? null, error: null }) }) }) };
      }
      if (table === "users") {
        return { select: () => ({ eq: () => ({ maybeSingle: async () => ({ data: opts.user ?? null, error: null }) }) }) };
      }
      if (table === "lookalike_domain_sweeps") {
        return {
          select: () => ({
            eq: () => ({
              eq: () => ({
                maybeSingle: async () => (opts.sweepTableMissing ? { data: null, error: { code: "42P01", message: "missing" } } : { data: opts.sweepRow ?? null, error: null }),
              }),
            }),
          }),
          upsert: async (row: Row) => {
            sweptUpserts.push(row);
            return { error: null };
          },
        };
      }
      if (table === "lookalike_domains") {
        return {
          upsert: async (rows: Row[]) => {
            insertedRows.push(rows);
            for (const r of rows) {
              const domain = r.candidate_domain as string;
              if (!known.has(domain)) {
                known.add(domain);
                notifiedState.set(domain, null);
              }
            }
            return { error: opts.insertFails ? { message: "insert failed" } : null };
          },
          update(values: { notified_at: string | null }) {
            let capturedDomains: string[] = [];
            const runUpdate = (): Row[] => {
              const claimedNow: Row[] = [];
              for (const d of capturedDomains) {
                if (values.notified_at !== null) {
                  if (notifiedState.get(d) === null) {
                    notifiedState.set(d, values.notified_at as string);
                    claimedNow.push({ candidate_domain: d, technique: "omission", first_seen_at: "2024-01-01T00:00:00" });
                  }
                } else {
                  notifiedState.set(d, null);
                }
              }
              claimedUpdates.push({ notified_at: values.notified_at, candidateDomains: [...capturedDomains] });
              return claimedNow;
            };
            // Mirrors supabase-js: the builder chain is itself thenable (awaiting
            // it without .select() still issues the update), and .select() also
            // returns the affected rows.
            const chain: Record<string, unknown> = {
              eq: () => chain,
              is: () => chain,
              in: (_col: string, domains: string[]) => {
                capturedDomains = domains;
                return chain;
              },
              select: async () => {
                if (opts.claimFails && values.notified_at !== null) return { data: null, error: { message: "claim failed" } };
                return { data: runUpdate(), error: null };
              },
              then: (resolve: (v: { data: null; error: null }) => void) => {
                runUpdate();
                resolve({ data: null, error: null });
              },
            };
            return chain;
          },
        };
      }
      throw new Error(`unexpected table: ${table}`);
    },
  };

  return { supabase, sweptUpserts, insertedRows, claimedUpdates, notifiedState };
}

const PAID_SUB: Row = { plan: "pro", status: "active", slack_webhook_url: null, ms_teams_webhook_url: null };
const USER: Row = { email: "owner@example.com", is_admin: false };

describe("sendLookalikeDomainAlerts", () => {
  beforeEach(() => {
    sendEmailMock.mockReset();
    sendEmailMock.mockResolvedValue({ ok: true });
  });

  it("does nothing for a URL with no owner domain (an IP)", async () => {
    const { supabase } = fakeSupabase({});
    const result = await sendLookalikeDomainAlerts(supabase as never, "owner-1", "https://192.0.2.1/");
    expect(result).toEqual({ swept: false, candidatesChecked: 0, found: [], delivered: false, migrationPending: false, errors: [] });
  });

  it("skips entirely for a non-alerting owner, before any check", async () => {
    const { supabase } = fakeSupabase({ subscription: { plan: null, status: null, slack_webhook_url: null, ms_teams_webhook_url: null }, user: USER });
    const checkCandidate = vi.fn();
    const result = await sendLookalikeDomainAlerts(supabase as never, "owner-1", "https://example.com/", { checkCandidate });
    expect(result.swept).toBe(false);
    expect(checkCandidate).not.toHaveBeenCalled();
  });

  it("reports migrationPending before the table exists", async () => {
    const { supabase } = fakeSupabase({ subscription: PAID_SUB, user: USER, sweepTableMissing: true });
    const result = await sendLookalikeDomainAlerts(supabase as never, "owner-1", "https://example.com/", { checkCandidate: vi.fn() });
    expect(result.migrationPending).toBe(true);
  });

  it("skips a sweep that isn't due yet", async () => {
    const now = new Date("2024-06-10T00:00:00Z");
    const sweptAt = new Date(now.getTime() - (SWEEP_INTERVAL_DAYS - 1) * 24 * 60 * 60 * 1000).toISOString();
    const { supabase } = fakeSupabase({ subscription: PAID_SUB, user: USER, sweepRow: { swept_at: sweptAt } });
    const checkCandidate = vi.fn();
    const result = await sendLookalikeDomainAlerts(supabase as never, "owner-1", "https://example.com/", { now, checkCandidate });
    expect(result.swept).toBe(false);
    expect(checkCandidate).not.toHaveBeenCalled();
  });

  it("sweeps when due, finds a registered candidate, claims and delivers it by email", async () => {
    const { supabase, sweptUpserts } = fakeSupabase({ subscription: PAID_SUB, user: USER });
    const checkCandidate = vi.fn(async (domain: string): Promise<CandidateCheckResult> => (domain === "exarnple.com" ? { status: "exists", firstSeen: "2024-01-01T00:00:00" } : { status: "not_found" }));
    const result = await sendLookalikeDomainAlerts(supabase as never, "owner-1", "https://example.com/", { checkCandidate });

    expect(result.swept).toBe(true);
    expect(result.candidatesChecked).toBeGreaterThan(0);
    expect(result.found.some((f) => f.domain === "exarnple.com")).toBe(true);
    expect(result.delivered).toBe(true);
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
    expect(sweptUpserts).toHaveLength(1);
  });

  it("never re-alerts an already-known candidate", async () => {
    const { supabase } = fakeSupabase({ subscription: PAID_SUB, user: USER, existingLookalikeDomains: new Set(["exarnple.com"]) });
    const checkCandidate = vi.fn(async (domain: string): Promise<CandidateCheckResult> => (domain === "exarnple.com" ? { status: "exists", firstSeen: "2024-01-01T00:00:00" } : { status: "not_found" }));
    const result = await sendLookalikeDomainAlerts(supabase as never, "owner-1", "https://example.com/", { checkCandidate });
    expect(result.found).toEqual([]);
    expect(result.delivered).toBe(false);
  });

  it("returns no findings when nothing is registered", async () => {
    const { supabase } = fakeSupabase({ subscription: PAID_SUB, user: USER });
    const checkCandidate = vi.fn(async (): Promise<CandidateCheckResult> => ({ status: "not_found" }));
    const result = await sendLookalikeDomainAlerts(supabase as never, "owner-1", "https://example.com/", { checkCandidate });
    expect(result.swept).toBe(true);
    expect(result.found).toEqual([]);
  });

  it("releases the claim for a retry when delivery fails entirely", async () => {
    const { supabase, claimedUpdates } = fakeSupabase({ subscription: { ...PAID_SUB }, user: { email: null, is_admin: false } });
    const checkCandidate = vi.fn(async (domain: string): Promise<CandidateCheckResult> => (domain === "exarnple.com" ? { status: "exists", firstSeen: "2024-01-01T00:00:00" } : { status: "not_found" }));
    const result = await sendLookalikeDomainAlerts(supabase as never, "owner-1", "https://example.com/", { checkCandidate });
    expect(result.delivered).toBe(false);
    expect(result.errors.some((e) => e.includes("no email address"))).toBe(true);
    // Claimed, then released: the second update call for the same domain set passes notified_at: null.
    expect(claimedUpdates.some((u) => u.notified_at === null && u.candidateDomains.includes("exarnple.com"))).toBe(true);
  });

  it("never throws, even on an unexpected failure", async () => {
    const supabase = { from: () => { throw new Error("boom"); } };
    const result = await sendLookalikeDomainAlerts(supabase as never, "owner-1", "https://example.com/");
    expect(result.errors.length).toBeGreaterThan(0);
  });
});
