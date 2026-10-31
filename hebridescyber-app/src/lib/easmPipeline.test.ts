import { describe, it, expect, vi } from "vitest";
import { runEasmPipeline } from "./easmPipeline";

// A tiny Supabase stub: subscriptions + monitored_targets reads, plus whatever
// isDomainVerified queries (users.is_admin, verifications). We make every owner
// an admin so isDomainVerified short-circuits true without a verifications row.
function stubDb(targets: Array<{ owner: string; target_url: string }>) {
  const subs = [...new Set(targets.map((t) => t.owner))].map((owner) => ({ owner }));
  return {
    from(table: string) {
      if (table === "subscriptions") {
        return { select: () => ({ eq: () => ({ data: subs, error: null }) }) };
      }
      if (table === "monitored_targets") {
        return { select: () => ({ in: () => ({ data: targets, error: null }) }) };
      }
      if (table === "users") {
        // isDomainVerified: admin short-circuit
        return { select: () => ({ eq: () => ({ maybeSingle: async () => ({ data: { is_admin: true } }) }) }) };
      }
      throw new Error(`unexpected table ${table}`);
    },
  } as unknown as import("@supabase/supabase-js").SupabaseClient;
}

type Alert = NonNullable<Parameters<typeof runEasmPipeline>[1]>["alert"];

/** What runEasmDiscovery returns, with crt.sh read successfully unless a test says otherwise. */
const sweepResult = (over: Record<string, unknown> = {}) => ({
  domain: "x",
  assetsDiscovered: 3,
  newAssets: 2,
  assets: [],
  firstCertificates: new Map([["new.example.com", "2026-10-05T00:00:00"]]),
  ctRead: true,
  ...over,
});

/** An alert that found nothing to send. */
const quietAlert = () =>
  vi.fn().mockResolvedValue({ reported: null, silentlyRecorded: [], hostnamesDeferred: false, delivered: false, migrationPending: false, errors: [] }) as unknown as NonNullable<Alert> & ReturnType<typeof vi.fn>;

describe("runEasmPipeline", () => {
  it("sweeps each verified target once, reusing runEasmDiscovery, and sums new assets", async () => {
    const db = stubDb([
      { owner: "o1", target_url: "https://a.example.com" },
      { owner: "o1", target_url: "https://shop.example.net" },
    ]);
    const discover = vi.fn().mockResolvedValue(sweepResult());

    const res = await runEasmPipeline(db, { discover, alert: quietAlert() });

    expect(res.targetsSwept).toBe(2);
    expect(res.newAssets).toBe(4);
    expect(res.errors).toBe(0);
    // Scopes to the registrable owner-domain (so a sweep covers the whole zone),
    // never runs brute-force from a standalone sweep, and stores rows under the
    // monitored site's own URL so a scan of that site's alert can find them.
    expect(discover).toHaveBeenCalledWith(db, "o1", "example.com", { bruteForce: false, targetUrl: "https://a.example.com" });
    expect(discover).toHaveBeenCalledWith(db, "o1", "example.net", { bruteForce: false, targetUrl: "https://shop.example.net" });
  });

  it("counts a failing sweep as an error and keeps going", async () => {
    const db = stubDb([
      { owner: "o1", target_url: "https://a.example.com" },
      { owner: "o1", target_url: "https://b.example.com" },
    ]);
    const discover = vi
      .fn()
      .mockRejectedValueOnce(new Error("crt.sh down"))
      .mockResolvedValueOnce(sweepResult({ assetsDiscovered: 1, newAssets: 1 }));
    const alert = quietAlert();

    const res = await runEasmPipeline(db, { discover, alert });

    expect(res.errors).toBe(1);
    expect(res.targetsSwept).toBe(1);
    expect(res.newAssets).toBe(1);
    // No discovery, no evidence: the failed target is not alerted on.
    expect(alert).toHaveBeenCalledTimes(1);
  });

  it("dry-run considers targets but discovers nothing and alerts nobody", async () => {
    const db = stubDb([{ owner: "o1", target_url: "https://a.example.com" }]);
    const discover = vi.fn();
    const alert = quietAlert();

    const res = await runEasmPipeline(db, { dryRun: true, discover, alert });

    expect(res.targetsSwept).toBe(1);
    expect(discover).not.toHaveBeenCalled();
    expect(alert).not.toHaveBeenCalled();
  });

  describe("alerting", () => {
    it("alerts each swept target with the certificate dates its own discovery just read", async () => {
      const db = stubDb([{ owner: "o1", target_url: "https://www.example.com" }]);
      const certs = new Map([["new.example.com", "2026-10-05T00:00:00"]]);
      const discover = vi.fn().mockResolvedValue(sweepResult({ firstCertificates: certs }));
      const alert = quietAlert();

      await runEasmPipeline(db, { discover, alert });

      expect(alert).toHaveBeenCalledWith(db, "o1", "https://www.example.com", { firstCertificates: certs, ctRead: true });
    });

    it("sums the hostnames owners were told about", async () => {
      const db = stubDb([{ owner: "o1", target_url: "https://a.example.com" }]);
      const reported = { site: "example.com", dnsChanges: [], newHostnames: [{ name: "x.example.com", firstCertificate: "2026-10-05T00:00:00" }, { name: "y.example.com", firstCertificate: "2026-10-05T00:00:00" }] };
      const alert = vi.fn().mockResolvedValue({ reported, silentlyRecorded: [], hostnamesDeferred: false, delivered: true, migrationPending: false, errors: [] });

      const res = await runEasmPipeline(db, { discover: vi.fn().mockResolvedValue(sweepResult()), alert });

      expect(res.hostnamesReported).toBe(2);
      expect(res.alertFailures).toBe(0);
    });

    it("still decides pending rows on a run that discovered nothing new (a retry after a failed delivery)", async () => {
      const db = stubDb([{ owner: "o1", target_url: "https://a.example.com" }]);
      const alert = quietAlert();

      await runEasmPipeline(db, { discover: vi.fn().mockResolvedValue(sweepResult({ newAssets: 0 })), alert });

      expect(alert).toHaveBeenCalledTimes(1);
    });

    it("passes ctRead false through when crt.sh could not be read, and counts it", async () => {
      const db = stubDb([{ owner: "o1", target_url: "https://a.example.com" }]);
      const discover = vi.fn().mockResolvedValue(sweepResult({ ctRead: false, firstCertificates: new Map() }));
      const alert = quietAlert();

      const res = await runEasmPipeline(db, { discover, alert });

      expect(res.ctFailed).toBe(1);
      // The alert is told there is no evidence, so it can leave the rows pending rather than guess.
      expect(alert).toHaveBeenCalledWith(db, "o1", "https://a.example.com", { firstCertificates: new Map(), ctRead: false });
    });

    it("counts an alert that was due but could not be delivered, without aborting the sweep", async () => {
      const db = stubDb([
        { owner: "o1", target_url: "https://a.example.com" },
        { owner: "o1", target_url: "https://b.example.net" },
      ]);
      const alert = vi
        .fn()
        .mockResolvedValueOnce({ reported: null, silentlyRecorded: [], hostnamesDeferred: false, delivered: false, migrationPending: false, errors: ["email failed: no key"] })
        .mockResolvedValueOnce({ reported: null, silentlyRecorded: [], hostnamesDeferred: false, delivered: false, migrationPending: false, errors: [] });

      const res = await runEasmPipeline(db, { discover: vi.fn().mockResolvedValue(sweepResult()), alert });

      expect(res.alertFailures).toBe(1);
      expect(res.targetsSwept).toBe(2); // the second target was still swept and alerted
      expect(alert).toHaveBeenCalledTimes(2);
    });

    it("counts an alert that throws instead of aborting the run", async () => {
      const db = stubDb([{ owner: "o1", target_url: "https://a.example.com" }]);
      const alert = vi.fn().mockRejectedValue(new Error("boom"));

      const res = await runEasmPipeline(db, { discover: vi.fn().mockResolvedValue(sweepResult()), alert });

      expect(res.alertFailures).toBe(1);
      expect(res.errors).toBe(0);
    });
  });

  it("returns an empty result when there are no active subscriptions", async () => {
    const db = stubDb([]);
    const res = await runEasmPipeline(db, { discover: vi.fn() });
    expect(res.targetsConsidered).toBe(0);
    expect(res.targetsSwept).toBe(0);
  });

  it("skips a target whose URL has no resolvable registrable domain", async () => {
    const db = stubDb([{ owner: "o1", target_url: "https://localhost" }]);
    const discover = vi.fn();
    const res = await runEasmPipeline(db, { discover });
    // localhost has no registrable domain under the public suffix list
    expect(res.skippedNoDomain + res.targetsSwept).toBe(1);
  });
});
