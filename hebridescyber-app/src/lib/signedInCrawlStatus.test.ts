import { describe, it, expect } from "vitest";
import { signedInCrawlStatus } from "./signedInCrawlStatus";
import { incompleteChecks } from "./executiveReport";

const withAuth = (authCheck: unknown) => ({ tls: { status: "checked" }, extended: { authCheck } });
const page = { url: "https://example.com/account" };

describe("signedInCrawlStatus", () => {
  it("is null when no signed-in crawl was attempted", () => {
    expect(signedInCrawlStatus(null)).toBeNull();
    expect(signedInCrawlStatus({ tls: {} })).toBeNull();
    expect(signedInCrawlStatus({ extended: {} })).toBeNull();
    expect(signedInCrawlStatus(withAuth({ status: "not_applicable", note: "No authentication credential connected" }))).toBeNull();
    // A scan stored before the crawl rode on authCheck.
    expect(signedInCrawlStatus(withAuth({ status: "checked" }))).toBeNull();
  });

  it("reports a rejected credential, which authCheck itself hides behind status checked", () => {
    const note = "The saved credential was not accepted (the site redirected to its login page), so the signed-in pages were not crawled.";
    expect(signedInCrawlStatus(withAuth({ status: "checked", crawl: { status: "error", note } }))).toEqual({ state: "failed", note });
  });

  it("reports the whole authenticated check failing", () => {
    expect(signedInCrawlStatus(withAuth({ status: "error", note: "timeout" }))).toEqual({ state: "failed", note: "timeout" });
    expect(signedInCrawlStatus(withAuth({ status: "error" }))).toEqual({ state: "failed", note: "The signed-in check could not complete." });
  });

  it("reports a partial crawl with its page count", () => {
    expect(signedInCrawlStatus(withAuth({ status: "checked", crawl: { status: "partial", pages: [page, page], note: "time budget" } }))).toEqual({
      state: "partial",
      pages: 2,
      note: "time budget",
    });
  });

  it("reports a completed crawl", () => {
    expect(signedInCrawlStatus(withAuth({ status: "checked", crawl: { status: "checked", pages: [page], truncated: false } }))).toEqual({ state: "crawled", pages: 1 });
  });
});

describe("incompleteChecks and the signed-in crawl", () => {
  it("lists a rejected or partial signed-in crawl as not finished", () => {
    expect(incompleteChecks(withAuth({ status: "checked", crawl: { status: "error", note: "x" } }))).toEqual([{ name: "signed-in crawl", status: "error" }]);
    expect(incompleteChecks(withAuth({ status: "checked", crawl: { status: "partial", pages: [], note: "x" } }))).toEqual([{ name: "signed-in crawl", status: "partial" }]);
  });

  it("adds nothing when the crawl completed or was never attempted", () => {
    expect(incompleteChecks(withAuth({ status: "checked", crawl: { status: "checked", pages: [] } }))).toEqual([]);
    expect(incompleteChecks(withAuth({ status: "not_applicable", note: "x" }))).toEqual([]);
  });
});
