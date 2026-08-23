import { describe, it, expect } from "vitest";
import { normaliseBody, looksLikeSameDocument, matchesBaselineHeaders, isCatchAllBody, type Baseline } from "./httpProbe";

describe("normaliseBody", () => {
  it("collapses whitespace", () => {
    expect(normaliseBody("hello   \n\n  world", "/x")).toBe("hello world");
  });

  it("masks the raw request path out of the body", () => {
    // Masking runs after the initial whitespace collapse but produces its
    // own join spacing, so the surrounding single spaces plus the " PATH "
    // join leave double spaces around the token — a harmless artifact for
    // the fuzzy same-document comparison this feeds into.
    const body = "Page not found: /some/random/path was not located";
    expect(normaliseBody(body, "/some/random/path")).toBe("Page not found:  PATH  was not located");
  });

  it("masks a URL-encoded variant of the request path too", () => {
    const body = "requested %2Fadmin%2Fsecret unavailable";
    expect(normaliseBody(body, "/admin/secret")).toContain("PATH");
  });

  it("masks the path without its leading slash as well", () => {
    const body = "resource admin/secret missing";
    expect(normaliseBody(body, "/admin/secret")).toBe("resource  PATH  missing");
  });

  it("ignores path variants shorter than 3 characters to avoid over-masking", () => {
    // A one/two-char path variant is too likely to collide with unrelated
    // text — the function should leave the body otherwise untouched here.
    const body = "the number is 42 and so is /x";
    expect(normaliseBody(body, "/x")).toBe("the number is 42 and so is /x");
  });

  it("caps output length at 4000 characters", () => {
    const longBody = "a".repeat(5000);
    expect(normaliseBody(longBody, "/y").length).toBe(4000);
  });
});

describe("looksLikeSameDocument", () => {
  it("returns false when either input is empty", () => {
    expect(looksLikeSameDocument("", "something")).toBe(false);
    expect(looksLikeSameDocument("something", "")).toBe(false);
  });

  it("returns true for identical strings", () => {
    expect(looksLikeSameDocument("identical body", "identical body")).toBe(true);
  });

  it("returns false when both strings are short and different (too little signal)", () => {
    expect(looksLikeSameDocument("short a", "short b")).toBe(false);
  });

  it("returns true when a long shared shell differs only by a short embedded token", () => {
    const prefix = "x".repeat(200);
    const suffix = "y".repeat(200);
    const a = `${prefix}nonce-aaaaaaaa${suffix}`;
    const b = `${prefix}nonce-bbbbbbbb${suffix}`;
    expect(looksLikeSameDocument(a, b)).toBe(true);
  });

  it("returns false when two long documents genuinely differ throughout", () => {
    const a = "alpha ".repeat(100);
    const b = "beta ".repeat(100);
    expect(looksLikeSameDocument(a, b)).toBe(false);
  });
});

describe("matchesBaselineHeaders", () => {
  function res(headers: Record<string, string>): Response {
    return { headers: new Headers(headers) } as Response;
  }

  it("matches when the ETag is present and equal", () => {
    const baseline: Baseline = { etag: '"abc123"', contentLength: null, notFoundBody: null, servesCatchAll: false };
    expect(matchesBaselineHeaders(baseline, res({ etag: '"abc123"' }))).toBe(true);
  });

  it("does not match when ETags differ", () => {
    const baseline: Baseline = { etag: '"abc123"', contentLength: null, notFoundBody: null, servesCatchAll: false };
    expect(matchesBaselineHeaders(baseline, res({ etag: '"different"' }))).toBe(false);
  });

  it("falls back to content-length comparison when there's no baseline ETag", () => {
    const baseline: Baseline = { etag: null, contentLength: "1234", notFoundBody: null, servesCatchAll: false };
    expect(matchesBaselineHeaders(baseline, res({ "content-length": "1234" }))).toBe(true);
    expect(matchesBaselineHeaders(baseline, res({ "content-length": "5678" }))).toBe(false);
  });

  it("returns false when neither ETag nor content-length is available to compare", () => {
    const baseline: Baseline = { etag: null, contentLength: null, notFoundBody: null, servesCatchAll: false };
    expect(matchesBaselineHeaders(baseline, res({}))).toBe(false);
  });
});

describe("isCatchAllBody", () => {
  it("returns false when the baseline has no recorded not-found body", () => {
    const baseline: Baseline = { etag: null, contentLength: null, notFoundBody: null, servesCatchAll: false };
    expect(isCatchAllBody(baseline, "anything")).toBe(false);
  });

  it("returns true when the masked body matches the baseline's not-found body", () => {
    const baseline: Baseline = { etag: null, contentLength: null, notFoundBody: "shared shell PATH", servesCatchAll: true };
    expect(isCatchAllBody(baseline, "shared shell PATH")).toBe(true);
  });

  it("returns false when the masked body genuinely differs from the baseline", () => {
    const baseline: Baseline = { etag: null, contentLength: null, notFoundBody: "y".repeat(200), servesCatchAll: true };
    expect(isCatchAllBody(baseline, "z".repeat(200))).toBe(false);
  });
});
