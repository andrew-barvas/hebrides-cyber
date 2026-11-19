import { describe, expect, it } from "vitest";
import { pickRepoForTarget, repoTargetHost, sameSite } from "./repoTargets";

describe("repoTargetHost", () => {
  it.each([
    ["https://www.Example.com/path?x=1", "www.example.com"],
    ["example.com", "example.com"],
    ["http://shop.example.org:8080", "shop.example.org"],
  ])("%s -> %s", (input, host) => expect(repoTargetHost(input)).toBe(host));

  it.each(["", "   ", "not a host", "localhost", "https://"])("rejects %j", (input) => expect(repoTargetHost(input)).toBeNull());
});

describe("sameSite", () => {
  it("treats www and the bare domain as one site", () => {
    expect(sameSite("www.example.com", "example.com")).toBe(true);
    expect(sameSite("shop.example.com", "example.com")).toBe(false);
    expect(sameSite(null, "example.com")).toBe(false);
  });
});

describe("pickRepoForTarget", () => {
  const rows = [
    { github_repo: "acme/scanner", target_host: "www.hebridescyber.co.uk", connected_at: "2026-11-10T00:00:00Z" },
    { github_repo: "acme/church", target_host: "www.barvasfreechurch.org", connected_at: "2026-11-01T00:00:00Z" },
    { github_repo: "acme/church-v2", target_host: "barvasfreechurch.org", connected_at: "2026-11-05T00:00:00Z" },
    { github_repo: "acme/unlinked", target_host: null, connected_at: "2026-11-15T00:00:00Z" },
  ];

  it("uses only the repository linked to the scanned site, newest first", () => {
    expect(pickRepoForTarget(rows, "https://www.barvasfreechurch.org")).toBe("acme/church-v2");
    expect(pickRepoForTarget(rows, "https://www.hebridescyber.co.uk/")).toBe("acme/scanner");
  });

  it("never falls back to another site's or an unlinked repository", () => {
    expect(pickRepoForTarget(rows, "https://example.com")).toBeNull();
    expect(pickRepoForTarget([{ github_repo: "acme/unlinked", target_host: null }], "https://example.com")).toBeNull();
    expect(pickRepoForTarget(rows, "not a url")).toBeNull();
  });
});
