import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import EstateMap from "./EstateMap";

const payload = {
  domains: [
    {
      domain: "example.com",
      hosts: [
        { host: "www.example.com", kind: "domain", firstSeenAt: null, lastSeenAt: null, web: { statusCode: 200, title: "Home", webserver: null, url: "https://www.example.com/" }, certificate: { expiresAt: "2026-12-01", daysLeft: 11, issuer: "R3" }, exposedPorts: ["3389"], openFindings: { critical: 1, high: 0, medium: 2, low: 0, info: 0 }, scanId: "s2" },
        { host: "mail.example.com", kind: "subdomain", firstSeenAt: null, lastSeenAt: null, web: null, certificate: null, exposedPorts: [], openFindings: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, scanId: null },
      ],
    },
  ],
  totals: { hosts: 2, live: 1, certificatesExpiringSoon: 1, withCriticalOrHigh: 1 },
};

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn(async () => ({ ok: true, json: async () => payload })));
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("EstateMap", () => {
  it("shows each host's web status, certificate, exposed services and issues, and unknowns as unknown", async () => {
    render(<EstateMap token="tok" />);
    expect(await screen.findByText("example.com")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "www.example.com" })).toHaveAttribute("href", "/dashboard/scans/s2");
    expect(screen.getByText("11 days left")).toBeInTheDocument();
    expect(screen.getByText("port 3389")).toBeInTheDocument();
    expect(screen.getByText("1 critical/high")).toBeInTheDocument();
    expect(screen.getByText("not probed")).toBeInTheDocument();
    expect(screen.getByText("not checked")).toBeInTheDocument();
    expect(screen.getByText("none open")).toBeInTheDocument();
  });

  it("says so when nothing is mapped yet", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: true, json: async () => ({ domains: [], totals: { hosts: 0, live: 0, certificatesExpiringSoon: 0, withCriticalOrHigh: 0 } }) })));
    render(<EstateMap token="tok" />);
    expect(await screen.findByText(/Nothing mapped yet/)).toBeInTheDocument();
  });
});
