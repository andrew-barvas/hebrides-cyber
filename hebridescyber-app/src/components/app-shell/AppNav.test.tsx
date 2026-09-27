import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";

const state = vi.hoisted(() => ({ pathname: "/dashboard" }));
vi.mock("next/navigation", () => ({ usePathname: () => state.pathname }));

import { activeNavHref, AppMobileNav, AppSidebar } from "./AppNav";

beforeEach(() => {
  state.pathname = "/dashboard";
});

describe("activeNavHref", () => {
  it.each([
    ["/dashboard", "/dashboard"],
    ["/dashboard/scans", "/dashboard/scans"],
    ["/dashboard/scans/abc-123", "/dashboard/scans"],
    ["/dashboard/scans/abc-123/diff", "/dashboard/scans"],
    // Longest match wins — history is its own nav item, not "Scans".
    ["/dashboard/scans/history", "/dashboard/scans/history"],
    ["/dashboard/assets", "/dashboard/assets"],
    ["/dashboard/integrations", "/dashboard/integrations"],
    ["/account", "/account"],
    ["/account/security", "/account"],
  ])("%s → %s", (pathname, expected) => {
    expect(activeNavHref(pathname)).toBe(expected);
  });

  it("does not treat a shared prefix as a segment match", () => {
    expect(activeNavHref("/dashboardx")).toBeNull();
    expect(activeNavHref("/accounting")).toBeNull();
  });
});

describe("AppSidebar", () => {
  it("marks exactly the current section with aria-current=page", () => {
    state.pathname = "/dashboard/scans/history";
    render(<AppSidebar summary={{ plan: "pro", billingPlan: "pro", planStatus: "active" }} />);
    const nav = screen.getByRole("navigation", { name: "Dashboard" });
    const current = within(nav).getAllByRole("link").filter((a) => a.getAttribute("aria-current") === "page");
    expect(current).toHaveLength(1);
    expect(current[0]).toHaveTextContent("Trends");
  });

  it("offers an upgrade path on the free tier", () => {
    render(<AppSidebar summary={{ plan: "none", billingPlan: "none", planStatus: null }} />);
    expect(screen.getByText("Free")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Upgrade →" })).toHaveAttribute("href", "/pricing");
  });

  it("links a paid plan to billing management", () => {
    render(<AppSidebar summary={{ plan: "agency", billingPlan: "agency", planStatus: "active" }} />);
    expect(screen.getByText("Agency")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Manage →" })).toHaveAttribute("href", "/account");
  });

  it("flags a failed payment instead of a plan name", () => {
    render(<AppSidebar summary={{ plan: "none", billingPlan: "pro", planStatus: "past_due" }} />);
    expect(screen.getByText("Payment failed")).toBeInTheDocument();
    expect(screen.getByText(/Pro features are paused/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Update billing →" })).toHaveAttribute("href", "/account");
  });

  it("puts the primary 'New scan' action first", () => {
    render(<AppSidebar summary={null} />);
    expect(screen.getByRole("link", { name: "New scan" })).toHaveAttribute("href", "/dashboard/scans#run-a-scan");
  });
});

describe("AppMobileNav", () => {
  it("renders every section with the current one marked", () => {
    state.pathname = "/dashboard/integrations";
    render(<AppMobileNav />);
    const links = screen.getAllByRole("link");
    expect(links.map((l) => l.textContent)).toEqual(["Overview", "Scans", "Trends", "Assets", "SLAs", "Integrations", "Account"]);
    expect(screen.getByRole("link", { name: "Integrations" })).toHaveAttribute("aria-current", "page");
  });
});
