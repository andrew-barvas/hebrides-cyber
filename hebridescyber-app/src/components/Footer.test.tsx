import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import Footer from "./Footer";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("Footer layout", () => {
  const hrefsIn = (name: string) =>
    [...screen.getByRole("navigation", { name }).querySelectorAll("a")].map((a) => a.getAttribute("href"));

  it("groups links into titled columns, like other security vendors' footers", () => {
    render(<Footer />);
    for (const name of ["Product", "Resources", "Company"]) {
      expect(screen.getByRole("heading", { name: new RegExp(name) })).toBeInTheDocument();
    }
    expect(hrefsIn("Product")).toEqual(["/services", "/what-we-check", "/pricing", "/sample-reports"]);
    expect(hrefsIn("Company")).toEqual(["/contact", "/agencies"]);
  });

  it("no longer links the sector landing pages", () => {
    render(<Footer />);
    const hrefs = [...document.querySelectorAll("footer a")].map((a) => a.getAttribute("href"));
    for (const sector of ["/tourism", "/churches", "/local-trades"]) expect(hrefs).not.toContain(sector);
    expect(screen.queryByRole("navigation", { name: "Industries" })).not.toBeInTheDocument();
  });

  it("gives a contact address", () => {
    render(<Footer />);
    expect(screen.getByRole("link", { name: "hello@hebridescyber.co.uk" })).toHaveAttribute("href", "mailto:hello@hebridescyber.co.uk");
  });
});

describe("Footer status link", () => {
  it("has no Status link until a status page URL is configured", () => {
    vi.stubEnv("NEXT_PUBLIC_STATUS_PAGE_URL", "");
    render(<Footer />);
    expect(screen.queryByRole("link", { name: /status/i })).not.toBeInTheDocument();
  });

  it("links to the configured status page in a new tab", () => {
    vi.stubEnv("NEXT_PUBLIC_STATUS_PAGE_URL", "https://stats.uptimerobot.com/abc123");
    render(<Footer />);
    const link = screen.getByRole("link", { name: /status/i });
    expect(link).toHaveAttribute("href", "https://stats.uptimerobot.com/abc123");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
  });
});
