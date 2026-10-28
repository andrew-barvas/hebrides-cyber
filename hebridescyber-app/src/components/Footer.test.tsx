import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import Footer from "./Footer";

afterEach(() => {
  vi.unstubAllEnvs();
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
