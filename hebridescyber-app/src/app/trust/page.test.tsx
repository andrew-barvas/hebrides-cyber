import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import TrustPage, { metadata } from "./page";
import Footer from "@/components/Footer";
import sitemap from "@/app/sitemap";

// The sitemap also lists blog posts; keep the test off the network.
vi.mock("@/lib/supabaseClient", () => {
  const q: Record<string, unknown> = {};
  for (const m of ["select", "eq", "not"]) q[m] = () => q;
  q.order = () => Promise.resolve({ data: [] });
  return { supabase: { from: () => q } };
});

describe("/trust", () => {
  it("says plainly that the platform is not certified", () => {
    const { container } = render(<TrustPage />);
    expect(container.textContent).toMatch(/not SOC 2 attested and not ISO 27001 certified/);
  });

  it("makes no compliance or certification claim", () => {
    const { container } = render(<TrustPage />);
    const text = container.textContent ?? "";
    expect(text).not.toMatch(/\b(SOC 2|ISO 27001)[- ](compliant|certified platform)/i);
    expect(text).not.toMatch(/we are (SOC 2|ISO 27001) (compliant|certified)/i);
  });

  it("lists the sub-processors named in the privacy policy and a security contact", () => {
    render(<TrustPage />);
    for (const name of ["Supabase", "Microsoft Azure", "Stripe", "Resend", "Sentry", "Google Analytics"]) {
      expect(screen.getByText(name)).toBeTruthy();
    }
    expect(screen.getByRole("link", { name: /hello@hebridescyber\.co\.uk/ })).toBeTruthy();
  });

  it("has its own search title and a description that fits a result", () => {
    expect(String(metadata.title)).toMatch(/Trust/);
    expect(String(metadata.description).length).toBeLessThanOrEqual(160);
  });
});

describe("/trust discovery", () => {
  it("is linked from the footer", () => {
    render(<Footer />);
    const nav = screen.getByRole("navigation", { name: "Legal" });
    const hrefs = [...nav.querySelectorAll("a")].map((a) => a.getAttribute("href"));
    expect(hrefs).toContain("/trust");
  });

  it("is in the sitemap", async () => {
    const entries = await sitemap();
    expect(entries.some((e) => e.url.endsWith("/trust"))).toBe(true);
  });
});
