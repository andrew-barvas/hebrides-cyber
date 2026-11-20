import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import SampleLookoutReportPage, { metadata } from "./page";
import LookoutPage from "../page";

describe("/lookout/sample", () => {
  const text = () => render(<SampleLookoutReportPage />).container.textContent ?? "";

  it("says up front that it's an example with a fictional business", () => {
    render(<SampleLookoutReportPage />);
    expect(screen.getByRole("note")).toHaveTextContent(/Example report\. Harbour Bakery is a fictional business/);
    expect(String(metadata.description)).toMatch(/Fictional business/);
  });

  it("uses only reserved .example domains, never a real-looking one", () => {
    const domains = text().match(/\b[a-z0-9.-]+\.(?:co\.uk|com|org|net|uk|example)\b/g) ?? [];
    expect(domains.length).toBeGreaterThan(0);
    for (const d of domains) expect(d.endsWith(".example")).toBe(true);
  });

  it("shows the sections the real report has, and not the breach section that's still dark", () => {
    const t = text();
    for (const heading of ["Summary", "Your security score over this period", "What to fix, in order", "Lookalike domains"]) expect(t).toContain(heading);
    expect(t).toMatch(/Engineer's note:/);
    expect(t).toMatch(/isn't acceptance of any risk/);
    expect(t).not.toMatch(/breach/i);
  });

  it("keeps the site table consistent with the chart's start and end", () => {
    const t = text();
    expect(t).toMatch(/www\.harbourbakery\.example5881\+23/);
    expect(t).toMatch(/staff\.harbourbakery\.example6149−12/);
  });

  it("makes no forbidden claims and names no tools", () => {
    const t = text();
    expect(t).not.toMatch(/24\/7|\bSOC\b|guarantee|certified by/i);
    expect(t).toMatch(/not a certification or a penetration test/);
  });

  it("is what the Lookout page's report button opens", () => {
    render(<LookoutPage />);
    expect(screen.getByRole("link", { name: "See a sample report" }).getAttribute("href")).toMatch(/\/lookout\/sample$/);
  });
});
