import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import LookoutPage, { metadata } from "./page";

describe("/lookout", () => {
  const text = () => render(<LookoutPage />).container.textContent ?? "";

  it("says plainly that it is not a penetration test and never tries to break in", () => {
    expect(text()).toMatch(/Not a penetration test/);
    expect(text()).toMatch(/never try to break in/);
  });

  it("keeps the disclosure of what the checks send, including the login attempts", () => {
    const t = text();
    expect(t).toMatch(/What Lookout sends to your systems/);
    expect(t).toMatch(/submit your login page five times with made-up details/);
  });

  it("shows the approved prices", () => {
    const t = text();
    for (const price of ["£149", "£299", "£399 a quarter", "£1,490 a year", "£799 a quarter", "£2,990 a year"]) expect(t).toContain(price);
  });

  it("makes none of the claims the brand rules forbid, and names no tools", () => {
    const t = text();
    expect(t).not.toMatch(/24\/7 monitoring(?! or incident response)/);
    expect(t).not.toMatch(/\bSOC\b|\bSLA\b|we are (certified|compliant)|(?<!not a )guaranteed response/i);
    expect(t).not.toMatch(/nmap|nuclei|naabu|httpx|OpenVAS|Nikto|ZAP\b/i);
  });

  it("links into the platform with main-site URLs, so links work on the lookout subdomain too", () => {
    const { container } = render(<LookoutPage />);
    const hrefs = [...container.querySelectorAll("a")].map((a) => a.getAttribute("href") ?? "");
    for (const h of hrefs) expect(h.startsWith("#") || h.startsWith("https://www.hebridescyber.co.uk/"), h).toBe(true);
    expect(hrefs).toContain("https://www.hebridescyber.co.uk/contact");
    expect(hrefs.some((h) => h.includes("/exploit"))).toBe(false);
  });

  it("is indexable, with its own title and a canonical URL", () => {
    expect(metadata.robots).toBeUndefined();
    expect(String(metadata.title)).toMatch(/^Lookout/);
    expect(metadata.alternates?.canonical).toBe("https://www.hebridescyber.co.uk/lookout");
  });
});
