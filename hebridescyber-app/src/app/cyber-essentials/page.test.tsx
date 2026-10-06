import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import CyberEssentialsPage, { metadata } from "./page";
import Footer from "@/components/Footer";

describe("/cyber-essentials", () => {
  it("covers all five controls, each with what a scan can't see", () => {
    render(<CyberEssentialsPage />);
    for (const control of ["Firewalls and internet gateways", "Secure configuration", "Security update management", "User access control", "Malware protection"]) {
      expect(screen.getByRole("heading", { level: 3, name: control })).toBeTruthy();
    }
    expect(screen.getAllByText("We check")).toHaveLength(5);
    expect(screen.getAllByText("You answer")).toHaveLength(5);
  });

  it("says plainly that it is not a certification", () => {
    const { container } = render(<CyberEssentialsPage />);
    expect(container.textContent).toMatch(/not a\s+certification/);
    expect(container.textContent).toMatch(/not a certification body/);
    expect(container.textContent).not.toMatch(/\bcertified by\b|\bofficial\b|NCSC-approved/i);
  });

  it("has its own search title and a description that fits a result", () => {
    expect(String(metadata.title)).toMatch(/Cyber Essentials/);
    expect(String(metadata.description).length).toBeLessThanOrEqual(160);
  });
});

describe("footer resources", () => {
  it("links the landing pages that nothing else links to", () => {
    render(<Footer />);
    const nav = screen.getByRole("navigation", { name: "Resources" });
    const hrefs = [...nav.querySelectorAll("a")].map((a) => a.getAttribute("href"));
    expect(hrefs).toEqual(expect.arrayContaining(["/web-check-alternative", "/cyber-essentials", "/ai-threats", "/docs/ci"]));
  });
});
