import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import WhatWeCheckPage from "./page";

describe("/what-we-check", () => {
  // The Nmap Public Source License §6 requires a hosted service that runs Nmap
  // scans to show this notice prominently, with a link to nmap.org.
  it("shows the Nmap Security Scanner notice with a link to nmap.org", () => {
    const { container } = render(<WhatWeCheckPage />);
    expect(container.textContent).toMatch(/This service uses the Nmap Security Scanner/);
    expect(screen.getByRole("link", { name: "https://nmap.org/" })).toHaveAttribute("href", "https://nmap.org/");
  });
});
