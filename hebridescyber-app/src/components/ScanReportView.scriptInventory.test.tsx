import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ScriptInventorySection } from "./ScanReportView";
import type { ScriptInventoryResult } from "@/lib/scanners/scriptInventory";

const checked: ScriptInventoryResult = {
  status: "checked",
  pageUrl: "https://www.example.com/",
  origins: [
    { origin: "https://js.stripe.com", sampleUrls: ["https://js.stripe.com/v3/"], scriptCount: 1, integrity: "none", foundBy: "both", paymentProvider: "Stripe" },
    { origin: "https://www.googletagmanager.com", sampleUrls: ["https://www.googletagmanager.com/gtm.js?id=GTM-TEST"], scriptCount: 3, integrity: "unknown", foundBy: "runtime" },
  ],
  totalOrigins: 2,
  truncated: false,
  sources: { html: true, runtime: true },
  paymentPage: { detected: true, signals: ["Stripe script from js.stripe.com"] },
};

describe("ScriptInventorySection", () => {
  it("renders nothing for a scan stored before the inventory existed", () => {
    const { container } = render(<ScriptInventorySection inventory={undefined} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders one table row per origin with found-by, integrity and a sample", () => {
    render(<ScriptInventorySection inventory={checked} />);
    expect(screen.getAllByRole("row")).toHaveLength(3);
    expect(screen.getByText("https://js.stripe.com")).toBeInTheDocument();
    expect(screen.getByText("Stripe payment script")).toBeInTheDocument();
    expect(screen.getByText("HTML + runtime")).toBeInTheDocument();
    expect(screen.getByText("Runtime")).toBeInTheDocument();
    expect(screen.getByText("None")).toBeInTheDocument();
    expect(screen.getByText("Unknown")).toBeInTheDocument();
    expect(screen.getByText("+2 more from this origin")).toBeInTheDocument();
    expect(screen.getByText("This looks like a payment page")).toBeInTheDocument();
  });

  it("says when the inventory is partial or truncated", () => {
    render(
      <ScriptInventorySection
        inventory={{ ...checked, status: "partial", origins: [], totalOrigins: 0, note: "The headless browser couldn't load the page this scan.", paymentPage: { detected: false, signals: [] } }}
      />
    );
    expect(screen.getByText("The headless browser couldn't load the page this scan.")).toBeInTheDocument();
    expect(screen.getByText("No third-party scripts in the page's HTML.")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("shows the count when truncated", () => {
    render(<ScriptInventorySection inventory={{ ...checked, truncated: true, totalOrigins: 61 }} />);
    expect(screen.getByText("Showing 2 of 61 origins.")).toBeInTheDocument();
  });

  it("shows an error rather than an empty table when the check failed", () => {
    render(<ScriptInventorySection inventory={{ status: "error", note: "Neither source could be read." }} />);
    expect(screen.getByText("Script inventory unavailable this scan")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });
});
