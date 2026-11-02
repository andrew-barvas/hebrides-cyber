import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { SignedInCrawlSection } from "./ScanReportView";

describe("SignedInCrawlSection", () => {
  it("renders nothing when no signed-in crawl was attempted", () => {
    const { container } = render(<SignedInCrawlSection status={null} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("says the signed-in pages were not checked when the login was rejected", () => {
    render(<SignedInCrawlSection status={{ state: "failed", note: "The saved credential was not accepted." }} />);
    expect(screen.getByText("Signed-in pages were not checked this scan")).toBeInTheDocument();
    expect(screen.getByText("The saved credential was not accepted.")).toBeInTheDocument();
  });

  it("says a partial crawl did not cover the whole site", () => {
    render(<SignedInCrawlSection status={{ state: "partial", pages: 1, note: "time budget" }} />);
    expect(screen.getByText("Signed-in crawl covered 1 page, not the whole site")).toBeInTheDocument();
  });

  it("confirms a completed crawl with its page count", () => {
    render(<SignedInCrawlSection status={{ state: "crawled", pages: 12 }} />);
    expect(screen.getByText(/checked 12 pages/)).toBeInTheDocument();
  });
});
