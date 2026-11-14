import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { PageScreenshotSection } from "./ScanReportView";

describe("PageScreenshotSection", () => {
  it("shows the stored screenshot with descriptive alt text", () => {
    render(<PageScreenshotSection screenshot="data:image/jpeg;base64,/9j/2Q==" url="https://www.example.com/" />);
    expect(screenshot()).toHaveAttribute("src", "data:image/jpeg;base64,/9j/2Q==");
    expect(screen.getByText("what we saw")).toBeInTheDocument();
  });

  it("renders nothing for a missing value or anything that isn't a scanner JPEG data URI", () => {
    for (const value of [undefined, 42, "https://evil.example/x.jpg", "data:image/svg+xml;base64,PHN2Zz4=", 'data:image/jpeg;base64,abc" onerror="x']) {
      const { container, unmount } = render(<PageScreenshotSection screenshot={value} url="https://www.example.com/" />);
      expect(container).toBeEmptyDOMElement();
      unmount();
    }
  });
});

function screenshot() {
  return screen.getByRole("img", { name: /Screenshot of https:\/\/www.example.com\//i });
}
