import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { FindingCard, type ViewFinding } from "./ScanReportView";

function finding(overrides: Partial<ViewFinding> = {}): ViewFinding {
  return { severity: "high", title: "Certificate expired", detail: "detail", ...overrides };
}

describe("FindingCard ATT&CK and CWE badges", () => {
  it("maps a scan stored before attackMap.ts from its checkId", () => {
    render(<FindingCard finding={finding({ checkId: "tls.cert-expired" })} />);
    expect(screen.getByRole("link", { name: /T1557/ }).getAttribute("href")).toBe("https://attack.mitre.org/techniques/T1557/");
    expect(screen.getByRole("link", { name: /CWE-298/ }).getAttribute("href")).toBe("https://cwe.mitre.org/data/definitions/298.html");
  });

  it("prefers the refs stored on the finding", () => {
    render(
      <FindingCard
        finding={finding({ checkId: "tls.cert-expired", attackRefs: [{ id: "T1190", name: "Exploit Public-Facing Application", url: "https://attack.mitre.org/techniques/T1190/" }], cwe: ["CWE-1"] })}
      />,
    );
    expect(screen.getByRole("link", { name: /T1190/ })).toBeTruthy();
    expect(screen.queryByRole("link", { name: /T1557/ })).toBeNull();
    expect(screen.getByRole("link", { name: /CWE-1/ })).toBeTruthy();
  });

  it("renders nothing for an unmapped finding", () => {
    render(<FindingCard finding={finding({ checkId: "unmapped.check" })} />);
    expect(screen.queryByRole("link", { name: /^T\d|CWE-/ })).toBeNull();
  });
});
