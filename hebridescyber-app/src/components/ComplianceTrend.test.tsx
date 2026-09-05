import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import ComplianceTrend from "./ComplianceTrend";
import type { CompliancePoint } from "@/lib/clientScanHistory";

describe("ComplianceTrend — category breakdown", () => {
  it("shows a message rather than an empty chart when there are no open findings", () => {
    render(<ComplianceTrend findings={[]} history={[]} />);
    expect(screen.getByText(/No open findings in the latest scan/)).toBeInTheDocument();
  });

  it("excludes info-severity findings from the breakdown", () => {
    render(<ComplianceTrend findings={[{ severity: "info", checkId: "recon.shodan-cves" }]} history={[]} />);
    expect(screen.getByText(/No open findings in the latest scan/)).toBeInTheDocument();
  });

  it("groups findings by their checkId's module prefix, with a human label", () => {
    render(
      <ComplianceTrend
        findings={[
          { severity: "high", checkId: "tls.no-https" },
          { severity: "medium", checkId: "tls.weak-protocol" },
          { severity: "low", checkId: "headers.missing-recommended" },
        ]}
        history={[]}
      />
    );
    expect(screen.getByText("TLS")).toBeInTheDocument();
    expect(screen.getByText("Headers")).toBeInTheDocument();
  });

  it("falls back to a humanised label for a category not in the known list", () => {
    render(<ComplianceTrend findings={[{ severity: "high", checkId: "brand-new-module.some-check" }]} history={[]} />);
    expect(screen.getByText("Brand new module")).toBeInTheDocument();
  });

  it("sorts categories by count, highest first", () => {
    render(
      <ComplianceTrend
        findings={[
          { severity: "high", checkId: "headers.missing-critical" },
          { severity: "high", checkId: "tls.no-https" },
          { severity: "high", checkId: "tls.weak-protocol" },
        ]}
        history={[]}
      />
    );
    const labels = screen.getAllByText(/TLS|Headers/).map((el) => el.textContent);
    expect(labels[0]).toBe("TLS"); // 2 findings, vs Headers' 1
  });
});

describe("ComplianceTrend — coverage trend", () => {
  it("shows a message rather than a chart with fewer than 2 history points", () => {
    render(
      <ComplianceTrend
        findings={[]}
        history={[
          {
            date: "2026-01-01",
            coverage: {
              "cyber-essentials": 1,
              "owasp-top-10": 1,
              "cis-controls-v8": 1,
              "iso-27001": 1,
              "pci-dss": 1,
              nis2: 1,
              dora: 1,
            },
          },
        ]}
      />
    );
    expect(screen.getByText(/Not enough scan history yet/)).toBeInTheDocument();
  });

  it("renders every framework's current coverage percentage", () => {
    const history: CompliancePoint[] = [
      {
        date: "2026-01-01",
        coverage: { "cyber-essentials": 0.5, "owasp-top-10": 0.6, "cis-controls-v8": 0.7, "iso-27001": 0.5, "pci-dss": 0.5, nis2: 0.5, dora: 0.5 },
      },
      {
        date: "2026-02-01",
        coverage: { "cyber-essentials": 0.8, "owasp-top-10": 0.6, "cis-controls-v8": 0.9, "iso-27001": 0.5, "pci-dss": 0.5, nis2: 0.5, dora: 0.5 },
      },
    ];
    render(<ComplianceTrend findings={[]} history={history} />);

    expect(screen.getByText("Cyber Essentials")).toBeInTheDocument();
    expect(screen.getByText("OWASP Top 10")).toBeInTheDocument();
    expect(screen.getByText("CIS Controls v8")).toBeInTheDocument();
    expect(screen.getByText("ISO 27001")).toBeInTheDocument();
    expect(screen.getByText("PCI DSS")).toBeInTheDocument();
    expect(screen.getByText("NIS2")).toBeInTheDocument();
    expect(screen.getByText("DORA")).toBeInTheDocument();
    expect(screen.getByText("80%")).toBeInTheDocument();
    expect(screen.getByText("90%")).toBeInTheDocument();
  });

  it("shows an up arrow with the delta when coverage improved", () => {
    const history: CompliancePoint[] = [
      {
        date: "2026-01-01",
        coverage: { "cyber-essentials": 0.5, "owasp-top-10": 0.5, "cis-controls-v8": 0.5, "iso-27001": 0.5, "pci-dss": 0.5, nis2: 0.5, dora: 0.5 },
      },
      {
        date: "2026-02-01",
        coverage: { "cyber-essentials": 0.75, "owasp-top-10": 0.5, "cis-controls-v8": 0.5, "iso-27001": 0.5, "pci-dss": 0.5, nis2: 0.5, dora: 0.5 },
      },
    ];
    render(<ComplianceTrend findings={[]} history={history} />);
    // "▲" and "25" render as adjacent text nodes inside the same span, so
    // their combined normalised text is "▲25", not two separately-matchable strings.
    expect(screen.getByText("▲25")).toBeInTheDocument();
  });

  it("shows no delta indicator when coverage hasn't changed", () => {
    const history: CompliancePoint[] = [
      {
        date: "2026-01-01",
        coverage: { "cyber-essentials": 0.5, "owasp-top-10": 0.5, "cis-controls-v8": 0.5, "iso-27001": 0.5, "pci-dss": 0.5, nis2: 0.5, dora: 0.5 },
      },
      {
        date: "2026-02-01",
        coverage: { "cyber-essentials": 0.5, "owasp-top-10": 0.5, "cis-controls-v8": 0.5, "iso-27001": 0.5, "pci-dss": 0.5, nis2: 0.5, dora: 0.5 },
      },
    ];
    render(<ComplianceTrend findings={[]} history={history} />);
    expect(screen.queryByText("▲")).not.toBeInTheDocument();
    expect(screen.queryByText("▼")).not.toBeInTheDocument();
  });
});
