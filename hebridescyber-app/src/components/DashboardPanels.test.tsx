import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { WafIndicator, CmsStatusPanel, TechStackPanel, OsintSummaryPanel } from "./DashboardPanels";
import type { DetectedTech } from "@/lib/scanners/fingerprint";

// Regression coverage for the 2026-09-19 Dashboard crash: results.fingerprint.
// technologies is really DetectedTech[] (full objects — see
// src/lib/scanners/index.ts:39,210 and fingerprint.ts's DetectedTech type),
// not string[]. TechStackPanel rendered the raw object directly ({tech}
// instead of {tech.name}), which throws "Objects are not valid as a React
// child" (React error #31) the moment any scan with detected technologies
// loaded on the Dashboard — i.e. almost every account, since fingerprinting
// is part of the always-on base passive suite. Nothing caught this because
// the call site in dashboard/page.tsx force-casts a loosely-typed
// Record<string, unknown> into each panel's props (`as Parameters<...>`),
// bypassing structural type-checking entirely, and this component had zero
// test coverage before this file.
describe("TechStackPanel", () => {
  const techs: DetectedTech[] = [
    { name: "Nginx", category: "Web server", version: "1.25.2", confidence: "high", source: "header" },
    { name: "WordPress", category: "CMS", version: null, confidence: "medium", source: "html" },
  ];

  it("renders each technology's name (and version), not the raw object", () => {
    render(<TechStackPanel results={{ fingerprint: { status: "checked", technologies: techs } }} />);
    expect(screen.getByText("Nginx 1.25.2")).toBeInTheDocument();
    expect(screen.getByText("WordPress")).toBeInTheDocument();
  });

  it("renders nothing when there are no detected technologies", () => {
    const { container } = render(<TechStackPanel results={{ fingerprint: { status: "checked", technologies: [] } }} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing when fingerprint is missing entirely", () => {
    const { container } = render(<TechStackPanel results={{}} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("WafIndicator", () => {
  it("renders nothing when whatwaf hasn't completed", () => {
    const { container } = render(<WafIndicator results={{ extended: { whatwaf: { status: "not_configured" } } }} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the detected WAF name and what WhatWaf reported, with no invented confidence", () => {
    render(
      <WafIndicator
        results={{ extended: { whatwaf: { status: "completed", waf: "Cloudflare", vendor: "Cloudflare Inc.", evidence: "WhatWaf identified the firewall as Cloudflare." } } }}
      />
    );
    expect(screen.getByText("Cloudflare")).toBeInTheDocument();
    expect(screen.getByText("WhatWaf identified the firewall as Cloudflare.")).toBeInTheDocument();
    expect(screen.queryByText(/Confidence/)).not.toBeInTheDocument();
  });

  it("renders nothing when whatwaf errored, rather than 'No WAF detected'", () => {
    const { container } = render(<WafIndicator results={{ extended: { whatwaf: { status: "error" } } }} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows 'No WAF detected' with its evidence when WhatWaf reported none", () => {
    render(
      <WafIndicator
        results={{ extended: { whatwaf: { status: "completed", waf: null, vendor: null, evidence: "WhatWaf reported is_protected: false." } } }}
      />
    );
    expect(screen.getByText("No WAF detected")).toBeInTheDocument();
    expect(screen.getByText("WhatWaf reported is_protected: false.")).toBeInTheDocument();
  });
});

describe("CmsStatusPanel", () => {
  it("renders nothing when neither cmsmap nor wpscan has data", () => {
    const { container } = render(<CmsStatusPanel results={{}} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the detected CMS type and finding count", () => {
    render(
      <CmsStatusPanel
        results={{
          extended: {
            cmsmap: { status: "completed", cmsType: "WordPress", findings: [{ type: "vulnerability", detail: "x" }] },
          },
        }}
      />
    );
    expect(screen.getByText("WordPress")).toBeInTheDocument();
    expect(screen.getByText("1 issues")).toBeInTheDocument();
  });
});

describe("OsintSummaryPanel", () => {
  it("renders nothing when no OSINT sources have data", () => {
    const { container } = render(<OsintSummaryPanel results={{}} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("summarises photon and gospider findings into stat tiles", () => {
    render(
      <OsintSummaryPanel
        results={{
          extended: {
            photon: { status: "completed", assets: [{ type: "email", value: "a@example.com" }] },
            gospider: { status: "completed", endpoints: [{ type: "url", value: "https://example.com/x", source: "crawl" }] },
          },
        }}
      />
    );
    expect(screen.getByText("Emails found")).toBeInTheDocument();
    expect(screen.getByText("URLs crawled")).toBeInTheDocument();
  });
});
