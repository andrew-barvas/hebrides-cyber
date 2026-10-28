import { describe, it, expect } from "vitest";
import { parseDmarcAggregateReport } from "./dmarcAggregate";

// A realistic RFC 7489 §7.2.1.1 aggregate report (Google-style), two sources:
// one fully aligned (passes), one spoof-looking (both fail, quarantined).
const GOOGLE_REPORT = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>12345678901234567890</report_id>
    <date_range><begin>1696118400</begin><end>1696204800</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <p>quarantine</p>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>209.85.220.41</source_ip>
      <count>42</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.7</source_ip>
      <count>13</count>
      <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
  </record>
</feedback>`;

// A namespaced variant (some reporters prefix every element).
const NAMESPACED = `<ns0:feedback xmlns:ns0="http://dmarc.org/dmarc-xml/0.1">
  <ns0:report_metadata><ns0:org_name>enterprise.microsoft.com</ns0:org_name><ns0:report_id>abc-1</ns0:report_id></ns0:report_metadata>
  <ns0:policy_published><ns0:domain>acme.co.uk</ns0:domain></ns0:policy_published>
  <ns0:record><ns0:row><ns0:source_ip>40.92.1.1</ns0:source_ip><ns0:count>5</ns0:count>
    <ns0:policy_evaluated><ns0:disposition>none</ns0:disposition><ns0:dkim>pass</ns0:dkim><ns0:spf>fail</ns0:spf></ns0:policy_evaluated>
  </ns0:row></ns0:record>
</ns0:feedback>`;

describe("parseDmarcAggregateReport", () => {
  it("parses org, domain, date range and per-source rows", () => {
    const r = parseDmarcAggregateReport(GOOGLE_REPORT)!;
    expect(r).not.toBeNull();
    expect(r.orgName).toBe("google.com");
    expect(r.reportId).toBe("12345678901234567890");
    expect(r.domain).toBe("example.com");
    expect(r.dateBegin).toBe(1696118400);
    expect(r.dateEnd).toBe(1696204800);
    expect(r.rows).toHaveLength(2);
  });

  it("computes pass/fail rollups (SPF-or-DKIM pass counts as aligned)", () => {
    const r = parseDmarcAggregateReport(GOOGLE_REPORT)!;
    expect(r.totalMessages).toBe(55);
    expect(r.passingMessages).toBe(42);
    expect(r.failingMessages).toBe(13);
  });

  it("captures disposition and the header-from identifier per row", () => {
    const r = parseDmarcAggregateReport(GOOGLE_REPORT)!;
    const spoof = r.rows.find((x) => x.sourceIp === "198.51.100.7")!;
    expect(spoof.disposition).toBe("quarantine");
    expect(spoof.dkim).toBe("fail");
    expect(spoof.spf).toBe("fail");
    expect(spoof.headerFrom).toBe("example.com");
  });

  it("handles namespaced element prefixes", () => {
    const r = parseDmarcAggregateReport(NAMESPACED)!;
    expect(r.orgName).toBe("enterprise.microsoft.com");
    expect(r.domain).toBe("acme.co.uk");
    expect(r.rows).toHaveLength(1);
    expect(r.passingMessages).toBe(5); // dkim pass, spf fail -> still aligned
  });

  it("returns null for non-DMARC or empty XML (evidence discipline)", () => {
    expect(parseDmarcAggregateReport("<html><body>not a report</body></html>")).toBeNull();
    expect(parseDmarcAggregateReport("")).toBeNull();
    // feedback doc with no records is not a usable report
    expect(parseDmarcAggregateReport("<feedback><report_metadata><org_name>x</org_name></report_metadata></feedback>")).toBeNull();
    // records but no org_name
    expect(parseDmarcAggregateReport("<feedback><record><row><source_ip>1.2.3.4</source_ip><count>1</count></row></record></feedback>")).toBeNull();
  });
});
