import { describe, it, expect } from "vitest";
import { PDFDocument, StandardFonts } from "pdf-lib";
import { renderEvidencePackPdf, toWinAnsi } from "./evidencePackPdf";
import { ceReadinessFromRows, insuranceAnswers, type EvidencePack } from "./evidencePack";
import type { FindingRow } from "./findingsView";

async function helvetica() {
  const doc = await PDFDocument.create();
  return doc.embedFont(StandardFonts.Helvetica);
}

function emptyPack(): EvidencePack {
  return {
    company: null,
    generatedAt: "2026-11-20T10:00:00Z",
    sites: [],
    ce: ceReadinessFromRows([], []),
    insurance: insuranceAnswers({ rows: [], scannedSites: [], m365Checked: null, workspaceChecked: null, answers: [] }),
    fixFirst: [],
  };
}

describe("toWinAnsi", () => {
  it("keeps what the standard font encodes and spells out or replaces the rest", async () => {
    const font = await helvetica();
    expect(toWinAnsi("Café — “quoted” £5 · ok", font)).toBe("Café — “quoted” £5 · ok");
    expect(toWinAnsi("a → b ≥ c ✓", font)).toBe("a -> b >= c Yes");
    expect(toWinAnsi("Łódź", font)).toBe("Lódz");
    expect(toWinAnsi("Ω", font)).toBe("?");
    expect(toWinAnsi("rocket 🚀 漢", font)).toBe("rocket ? ?");
    expect(toWinAnsi("  line one\n\tline two  ", font)).toBe("line one line two");
    // Everything it returns can be drawn.
    expect(() => font.encodeText(toWinAnsi("Ω ∑ 🚀 Łódź → ✓", font))).not.toThrow();
  });
});

describe("renderEvidencePackPdf", () => {
  it("renders a pack for an account with nothing scanned or answered", async () => {
    const doc = await PDFDocument.load(await renderEvidencePackPdf(emptyPack()));
    expect(doc.getPageCount()).toBeGreaterThanOrEqual(1);
    expect(doc.getAuthor()).toBe("Hebrides Cyber");
  });

  it("runs onto more pages for a long pack, and survives text it can't wrap or encode", async () => {
    const rows = Array.from({ length: 60 }, (_, i) => ({
      key: `h${i}.example.com dns.spf-missing`,
      host: `h${i}.example.com`,
      checkId: "dns.spf-missing",
      checkBase: "dns.spf-missing",
      category: "dns",
      severity: "high",
      title: `SPF record missing ${"x".repeat(i === 0 ? 400 : 10)} 🚀`,
      detail: null,
      firstSeenAt: "2026-11-19T09:00:00Z",
      ageDays: 1,
    })) as unknown as FindingRow[];
    const sites = rows.map((r) => ({ host: r.host, lastScanAt: "2026-11-19T09:00:00Z" }));
    const pack: EvidencePack = {
      ...emptyPack(),
      company: "Ünïcode Ltd 漢字",
      sites,
      ce: ceReadinessFromRows(rows, [{ questionKey: "malware.protection", answer: "yes", note: null }]),
      insurance: insuranceAnswers({ rows, scannedSites: sites, m365Checked: "2026-11-18T00:00:00Z", workspaceChecked: null, answers: [] }),
      fixFirst: rows.map((r) => ({ ...r, priority: { score: 1, reasons: [] } })) as unknown as EvidencePack["fixFirst"],
    };
    const doc = await PDFDocument.load(await renderEvidencePackPdf(pack));
    expect(doc.getPageCount()).toBeGreaterThan(1);
  });
});
