import { describe, expect, it, vi } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import {
  MAX_BYTES,
  MAX_DOWNLOADS,
  deleteOwnerDocumentFiles,
  downloadFileName,
  downloadProblem,
  downloadUrl,
  hashDownloadToken,
  isDownloadToken,
  newDownloadToken,
  objectKey,
  parsePdfDataUrl,
  pdfHeaders,
  publicDocuments,
  type DocumentRow,
} from "./trustDocuments";
import { DOCUMENT_KINDS as CLIENT_KINDS, formatSize } from "./trustDocumentKinds";

const pdf = (body = "%PDF-1.7\n%test\n") => `data:application/pdf;base64,${Buffer.from(body, "latin1").toString("base64")}`;

describe("parsePdfDataUrl", () => {
  it("accepts a real PDF and fingerprints it", () => {
    const r = parsePdfDataUrl(pdf());
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.bytes.subarray(0, 5).toString("latin1")).toBe("%PDF-");
      expect(r.sha256).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("refuses anything that isn't a PDF, by type or by its bytes", () => {
    expect(parsePdfDataUrl(`data:text/html;base64,${Buffer.from("<script>").toString("base64")}`)).toEqual({ ok: false, error: "Upload a PDF file." });
    expect(parsePdfDataUrl(pdf("<html><script>alert(1)</script>"))).toEqual({ ok: false, error: "That file isn't a PDF." });
    expect(parsePdfDataUrl("data:application/pdf;base64,")).toMatchObject({ ok: false });
  });

  it("refuses a file over 5 MB", () => {
    const big = `data:application/pdf;base64,${Buffer.concat([Buffer.from("%PDF-"), Buffer.alloc(MAX_BYTES)]).toString("base64")}`;
    expect(parsePdfDataUrl(big)).toEqual({ ok: false, error: "That file is over 5 MB. Upload a smaller PDF." });
  });
});

describe("names and tokens", () => {
  it("stores files under the owner and site", () => {
    expect(objectKey("o1", "shop.example.com", "d1")).toBe("o1/shop.example.com/d1.pdf");
  });

  it("makes a safe download filename, never empty and never with quotes or paths", () => {
    expect(downloadFileName("Cyber Essentials 2026 (signed)")).toBe("Cyber-Essentials-2026-signed.pdf");
    expect(downloadFileName('../../etc/"passwd"')).toBe("etc-passwd.pdf");
    expect(downloadFileName("证书")).toBe("document.pdf");
  });

  it("issues 43-character tokens and keeps only their hash", () => {
    const { token, hash } = newDownloadToken();
    expect(isDownloadToken(token)).toBe(true);
    expect(hashDownloadToken(token)).toBe(hash);
    expect(isDownloadToken("nope")).toBe(false);
    expect(downloadUrl(token, "https://www.hebridescyber.co.uk/")).toBe(`https://www.hebridescyber.co.uk/api/trust-download?token=${token}`);
  });
});

describe("downloadProblem", () => {
  const now = new Date("2026-11-20T12:00:00Z");
  const ok = { status: "approved" as const, expires_at: "2026-11-25T00:00:00Z", download_count: 0 };
  it("allows an approved, unexpired link with downloads left", () => {
    expect(downloadProblem(ok, now)).toBeNull();
  });
  it("refuses pending, declined, expired and used-up links", () => {
    expect(downloadProblem({ ...ok, status: "pending" }, now)).toMatch(/isn't valid/);
    expect(downloadProblem({ ...ok, status: "declined" }, now)).toMatch(/isn't valid/);
    expect(downloadProblem({ ...ok, expires_at: "2026-11-20T11:59:59Z" }, now)).toMatch(/expired/);
    expect(downloadProblem({ ...ok, download_count: MAX_DOWNLOADS }, now)).toMatch(/maximum/);
    expect(downloadProblem(null, now)).toMatch(/isn't valid/);
  });
});

describe("publicDocuments", () => {
  const row = (id: string, kind: DocumentRow["kind"], extra: Partial<DocumentRow> = {}): DocumentRow => ({
    id, owner: "o1", target_host: "a.example", title: id, kind, visibility: "public", object_key: `k/${id}`, size_bytes: 2048, uploaded_at: "2026-11-01T00:00:00Z", deleted_at: null, ...extra,
  });
  it("orders by kind, drops deleted ones, and exposes no owner or storage key", () => {
    const out = publicDocuments([row("p", "policy"), row("ce", "cyber_essentials"), row("gone", "insurance", { deleted_at: "2026-11-02T00:00:00Z" })]);
    expect(out.map((d) => [d.id, d.kindLabel])).toEqual([
      ["ce", "Cyber Essentials certificate"],
      ["p", "Security policy"],
    ]);
    expect(JSON.stringify(out)).not.toMatch(/o1|k\//);
  });
  it("keeps the client-safe kind list identical to the server's", async () => {
    const server = await import("./trustDocuments");
    expect(server.DOCUMENT_KINDS).toEqual(CLIENT_KINDS);
  });
});

describe("pdfHeaders and formatSize", () => {
  it("always serves an attachment that browsers won't sniff or cache publicly", () => {
    expect(pdfHeaders("CE cert", 10)).toMatchObject({ "Content-Type": "application/pdf", "Content-Disposition": 'attachment; filename="CE-cert.pdf"', "X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store" });
    expect(formatSize(2048)).toBe("2 KB");
    expect(formatSize(3 * 1024 * 1024)).toBe("3.0 MB");
  });
});

describe("deleteOwnerDocumentFiles", () => {
  const db = (rows: unknown[], removeError: unknown = null) => {
    const remove = vi.fn().mockResolvedValue({ error: removeError });
    const client = {
      from: () => ({ select: () => ({ eq: async () => ({ data: rows, error: null }) }) }),
      storage: { from: () => ({ remove }) },
    } as unknown as SupabaseClient;
    return { client, remove };
  };
  it("removes every file the owner stored and counts them", async () => {
    const { client, remove } = db([{ object_key: "o1/a/1.pdf" }, { object_key: "o1/a/2.pdf" }]);
    expect(await deleteOwnerDocumentFiles(client, "o1")).toBe(2);
    expect(remove).toHaveBeenCalledWith(["o1/a/1.pdf", "o1/a/2.pdf"]);
  });
  it("throws on a storage error so the erasure stops and can be retried", async () => {
    const { client } = db([{ object_key: "x" }], { message: "down" });
    await expect(deleteOwnerDocumentFiles(client, "o1")).rejects.toThrow("down");
  });
});

describe("loaders that must never break the profile or block erasure on a missing table", () => {
  it("loadSiteDocuments is empty on an error or a throw", async () => {
    const { loadSiteDocuments } = await import("./trustDocuments");
    const chain = (result: unknown) => {
      const q: Record<string, unknown> = {};
      for (const m of ["select", "eq", "is"]) q[m] = () => q;
      q.order = result instanceof Error ? () => { throw result; } : async () => result;
      return { from: () => q } as unknown as SupabaseClient;
    };
    expect(await loadSiteDocuments(chain({ data: null, error: { message: "x" } }), "o1", "a.example")).toEqual([]);
    expect(await loadSiteDocuments(chain(new Error("boom")), "o1", "a.example")).toEqual([]);
  });

  it("deleteOwnerDocumentFiles treats a missing table as nothing to delete, and throws on other errors", async () => {
    const db = (message: string) => ({ from: () => ({ select: () => ({ eq: async () => ({ data: null, error: { message } }) }) }) }) as unknown as SupabaseClient;
    expect(await deleteOwnerDocumentFiles(db('relation "trust_documents" does not exist'), "o1")).toBe(0);
    await expect(deleteOwnerDocumentFiles(db("permission denied"), "o1")).rejects.toThrow("permission denied");
  });
});
