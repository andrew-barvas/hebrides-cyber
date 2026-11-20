// Documents on the public security profile (migration 087,
// COMPETITOR-ANALYSIS-ENTERPRISE-2026-11.md idea 14): a small trust centre.
// UpGuard's Trust Exchange and Vanta's Trust Center are the pattern; ours
// sits on the profile a customer already publishes.
//
// Safety rules:
//   - PDFs only: the data URL must say application/pdf AND the bytes must
//     start with "%PDF-"; at most MAX_BYTES; MAX_DOCS_PER_SITE per site.
//   - Files are only ever served through the API, as an attachment with
//     nosniff, never inline, so a hostile file can't run on our origin.
//   - An on-request document is released only by the owner's approval, by a
//     link that works for DOWNLOAD_TTL_DAYS and MAX_DOWNLOADS downloads; only
//     the link token's SHA-256 is stored.
//   - Public endpoints answer the same "not available" for every missing,
//     deleted or unpublished document, so nothing about a profile leaks.
import { createHash, randomBytes } from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import { supabaseObjectStore, type ObjectStore } from "./objectStore";
import { DOCUMENT_KINDS, KIND_LABELS, type DocumentKind } from "./trustDocumentKinds";

export const TRUST_BUCKET = "trust-documents";
export const MAX_BYTES = 5 * 1024 * 1024;
export const MAX_DOCS_PER_SITE = 10;
export const DOWNLOAD_TTL_DAYS = 7;
export const MAX_DOWNLOADS = 5;
export const MAX_PENDING_PER_DOCUMENT = 25;

export { DOCUMENT_KINDS, KIND_LABELS, formatSize, type DocumentKind } from "./trustDocumentKinds";

export type Visibility = "public" | "on_request";

export type DocumentRow = {
  id: string;
  owner: string;
  target_host: string;
  title: string;
  kind: DocumentKind;
  visibility: Visibility;
  object_key: string;
  size_bytes: number;
  uploaded_at: string;
  deleted_at: string | null;
};

export type RequestRow = {
  id: string;
  document_id: string;
  requester_name: string;
  requester_email: string;
  requester_company: string;
  reason: string;
  status: "pending" | "approved" | "declined";
  created_at: string;
  decided_at: string | null;
  expires_at: string | null;
  download_count: number;
};

export type PublicDocument = { id: string; title: string; kind: DocumentKind; kindLabel: string; visibility: Visibility; sizeBytes: number; uploadedAt: string };

export const NOT_AVAILABLE = "This document isn't available.";

export type PdfParse = { ok: true; bytes: Buffer; sha256: string } | { ok: false; error: string };

/** Pure. A base64 PDF data URL to bytes, or why it was refused. */
export function parsePdfDataUrl(dataUrl: string): PdfParse {
  const match = /^data:application\/pdf;base64,([A-Za-z0-9+/=\s]+)$/.exec(dataUrl);
  if (!match) return { ok: false, error: "Upload a PDF file." };
  const bytes = Buffer.from(match[1].replace(/\s/g, ""), "base64");
  if (bytes.length === 0) return { ok: false, error: "That file is empty." };
  if (bytes.length > MAX_BYTES) return { ok: false, error: "That file is over 5 MB. Upload a smaller PDF." };
  if (bytes.subarray(0, 5).toString("latin1") !== "%PDF-") return { ok: false, error: "That file isn't a PDF." };
  return { ok: true, bytes, sha256: createHash("sha256").update(bytes).digest("hex") };
}

export function objectKey(owner: string, host: string, id: string): string {
  return `${owner}/${host}/${id}.pdf`;
}

/** Pure. A filename safe for Content-Disposition: ASCII letters, digits, hyphens; never empty. */
export function downloadFileName(title: string): string {
  const base = title
    .normalize("NFKD")
    .replace(/[^\x20-\x7e]/g, "")
    .replace(/[^A-Za-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return `${base || "document"}.pdf`;
}

export function newDownloadToken(): { token: string; hash: string } {
  const token = randomBytes(32).toString("base64url");
  return { token, hash: hashDownloadToken(token) };
}

export function hashDownloadToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function isDownloadToken(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

export function downloadUrl(token: string, siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk"): string {
  return `${siteUrl.replace(/\/$/, "")}/api/trust-download?token=${token}`;
}

/** Pure. Why an approved link can't be used, or null when it can. */
export function downloadProblem(req: Pick<RequestRow, "status" | "expires_at" | "download_count"> | null, now: Date): string | null {
  if (!req || req.status !== "approved" || !req.expires_at) return "This download link isn't valid. Ask the site's owner again.";
  if (Date.parse(req.expires_at) <= now.getTime()) return "This download link has expired. Ask the site's owner again.";
  if (req.download_count >= MAX_DOWNLOADS) return "This download link has been used the maximum number of times. Ask the site's owner again.";
  return null;
}

/** Pure. What a profile visitor may see of each live document. */
export function publicDocuments(rows: readonly DocumentRow[]): PublicDocument[] {
  return rows
    .filter((r) => !r.deleted_at)
    .sort((a, b) => DOCUMENT_KINDS.indexOf(a.kind) - DOCUMENT_KINDS.indexOf(b.kind) || a.title.localeCompare(b.title))
    .map((r) => ({ id: r.id, title: r.title, kind: r.kind, kindLabel: KIND_LABELS[r.kind] ?? "Document", visibility: r.visibility, sizeBytes: r.size_bytes, uploadedAt: r.uploaded_at }));
}

export function trustStore(db: SupabaseClient): ObjectStore {
  return supabaseObjectStore(db, TRUST_BUCKET);
}

const DOC_SELECT = "id, owner, target_host, title, kind, visibility, object_key, size_bytes, uploaded_at, deleted_at";

/** A site's live documents. Empty on a read failure: the profile still renders. */
export async function loadSiteDocuments(db: SupabaseClient, owner: string, host: string): Promise<DocumentRow[]> {
  try {
    const { data, error } = await db.from("trust_documents").select(DOC_SELECT).eq("owner", owner).eq("target_host", host).is("deleted_at", null).order("uploaded_at", { ascending: true });
    return error ? [] : ((data ?? []) as DocumentRow[]);
  } catch {
    return [];
  }
}

/** One live document on a published profile, or null. Throws on a read error. */
export async function loadProfileDocument(db: SupabaseClient, profile: { owner: string; target_host: string }, id: string): Promise<DocumentRow | null> {
  if (!/^[0-9a-f-]{36}$/i.test(id)) return null;
  const { data, error } = await db.from("trust_documents").select(DOC_SELECT).eq("id", id).eq("owner", profile.owner).eq("target_host", profile.target_host).is("deleted_at", null).maybeSingle();
  if (error) throw new Error(error.message);
  return (data as DocumentRow | null) ?? null;
}

/** Response headers for serving a stored PDF: always an attachment, never sniffed or cached publicly. */
export function pdfHeaders(title: string, size: number): Record<string, string> {
  return {
    "Content-Type": "application/pdf",
    "Content-Disposition": `attachment; filename="${downloadFileName(title)}"`,
    "Content-Length": String(size),
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "private, no-store",
    "X-Robots-Tag": "noindex",
  };
}

/** Account erasure: deletes every profile document file the owner ever stored. Throws on a storage error so the erasure stops and can be retried. */
export async function deleteOwnerDocumentFiles(db: SupabaseClient, owner: string): Promise<number> {
  const { data, error } = await db.from("trust_documents").select("object_key").eq("owner", owner);
  if (error) {
    if (/does not exist|schema cache/i.test(error.message)) return 0;
    throw new Error(`could not list profile documents: ${error.message}`);
  }
  const keys = ((data ?? []) as Array<{ object_key: string }>).map((r) => r.object_key);
  for (let i = 0; i < keys.length; i += 100) {
    const { error: removeError } = await db.storage.from(TRUST_BUCKET).remove(keys.slice(i, i + 100));
    if (removeError) throw new Error(`could not delete profile documents: ${removeError.message}`);
  }
  return keys.length;
}
