// Metadata leak detection — checks publicly accessible documents
// and images for information leakage via metadata (author names,
// internal paths, software versions, GPS coordinates, email addresses).
//
// Parses PDF, Office, and image file metadata from URLs discovered
// during the crawl phase. No external binary needed — node:zlib plus
// byte-level parsing:
// - every file: regex pass over the raw bytes (catches uncompressed text)
// - Office Open XML / OpenDocument: these are zip archives, so the
//   metadata parts (docProps/*.xml, meta.xml) are inflated and read
// - PDF: Info dictionary strings (incl. UTF-16), XMP packets, and
//   FlateDecode metadata/object streams (PDF 1.5+ hides Info in these)
// - JPEG/TIFF: EXIF IFD0 (Artist, Software, XPAuthor) and the GPS IFD

import { inflateRawSync, inflateSync } from "node:zlib";

export type MetadataFinding = {
  url: string;
  type: "author" | "path" | "software" | "email" | "gps" | "internal-ip";
  value: string;
};

export type MetadataLeakResult =
  | { status: "completed"; findings: MetadataFinding[] }
  | { status: "error"; note: string };

const DOCUMENT_EXTENSIONS = /\.(pdf|docx?|xlsx?|pptx?|odt|ods|odp)$/i;
const IMAGE_EXTENSIONS = /\.(jpe?g|tiff?)$/i;
const MAX_FILES_TO_CHECK = 20;
const FETCH_TIMEOUT_MS = 10_000;
// The body is downloaded in full either way; this caps how much is parsed.
// Large enough to hold a typical Office file whole, since its zip central
// directory (and often docProps) sits at the end.
const MAX_BYTES = 4 * 1024 * 1024;
// Ceiling on any single inflated part, so a crafted file can't zip-bomb the worker.
const MAX_INFLATED_BYTES = 1024 * 1024;
const MAX_PDF_STREAMS = 50;
const MAX_VALUE_LENGTH = 120;

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const INTERNAL_IP_RE = /(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/g;
const WINDOWS_PATH_RE = /[A-Z]:\\(?:Users|Documents|Desktop|home|builds?)[^\x00"<>|]{5,80}/gi;
const UNIX_PATH_RE = /\/(?:home|Users|var|opt|builds?|srv)\/[a-zA-Z0-9._/-]{5,80}/g;

function clean(value: string): string {
  return value.replace(/[\x00-\x1f]/g, "").trim().slice(0, MAX_VALUE_LENGTH);
}

function extractTextMetadata(buf: Buffer, url: string): MetadataFinding[] {
  const findings: MetadataFinding[] = [];
  const text = buf.toString("latin1");

  for (const match of text.matchAll(EMAIL_RE)) {
    findings.push({ url, type: "email", value: match[0] });
  }

  for (const match of text.matchAll(INTERNAL_IP_RE)) {
    findings.push({ url, type: "internal-ip", value: match[0] });
  }

  for (const match of text.matchAll(WINDOWS_PATH_RE)) {
    findings.push({ url, type: "path", value: match[0] });
  }

  for (const match of text.matchAll(UNIX_PATH_RE)) {
    if (match[0].includes("/node_modules/") || match[0].includes("/dist/")) continue;
    findings.push({ url, type: "path", value: match[0] });
  }

  // PDF Info dictionary: literal "(...)" or hex "<...>" strings
  const infoKeys: Array<[string, MetadataFinding["type"]]> = [
    ["Author", "author"],
    ["Creator", "software"],
    ["Producer", "software"],
  ];
  for (const [key, type] of infoKeys) {
    const literal = text.match(new RegExp(`/${key}\\s*\\(((?:\\\\.|[^\\\\)]){2,200})\\)`));
    const hex = text.match(new RegExp(`/${key}\\s*<([0-9A-Fa-f\\s]{4,400})>`));
    const raw = literal ? decodePdfLiteral(literal[1]) : hex ? decodePdfHex(hex[1]) : null;
    const value = raw ? clean(raw) : "";
    if (value.length >= 2) findings.push({ url, type, value });
  }

  // XMP packet (PDF, and sometimes embedded in images)
  const xmpCreator = text.match(/<dc:creator>[\s\S]{0,200}?<rdf:li[^>]*>([^<]{2,200})<\/rdf:li>/);
  if (xmpCreator) findings.push({ url, type: "author", value: clean(decodeXml(xmpCreator[1])) });
  for (const tag of ["xmp:CreatorTool", "pdf:Producer"]) {
    const m = text.match(new RegExp(`<${tag}>([^<]{2,200})</${tag}>`)) ??
      text.match(new RegExp(`${tag}="([^"]{2,200})"`));
    if (m) findings.push({ url, type: "software", value: clean(decodeXml(m[1])) });
  }

  return findings;
}

// --- PDF strings ---

function decodeUtf16(bytes: Buffer, littleEndian: boolean): string {
  let out = "";
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    out += String.fromCharCode(littleEndian ? bytes.readUInt16LE(i) : bytes.readUInt16BE(i));
  }
  return out;
}

function decodePdfBytes(bytes: Buffer): string {
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    return decodeUtf16(bytes.subarray(2), false);
  }
  return bytes.toString("latin1");
}

function decodePdfLiteral(s: string): string {
  const unescaped = s.replace(/\\([nrtbf()\\]|[0-7]{1,3})/g, (_, e: string) => {
    if (/^[0-7]+$/.test(e)) return String.fromCharCode(parseInt(e, 8) & 0xff);
    return ({ n: "\n", r: "\r", t: "\t", b: "\b", f: "\f" } as Record<string, string>)[e] ?? e;
  });
  return decodePdfBytes(Buffer.from(unescaped, "latin1"));
}

function decodePdfHex(s: string): string {
  const hex = s.replace(/\s/g, "");
  return decodePdfBytes(Buffer.from(hex.length % 2 ? hex + "0" : hex, "hex"));
}

// Inflates FlateDecode streams that can hold metadata: XMP (/Type /Metadata)
// and object streams (/Type /ObjStm), where PDF 1.5+ writers put the Info dict.
function inflatePdfMetadataStreams(buf: Buffer): Buffer[] {
  const text = buf.toString("latin1");
  const out: Buffer[] = [];
  const streamRe = /<<((?:(?!>>\s*stream)[\s\S]){0,2000})>>\s*stream\r?\n/g;
  let match: RegExpExecArray | null;
  while ((match = streamRe.exec(text)) && out.length < MAX_PDF_STREAMS) {
    const dict = match[1];
    if (!/\/FlateDecode/.test(dict) || !/\/Type\s*\/(?:ObjStm|Metadata)/.test(dict)) continue;
    const start = match.index + match[0].length;
    const end = text.indexOf("endstream", start);
    if (end === -1) break;
    try {
      out.push(inflateSync(buf.subarray(start, end), { maxOutputLength: MAX_INFLATED_BYTES }));
    } catch {
      // Truncated or non-zlib stream; the raw-bytes pass still ran
    }
    streamRe.lastIndex = end;
  }
  return out;
}

// --- Office Open XML / OpenDocument (zip) ---

const ZIP_METADATA_PARTS = new Set([
  "docProps/core.xml",
  "docProps/app.xml",
  "docProps/custom.xml",
  "meta.xml",
]);

type ZipEntry = { name: string; method: number; compressedSize: number; dataOffset: number };

function localDataOffset(buf: Buffer, headerOffset: number): number | null {
  if (headerOffset + 30 > buf.length || buf.readUInt32LE(headerOffset) !== 0x04034b50) return null;
  return headerOffset + 30 + buf.readUInt16LE(headerOffset + 26) + buf.readUInt16LE(headerOffset + 28);
}

// Prefers the central directory (authoritative sizes); falls back to walking
// local headers when the file was cut off before the central directory.
function listZipEntries(buf: Buffer): ZipEntry[] {
  const entries: ZipEntry[] = [];
  const eocd = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (eocd !== -1 && eocd + 22 <= buf.length) {
    const count = buf.readUInt16LE(eocd + 10);
    let p = buf.readUInt32LE(eocd + 16);
    for (let i = 0; i < count && p + 46 <= buf.length; i++) {
      if (buf.readUInt32LE(p) !== 0x02014b50) break;
      const nameLen = buf.readUInt16LE(p + 28);
      const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
      const dataOffset = localDataOffset(buf, buf.readUInt32LE(p + 42));
      if (dataOffset !== null) {
        entries.push({ name, method: buf.readUInt16LE(p + 10), compressedSize: buf.readUInt32LE(p + 20), dataOffset });
      }
      p += 46 + nameLen + buf.readUInt16LE(p + 30) + buf.readUInt16LE(p + 32);
    }
    if (entries.length > 0) return entries;
  }

  let p = 0;
  while (p + 30 <= buf.length && buf.readUInt32LE(p) === 0x04034b50) {
    const flags = buf.readUInt16LE(p + 6);
    const compressedSize = buf.readUInt32LE(p + 18);
    const nameLen = buf.readUInt16LE(p + 26);
    const name = buf.toString("utf8", p + 30, p + 30 + nameLen);
    const dataOffset = p + 30 + nameLen + buf.readUInt16LE(p + 28);
    // Bit 3: sizes live in a trailing data descriptor, so the next header can't be found
    if (flags & 0x08) break;
    entries.push({ name, method: buf.readUInt16LE(p + 8), compressedSize, dataOffset });
    p = dataOffset + compressedSize;
  }
  return entries;
}

function decodeXml(s: string): string {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, d: string) => String.fromCharCode(Number(d)))
    .replace(/&amp;/g, "&");
}

function xmlValues(xml: string, tags: string[]): string[] {
  const values: string[] = [];
  for (const tag of tags) {
    for (const m of xml.matchAll(new RegExp(`<${tag}(?:\\s[^>]*)?>([^<]+)</${tag}>`, "g"))) {
      const value = clean(decodeXml(m[1]));
      if (value.length >= 2) values.push(value);
    }
  }
  return values;
}

function extractZipMetadata(buf: Buffer, url: string): MetadataFinding[] {
  const findings: MetadataFinding[] = [];
  for (const entry of listZipEntries(buf)) {
    if (!ZIP_METADATA_PARTS.has(entry.name)) continue;
    const data = buf.subarray(entry.dataOffset, entry.dataOffset + entry.compressedSize);
    let xmlBuf: Buffer;
    try {
      if (entry.method === 0) xmlBuf = data;
      else if (entry.method === 8) xmlBuf = inflateRawSync(data, { maxOutputLength: MAX_INFLATED_BYTES });
      else continue;
    } catch {
      continue;
    }
    const xml = xmlBuf.toString("utf8");

    for (const value of xmlValues(xml, ["dc:creator", "cp:lastModifiedBy", "meta:initial-creator"])) {
      findings.push({ url, type: "author", value });
    }
    const app = xmlValues(xml, ["Application"])[0];
    const appVersion = xmlValues(xml, ["AppVersion"])[0];
    if (app) findings.push({ url, type: "software", value: appVersion ? `${app} ${appVersion}` : app });
    for (const value of xmlValues(xml, ["meta:generator"])) {
      findings.push({ url, type: "software", value });
    }
    // Template paths, custom properties holding emails or hostnames, etc.
    findings.push(...extractTextMetadata(Buffer.from(decodeXml(xml), "utf8"), url));
  }
  return findings;
}

// --- EXIF (JPEG APP1 / TIFF) ---

const TIFF_TYPE_SIZES: Record<number, number> = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };

type IfdEntry = { tag: number; type: number; count: number; valueOffset: number };

function readIfd(tiff: Buffer, offset: number, le: boolean): IfdEntry[] {
  if (offset < 8 || offset + 2 > tiff.length) return [];
  const u16 = (o: number) => (le ? tiff.readUInt16LE(o) : tiff.readUInt16BE(o));
  const u32 = (o: number) => (le ? tiff.readUInt32LE(o) : tiff.readUInt32BE(o));
  const count = Math.min(u16(offset), 512);
  const entries: IfdEntry[] = [];
  for (let i = 0; i < count; i++) {
    const p = offset + 2 + i * 12;
    if (p + 12 > tiff.length) break;
    const type = u16(p + 2);
    const n = u32(p + 4);
    const size = (TIFF_TYPE_SIZES[type] ?? 1) * n;
    // Values of 4 bytes or fewer are stored inline in the entry
    entries.push({ tag: u16(p), type, count: n, valueOffset: size <= 4 ? p + 8 : u32(p + 8) });
  }
  return entries;
}

function readExifString(tiff: Buffer, e: IfdEntry): string {
  if (e.valueOffset + e.count > tiff.length) return "";
  return tiff.toString("latin1", e.valueOffset, e.valueOffset + e.count);
}

function readRationals(tiff: Buffer, e: IfdEntry, le: boolean): number[] | null {
  if (e.type !== 5 || e.count !== 3 || e.valueOffset + 24 > tiff.length) return null;
  const u32 = (o: number) => (le ? tiff.readUInt32LE(o) : tiff.readUInt32BE(o));
  const out: number[] = [];
  for (let i = 0; i < 3; i++) {
    const den = u32(e.valueOffset + i * 8 + 4);
    if (den === 0) return null;
    out.push(u32(e.valueOffset + i * 8) / den);
  }
  return out;
}

function extractTiffMetadata(tiff: Buffer, url: string): MetadataFinding[] {
  if (tiff.length < 8) return [];
  const order = tiff.toString("latin1", 0, 2);
  if (order !== "II" && order !== "MM") return [];
  const le = order === "II";
  const ifd0Offset = le ? tiff.readUInt32LE(4) : tiff.readUInt32BE(4);
  const findings: MetadataFinding[] = [];
  let gpsOffset = 0;

  for (const e of readIfd(tiff, ifd0Offset, le)) {
    if (e.tag === 0x013b && e.type === 2) {
      const value = clean(readExifString(tiff, e));
      if (value.length >= 2) findings.push({ url, type: "author", value });
    } else if (e.tag === 0x0131 && e.type === 2) {
      const value = clean(readExifString(tiff, e));
      if (value.length >= 2) findings.push({ url, type: "software", value });
    } else if (e.tag === 0x9c9d && e.valueOffset + e.count <= tiff.length) {
      // XPAuthor: UTF-16LE bytes, written by Windows Explorer
      const value = clean(decodeUtf16(tiff.subarray(e.valueOffset, e.valueOffset + e.count), true));
      if (value.length >= 2) findings.push({ url, type: "author", value });
    } else if (e.tag === 0x8825) {
      gpsOffset = e.valueOffset + 4 <= tiff.length
        ? (le ? tiff.readUInt32LE(e.valueOffset) : tiff.readUInt32BE(e.valueOffset))
        : 0;
    }
  }

  if (gpsOffset) {
    const gps = new Map(readIfd(tiff, gpsOffset, le).map((e) => [e.tag, e]));
    const lat = gps.get(0x02) && readRationals(tiff, gps.get(0x02)!, le);
    const lon = gps.get(0x04) && readRationals(tiff, gps.get(0x04)!, le);
    if (lat && lon) {
      const toDeg = ([d, m, s]: number[]) => d + m / 60 + s / 3600;
      const latRef = gps.get(0x01) ? readExifString(tiff, gps.get(0x01)!)[0] : "N";
      const lonRef = gps.get(0x03) ? readExifString(tiff, gps.get(0x03)!)[0] : "E";
      const latDeg = toDeg(lat) * (latRef === "S" ? -1 : 1);
      const lonDeg = toDeg(lon) * (lonRef === "W" ? -1 : 1);
      // 0,0 is what some cameras write when they have no fix
      if (latDeg !== 0 || lonDeg !== 0) {
        findings.push({ url, type: "gps", value: `${latDeg.toFixed(5)}, ${lonDeg.toFixed(5)}` });
      }
    }
  }
  return findings;
}

function extractJpegExif(buf: Buffer, url: string): MetadataFinding[] {
  let p = 2;
  while (p + 4 <= buf.length && buf[p] === 0xff) {
    const marker = buf[p + 1];
    if (marker === 0xda || marker === 0xd9) break; // image data / end: no more metadata
    const len = buf.readUInt16BE(p + 2);
    if (marker === 0xe1 && buf.toString("latin1", p + 4, p + 10) === "Exif\0\0") {
      return extractTiffMetadata(buf.subarray(p + 10, p + 2 + len), url);
    }
    p += 2 + len;
  }
  return [];
}

function extractMetadata(buf: Buffer, url: string): MetadataFinding[] {
  const findings = extractTextMetadata(buf, url);
  if (buf.readUInt32LE(0) === 0x04034b50) {
    findings.push(...extractZipMetadata(buf, url));
  } else if (buf.toString("latin1", 0, 5) === "%PDF-") {
    for (const stream of inflatePdfMetadataStreams(buf)) {
      findings.push(...extractTextMetadata(stream, url));
    }
  } else if (buf[0] === 0xff && buf[1] === 0xd8) {
    findings.push(...extractJpegExif(buf, url));
  } else if (/^(II\*\0|MM\0\*)$/.test(buf.toString("latin1", 0, 4))) {
    findings.push(...extractTiffMetadata(buf, url));
  }
  return findings;
}

export async function runMetadataLeakCheck(
  fileUrls: string[]
): Promise<MetadataLeakResult> {
  const candidateUrls = fileUrls
    .filter((u) => DOCUMENT_EXTENSIONS.test(u) || IMAGE_EXTENSIONS.test(u))
    .slice(0, MAX_FILES_TO_CHECK);

  if (candidateUrls.length === 0) {
    return { status: "completed", findings: [] };
  }

  const findings: MetadataFinding[] = [];

  try {
    const results = await Promise.allSettled(
      candidateUrls.map(async (url) => {
        const res = await fetch(url, {
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
          headers: { "User-Agent": "Mozilla/5.0 HebridesCyber-Scanner/1.0" },
        });
        if (!res.ok) return;

        const contentType = res.headers.get("content-type") ?? "";
        if (contentType.includes("text/html")) return;

        const arrayBuf = await res.arrayBuffer();
        const buf = Buffer.from(arrayBuf.slice(0, MAX_BYTES));
        if (buf.length < 4) return;
        findings.push(...extractMetadata(buf, url));
      })
    );

    // Log but don't fail for individual fetch errors
    for (const r of results) {
      if (r.status === "rejected") {
        // Silently skip inaccessible files
      }
    }

    // Deduplicate
    const seen = new Set<string>();
    const deduped = findings.filter((f) => {
      if (!f.value) return false;
      const key = `${f.type}:${f.value}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    return { status: "completed", findings: deduped };
  } catch (err) {
    return {
      status: "error",
      note: `Metadata leak check failed: ${(err as Error).message}`,
    };
  }
}
