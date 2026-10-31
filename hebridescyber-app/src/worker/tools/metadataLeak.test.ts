import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { deflateRawSync, deflateSync } from "node:zlib";
import { runMetadataLeakCheck } from "./metadataLeak";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function makeResponse(body: string, contentType = "application/pdf") {
  const buf = Buffer.from(body, "latin1");
  return {
    ok: true,
    headers: new Map([["content-type", contentType]]),
    arrayBuffer: () => Promise.resolve(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)),
  };
}

function makeBinaryResponse(buf: Buffer, contentType = "application/octet-stream") {
  return {
    ok: true,
    headers: new Map([["content-type", contentType]]),
    arrayBuffer: () => Promise.resolve(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)),
  };
}

// Minimal zip writer (deflate, no data descriptors) — enough for docProps parsing.
function makeZip(files: Array<{ name: string; data: string }>): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const f of files) {
    const name = Buffer.from(f.name, "utf8");
    const raw = Buffer.from(f.data, "utf8");
    const data = deflateRawSync(raw);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, name, data);
    centrals.push(central, name);
    offset += 30 + name.length + data.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

// JPEG whose APP1 holds a big-endian TIFF: IFD0 (Artist, Software, GPS pointer)
// and a GPS IFD at 57°30'N, 6°15'W.
function makeJpegWithExif(): Buffer {
  const tiff = Buffer.alloc(200);
  tiff.write("MM", 0, "latin1");
  tiff.writeUInt16BE(42, 2);
  tiff.writeUInt32BE(8, 4);
  const entry = (p: number, tag: number, type: number, count: number, value: number) => {
    tiff.writeUInt16BE(tag, p);
    tiff.writeUInt16BE(type, p + 2);
    tiff.writeUInt32BE(count, p + 4);
    tiff.writeUInt32BE(value, p + 8);
  };
  tiff.writeUInt16BE(3, 8); // IFD0: 3 entries, 8 + 2 + 36 + 4 = 50
  entry(10, 0x013b, 2, 12, 120); // Artist
  entry(22, 0x0131, 2, 10, 132); // Software
  entry(34, 0x8825, 4, 1, 60); // GPS IFD pointer
  tiff.writeUInt16BE(4, 60); // GPS IFD: 4 entries, ends at 60 + 2 + 48 + 4 = 114; values from 120
  entry(62, 0x01, 2, 2, 0); tiff.write("N\0", 70, "latin1");
  entry(74, 0x02, 5, 3, 144);
  entry(86, 0x03, 2, 2, 0); tiff.write("W\0", 94, "latin1");
  entry(98, 0x04, 5, 3, 168);
  tiff.write("Iain Camera\0", 120, "latin1");
  tiff.write("GIMP 2.10\0", 132, "latin1");
  const rationals = (p: number, vals: Array<[number, number]>) =>
    vals.forEach(([n, d], i) => {
      tiff.writeUInt32BE(n, p + i * 8);
      tiff.writeUInt32BE(d, p + i * 8 + 4);
    });
  rationals(144, [[57, 1], [30, 1], [0, 1]]);
  rationals(168, [[6, 1], [15, 1], [0, 1]]);
  const exif = Buffer.concat([Buffer.from("Exif\0\0", "latin1"), tiff.subarray(0, 192)]);
  const app1 = Buffer.alloc(4);
  app1.writeUInt16BE(0xffe1, 0);
  app1.writeUInt16BE(exif.length + 2, 2);
  return Buffer.concat([Buffer.from([0xff, 0xd8]), app1, exif, Buffer.from([0xff, 0xda, 0x00, 0x02, 0xff, 0xd9])]);
}

describe("runMetadataLeakCheck", () => {
  it("returns empty findings when no document URLs are provided", async () => {
    const result = await runMetadataLeakCheck([
      "https://example.com/page.html",
      "https://example.com/style.css",
    ]);
    expect(result).toEqual({ status: "completed", findings: [] });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("extracts email addresses from PDF metadata", async () => {
    fetchMock.mockResolvedValueOnce(
      makeResponse("Some text admin@internal.corp more text")
    );
    const result = await runMetadataLeakCheck(["https://example.com/doc.pdf"]);
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.findings).toContainEqual({
      url: "https://example.com/doc.pdf",
      type: "email",
      value: "admin@internal.corp",
    });
  });

  it("extracts internal IP addresses", async () => {
    fetchMock.mockResolvedValueOnce(
      makeResponse("Server: 192.168.1.100 responded")
    );
    const result = await runMetadataLeakCheck(["https://example.com/report.docx"]);
    if (result.status !== "completed") return;
    expect(result.findings).toContainEqual({
      url: "https://example.com/report.docx",
      type: "internal-ip",
      value: "192.168.1.100",
    });
  });

  it("extracts Windows paths", async () => {
    fetchMock.mockResolvedValueOnce(
      makeResponse("path: C:\\Users\\jsmith\\Documents\\secret-project\\file.txt")
    );
    const result = await runMetadataLeakCheck(["https://example.com/file.xlsx"]);
    if (result.status !== "completed") return;
    expect(result.findings.some((f) => f.type === "path" && f.value.includes("jsmith"))).toBe(true);
  });

  it("extracts PDF /Author metadata", async () => {
    fetchMock.mockResolvedValueOnce(
      makeResponse("/Author (John Smith) /Creator (Microsoft Word)")
    );
    const result = await runMetadataLeakCheck(["https://example.com/internal.pdf"]);
    if (result.status !== "completed") return;
    expect(result.findings).toContainEqual({
      url: "https://example.com/internal.pdf",
      type: "author",
      value: "John Smith",
    });
    expect(result.findings).toContainEqual({
      url: "https://example.com/internal.pdf",
      type: "software",
      value: "Microsoft Word",
    });
  });

  it("deduplicates findings by type+value", async () => {
    fetchMock
      .mockResolvedValueOnce(makeResponse("leak@corp.com another leak@corp.com"))
      .mockResolvedValueOnce(makeResponse("leak@corp.com again"));
    const result = await runMetadataLeakCheck([
      "https://example.com/a.pdf",
      "https://example.com/b.pdf",
    ]);
    if (result.status !== "completed") return;
    const emails = result.findings.filter((f) => f.type === "email" && f.value === "leak@corp.com");
    expect(emails).toHaveLength(1);
  });

  it("skips HTML responses", async () => {
    fetchMock.mockResolvedValueOnce(
      makeResponse("admin@internal.corp", "text/html")
    );
    const result = await runMetadataLeakCheck(["https://example.com/doc.pdf"]);
    if (result.status !== "completed") return;
    expect(result.findings).toEqual([]);
  });

  it("reads author and app metadata from a zipped Office file", async () => {
    const core =
      '<?xml version="1.0"?><cp:coreProperties xmlns:cp="x" xmlns:dc="y">' +
      "<dc:creator>Jane Doe</dc:creator><cp:lastModifiedBy>J. Smith &amp; Co</cp:lastModifiedBy></cp:coreProperties>";
    const app =
      "<Properties><Template>C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Templates\\Normal.dotm</Template>" +
      "<Application>Microsoft Office Word</Application><AppVersion>16.0000</AppVersion></Properties>";
    fetchMock.mockResolvedValueOnce(
      makeBinaryResponse(
        makeZip([
          { name: "word/document.xml", data: "<w:document>body text</w:document>" },
          { name: "docProps/core.xml", data: core },
          { name: "docProps/app.xml", data: app },
        ]),
      ),
    );
    const url = "https://example.com/report.docx";
    const result = await runMetadataLeakCheck([url]);
    if (result.status !== "completed") throw new Error("expected completed");
    expect(result.findings).toContainEqual({ url, type: "author", value: "Jane Doe" });
    expect(result.findings).toContainEqual({ url, type: "author", value: "J. Smith & Co" });
    expect(result.findings).toContainEqual({ url, type: "software", value: "Microsoft Office Word 16.0000" });
    expect(result.findings.some((f) => f.type === "path" && f.value.includes("jdoe"))).toBe(true);
  });

  it("finds docProps by walking local headers when the central directory was cut off", async () => {
    const zip = makeZip([{ name: "docProps/core.xml", data: "<dc:creator>Cut Off</dc:creator>" }]);
    const truncated = zip.subarray(0, zip.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02])));
    fetchMock.mockResolvedValueOnce(makeBinaryResponse(truncated));
    const result = await runMetadataLeakCheck(["https://example.com/a.xlsx"]);
    if (result.status !== "completed") throw new Error("expected completed");
    expect(result.findings.map((f) => f.value)).toContain("Cut Off");
  });

  it("reads OpenDocument meta.xml", async () => {
    fetchMock.mockResolvedValueOnce(
      makeBinaryResponse(
        makeZip([
          {
            name: "meta.xml",
            data: "<office:meta><meta:initial-creator>Ola Nordmann</meta:initial-creator><meta:generator>LibreOffice/7.6</meta:generator></office:meta>",
          },
        ]),
      ),
    );
    const url = "https://example.com/minutes.odt";
    const result = await runMetadataLeakCheck([url]);
    if (result.status !== "completed") throw new Error("expected completed");
    expect(result.findings).toContainEqual({ url, type: "author", value: "Ola Nordmann" });
    expect(result.findings).toContainEqual({ url, type: "software", value: "LibreOffice/7.6" });
  });

  it("inflates PDF object streams and decodes UTF-16 Info strings", async () => {
    const utf16Author = "<FEFF" + Buffer.from("Zoë Admin", "utf16le").swap16().toString("hex") + ">";
    const objStm = deflateSync(Buffer.from(`<< /Author ${utf16Author} /Producer (pdfTeX-1.40.25) >>`, "latin1"));
    const pdf = Buffer.concat([
      Buffer.from("%PDF-1.7\n5 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length " + objStm.length + " >>\nstream\n", "latin1"),
      objStm,
      Buffer.from("\nendstream\nendobj\n%%EOF", "latin1"),
    ]);
    fetchMock.mockResolvedValueOnce(makeBinaryResponse(pdf));
    const url = "https://example.com/paper.pdf";
    const result = await runMetadataLeakCheck([url]);
    if (result.status !== "completed") throw new Error("expected completed");
    expect(result.findings).toContainEqual({ url, type: "author", value: "Zoë Admin" });
    expect(result.findings).toContainEqual({ url, type: "software", value: "pdfTeX-1.40.25" });
  });

  it("reads XMP creator and creator tool", async () => {
    fetchMock.mockResolvedValueOnce(
      makeResponse(
        "%PDF-1.4 <x:xmpmeta><dc:creator><rdf:Seq><rdf:li>Pat Example</rdf:li></rdf:Seq></dc:creator>" +
          "<xmp:CreatorTool>Adobe InDesign 18.0</xmp:CreatorTool></x:xmpmeta>",
      ),
    );
    const url = "https://example.com/brochure.pdf";
    const result = await runMetadataLeakCheck([url]);
    if (result.status !== "completed") throw new Error("expected completed");
    expect(result.findings).toContainEqual({ url, type: "author", value: "Pat Example" });
    expect(result.findings).toContainEqual({ url, type: "software", value: "Adobe InDesign 18.0" });
  });

  it("decodes EXIF GPS, Artist and Software from a JPEG", async () => {
    fetchMock.mockResolvedValueOnce(makeBinaryResponse(makeJpegWithExif()));
    const url = "https://example.com/team.jpg";
    const result = await runMetadataLeakCheck([url]);
    if (result.status !== "completed") throw new Error("expected completed");
    expect(result.findings).toContainEqual({ url, type: "gps", value: "57.50000, -6.25000" });
    expect(result.findings).toContainEqual({ url, type: "author", value: "Iain Camera" });
    expect(result.findings).toContainEqual({ url, type: "software", value: "GIMP 2.10" });
  });

  it("does not throw on a corrupt zip or JPEG", async () => {
    fetchMock
      .mockResolvedValueOnce(makeBinaryResponse(Buffer.from([0x50, 0x4b, 0x03, 0x04, 0xff, 0xff, 0xff])))
      .mockResolvedValueOnce(makeBinaryResponse(Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0x00, 0x02, 0x45])));
    const result = await runMetadataLeakCheck(["https://example.com/x.docx", "https://example.com/y.jpg"]);
    expect(result).toEqual({ status: "completed", findings: [] });
  });

  it("limits to MAX_FILES_TO_CHECK", async () => {
    const urls = Array.from({ length: 25 }, (_, i) => `https://example.com/file${i}.pdf`);
    fetchMock.mockResolvedValue(makeResponse("nothing here"));
    await runMetadataLeakCheck(urls);
    expect(fetchMock).toHaveBeenCalledTimes(20);
  });
});
