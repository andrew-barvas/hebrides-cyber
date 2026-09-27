import { describe, it, expect } from "vitest";
import { csvCell } from "./csv";

describe("csvCell", () => {
  it("leaves plain text alone", () => {
    expect(csvCell("Missing HSTS header")).toBe("Missing HSTS header");
  });

  it("quotes cells containing commas, quotes or line breaks", () => {
    expect(csvCell('a "quote", here')).toBe('"a ""quote"", here"');
    expect(csvCell("two\nlines")).toBe('"two\nlines"');
    expect(csvCell("cr\rlf")).toBe('"cr\rlf"');
  });

  // Finding titles quote text from the scanned site, which the site's owner
  // (or an attacker who controls it) chooses.
  it.each(["=HYPERLINK(\"http://x\")", "+1+1", "-2+3", "@SUM(A1)", "\tcmd"])(
    "neutralises a formula-leading cell: %s",
    (value) => {
      const out = csvCell(value);
      expect(out.replace(/^"/, "").startsWith("'")).toBe(true);
    }
  );

  it("neutralises and quotes when both apply", () => {
    expect(csvCell('=A1,"x"')).toBe(`"'=A1,""x"""`);
  });
});
