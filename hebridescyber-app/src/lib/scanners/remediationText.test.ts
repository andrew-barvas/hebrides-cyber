import { describe, it, expect } from "vitest";
import {
  sqlmapRemediation,
  SQLMAP_SQLI_BASE,
  commixRemediation,
  COMMIX_COMMAND_INJECTION_BASE,
  nmapDangerousPortRemediation,
} from "./remediationText";

describe("sqlmapRemediation", () => {
  it("returns the base text with no DBMS-specific snippet when dbms is null", () => {
    expect(sqlmapRemediation(null)).toBe(SQLMAP_SQLI_BASE);
  });

  it("returns the base text with no snippet for an unrecognised DBMS string", () => {
    expect(sqlmapRemediation("some obscure database")).toBe(SQLMAP_SQLI_BASE);
  });

  it("appends the MySQL snippet, matched case-insensitively", () => {
    const result = sqlmapRemediation("MySQL >= 5.0.12");
    expect(result.startsWith(SQLMAP_SQLI_BASE)).toBe(true);
    expect(result).toContain("mysqli");
  });

  it("appends the PostgreSQL snippet", () => {
    expect(sqlmapRemediation("PostgreSQL")).toContain("node-postgres");
  });

  it("appends the SQL Server snippet for sqlmap's exact DBMS label", () => {
    expect(sqlmapRemediation("Microsoft SQL Server 2019")).toContain("mssql");
  });
});

describe("commixRemediation", () => {
  it("always returns the fixed command-injection remediation text", () => {
    expect(commixRemediation()).toBe(COMMIX_COMMAND_INJECTION_BASE);
  });

  it("mentions avoiding shell execution of user input as the fix", () => {
    const text = commixRemediation();
    expect(text).toMatch(/shell/i);
  });
});

describe("nmapDangerousPortRemediation", () => {
  it("has specific text for each of the documented dangerous ports", () => {
    for (const port of [2375, 2376, 6379, 9200, 27017]) {
      const text = nmapDangerousPortRemediation(port);
      expect(text.length).toBeGreaterThan(0);
      expect(text).toContain(String(port));
    }
  });

  it("names the correct service for a couple of specific ports", () => {
    expect(nmapDangerousPortRemediation(6379)).toMatch(/Redis/);
    expect(nmapDangerousPortRemediation(27017)).toMatch(/MongoDB/);
  });
});

describe("sqlmapRemediation context", () => {
  it("adds nothing without context or for an unknown place", () => {
    expect(sqlmapRemediation(null, {})).toBe(SQLMAP_SQLI_BASE);
    expect(sqlmapRemediation(null, { place: "Weird", techniques: ["something else"] })).toBe(SQLMAP_SQLI_BASE);
  });

  it("says where the value arrives, case-insensitively", () => {
    expect(sqlmapRemediation(null, { place: "Cookie" })).toContain("comes from a cookie");
    expect(sqlmapRemediation(null, { place: "post" })).toContain("form or request body");
    expect(sqlmapRemediation(null, { place: "URI" })).toContain("path");
  });

  it("adds a note for each technique that worked", () => {
    const text = sqlmapRemediation("SQLite", { place: "GET", techniques: ["error-based", "time-based blind", "UNION query", "stacked queries"] });
    expect(text).toContain("**For this finding:**");
    expect(text).toContain("verbose errors");
    expect(text).toContain("only parameterised queries are");
    expect(text).toContain("read other tables");
    expect(text).toContain("extra statements");
    expect(text).toContain("SQLite (better-sqlite3)");
  });
});
