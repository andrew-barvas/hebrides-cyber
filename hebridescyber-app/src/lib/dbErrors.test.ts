import { describe, it, expect } from "vitest";
import { isMissingSchemaError } from "./dbErrors";

describe("isMissingSchemaError", () => {
  it("returns true for undefined_column (42703)", () => {
    expect(isMissingSchemaError({ code: "42703" })).toBe(true);
  });

  it("returns true for undefined_table (42P01)", () => {
    expect(isMissingSchemaError({ code: "42P01" })).toBe(true);
  });

  // PostgREST's own schema-cache errors — what production actually returns
  // for a missing table on PostgREST 12.2+, and for a missing column in a
  // write payload.
  it("returns true for PostgREST's PGRST205 (table) and PGRST204 (column)", () => {
    expect(isMissingSchemaError({ code: "PGRST205" })).toBe(true);
    expect(isMissingSchemaError({ code: "PGRST204" })).toBe(true);
  });

  it("returns false for a different Postgres error code", () => {
    expect(isMissingSchemaError({ code: "23505" })).toBe(false);
  });

  it("returns false for null/undefined error", () => {
    expect(isMissingSchemaError(null)).toBe(false);
    expect(isMissingSchemaError(undefined)).toBe(false);
  });

  it("returns false for an error object with no code", () => {
    expect(isMissingSchemaError({})).toBe(false);
  });
});
