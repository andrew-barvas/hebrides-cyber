import { describe, it, expect } from "vitest";
import { isMissingSchemaError } from "./dbErrors";

describe("isMissingSchemaError", () => {
  it("returns true for undefined_column (42703)", () => {
    expect(isMissingSchemaError({ code: "42703" })).toBe(true);
  });

  it("returns true for undefined_table (42P01)", () => {
    expect(isMissingSchemaError({ code: "42P01" })).toBe(true);
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
