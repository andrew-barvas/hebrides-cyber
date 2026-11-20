import { describe, expect, it } from "vitest";
import { customerInputKind } from "./lookoutCustomer";

describe("customerInputKind", () => {
  it.each([
    ["11111111-1111-4111-8111-111111111111", "id"],
    [" Owner@Example.com ", "email"],
    ["not an account", null],
    ["", null],
  ])("%j is %s", (input, kind) => expect(customerInputKind(input)).toBe(kind));
});
