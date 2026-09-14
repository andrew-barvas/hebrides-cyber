import { describe, it, expect } from "vitest";
import { parseScimUser, toScimUser, toScimListResponse, validateScimBearerToken, scimError } from "./scimProvisioning";

describe("parseScimUser", () => {
  it("parses a valid SCIM user", () => {
    const user = parseScimUser({
      userName: "jane@example.com",
      name: { givenName: "Jane", familyName: "Doe" },
      emails: [{ value: "jane@example.com", primary: true }],
      active: true,
      externalId: "ext-123",
    });
    expect(user).not.toBeNull();
    expect(user!.userName).toBe("jane@example.com");
    expect(user!.active).toBe(true);
    expect(user!.externalId).toBe("ext-123");
  });

  it("rejects missing userName", () => {
    expect(parseScimUser({ name: { givenName: "Jane" } })).toBeNull();
    expect(parseScimUser(null)).toBeNull();
    expect(parseScimUser({})).toBeNull();
  });

  it("defaults active to true", () => {
    const user = parseScimUser({ userName: "test@example.com" });
    expect(user!.active).toBe(true);
  });

  it("handles active=false", () => {
    const user = parseScimUser({ userName: "test@example.com", active: false });
    expect(user!.active).toBe(false);
  });
});

describe("toScimUser", () => {
  it("converts a member to SCIM format", () => {
    const scim = toScimUser({
      id: "uuid-1",
      email: "bob@example.com",
      display_name: "Bob Smith",
      active: true,
    });
    expect(scim.id).toBe("uuid-1");
    expect(scim.userName).toBe("bob@example.com");
    expect(scim.name?.givenName).toBe("Bob");
    expect(scim.name?.familyName).toBe("Smith");
  });
});

describe("toScimListResponse", () => {
  it("wraps users in list response", () => {
    const users = [toScimUser({ id: "1", email: "a@b.com" })];
    const response = toScimListResponse(users);
    expect(response.totalResults).toBe(1);
    expect(response.Resources).toHaveLength(1);
  });
});

describe("validateScimBearerToken", () => {
  it("validates correct token", () => {
    expect(validateScimBearerToken("Bearer my-secret", "my-secret")).toBe(true);
  });

  it("rejects wrong token", () => {
    expect(validateScimBearerToken("Bearer wrong", "my-secret")).toBe(false);
  });

  it("rejects missing header", () => {
    expect(validateScimBearerToken(undefined, "my-secret")).toBe(false);
  });

  it("rejects non-Bearer scheme", () => {
    expect(validateScimBearerToken("Basic abc", "my-secret")).toBe(false);
  });
});

describe("scimError", () => {
  it("returns structured error", () => {
    const err = scimError(404, "Not found");
    expect(err.status).toBe("404");
    expect(err.detail).toBe("Not found");
  });
});
