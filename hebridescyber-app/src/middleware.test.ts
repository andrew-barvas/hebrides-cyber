import { describe, it, expect } from "vitest";
import { isProtectedPath } from "./middleware";

describe("isProtectedPath", () => {
  it.each(["/dashboard", "/dashboard/scans/1", "/admin", "/admin/x", "/account", "/account/security"])("protects %s", (p) =>
    expect(isProtectedPath(p)).toBe(true)
  );

  // /login must stay open or signed-out users redirect-loop forever.
  it.each(["/", "/login", "/login/mfa-challenge", "/pricing", "/dashboardx", "/accounts", "/blog/admin"])("leaves %s public", (p) =>
    expect(isProtectedPath(p)).toBe(false)
  );
});
