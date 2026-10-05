import type { BrowserContext, Page } from "@playwright/test";

// The Supabase project ref is hardcoded to "example-project" by
// playwright.config.ts, so the browser client reads its session from the
// cookie `sb-example-project-auth-token` (src/lib/supabase/browser.ts uses
// @supabase/ssr's cookie storage, NOT localStorage) and middleware reads the
// same cookie server-side.
export const TEST_USER = { id: "11111111-1111-4111-8111-111111111111", email: "e2e@example.com" };
const COOKIE_NAME = "sb-example-project-auth-token";

const b64url = (value: string | object) =>
  Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");

// Unsigned JWT: nothing in the browser verifies the signature, and the server
// side is answered by helpers/supabase-auth-preload.cjs, which recognises it
// by `iss: "e2e-test"`. aal1 with no factors means no MFA step-up redirect.
function fakeJwt(exp: number): string {
  return [
    b64url({ alg: "none", typ: "JWT" }),
    b64url({ iss: "e2e-test", sub: TEST_USER.id, email: TEST_USER.email, aud: "authenticated", role: "authenticated", aal: "aal1", exp }),
    "e2e-signature",
  ].join(".");
}

const expiresAt = Math.floor(Date.now() / 1000) + 24 * 3600;
export const ACCESS_TOKEN = fakeJwt(expiresAt);

/** Seeds a signed-in session for the whole browser context. */
export async function signIn(context: BrowserContext): Promise<void> {
  const session = {
    access_token: ACCESS_TOKEN,
    refresh_token: "e2e-refresh-token",
    token_type: "bearer",
    expires_in: 24 * 3600,
    expires_at: expiresAt,
    user: {
      id: TEST_USER.id,
      aud: "authenticated",
      role: "authenticated",
      email: TEST_USER.email,
      app_metadata: {},
      user_metadata: {},
      created_at: "2026-01-01T00:00:00Z",
    },
  };
  await context.addCookies([
    { name: COOKIE_NAME, value: `base64-${b64url(session)}`, domain: "localhost", path: "/", httpOnly: false, secure: false, sameSite: "Lax" },
  ]);
}

/** Convenience for tests that only have a Page. */
export const signInPage = (page: Page) => signIn(page.context());
