import { test, expect } from "@playwright/test";

// The Playwright webServer hardcodes NEXT_PUBLIC_SUPABASE_URL so the dev
// server uses "example-project" as the Supabase project ref. HOWEVER, if env
// injection silently fails (e.g. .env.local empty value overrides) the client
// falls back to the placeholder URL and auth hangs on real DNS. Defence:
//   • route pattern matches ALL *.supabase.co traffic (not just example-project)
//   • we still seed the example-project storage key for the auth test
// FAKE_PROJECT_REF = "example-project" — the intended project ref when env
// injection works; we now intercept *.supabase.co broadly to cover the
// fallback ("placeholder.supabase.co") too.
const FAKE_USER_ID = "22222222-2222-2222-2222-222222222222";
const FAKE_EMAIL = "test-user@example.com";

// Build a structurally-valid JWT in Node.js context (Buffer-based base64url).
// Supabase JS v2 calls jwtDecode() locally — the token must have three
// dot-separated base64url parts even though the signature is never verified
// client-side. Both the route mock AND the browser init script use this token
// so they agree on what "the session" looks like.
function buildFakeJwt(): string {
  const b64url = (s: string) =>
    Buffer.from(s, "utf8")
      .toString("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64url(
    JSON.stringify({
      sub: FAKE_USER_ID,
      email: FAKE_EMAIL,
      exp: 9_999_999_999,
      aud: "authenticated",
      role: "authenticated",
      aal: "aal1",
      iss: "supabase",
      session_id: "test-session-id",
    })
  );
  return `${header}.${payload}.fakesig`;
}

const FAKE_JWT = buildFakeJwt();

// The full session object as Supabase JS stores it in localStorage.
const FAKE_SESSION = {
  access_token: FAKE_JWT,
  token_type: "bearer",
  expires_in: 3600,
  expires_at: 9_999_999_999,
  refresh_token: "fake-refresh-token",
  user: {
    id: FAKE_USER_ID,
    aud: "authenticated",
    role: "authenticated",
    email: FAKE_EMAIL,
    email_confirmed_at: "2026-01-01T00:00:00Z",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    identities: [],
    app_metadata: { provider: "email" },
    user_metadata: {},
  },
};

// Full mock handler for the fake Supabase project.
// Newer Supabase JS versions (2.65+) make background auth verification calls
// on init even for non-expired stored sessions. Returning `{}` for those
// causes Supabase to clear the session, so we return a properly-shaped
// auth response for any auth/* endpoint.
async function mockSupabase(
  route: import("@playwright/test").Route,
  authenticated: boolean
) {
  const url = route.request().url();

  // ── Auth endpoints ──────────────────────────────────────────────────────
  if (url.includes("/auth/v1/token")) {
    if (authenticated) {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(FAKE_SESSION),
      });
    }
    // Unauthenticated: 400 = no refresh token available
    return route.fulfill({
      status: 400,
      contentType: "application/json",
      body: JSON.stringify({ error: "invalid_grant", error_description: "Invalid refresh token" }),
    });
  }

  if (url.includes("/auth/v1/user")) {
    if (authenticated) {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(FAKE_SESSION.user),
      });
    }
    return route.fulfill({
      status: 401,
      contentType: "application/json",
      body: JSON.stringify({ message: "JWT expired" }),
    });
  }

  if (url.includes("/auth/v1/factors")) {
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ totp: [], phone: [] }),
    });
  }

  // ── REST / data endpoints ───────────────────────────────────────────────
  if (url.includes("/rest/v1/scans")) {
    if (authenticated) {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([
          {
            id: "11111111-1111-1111-1111-111111111111",
            target_url: "https://example.com",
            status: "completed",
            created_at: new Date().toISOString(),
            scan_results: [{ score: 82 }],
          },
        ]),
      });
    }
  }

  if (url.includes("/rest/v1/subscriptions")) {
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(null),
    });
  }

  // Default: empty success
  return route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({}),
  });
}

// ── Tests ───────────────────────────────────────────────────────────────────

test("unauthenticated dashboard prompts sign-in", async ({ page }) => {
  // Intercept ALL Supabase traffic regardless of which project ref is compiled
  // into the bundle. This guards against env-injection failures where the
  // client falls back to "placeholder.supabase.co" — without interception
  // those requests would block on DNS, keeping the page in loading state.
  await page.route(/\.supabase\.co/, (route) =>
    mockSupabase(route, false)
  );

  await page.goto("/dashboard");
  // The page starts in a loading state while getSession() resolves. Once it
  // resolves without a session it renders the "Sign in required" heading.
  // expectTimeout is 15 s (set in playwright.config.ts).
  await expect(page.getByRole("heading", { name: "Sign in required" })).toBeVisible();
});

test("authenticated dashboard lists scans (mocked session + API)", async ({ page }) => {
  // Intercept ALL Supabase traffic — auth verification, token refresh, data
  // queries — regardless of the compiled project ref.
  await page.route(/\.supabase\.co/, (route) =>
    mockSupabase(route, true)
  );

  // Seed the fake session into localStorage BEFORE any page script runs.
  // We seed every possible storage key that the Supabase client might use:
  //   - sb-example-project-auth-token  (when NEXT_PUBLIC_SUPABASE_URL is properly injected)
  //   - sb-placeholder-auth-token      (fallback when injection is missing / .env.local wins)
  // Both are intercepted by the regex route mock above, so auth resolves
  // immediately whichever key the client actually reads.
  await page.addInitScript(
    ({ session }) => {
      const POSSIBLE_KEYS = [
        "sb-example-project-auth-token",
        "sb-placeholder-auth-token",
      ];
      for (const key of POSSIBLE_KEYS) {
        window.localStorage.setItem(key, JSON.stringify(session));
      }
    },
    { session: FAKE_SESSION }
  );

  await page.goto("/dashboard");

  // The main h1 when authenticated is "Dashboard".
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("https://example.com")).toBeVisible();
  await expect(page.getByText("completed")).toBeVisible();
});
