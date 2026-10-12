// Login recording (docs/AUTHENTICATED-CRAWL.md's deferred "slice 2"): drives
// a real Playwright browser through a login FORM so the owner doesn't have
// to manually copy a session cookie out of devtools. The browser does
// exactly what a person would — load the login page, fill the two fields,
// submit — so cookies, CSRF tokens and redirects are all handled by the
// target site itself rather than guessed at. Scope matches the design doc:
// a single username/password form, no CSRF-token-as-a-separate-field
// gymnastics, no MFA (an MFA challenge page reads as a failed login below,
// not a silent false success).
//
// Safety: the password is used once, in this one request, and is never
// logged or returned — only the resulting cookies are. The caller (the API
// route) is responsible for only ever calling this against a domain the
// owner has verified they own, same as every other authenticated-scan path.
export type LoginFields = {
  loginUrl: string;
  username: string;
  password: string;
  usernameSelector?: string;
  passwordSelector?: string;
};

export type LoginOutcome = { success: boolean; cookies: Array<{ name: string; value: string }> };
export type LoginRunner = (fields: LoginFields) => Promise<LoginOutcome>;

export type LoginRecordResult =
  | { status: "recorded"; cookieValue: string }
  | { status: "error"; note: string };

const DEFAULT_USERNAME_SELECTOR = 'input[type="email"], input[autocomplete="username"], input[name*="user" i], input[type="text"]';
const DEFAULT_PASSWORD_SELECTOR = 'input[type="password"]';

export async function recordLogin(fields: LoginFields, run: LoginRunner): Promise<LoginRecordResult> {
  let url: URL;
  try {
    url = new URL(fields.loginUrl);
  } catch {
    return { status: "error", note: "loginUrl is not a valid URL." };
  }
  // The password is about to be typed into a real page — never over plain HTTP.
  if (url.protocol !== "https:") {
    return { status: "error", note: "loginUrl must be https:// — a login page served over plain HTTP would send the password unencrypted." };
  }
  if (!fields.username || !fields.password) {
    return { status: "error", note: "username and password are both required." };
  }

  let outcome: LoginOutcome;
  try {
    outcome = await run(fields);
  } catch (err) {
    return { status: "error", note: `The login attempt failed: ${(err as Error).message}` };
  }

  if (!outcome.success) {
    return { status: "error", note: "Login did not appear to succeed — a password field was still visible afterwards. Check the URL, username and password, or that the account has no MFA step (not supported)." };
  }
  if (outcome.cookies.length === 0) {
    return { status: "error", note: "Login appeared to succeed, but the browser was left with no cookies to save." };
  }

  return { status: "recorded", cookieValue: outcome.cookies.map((c) => `${c.name}=${c.value}`).join("; ") };
}

/** Browser runner used in production — a fresh, isolated browser context per call. */
export const playwrightLoginRun: LoginRunner = async (fields) => {
  const { chromium } = await import("playwright");
  const browser = await chromium.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(fields.loginUrl, { waitUntil: "load", timeout: 20_000 });

    const usernameField = page.locator(fields.usernameSelector || DEFAULT_USERNAME_SELECTOR).first();
    const passwordField = page.locator(fields.passwordSelector || DEFAULT_PASSWORD_SELECTOR).first();
    await usernameField.fill(fields.username, { timeout: 10_000 });
    await passwordField.fill(fields.password, { timeout: 10_000 });

    // Pressing Enter submits the real <form> — the page's own CSRF token
    // (if any) and cookies travel with it exactly as a real visitor's would.
    await Promise.all([
      page.waitForLoadState("networkidle", { timeout: 15_000 }).catch(() => undefined),
      passwordField.press("Enter"),
    ]);

    // A password field still on screen after submitting means the form
    // rejected the credentials (or asked for an MFA step this doesn't
    // support) rather than logging in.
    const stillOnLogin = await passwordField.isVisible().catch(() => false);
    const cookies = await context.cookies();
    return { success: !stillOnLogin, cookies: cookies.map((c) => ({ name: c.name, value: c.value })) };
  } finally {
    await browser.close();
  }
};
