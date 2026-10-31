// Login recording (docs/AUTHENTICATED-CRAWL.md's deferred "slice 2"): drives
// a real Playwright browser through a login FORM so the owner doesn't have
// to manually copy a session cookie out of devtools. The browser does
// exactly what a person would — load the login page, fill the two fields,
// submit — so cookies, CSRF tokens and redirects are all handled by the
// target site itself rather than guessed at. Scope matches the design doc:
// a single username/password form, no CSRF-token-as-a-separate-field
// gymnastics. MFA is supported for TOTP only: with an optional shared secret
// the recorder types the current RFC 6238 code into the MFA field after the
// password step. Any other challenge (SMS, push, WebAuthn, OAuth redirects)
// reads as a failed login below, not a silent false success.
//
// Safety: the password and TOTP secret are used once, in this one request,
// and are never logged or returned — only the resulting cookies are. The
// secret never reaches the browser runner: it only receives a function that
// yields the current code, called after the password step. The caller (the
// API route) is responsible for only ever calling this against a domain the
// owner has verified they own, same as every other authenticated-scan path.
import { generateTotp, isValidTotpSecret, msUntilNextTotp } from "../totp";

export type LoginFields = {
  loginUrl: string;
  username: string;
  password: string;
  usernameSelector?: string;
  passwordSelector?: string;
  /** Base32 TOTP shared secret (RFC 6238). Only for the customer's own verified target. */
  totpSecret?: string;
  mfaSelector?: string;
};

/** What the browser runner is given: the TOTP secret is swapped for a code supplier. */
export type RunnerFields = Omit<LoginFields, "totpSecret"> & { mfa?: { code: () => string; msUntilRollover: () => number } };

export type LoginOutcome = {
  success: boolean;
  cookies: Array<{ name: string; value: string }>;
  /** Why it failed, when known: the password step, or the MFA step. */
  failedAt?: "login" | "mfa";
};
export type LoginRunner = (fields: RunnerFields) => Promise<LoginOutcome>;

export type LoginRecordResult =
  | { status: "recorded"; cookieValue: string }
  | { status: "error"; note: string };

const DEFAULT_USERNAME_SELECTOR = 'input[type="email"], input[autocomplete="username"], input[name*="user" i], input[type="text"]';
const DEFAULT_PASSWORD_SELECTOR = 'input[type="password"]';
const DEFAULT_MFA_SELECTOR =
  'input[autocomplete="one-time-code"], input[name*="otp" i], input[name*="totp" i], input[name*="mfa" i], input[name*="code" i], input[inputmode="numeric"]';
// Don't type a code that rolls over before the site checks it.
const ROLLOVER_GUARD_MS = 2_000;

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
  const { totpSecret, ...rest } = fields;
  if (totpSecret !== undefined && !isValidTotpSecret(totpSecret)) {
    return { status: "error", note: "The TOTP secret is not a valid base32 key." };
  }

  let outcome: LoginOutcome;
  try {
    outcome = await run(
      totpSecret === undefined ? rest : { ...rest, mfa: { code: () => generateTotp(totpSecret), msUntilRollover: () => msUntilNextTotp() } }
    );
  } catch (err) {
    return { status: "error", note: `The login attempt failed: ${(err as Error).message}` };
  }

  if (!outcome.success && outcome.failedAt === "mfa") {
    return {
      status: "error",
      note: "The MFA step did not complete — the one-time code was rejected, or the MFA field was not found. Check the TOTP secret (and that the account uses an authenticator app, not SMS or push), or supply an MFA field selector.",
    };
  }
  if (!outcome.success) {
    return { status: "error", note: "Login did not appear to succeed — a password field was still visible afterwards. Check the URL, username and password, or, if the account uses MFA, add its TOTP secret (other MFA types are not supported)." };
  }
  if (outcome.cookies.length === 0) {
    return { status: "error", note: "Login appeared to succeed, but the browser was left with no cookies to save." };
  }

  return { status: "recorded", cookieValue: outcome.cookies.map((c) => `${c.name}=${c.value}`).join("; ") };
}

/** The slice of a Playwright Page the login steps use, so their order is testable without a browser. */
export type LoginPage = {
  goto(url: string): Promise<void>;
  fill(selector: string, value: string): Promise<void>;
  pressEnterAndSettle(selector: string): Promise<void>;
  isVisible(selector: string): Promise<boolean>;
  waitForVisible(selector: string): Promise<boolean>;
  cookies(): Promise<Array<{ name: string; value: string }>>;
};

/** The recorded steps: load, username, password, submit, then (TOTP only) wait for the MFA field, type the code, submit. */
export async function driveLogin(
  page: LoginPage,
  fields: RunnerFields,
  sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms))
): Promise<LoginOutcome> {
  const userSel = fields.usernameSelector || DEFAULT_USERNAME_SELECTOR;
  const passSel = fields.passwordSelector || DEFAULT_PASSWORD_SELECTOR;
  await page.goto(fields.loginUrl);
  await page.fill(userSel, fields.username);
  await page.fill(passSel, fields.password);
  await page.pressEnterAndSettle(passSel);

  if (fields.mfa) {
    const mfaSel = fields.mfaSelector || DEFAULT_MFA_SELECTOR;
    if (await page.waitForVisible(mfaSel)) {
      const wait = fields.mfa.msUntilRollover();
      if (wait < ROLLOVER_GUARD_MS) await sleep(wait + 100);
      // Generated only now, with the challenge on screen, so the code is fresh.
      await page.fill(mfaSel, fields.mfa.code());
      await page.pressEnterAndSettle(mfaSel);
      if (await page.isVisible(mfaSel)) return { success: false, cookies: [], failedAt: "mfa" };
    }
  }

  // A password field still on screen after submitting means the form
  // rejected the credentials (or asked for an MFA step this can't answer)
  // rather than logging in.
  if (await page.isVisible(passSel)) return { success: false, cookies: [], failedAt: fields.mfa ? "mfa" : "login" };
  return { success: true, cookies: await page.cookies() };
}

/** Browser runner used in production — a fresh, isolated browser context per call. */
export const playwrightLoginRun: LoginRunner = async (fields) => {
  const { chromium } = await import("playwright");
  const browser = await chromium.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
  try {
    const context = await browser.newContext();
    const pw = await context.newPage();
    const page: LoginPage = {
      goto: async (url) => {
        await pw.goto(url, { waitUntil: "load", timeout: 20_000 });
      },
      fill: (selector, value) => pw.locator(selector).first().fill(value, { timeout: 10_000 }),
      // Pressing Enter submits the real <form> — the page's own CSRF token
      // (if any) and cookies travel with it exactly as a real visitor's would.
      pressEnterAndSettle: async (selector) => {
        await Promise.all([
          pw.waitForLoadState("networkidle", { timeout: 15_000 }).catch(() => undefined),
          pw.locator(selector).first().press("Enter"),
        ]);
      },
      isVisible: (selector) => pw.locator(selector).first().isVisible().catch(() => false),
      waitForVisible: (selector) =>
        pw.locator(selector).first().waitFor({ state: "visible", timeout: 10_000 }).then(() => true, () => false),
      cookies: async () => (await context.cookies()).map((c) => ({ name: c.name, value: c.value })),
    };
    return await driveLogin(page, fields);
  } finally {
    await browser.close();
  }
};
