import { supabase } from "./supabaseClient";
import type { Session, User } from "@supabase/supabase-js";

// Thin helpers around Supabase Auth, used by the dashboard pages.

// supabase-js v2 serialises auth calls (getSession/getUser/mfa.*) behind a
// navigator.locks-based mutex shared across tabs. If that lock is ever left
// held — a tab that crashed or was killed mid-call, or a browser Locks API
// quirk — every subsequent auth call in every tab hangs forever with no
// error, no timeout, no rejection. Since every page below gates its
// "loading" state on one of these calls, a stuck lock looks exactly like
// the dashboard (or account/admin/login/etc.) being frozen on "// loading…"
// until the user manually refreshes — a refresh works because it's a fresh
// JS context that re-acquires the lock cleanly. AUTH_CALL_TIMEOUT_MS bounds
// every call below so a stuck lock degrades to "treated as signed out"
// (same fallback already used for a real getSession error) instead of an
// infinite spinner.
const AUTH_CALL_TIMEOUT_MS = 8_000;

function withAuthTimeout<T>(promise: Promise<T>, label: string, fallback: T): Promise<T> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      console.error(`[auth] ${label} timed out after ${AUTH_CALL_TIMEOUT_MS}ms — likely a stuck cross-tab auth lock`);
      resolve(fallback);
    }, AUTH_CALL_TIMEOUT_MS);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        console.error(`[auth] ${label} threw:`, (err as Error)?.message ?? err);
        resolve(fallback);
      }
    );
  });
}

export async function getSession(): Promise<Session | null> {
  return withAuthTimeout(
    (async () => {
      const { data, error } = await supabase.auth.getSession();
      if (error) {
        console.error("[auth] getSession error:", error.message);
        return null;
      }
      return data.session;
    })(),
    "getSession",
    null
  );
}

export async function getUser(): Promise<User | null> {
  return withAuthTimeout(
    (async () => {
      const { data, error } = await supabase.auth.getUser();
      if (error) return null;
      return data.user;
    })(),
    "getUser",
    null
  );
}

// Passwordless by design: magic link avoids the whole class of risk that
// comes with storing/reusing passwords (credential stuffing, weak reused
// passwords, etc.) — the recommended default for a small SaaS product
// without a dedicated security team managing password policy/breach
// monitoring. Google OAuth (below) is offered as a faster alternative for
// users who'd rather not check email.
export async function signInWithMagicLink(email: string) {
  const redirectTo = typeof window !== "undefined" ? `${window.location.origin}/auth/callback` : undefined;
  return supabase.auth.signInWithOtp({ email, options: { emailRedirectTo: redirectTo } });
}

// Password sign-in — kept as a secondary option (magic link is the
// default/recommended path above) specifically so seeded demo accounts
// (src/scripts/seed-users.ts) are actually usable without inbox access.
// Real customers are never required to set a password; this exists
// alongside, not instead of, the passwordless flow.
export async function signInWithPassword(email: string, password: string) {
  return supabase.auth.signInWithPassword({ email, password });
}

// TODO: enable the Google provider in the Supabase Dashboard (Authentication
// > Providers) and set its OAuth client ID/secret before this works —
// until then it'll redirect to an error page, which is expected.
export async function signInWithGoogle() {
  const redirectTo = typeof window !== "undefined" ? `${window.location.origin}/auth/callback` : undefined;
  return supabase.auth.signInWithOAuth({ provider: "google", options: { redirectTo } });
}

export async function signOut() {
  return supabase.auth.signOut();
}

// ---- MFA (TOTP) -----------------------------------------------------------
// Uses Supabase Auth's built-in multi-factor support — no extra library or
// server-side code needed, Supabase hosts the factor verification itself.
// See src/app/account/security/page.tsx (enrollment) and
// src/app/login/mfa-challenge/page.tsx (the second-factor prompt shown
// after magic-link/OAuth sign-in when a factor is already enrolled).

/**
 * Supabase distinguishes "aal1" (single factor, e.g. just the magic link)
 * from "aal2" (a TOTP factor has also been verified this session).
 * `nextLevel` is what the account is CAPABLE of, `currentLevel` is what
 * this session has actually satisfied — if they differ, the user has MFA
 * enrolled but hasn't completed the challenge yet this session.
 */
export async function getMfaAssuranceLevel() {
  // Supabase JS v2 can throw AuthInvalidJwtError synchronously when the
  // stored access token is malformed — catch thrown errors as well as the
  // { data, error } return path so callers always get a safe default. Also
  // subject to the same stuck cross-tab lock as getSession()/getUser()
  // above — wrapped the same way so it can't hang a page's loading state
  // forever either.
  return withAuthTimeout(
    (async () => {
      try {
        const { data, error } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
        if (error) {
          console.error("[auth] getAuthenticatorAssuranceLevel error:", error.message);
          return { currentLevel: null, nextLevel: null };
        }
        return data;
      } catch (err) {
        console.error("[auth] getAuthenticatorAssuranceLevel threw:", (err as Error).message);
        return { currentLevel: null, nextLevel: null };
      }
    })(),
    "getMfaAssuranceLevel",
    { currentLevel: null, nextLevel: null }
  );
}

export async function listMfaFactors() {
  const { data, error } = await supabase.auth.mfa.listFactors();
  if (error) {
    console.error("[auth] listFactors error:", error.message);
    return { totp: [] as NonNullable<typeof data>["totp"] };
  }
  return data;
}

/** Starts enrollment — returns a QR code (SVG data URI) and the raw secret as a manual-entry fallback. */
export async function enrollMfaTotp() {
  return supabase.auth.mfa.enroll({ factorType: "totp" });
}

/** Must be called immediately before verify() — challenges are single-use and short-lived. */
export async function challengeMfaFactor(factorId: string) {
  return supabase.auth.mfa.challenge({ factorId });
}

export async function verifyMfaFactor(factorId: string, challengeId: string, code: string) {
  return supabase.auth.mfa.verify({ factorId, challengeId, code });
}

export async function unenrollMfaFactor(factorId: string) {
  return supabase.auth.mfa.unenroll({ factorId });
}

