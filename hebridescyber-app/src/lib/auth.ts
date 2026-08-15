import { supabase } from "./supabaseClient";
import type { Session, User } from "@supabase/supabase-js";

// Thin helpers around Supabase Auth, used by the dashboard pages.
// TODO: add proper error handling / toasts for production use.

export async function getSession(): Promise<Session | null> {
  const { data, error } = await supabase.auth.getSession();
  if (error) {
    console.error("[auth] getSession error:", error.message);
    return null;
  }
  return data.session;
}

export async function getUser(): Promise<User | null> {
  const { data, error } = await supabase.auth.getUser();
  if (error) return null;
  return data.user;
}

// Passwordless by design: magic link avoids the whole class of risk that
// comes with storing/reusing passwords (credential stuffing, weak reused
// passwords, etc.) — the recommended default for a small SaaS product
// without a dedicated security team managing password policy/breach
// monitoring. Google OAuth (below) is offered as a faster alternative for
// users who'd rather not check email.
export async function signInWithMagicLink(email: string) {
  const redirectTo = typeof window !== "undefined" ? `${window.location.origin}/dashboard` : undefined;
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
  const { data, error } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
  if (error) {
    console.error("[auth] getAuthenticatorAssuranceLevel error:", error.message);
    return { currentLevel: null, nextLevel: null };
  }
  return data;
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

// TODO (production hardening): sessions currently live in localStorage via
// supabase-js's default browser storage — readable by any script on the
// page (XSS risk) and not sent to the server automatically. The stronger
// pattern for Next.js is @supabase/ssr with httpOnly cookies + a proxy.ts
// (Next.js 16+ renamed middleware.ts to proxy.ts) that redirects
// unauthenticated requests server-side before a protected page even
// renders. Worth doing before this handles real
// customer accounts at scale; deferred here to keep this scaffold's auth
// surface small and easy to follow.
