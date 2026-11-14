// Pending team invitations (migration 074). A one-time link for someone who
// has no account yet; only its SHA-256 hash is stored.
import { createHash, randomBytes } from "node:crypto";

export const INVITE_TTL_DAYS = 14;

export function newInviteToken(): { token: string; hash: string } {
  const token = randomBytes(32).toString("base64url");
  return { token, hash: hashInviteToken(token) };
}

export function hashInviteToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** 43 base64url characters: what newInviteToken() makes. Anything else is rejected before a lookup. */
export function isInviteToken(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

export function inviteUrl(token: string, siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk"): string {
  return `${siteUrl.replace(/\/$/, "")}/join/${token}`;
}

export type InviteRow = { id: string; team_id: string; email: string; role: string; expires_at: string; accepted_at: string | null };

/** Pure: why an invite can't be accepted by this signed-in address, or null when it can. */
export function acceptProblem(invite: InviteRow | null, callerEmail: string | null | undefined, now: Date): string | null {
  if (!invite) return "This invitation link isn't valid. Ask for a new one.";
  if (invite.accepted_at) return "This invitation has already been used.";
  if (Date.parse(invite.expires_at) <= now.getTime()) return "This invitation has expired. Ask for a new one.";
  if (!callerEmail || callerEmail.trim().toLowerCase() !== invite.email) {
    return `This invitation is for ${invite.email}. Sign in with that address to accept it.`;
  }
  return null;
}
