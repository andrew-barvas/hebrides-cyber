import { describe, it, expect } from "vitest";
import { acceptProblem, hashInviteToken, inviteUrl, isInviteToken, newInviteToken, type InviteRow } from "./teamInvites";

const NOW = new Date("2026-11-14T12:00:00Z");
const invite = (o: Partial<InviteRow> = {}): InviteRow => ({ id: "i1", team_id: "t1", email: "sam@example.com", role: "member", expires_at: "2026-11-28T00:00:00Z", accepted_at: null, ...o });

describe("invite tokens", () => {
  it("makes 43-character base64url tokens whose stored hash is not the token", () => {
    const { token, hash } = newInviteToken();
    expect(isInviteToken(token)).toBe(true);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash).toBe(hashInviteToken(token));
    expect(hash).not.toContain(token);
    expect(newInviteToken().token).not.toBe(token);
    for (const bad of ["", "short", "x".repeat(44), "../../etc/passwd-aaaaaaaaaaaaaaaaaaaaaaaaaa", 7]) expect(isInviteToken(bad)).toBe(false);
  });

  it("builds the join link on the site URL", () => {
    expect(inviteUrl("abc", "https://www.hebridescyber.co.uk/")).toBe("https://www.hebridescyber.co.uk/join/abc");
  });
});

describe("acceptProblem", () => {
  it("accepts the invited address, case-insensitively, before expiry", () => {
    expect(acceptProblem(invite(), " Sam@Example.com ", NOW)).toBeNull();
  });

  it("refuses unknown, used, expired and wrong-address invitations, saying why", () => {
    expect(acceptProblem(null, "sam@example.com", NOW)).toMatch(/isn't valid/);
    expect(acceptProblem(invite({ accepted_at: "2026-11-13T00:00:00Z" }), "sam@example.com", NOW)).toMatch(/already been used/);
    expect(acceptProblem(invite({ expires_at: "2026-11-14T11:59:59Z" }), "sam@example.com", NOW)).toMatch(/expired/);
    expect(acceptProblem(invite(), "someone@else.com", NOW)).toMatch(/is for sam@example.com/);
    expect(acceptProblem(invite(), null, NOW)).toMatch(/is for sam@example.com/);
  });
});
