"use client";

import { useCallback, useEffect, useState } from "react";

type TeamRole = "admin" | "developer" | "auditor" | "member";
type Member = { user_id: string; email: string; role: TeamRole; joined_at: string };
type OwnedTeam = { id: string; name: string; created_at: string; members: Member[] };
type Membership = { team_id: string; team_name: string; owner_email: string; role: TeamRole; joined_at: string };

// Q4 #18 (docs/24-FEATURE-EXPANSION-SPEC.md) — shown next to the role select
// so "developer" and "auditor" aren't cryptic labels; the API routes
// (src/lib/teamAccess.ts) are what actually enforce this, not this UI.
const ROLE_LABELS: Record<TeamRole, string> = {
  member: "Member (view only)",
  auditor: "Auditor (view only, plus exec/compliance views)",
  developer: "Developer (can replay scans, retest findings, create tickets)",
  admin: "Admin (can invite/remove members)",
};

export default function TeamSection({ token, currentUserId }: { token: string; currentUserId: string }) {
  const [ownedTeam, setOwnedTeam] = useState<OwnedTeam | null>(null);
  const [memberships, setMemberships] = useState<Membership[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [teamName, setTeamName] = useState("");
  const [creating, setCreating] = useState(false);

  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<TeamRole>("member");
  const [inviting, setInviting] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/team", { headers: { Authorization: `Bearer ${token}` } });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not load team");
      setOwnedTeam(body.owned_team);
      setMemberships(body.memberships ?? []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    load();
  }, [load]);

  async function createTeam(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    setError(null);
    try {
      const res = await fetch("/api/team", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ name: teamName }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not create team");
      setTeamName("");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setCreating(false);
    }
  }

  async function invite(e: React.FormEvent) {
    e.preventDefault();
    if (!ownedTeam) return;
    setInviting(true);
    setError(null);
    try {
      const res = await fetch("/api/team/members", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ team_id: ownedTeam.id, email: inviteEmail, role: inviteRole }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not add member");
      setInviteEmail("");
      setInviteRole("member");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setInviting(false);
    }
  }

  async function changeRole(userId: string, role: TeamRole) {
    if (!ownedTeam) return;
    setError(null);
    try {
      const res = await fetch("/api/team/members", {
        method: "PATCH",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ team_id: ownedTeam.id, user_id: userId, role }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not change role");
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function removeMember(teamId: string, userId: string) {
    setError(null);
    try {
      const res = await fetch("/api/team/members", {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ team_id: teamId, user_id: userId }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not remove member");
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <section className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <h2 className="mb-4 font-mono text-xs text-cybermuted uppercase tracking-wide">// team</h2>

      <p className="mb-4 text-xs text-cybertext/50 leading-relaxed">
        Share your scans, reports, and monitored targets with colleagues,
        read-only — they see the same security posture you do, without your
        login. Billing, API keys, and webhooks stay private to you.
      </p>

      {error && <p className="mb-3 text-xs text-red-400" role="alert">{error}</p>}

      {loading ? (
        <p className="font-mono text-xs text-cybermuted">// loading…</p>
      ) : (
        <>
          {!ownedTeam && (
            <form onSubmit={createTeam} className="flex flex-wrap gap-2">
              <input
                type="text"
                required
                maxLength={60}
                value={teamName}
                onChange={(e) => setTeamName(e.target.value)}
                placeholder="Team name (e.g. Acme Security)"
                className="min-w-0 w-full sm:min-w-[200px] flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-hidden transition-colors"
              />
              <button
                type="submit"
                disabled={creating || !teamName.trim()}
                className="rounded-md bg-neon px-4 py-2 text-sm font-semibold text-cyberbg shadow-glowsm hover:opacity-90 disabled:opacity-40 transition-opacity"
              >
                {creating ? "Creating…" : "Create team"}
              </button>
            </form>
          )}

          {ownedTeam && (
            <div>
              <p className="mb-3 text-sm font-medium text-cybertext/80">{ownedTeam.name}</p>

              <form onSubmit={invite} className="mb-4 flex flex-wrap gap-2">
                <input
                  type="email"
                  required
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  placeholder="colleague@example.com"
                  className="min-w-0 w-full sm:min-w-[200px] flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-hidden transition-colors"
                />
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as TeamRole)}
                  className="w-full sm:w-auto rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext focus:border-neon focus:outline-hidden transition-colors"
                >
                  {(["member", "auditor", "developer", "admin"] as const).map((role) => (
                    <option key={role} value={role}>{ROLE_LABELS[role]}</option>
                  ))}
                </select>
                <button
                  type="submit"
                  disabled={inviting || !inviteEmail.trim()}
                  className="rounded-md bg-neon px-4 py-2 text-sm font-semibold text-cyberbg shadow-glowsm hover:opacity-90 disabled:opacity-40 transition-opacity"
                >
                  {inviting ? "Adding…" : "Add"}
                </button>
              </form>
              <p className="mb-4 -mt-2 text-xs text-cybermuted">
                They need an existing Hebrides Cyber account — ask them to sign up first if adding fails.
              </p>

              {ownedTeam.members.length === 0 ? (
                <p className="text-xs text-cybermuted">No members yet — it&apos;s just you.</p>
              ) : (
                <ul className="divide-y divide-cyberborder rounded-lg border border-cyberborder">
                  {ownedTeam.members.map((m) => (
                    <li key={m.user_id} className="flex flex-wrap items-center justify-between gap-2 p-3">
                      <p className="text-sm text-cybertext/80 break-all">{m.email}</p>
                      <div className="flex shrink-0 items-center gap-3">
                        <select
                          value={m.role}
                          onChange={(e) => changeRole(m.user_id, e.target.value as TeamRole)}
                          className="rounded-sm border border-cyberborder bg-cyberbg px-2 py-1 text-xs text-cybertext/70 focus:border-neon focus:outline-hidden transition-colors"
                        >
                          <option value="member">Member</option>
                          <option value="auditor">Auditor</option>
                          <option value="developer">Developer</option>
                          <option value="admin">Admin</option>
                        </select>
                        <button
                          onClick={() => removeMember(ownedTeam.id, m.user_id)}
                          className="text-xs text-cybermuted hover:text-red-400 transition-colors"
                        >
                          Remove
                        </button>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {memberships.length > 0 && (
            <div className={ownedTeam ? "mt-5 pt-5 border-t border-cyberborder" : ""}>
              <p className="mb-2 text-xs font-semibold text-cybertext/50 uppercase tracking-wide">
                Teams you&apos;ve been added to
              </p>
              <ul className="divide-y divide-cyberborder rounded-lg border border-cyberborder">
                {memberships.map((m) => (
                  <li key={m.team_id} className="flex flex-wrap items-center justify-between gap-2 p-3">
                    <div>
                      <p className="text-sm text-cybertext/80">{m.team_name}</p>
                      <p className="text-xs text-cybermuted">
                        owned by {m.owner_email} · {m.role}
                      </p>
                    </div>
                    <button
                      onClick={() => removeMember(m.team_id, currentUserId)}
                      className="text-xs text-cybermuted hover:text-red-400 transition-colors"
                    >
                      Leave
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </section>
  );
}
