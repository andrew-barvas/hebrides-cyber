// Which connected repository belongs to which site (migration 077).
//
// Before this, every non-safe scan used the owner's most recently connected
// repository whatever site it was scanning, so repo findings (SAST, Trivy,
// secrets, dependencies) landed on unrelated sites: a church website showed
// 28 critical findings from the scanner's own code. A repository is now used
// only for the site it is linked to; an unlinked repository is never used.
//
// Pure, so scanExecution.ts, the scan page and connect-repo.ts agree.

export type RepoConnectionRow = { github_repo: string; target_host: string | null; connected_at?: string | null };

/** "https://www.Example.com/x" or "example.com" → "www.example.com" / "example.com"; null when it isn't a hostname. */
export function repoTargetHost(input: string): string | null {
  const raw = input.trim();
  if (!raw) return null;
  let host: string;
  try {
    host = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`).hostname.toLowerCase();
  } catch {
    return null;
  }
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(host) ? host : null;
}

const bare = (host: string) => host.replace(/^www\./, "");

/** Same site, treating www.example.com and example.com as one. */
export function sameSite(a: string | null, b: string | null): boolean {
  return Boolean(a && b) && bare(a as string) === bare(b as string);
}

/** The repository linked to this scan's site, newest link first; null when none is. */
export function pickRepoForTarget(connections: readonly RepoConnectionRow[], targetUrl: string): string | null {
  const host = repoTargetHost(targetUrl);
  if (!host) return null;
  const linked = connections
    .filter((c) => sameSite(c.target_host, host))
    .sort((x, y) => (y.connected_at ?? "").localeCompare(x.connected_at ?? ""));
  return linked[0]?.github_repo ?? null;
}
