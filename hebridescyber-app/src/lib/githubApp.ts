// GitHub App authentication — replaces the single shared GITHUB_PAT with
// per-installation tokens scoped to only the repos each customer explicitly
// installed the app on. `generate-fix-pr.ts`, `secretScan.ts`,
// `dependencyManifest.ts`, and `dockerBaseImage.ts` all previously
// authenticated with one org-wide PAT for every customer's repo — flagged in
// each of their own header comments as a real blast-radius risk: one leaked
// token gives access to everything, and it never expires on its own.
//
// Zero-regression, opt-in: every function here falls back to GITHUB_PAT when
// GITHUB_APP_ID/GITHUB_APP_PRIVATE_KEY aren't set, or when a given repo
// doesn't have the App installed on it. Nothing breaks for a repo still on
// the "add the bot as a collaborator" flow — resolveGithubAuth() just hands
// back the same PAT it always did.
//
// No webhook, no install-callback flow. `GET /repos/{owner}/{repo}/installation`
// (authenticated as the App itself, not an installation) tells you directly
// whether — and as which installation — the App is installed on a given
// repo, so there's nothing to persist: connect-repo.ts and every scanner
// module here just ask GitHub fresh. That is simpler than the self-serve
// "Install App" redirect-and-callback flow other integrations use, at the
// cost of one extra GitHub API round-trip per repo per token — acceptable at
// this volume, and cached in-memory below regardless.
//
// No new dependency: signs the App JWT with Node's built-in crypto (RS256)
// rather than pulling in jsonwebtoken/jose, matching this repo's established
// "hand-roll it if it's this small" convention (see newsletter.ts's RSS
// parsing, action/index.js's dependency-free Node).
//
// One-time setup in the GitHub UI (cannot be done from this codebase):
//   1. Create a GitHub App at https://github.com/settings/apps/new
//      - Repository permissions: Contents (Read & write), Pull requests
//        (Read & write), Metadata (Read-only, mandatory)
//      - No webhook subscription needed — this module never receives one
//   2. Generate a private key on the App's settings page (downloads a .pem)
//      — set its full contents as GITHUB_APP_PRIVATE_KEY (Azure app setting
//      / .env.local name; the GitHub Actions secret name is different —
//      see the NAMING NOTE at the top of .env.example)
//   3. Set the App's ID (shown on the same settings page) as GITHUB_APP_ID
//      (same naming caveat as step 2)
//   4. Each customer installs the App on their repo(s) via
//      https://github.com/apps/<your-app-slug>/installations/new — this
//      replaces "add the bot account as a collaborator" as the access step
// Until that setup happens, GITHUB_PAT keeps working exactly as before.
import { createSign } from "node:crypto";

const githubApi = "https://api.github.com";
const GITHUB_API_TIMEOUT_MS = 10_000;

// GitHub rejects an App JWT with exp more than 10 minutes out; 9 leaves
// margin for clock skew between this process and GitHub's.
const APP_JWT_TTL_SECONDS = 9 * 60;
// Installation tokens are valid for 1 hour; refreshing 5 minutes early
// avoids a request racing expiry mid-flight.
const INSTALLATION_TOKEN_TTL_MS = 55 * 60 * 1000;
// Installations rarely change; re-checking every request would be one extra
// GitHub round-trip per repo per call for no real benefit.
const INSTALLATION_ID_CACHE_TTL_MS = 10 * 60 * 1000;

export function isGithubAppConfigured(): boolean {
  return Boolean(process.env.GITHUB_APP_ID && process.env.GITHUB_APP_PRIVATE_KEY);
}

function base64url(input: Buffer | string): string {
  return (Buffer.isBuffer(input) ? input : Buffer.from(input))
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Signs a short-lived JWT identifying this process as the App itself (not
 * any one installation) — the only credential that can call
 * /repos/{owner}/{repo}/installation and /app/installations/{id}/access_tokens.
 */
function signAppJwt(): string {
  const appId = process.env.GITHUB_APP_ID ?? "";
  // Private keys are commonly stored as an env var with literal "\n"
  // sequences (Azure app settings and GitHub Actions secrets both collapse
  // real newlines), so this un-escapes them back into a valid PEM.
  const privateKey = (process.env.GITHUB_APP_PRIVATE_KEY ?? "").replace(/\\n/g, "\n");

  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url(JSON.stringify({ iat: now - 60, exp: now + APP_JWT_TTL_SECONDS, iss: appId }));
  const signature = base64url(createSign("RSA-SHA256").update(`${header}.${payload}`).sign(privateKey));
  return `${header}.${payload}.${signature}`;
}

function appAuthHeaders(): Record<string, string> {
  return {
    Authorization: `Bearer ${signAppJwt()}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

const installationIdCache = new Map<string, { id: number | null; checkedAt: number }>();

/**
 * Which installation (if any) covers this repo. Returns null — never
 * throws — when the App isn't configured, isn't installed on this repo, or
 * the lookup fails for any reason; callers treat null exactly like "use
 * GITHUB_PAT instead", so a transient GitHub API hiccup degrades gracefully
 * rather than breaking a scan.
 */
async function getInstallationIdForRepo(githubRepo: string): Promise<number | null> {
  if (!isGithubAppConfigured()) return null;

  const cached = installationIdCache.get(githubRepo);
  if (cached && Date.now() - cached.checkedAt < INSTALLATION_ID_CACHE_TTL_MS) return cached.id;

  let id: number | null = null;
  try {
    const res = await fetch(`${githubApi}/repos/${githubRepo}/installation`, {
      headers: appAuthHeaders(),
      signal: AbortSignal.timeout(GITHUB_API_TIMEOUT_MS),
    });
    if (res.ok) {
      const body = (await res.json()) as { id?: number };
      id = typeof body.id === "number" ? body.id : null;
    }
  } catch {
    id = null;
  }

  installationIdCache.set(githubRepo, { id, checkedAt: Date.now() });
  return id;
}

const installationTokenCache = new Map<number, { token: string; expiresAt: number }>();

async function mintInstallationToken(installationId: number): Promise<string | null> {
  const cached = installationTokenCache.get(installationId);
  if (cached && cached.expiresAt > Date.now()) return cached.token;

  try {
    const res = await fetch(`${githubApi}/app/installations/${installationId}/access_tokens`, {
      method: "POST",
      headers: appAuthHeaders(),
      signal: AbortSignal.timeout(GITHUB_API_TIMEOUT_MS),
    });
    if (!res.ok) return null;
    const body = (await res.json()) as { token?: string };
    if (!body.token) return null;
    installationTokenCache.set(installationId, { token: body.token, expiresAt: Date.now() + INSTALLATION_TOKEN_TTL_MS });
    return body.token;
  } catch {
    return null;
  }
}

/**
 * The one function every GitHub-touching module should call for a token,
 * instead of reading process.env.GITHUB_PAT directly. Tries a GitHub App
 * installation token first; falls back to GITHUB_PAT — for a repo that
 * hasn't installed the App, one that's been uninstalled, or a deployment
 * that never configured the App at all. `via` is informational only (worth
 * surfacing in a "not_configured" note so it's obvious which path was
 * missing), never something a caller needs to branch on.
 */
export async function resolveGithubAuth(githubRepo: string): Promise<{ token: string; via: "app" | "pat" | "none" }> {
  const installationId = await getInstallationIdForRepo(githubRepo);
  if (installationId !== null) {
    const token = await mintInstallationToken(installationId);
    if (token) return { token, via: "app" };
  }
  const pat = process.env.GITHUB_PAT ?? "";
  return pat ? { token: pat, via: "pat" } : { token: "", via: "none" };
}
