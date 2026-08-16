// Sensitive file exposure scanner — probes for commonly exposed files that
// should never be publicly accessible: git repos, env files, backups,
// debug pages, and admin panels. Uses only HTTP fetch — no binary tools.

export type ExposureResult =
  | { status: "checked"; exposed: ExposedFile[]; securityTxt: boolean }
  | { status: "error"; note: string };

export type ExposedFile = {
  path: string;
  name: string;
  severity: "critical" | "high" | "medium" | "info";
  hint: string;
};

type ProbeTarget = {
  path: string;
  name: string;
  severity: ExposedFile["severity"];
  hint: string;
  // Body must contain this string to be flagged (avoids 200-for-everything CMS/SPA pages)
  bodyContains?: string;
  // Stronger form of bodyContains — the body must structurally match the file
  // format we claim to have found. Use for formats where a single substring is
  // too weak a signal (e.g. "=" appears in every HTML page ever written).
  bodyPattern?: RegExp;
  // True for admin panels / debug UIs that legitimately serve HTML responses
  expectHtml?: boolean;
  goodIfPresent?: boolean;
};

// Baseline response fingerprint for the site root plus a known-nonexistent path.
// Used to detect catch-all patterns where every URL returns the same shell.
type Baseline = {
  etag: string | null;
  contentLength: string | null;
  // Body of a URL that definitely does not exist. If a probe response matches
  // this, the server is serving a catch-all and the "finding" is a phantom.
  notFoundBody: string | null;
  // True when the catch-all probe returned HTTP 200 for a random path — the
  // server never 404s, so status alone carries no information.
  servesCatchAll: boolean;
};

// An env var assignment at the start of a line: KEY=..., export KEY=...
// Real .env files match this; HTML shells with an "=" in an attribute do not.
const ENV_ASSIGNMENT = /^(?:export\s+)?[A-Z_][A-Z0-9_]{2,}\s*=/m;

const PROBE_TARGETS: ProbeTarget[] = [
  // ---- Git / version control ------------------------------------------------
  {
    path: "/.git/HEAD",
    name: "Exposed Git repository",
    severity: "critical",
    hint: "Source code, secrets, and commit history are accessible. Restrict with server config.",
    bodyContains: "ref:",
  },
  {
    path: "/.git/config",
    name: "Exposed Git config",
    severity: "critical",
    hint: "Git remote URLs (and potentially credentials) are readable.",
    bodyContains: "[core]",
  },
  {
    path: "/.svn/entries",
    name: "Exposed Subversion repository",
    severity: "critical",
    hint: "SVN repo metadata and file tree are accessible.",
    bodyContains: "svn",
  },

  // ---- Environment / config files ------------------------------------------
  { path: "/.env", name: "Exposed .env file", severity: "critical", hint: "May contain DB passwords, API keys, and secrets.", bodyPattern: ENV_ASSIGNMENT },
  { path: "/.env.local", name: "Exposed .env.local file", severity: "critical", hint: "Local environment secrets exposed.", bodyPattern: ENV_ASSIGNMENT },
  { path: "/.env.production", name: "Exposed .env.production file", severity: "critical", hint: "Production secrets exposed.", bodyPattern: ENV_ASSIGNMENT },
  { path: "/.env.backup", name: "Exposed .env backup", severity: "critical", hint: "Environment backup exposed.", bodyPattern: ENV_ASSIGNMENT },
  { path: "/config.php", name: "PHP config file exposed", severity: "high", hint: "May contain database credentials.", bodyContains: "<?php" },
  { path: "/configuration.php", name: "Joomla config exposed", severity: "critical", hint: "Joomla DB credentials likely readable.", bodyContains: "<?php" },
  { path: "/database.yml", name: "Database config exposed", severity: "critical", hint: "Rails/other DB credentials in plaintext.", bodyContains: "adapter:" },
  { path: "/config/database.yml", name: "Database config exposed", severity: "critical", hint: "Rails/other DB credentials in plaintext.", bodyContains: "adapter:" },
  { path: "/wp-config.php.bak", name: "WordPress config backup", severity: "critical", hint: "WordPress DB credentials in backup file.", bodyContains: "DB_" },
  { path: "/wp-config.php~", name: "WordPress config backup", severity: "critical", hint: "WordPress DB credentials in editor backup.", bodyContains: "DB_" },
  { path: "/settings.py", name: "Django settings exposed", severity: "high", hint: "May contain SECRET_KEY and DB credentials.", bodyContains: "SECRET_KEY" },

  // ---- Backup archives -------------------------------------------------------
  // Binary files — content-type and ETag checks eliminate SPA false positives.
  { path: "/backup.zip", name: "Site backup archive", severity: "high", hint: "Full site backup may contain all source code and config files." },
  { path: "/backup.tar.gz", name: "Site backup archive", severity: "high", hint: "Full site backup exposed." },
  { path: "/backup.sql", name: "Database dump exposed", severity: "critical", hint: "Raw SQL dump — full database contents readable.", bodyContains: "INSERT INTO" },
  { path: "/dump.sql", name: "Database dump exposed", severity: "critical", hint: "Raw SQL dump exposed.", bodyContains: "INSERT INTO" },
  { path: "/site.zip", name: "Site backup archive", severity: "high", hint: "Site backup archive exposed." },
  { path: "/www.zip", name: "Site backup archive", severity: "high", hint: "Site backup archive exposed." },

  // ---- Debug / admin pages --------------------------------------------------
  { path: "/phpinfo.php", name: "PHP info page", severity: "high", hint: "Reveals server configuration, PHP version, loaded modules, and env variables.", bodyContains: "PHP Version", expectHtml: true },
  { path: "/info.php", name: "PHP info page", severity: "high", hint: "phpinfo() output reveals server internals.", bodyContains: "PHP Version", expectHtml: true },
  { path: "/server-status", name: "Apache server-status", severity: "high", hint: "Reveals active connections, request URIs, and client IPs.", bodyContains: "Apache Server Status", expectHtml: true },
  { path: "/server-info", name: "Apache server-info", severity: "high", hint: "Reveals Apache configuration and loaded modules.", bodyContains: "Apache Server Information", expectHtml: true },
  { path: "/_profiler", name: "Symfony profiler", severity: "high", hint: "Debug profiler exposes request data, env vars, and SQL queries.", bodyContains: "Symfony", expectHtml: true },
  { path: "/telescope", name: "Laravel Telescope", severity: "high", hint: "Laravel debug dashboard — may expose queries and job data.", bodyContains: "Telescope", expectHtml: true },
  { path: "/.well-known/security.txt", name: "security.txt present", severity: "info", hint: "Good practice — security contact info is discoverable.", goodIfPresent: true },

  // ---- Authentication files --------------------------------------------------
  // user:$apr1$... / user:$2y$... — an htpasswd line, not just any colon.
  { path: "/.htpasswd", name: "htpasswd file exposed", severity: "critical", hint: "Password hashes are readable — crack offline.", bodyPattern: /^[^\s:]+:(?:\$[0-9a-z]{1,4}\$|\{SHA\}|[A-Za-z0-9./]{13}$)/m },
  { path: "/.htaccess", name: "htaccess file exposed", severity: "medium", hint: "Server routing rules and auth config readable.", bodyContains: "Rewrite" },

  // ---- Log files ------------------------------------------------------------
  // Log lines start with a bracketed or ISO timestamp — "[" alone matches any JS bundle.
  { path: "/storage/logs/laravel.log", name: "Laravel log exposed", severity: "high", hint: "Application logs may contain stack traces, user data, and query details.", bodyPattern: /^\[\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/m },
  { path: "/var/log/app.log", name: "Application log exposed", severity: "high", hint: "Application logs exposed.", bodyPattern: /^\[?\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/m },
  { path: "/error.log", name: "Error log exposed", severity: "medium", hint: "Error log may reveal internal paths and stack traces.", bodyPattern: /^\[?\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|^\[[A-Z][a-z]{2} [A-Z][a-z]{2} ?\d/m },

  // ---- Common admin panels --------------------------------------------------
  { path: "/phpmyadmin", name: "phpMyAdmin panel accessible", severity: "high", hint: "Database admin panel exposed to the internet.", bodyContains: "phpMyAdmin", expectHtml: true },
  { path: "/phpmyadmin/", name: "phpMyAdmin panel accessible", severity: "high", hint: "Database admin panel exposed.", bodyContains: "phpMyAdmin", expectHtml: true },
  { path: "/pma/", name: "phpMyAdmin panel accessible", severity: "high", hint: "Database admin panel exposed.", bodyContains: "phpMyAdmin", expectHtml: true },
  { path: "/adminer.php", name: "Adminer DB tool exposed", severity: "high", hint: "Single-file DB admin tool exposed.", bodyContains: "Adminer", expectHtml: true },
];

/**
 * Collapse whitespace, strip the requested path, and cap length, so two
 * renders of the same shell compare equal.
 *
 * Stripping the path matters: SPA shells routinely echo the requested URL back
 * into the markup (router state, a canonical link, an error message). That
 * makes every probe's body differ from the baseline's, and it also means a
 * probe for "/.svn/entries" contains the substring "svn" — which is exactly
 * what the bodyContains check is looking for. Masking the path removes both
 * problems at once.
 */
function normaliseBody(body: string, requestPath: string): string {
  let out = body.replace(/\s+/g, " ").trim();
  for (const variant of [requestPath, encodeURIComponent(requestPath), requestPath.replace(/^\//, "")]) {
    if (variant.length < 3) continue;
    out = out.split(variant).join(" PATH ");
  }
  return out.slice(0, 4000);
}

/** Length of the longest shared prefix of two strings. */
function commonPrefixLen(a: string, b: string): number {
  const max = Math.min(a.length, b.length);
  let i = 0;
  while (i < max && a[i] === b[i]) i++;
  return i;
}

/** Length of the longest shared suffix of two strings. */
function commonSuffixLen(a: string, b: string): number {
  const max = Math.min(a.length, b.length);
  let i = 0;
  while (i < max && a[a.length - 1 - i] === b[b.length - 1 - i]) i++;
  return i;
}

/**
 * True when two response bodies are almost certainly the same document.
 *
 * After path masking most catch-all shells compare byte-identical. The
 * prefix/suffix test covers what's left: a nonce, build hash, or CSRF token
 * embedded mid-document, which leaves a small variable region between two
 * large identical stretches.
 */
function looksLikeSameDocument(a: string, b: string): boolean {
  if (!a || !b) return false;
  if (a === b) return true;

  const shorter = Math.min(a.length, b.length);
  if (shorter < 80) return false; // too little signal to judge

  const shared = commonPrefixLen(a, b) + commonSuffixLen(a, b);
  return shared >= shorter * 0.85;
}

/**
 * Fingerprints the site root AND a URL that cannot exist. The second request is
 * what stops us reporting "/.env exposed" on every SPA on the internet: if a
 * random path returns 200 with the app shell, then so will /.env, and the only
 * way to tell a real finding from the shell is to compare the bodies.
 */
async function fetchBaseline(origin: string): Promise<Baseline> {
  const randomSlug = `/hc-probe-${crypto.randomUUID()}`;

  const [rootRes, notFoundRes] = await Promise.allSettled([
    fetch(origin + "/", {
      method: "HEAD",
      redirect: "manual",
      signal: AbortSignal.timeout(6000),
    }),
    fetch(origin + randomSlug, {
      redirect: "manual",
      signal: AbortSignal.timeout(6000),
    }),
  ]);

  const etag = rootRes.status === "fulfilled" ? rootRes.value.headers.get("etag") : null;
  const contentLength = rootRes.status === "fulfilled" ? rootRes.value.headers.get("content-length") : null;

  let notFoundBody: string | null = null;
  let servesCatchAll = false;
  if (notFoundRes.status === "fulfilled") {
    servesCatchAll = notFoundRes.value.status === 200;
    if (servesCatchAll) {
      notFoundBody = await notFoundRes.value
        .text()
        .then((t) => normaliseBody(t, randomSlug))
        .catch(() => null);
    }
  }

  return { etag, contentLength, notFoundBody, servesCatchAll };
}

async function probeFile(baseUrl: string, target: ProbeTarget, baseline: Baseline): Promise<ExposedFile | null> {
  const url = baseUrl.replace(/\/$/, "") + target.path;
  try {
    const res = await fetch(url, {
      redirect: "manual", // don't follow — a 301 to homepage is not exposure
      signal: AbortSignal.timeout(6000),
    });

    if (res.status !== 200) return null;

    // Files like .env, .git, backups are never legitimately served as text/html.
    // A text/html response for these paths = SPA/CMS catch-all, not real exposure.
    const contentType = res.headers.get("content-type") ?? "";
    if (contentType.includes("text/html") && !target.expectHtml) return null;

    // Belt-and-suspenders: if the probe response has the same ETag or Content-Length
    // as the site root, the server is returning the homepage for all paths.
    const resEtag = res.headers.get("etag");
    if (baseline.etag && resEtag && resEtag === baseline.etag) return null;
    if (!baseline.etag && baseline.contentLength) {
      const resLen = res.headers.get("content-length");
      if (resLen && resLen === baseline.contentLength) return null;
    }

    // Read the body when we have something to check it against. Targets with no
    // content assertion still need reading if the server 200s for everything,
    // otherwise a catch-all would be reported as an exposed backup archive.
    const needsBody =
      Boolean(target.bodyContains) || Boolean(target.bodyPattern) || baseline.servesCatchAll;

    if (needsBody) {
      const text = await res.text().catch(() => "");

      // The decisive check: this path returns the same document as a URL we know
      // does not exist, so nothing is actually exposed here.
      const masked = normaliseBody(text, target.path);
      if (baseline.notFoundBody && looksLikeSameDocument(masked, baseline.notFoundBody)) {
        return null;
      }

      // Match content assertions against the masked body so a shell that echoes
      // the URL cannot satisfy them with the probe path itself.
      if (target.bodyContains && !masked.includes(target.bodyContains)) return null;
      if (target.bodyPattern && !target.bodyPattern.test(text)) return null;

      // No content assertion available and the server 200s for everything —
      // we cannot prove exposure, so stay silent rather than guess.
      if (!target.bodyContains && !target.bodyPattern && baseline.servesCatchAll) return null;
    }

    return { path: target.path, name: target.name, severity: target.severity, hint: target.hint };
  } catch {
    return null; // Network errors are not findings.
  }
}

export async function checkExposure(targetUrl: string): Promise<ExposureResult> {
  try {
    const origin = new URL(targetUrl).origin;

    // Fetch the site root fingerprint before probing — used to detect catch-all 200s
    const baseline = await fetchBaseline(origin);

    const results = await Promise.allSettled(PROBE_TARGETS.map((t) => probeFile(origin, t, baseline)));

    const exposed: ExposedFile[] = results
      .filter((r): r is PromiseFulfilledResult<ExposedFile> => r.status === "fulfilled" && r.value !== null)
      .map((r) => r.value);

    // Check security.txt separately as info (present = good)
    const securityTxtTarget = PROBE_TARGETS.find((t) => t.path === "/.well-known/security.txt")!;
    const securityTxtUrl = origin + securityTxtTarget.path;
    let securityTxt = false;
    try {
      const res = await fetch(securityTxtUrl, { signal: AbortSignal.timeout(4000) });
      if (res.status === 200) {
        // A real security.txt declares at least a Contact: field. Without this
        // check every SPA catch-all would be credited with having one.
        const text = await res.text().catch(() => "");
        securityTxt = /^Contact:\s*\S/im.test(text);
      }
    } catch {
      // Not present — fine.
    }

    return { status: "checked", exposed, securityTxt };
  } catch (err) {
    return { status: "error", note: `Exposure scan failed: ${(err as Error).message}` };
  }
}
