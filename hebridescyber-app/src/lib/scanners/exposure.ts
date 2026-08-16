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
  // True for admin panels / debug UIs that legitimately serve HTML responses
  expectHtml?: boolean;
  goodIfPresent?: boolean;
};

// Baseline response fingerprint for the site root — used to detect SPA catch-all
// patterns where every URL returns the same homepage HTML.
type Baseline = { etag: string | null; contentLength: string | null };

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
  { path: "/.env", name: "Exposed .env file", severity: "critical", hint: "May contain DB passwords, API keys, and secrets.", bodyContains: "=" },
  { path: "/.env.local", name: "Exposed .env.local file", severity: "critical", hint: "Local environment secrets exposed.", bodyContains: "=" },
  { path: "/.env.production", name: "Exposed .env.production file", severity: "critical", hint: "Production secrets exposed.", bodyContains: "=" },
  { path: "/.env.backup", name: "Exposed .env backup", severity: "critical", hint: "Environment backup exposed.", bodyContains: "=" },
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
  { path: "/.htpasswd", name: "htpasswd file exposed", severity: "critical", hint: "Password hashes are readable — crack offline.", bodyContains: ":" },
  { path: "/.htaccess", name: "htaccess file exposed", severity: "medium", hint: "Server routing rules and auth config readable.", bodyContains: "Rewrite" },

  // ---- Log files ------------------------------------------------------------
  { path: "/storage/logs/laravel.log", name: "Laravel log exposed", severity: "high", hint: "Application logs may contain stack traces, user data, and query details.", bodyContains: "[" },
  { path: "/var/log/app.log", name: "Application log exposed", severity: "high", hint: "Application logs exposed.", bodyContains: "[" },
  { path: "/error.log", name: "Error log exposed", severity: "medium", hint: "Error log may reveal internal paths and stack traces.", bodyContains: "[" },

  // ---- Common admin panels --------------------------------------------------
  { path: "/phpmyadmin", name: "phpMyAdmin panel accessible", severity: "high", hint: "Database admin panel exposed to the internet.", bodyContains: "phpMyAdmin", expectHtml: true },
  { path: "/phpmyadmin/", name: "phpMyAdmin panel accessible", severity: "high", hint: "Database admin panel exposed.", bodyContains: "phpMyAdmin", expectHtml: true },
  { path: "/pma/", name: "phpMyAdmin panel accessible", severity: "high", hint: "Database admin panel exposed.", bodyContains: "phpMyAdmin", expectHtml: true },
  { path: "/adminer.php", name: "Adminer DB tool exposed", severity: "high", hint: "Single-file DB admin tool exposed.", bodyContains: "Adminer", expectHtml: true },
];

async function fetchBaseline(origin: string): Promise<Baseline> {
  try {
    const res = await fetch(origin + "/", {
      method: "HEAD",
      redirect: "manual",
      signal: AbortSignal.timeout(6000),
    });
    return {
      etag: res.headers.get("etag"),
      contentLength: res.headers.get("content-length"),
    };
  } catch {
    return { etag: null, contentLength: null };
  }
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

    if (target.bodyContains) {
      const text = await res.text().catch(() => "");
      if (!text.includes(target.bodyContains)) return null;
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
      securityTxt = res.status === 200;
    } catch {
      // Not present — fine.
    }

    return { status: "checked", exposed, securityTxt };
  } catch (err) {
    return { status: "error", note: `Exposure scan failed: ${(err as Error).message}` };
  }
}
