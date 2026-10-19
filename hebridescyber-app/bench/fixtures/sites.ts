// Fixture sites for the accuracy benchmark. Each site is a plain
// node:http request handler with deliberately seeded behaviour — a real
// misconfiguration the scanner must report, or a known false-positive trap it
// must stay silent on. Everything is served from 127.0.0.1 so the default run
// needs no internet access.
import type { IncomingMessage, ServerResponse } from "node:http";

export type SiteHandler = (req: IncomingMessage, res: ServerResponse) => void;

type Headers = Record<string, string | string[]>;

function send(req: IncomingMessage, res: ServerResponse, status: number, headers: Headers, body: string): void {
  res.writeHead(status, { ...headers, "content-length": String(Buffer.byteLength(body)) });
  res.end(req.method === "HEAD" ? undefined : body);
}

const HTML = { "content-type": "text/html; charset=utf-8" };
const TEXT = { "content-type": "text/plain; charset=utf-8" };

/** A complete, correct set of security headers. */
export const SECURE_HEADERS: Headers = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "geolocation=(), camera=()",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "cross-origin-embedder-policy": "require-corp",
  "cache-control": "no-store",
};

function pathOf(req: IncomingMessage): string {
  return new URL(req.url ?? "/", "http://fixture.invalid").pathname;
}

const HOME = `<!doctype html><html><head><title>Fixture</title></head><body><h1>Welcome</h1><p>Static page.</p></body></html>`;

/** Well-configured static site: proper 404s, full headers, security.txt. */
export const hardened: SiteHandler = (req, res) => {
  const p = pathOf(req);
  if (p === "/") return send(req, res, 200, { ...HTML, ...SECURE_HEADERS }, HOME);
  if (p === "/.well-known/security.txt") {
    return send(req, res, 200, { ...TEXT, ...SECURE_HEADERS }, "Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n");
  }
  if (p === "/robots.txt") return send(req, res, 200, { ...TEXT, ...SECURE_HEADERS }, "User-agent: *\nAllow: /\n");
  return send(req, res, 404, { ...HTML, ...SECURE_HEADERS }, "<!doctype html><title>Not found</title><p>Not found</p>");
};

/**
 * Single-page app: every unknown path returns the same 200 shell, which echoes
 * the requested URL back (router state) — the classic false-positive trap for
 * path-probing checks. Nothing is exposed.
 */
export const spaCatchAll: SiteHandler = (req, res) => {
  const p = pathOf(req);
  const shell = `<!doctype html><html><head><title>App</title><script>window.__ROUTE__=${JSON.stringify(p)}</script></head><body><div id="root" data-path="${p}"></div><script src="/static/app.js"></script></body></html>`;
  return send(req, res, 200, { ...HTML }, shell);
};

/** A GraphQL server at /graphql; the two fixtures below differ only in what they expose. */
function graphqlSite(opts: { introspection: boolean; suggestions: boolean; ide: boolean }): SiteHandler {
  return (req, res) => {
    const p = pathOf(req);
    if (p === "/graphql" && req.method === "POST") {
      let raw = "";
      req.on("data", (c) => (raw += c));
      req.on("end", () => {
        const json = { "content-type": "application/json" };
        if (raw.includes("__schema")) {
          const body = opts.introspection ? { data: { __schema: { types: [{ name: "Query" }, { name: "User" }] } } } : { errors: [{ message: "GraphQL introspection is not allowed" }] };
          return send(req, res, 200, json, JSON.stringify(body));
        }
        if (raw.includes("__typenam }")) {
          const message = opts.suggestions ? 'Cannot query field "__typenam" on type "Query". Did you mean "__typename"?' : 'Cannot query field "__typenam" on type "Query".';
          return send(req, res, 400, json, JSON.stringify({ errors: [{ message }] }));
        }
        return send(req, res, 200, json, JSON.stringify({ data: { __typename: "Query" } }));
      });
      return;
    }
    if (opts.ide && p === "/graphiql") return send(req, res, 200, { ...HTML }, "<!doctype html><title>GraphiQL</title><div id=graphiql></div>");
    if (p === "/") return send(req, res, 200, { ...HTML }, HOME);
    return send(req, res, 404, { ...HTML }, "<h1>Not found</h1>");
  };
}

/** GraphQL with introspection, field suggestions and GraphiQL all open. */
export const graphqlOpen: SiteHandler = graphqlSite({ introspection: true, suggestions: true, ide: true });
/** GraphQL with introspection off, no suggestions and no IDE: nothing to report. */
export const graphqlLocked: SiteHandler = graphqlSite({ introspection: false, suggestions: false, ide: false });

/** SPA catch-all whose shell embeds a per-request nonce (defeats byte-equal comparison). */
export const spaCatchAllNonce: SiteHandler = (req, res) => {
  const p = pathOf(req);
  const nonce = Math.random().toString(36).slice(2);
  const filler = "<p>Loading application assets, please wait while the bundle initialises.</p>".repeat(8);
  const shell = `<!doctype html><html><head><title>App</title><meta name="csrf" content="${nonce}"></head><body>${filler}<div id="root" data-route="${p}"></div>${filler}</body></html>`;
  return send(req, res, 200, { ...HTML }, shell);
};

/** Soft-404: unknown paths get a 200 "page not found" HTML page. */
export const soft404: SiteHandler = (req, res) => {
  const p = pathOf(req);
  if (p === "/") return send(req, res, 200, { ...HTML, ...SECURE_HEADERS }, HOME);
  return send(
    req,
    res,
    200,
    { ...HTML, ...SECURE_HEADERS },
    `<!doctype html><html><head><title>Oops</title></head><body><h1>Sorry, we could not find that page.</h1><p>Requested: ${p}</p></body></html>`
  );
};

/** Every unknown path redirects to the homepage (not an exposure). */
export const redirectAll: SiteHandler = (req, res) => {
  const p = pathOf(req);
  if (p === "/") return send(req, res, 200, { ...HTML, ...SECURE_HEADERS }, HOME);
  return send(req, res, 302, { location: "/", ...SECURE_HEADERS }, "");
};

const AUTOINDEX_APACHE = (dir: string) =>
  `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html><head><title>Index of ${dir}</title></head><body><h1>Index of ${dir}</h1><pre><a href="?C=N;O=D">Name</a><hr><a href="/">Parent Directory</a>\n<a href="a.zip">a.zip</a>\n<a href="b.txt">b.txt</a>\n</pre></body></html>`;

/**
 * Legacy PHP-on-Apache box with a long list of seeded misconfigurations:
 * missing headers, leaked secrets and dumps, debug pages, directory listing,
 * wildcard CORS, dangerous methods, verbose errors, insecure cookies.
 */
export const seededLegacy: SiteHandler = (req, res) => {
  const p = pathOf(req);
  const base: Headers = {
    server: "Apache/2.2.15 (CentOS)",
    "x-powered-by": "PHP/5.3.3",
    "access-control-allow-origin": "*",
    "set-cookie": "PHPSESSID=abc123; Path=/",
  };
  if (req.method === "OPTIONS") {
    return send(req, res, 200, { ...base, allow: "GET, POST, PUT, DELETE, OPTIONS" }, "");
  }
  switch (p) {
    case "/":
      return send(req, res, 200, { ...HTML, ...base }, `<!doctype html><html><head><title>Legacy</title></head><body><form method="post" action="/login.php"><input name="user"><input type="password" name="pass"></form></body></html>`);
    case "/.env":
      return send(req, res, 200, { ...TEXT, ...base }, "APP_ENV=production\nDB_PASSWORD=hunter2\nSECRET_KEY=abcdef123456\n");
    case "/.git/HEAD":
      return send(req, res, 200, { ...TEXT, ...base }, "ref: refs/heads/main\n");
    case "/.git/config":
      return send(req, res, 200, { ...TEXT, ...base }, "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://example.com/x.git\n");
    case "/backup.sql":
      return send(req, res, 200, { "content-type": "application/sql", ...base }, "INSERT INTO users VALUES (1,'admin','x');\n");
    case "/phpinfo.php":
      return send(req, res, 200, { ...HTML, ...base }, "<html><body><h1>PHP Version 5.3.3</h1><table></table></body></html>");
    case "/uploads/":
      return send(req, res, 200, { ...HTML, ...base }, AUTOINDEX_APACHE("/uploads/"));
    case "/backups/":
      return send(req, res, 200, { ...HTML, ...base }, AUTOINDEX_APACHE("/backups/"));
    case "/robots.txt":
      return send(req, res, 200, { ...TEXT, ...base }, "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /private/\n");
    default:
      return send(
        req,
        res,
        404,
        { ...HTML, ...base },
        `<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><pre>Fatal error: Uncaught exception in /var/www/html/index.php on line 42\nStack trace:\n#0 {main}</pre><address>Apache/2.2.15 (CentOS) Server at localhost Port 80</address></body></html>`
      );
  }
};

/**
 * SPA catch-all that ALSO genuinely leaks /.env and /backup.sql. The leak must
 * still be reported — over-hardening against catch-alls must not cost recall.
 */
export const spaWithLeak: SiteHandler = (req, res) => {
  const p = pathOf(req);
  if (p === "/.env") return send(req, res, 200, { ...TEXT }, "STRIPE_SECRET=sk_test_123456\nDATABASE_URL=postgres://u:p@h/db\n");
  if (p === "/backup.sql") return send(req, res, 200, { "content-type": "application/octet-stream" }, "-- dump\nINSERT INTO accounts VALUES (1,'a');\n");
  return spaCatchAll(req, res);
};

/** nginx-style autoindex on /assets/ only; otherwise a normal hardened site. */
export const nginxAutoindex: SiteHandler = (req, res) => {
  const p = pathOf(req);
  if (p === "/assets/") {
    return send(
      req,
      res,
      200,
      { ...HTML, ...SECURE_HEADERS, server: "nginx" },
      `<html><head><title>Index of /assets/</title></head><body><h1>Index of /assets/</h1><hr><pre><a href="../">../</a>\n<a href="logo.png">logo.png</a>\n<a href="site.css">site.css</a>\n</pre><hr></body></html>`
    );
  }
  return hardened(req, res);
};

/** Reflects any Origin with credentials allowed — real CORS misconfiguration. */
export const corsReflect: SiteHandler = (req, res) => {
  const origin = req.headers.origin;
  const h: Headers = { ...SECURE_HEADERS };
  if (typeof origin === "string") {
    h["access-control-allow-origin"] = origin;
    h["access-control-allow-credentials"] = "true";
  }
  if (pathOf(req) === "/") return send(req, res, 200, { ...HTML, ...h }, HOME);
  return send(req, res, 404, { ...HTML, ...h }, "<!doctype html><title>Not found</title>");
};

const NOT_FOUND = "<!doctype html><title>Not found</title>";

const LOGIN_PAGE = (csrf: boolean) =>
  `<!doctype html><html><head><title>Sign in</title></head><body><form method="post" action="/login">${
    csrf ? '<input type="hidden" name="csrf_token" value="tok123">' : ""
  }<input name="username"></form></body></html>`;

/** Login form with no CSRF token whose POST handler never throttles. */
export const loginUnthrottled: SiteHandler = (req, res) => {
  const p = pathOf(req);
  if (p === "/") return send(req, res, 200, { ...HTML, ...SECURE_HEADERS }, LOGIN_PAGE(false));
  if (p === "/login") {
    if (req.method === "POST") return send(req, res, 401, { ...SECURE_HEADERS }, "invalid credentials");
    return send(req, res, 200, { ...HTML, ...SECURE_HEADERS }, LOGIN_PAGE(false));
  }
  return send(req, res, 404, { ...HTML, ...SECURE_HEADERS }, NOT_FOUND);
};

/** Login form with a CSRF token whose POST handler answers 429 after two attempts. */
export function createLoginThrottled(): SiteHandler {
  let attempts = 0;
  return (req, res) => {
    const p = pathOf(req);
    if (p === "/") return send(req, res, 200, { ...HTML, ...SECURE_HEADERS }, LOGIN_PAGE(true));
    if (p === "/login") {
      if (req.method === "POST") {
        attempts += 1;
        if (attempts > 2) return send(req, res, 429, { ...SECURE_HEADERS, "retry-after": "60" }, "slow down");
        return send(req, res, 401, { ...SECURE_HEADERS }, "invalid credentials");
      }
      return send(req, res, 200, { ...HTML, ...SECURE_HEADERS }, LOGIN_PAGE(true));
    }
    return send(req, res, 404, { ...HTML, ...SECURE_HEADERS }, NOT_FOUND);
  };
}

/** Client-rendered login: every POST just re-serves the page with 200 (no credential handling). */
export const spaLogin: SiteHandler = (req, res) => {
  const p = pathOf(req);
  return send(req, res, 200, { ...HTML, ...SECURE_HEADERS }, `<!doctype html><html><body><div id="root" data-p="${p}"></div></body></html>`);
};

/**
 * A hardened site that has nonetheless been compromised: its homepage carries
 * three injected-content traces the crawler's malware check (injectedContent.ts)
 * must catch, all in the HTML a visitor receives — nothing is executed or fetched:
 *   - a hidden, cross-origin iframe (display:none, off-site src);
 *   - an obfuscated inline script (a long base64 payload handed to eval(atob()));
 *   - a hidden <div> of off-site SEO-spam links.
 * It is otherwise hardened (full headers, security.txt, real 404s) so the ONLY
 * findings are tls.no-https (every loopback fixture is HTTP) and the three
 * malware.* ones — the off-site hosts are never contacted (the check is pure
 * HTML parsing), so this stays loopback-only. The miner and defacement rules
 * must stay silent: the page carries no miner host/API name and an ordinary
 * <title>, so this also guards those two rules against over-firing.
 */
export const compromised: SiteHandler = (req, res) => {
  const p = pathOf(req);
  if (p === "/.well-known/security.txt") {
    return send(req, res, 200, { ...TEXT, ...SECURE_HEADERS }, "Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n");
  }
  if (p === "/robots.txt") return send(req, res, 200, { ...TEXT, ...SECURE_HEADERS }, "User-agent: *\nAllow: /\n");
  if (p !== "/") return send(req, res, 404, { ...HTML, ...SECURE_HEADERS }, "<!doctype html><title>Not found</title><p>Not found</p>");
  // 384 base64 characters — well over the obfuscated-script rule's 300-char floor.
  const payload = "ZG9jdW1lbnQud3JpdGUodW5lc2NhcGUoJyUzQ3NjcmlwdCUyMHNyYz0laHR0cDov".repeat(6);
  const spamLinks = ["cheap-watches", "payday-fast", "rx-pills", "casino-win", "replica-bags"]
    .map((h) => `<a href="http://${h}.example/buy">deal</a>`)
    .join("");
  const body =
    `<!doctype html><html><head><title>Welcome to our shop</title></head><body>` +
    `<h1>Shop</h1><p>Our normal content.</p>` +
    `<iframe src="http://ad-malware.example/landing" style="display:none" width="0" height="0"></iframe>` +
    `<script>eval(atob("${payload}"));</script>` +
    `<div style="display:none">${spamLinks}</div>` +
    `</body></html>`;
  return send(req, res, 200, { ...HTML, ...SECURE_HEADERS }, body);
};

/**
 * Site loading outdated client-side libraries, each detectable only one way:
 * jQuery from its filename, jQuery UI only from the banner in a
 * neutrally-named file, and a current Lodash that must not be reported.
 */
export const legacyJs: SiteHandler = (req, res) => {
  const p = pathOf(req);
  const js = { "content-type": "application/javascript", ...SECURE_HEADERS };
  if (p === "/") {
    return send(
      req,
      res,
      200,
      { ...HTML, ...SECURE_HEADERS },
      `<!doctype html><html><head><title>Shop</title><script src="/js/jquery-1.8.3.min.js"></script><script src="/vendor/ui.js"></script><script src="/vendor/utils.js"></script></head><body><h1>Shop</h1></body></html>`
    );
  }
  if (p === "/js/jquery-1.8.3.min.js") return send(req, res, 200, js, "/*! jQuery v1.8.3 jquery.com | jquery.org/license */\n(function(){})();");
  if (p === "/vendor/ui.js") return send(req, res, 200, js, "/*! jQuery UI - v1.12.1 - 2016-09-14\n* http://jqueryui.com */\n(function(){})();");
  if (p === "/vendor/utils.js") return send(req, res, 200, js, "/**\n * @license\n * Lodash v4.18.0 <https://lodash.com/>\n */\n(function(){})();");
  if (p === "/.well-known/security.txt") {
    return send(req, res, 200, { ...TEXT, ...SECURE_HEADERS }, "Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n");
  }
  return send(req, res, 404, { ...HTML, ...SECURE_HEADERS }, "<!doctype html><title>Not found</title><p>Not found</p>");
};
