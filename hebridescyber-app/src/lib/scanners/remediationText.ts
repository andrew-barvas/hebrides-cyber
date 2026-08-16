// Copy-pasteable fix guidance attached to findings at the point they are
// created (see summariseResults in ./index.ts), where the full check result is
// still in scope. Keeping the text here rather than inline keeps
// summariseResults readable, and keeping it attached to the Finding rather than
// re-derived later means the report never has to string-match a title to work
// out which fix applies.
//
// Each entry is Markdown. The report UI renders it as plain text with fenced
// blocks styled as code, so keep lines short and avoid nested formatting.

export const HEADER_VALUES: Record<string, string> = {
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "content-security-policy":
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "geolocation=(), microphone=(), camera=()",
};

/** Platform-specific instructions for adding response headers. */
export function headerRemediation(missing: string[]): string {
  const rawLines = missing
    .map((h) => {
      const value = HEADER_VALUES[h.toLowerCase()];
      return value ? `${h}: ${value}` : `${h}: <value>`;
    })
    .join("\n");

  return `Add these response headers at your edge/CDN or web server:

\`\`\`
${rawLines}
\`\`\`

**Next.js** — add to \`next.config.js\`:

\`\`\`js
async headers() {
  return [{
    source: "/:path*",
    headers: [
${missing
  .map((h) => {
    const value = HEADER_VALUES[h.toLowerCase()] ?? "<value>";
    return `      { key: "${h}", value: "${value}" },`;
  })
  .join("\n")}
    ],
  }];
}
\`\`\`

**Azure Static Web Apps** — add to \`staticwebapp.config.json\`:

\`\`\`json
"globalHeaders": {
${missing
  .map((h) => `  "${h}": "${HEADER_VALUES[h.toLowerCase()] ?? "<value>"}"`)
  .join(",\n")}
}
\`\`\`

**nginx** — inside the \`server\` block:

\`\`\`nginx
${missing
  .map((h) => `add_header ${h} "${HEADER_VALUES[h.toLowerCase()] ?? "<value>"}" always;`)
  .join("\n")}
\`\`\`

Deploy, then re-scan to confirm. Headers set in application code are ignored if
your CDN strips or overwrites them — verify with \`curl -I https://yoursite\`.`;
}

export const NO_HTTPS = `Obtain and install a TLS certificate, then force all traffic to HTTPS.

1. **Get a certificate** — most hosts issue one free (Let's Encrypt, Cloudflare,
   or your platform's managed SSL). No manual renewal is needed if managed.
2. **Redirect HTTP to HTTPS** at the server or CDN:

\`\`\`nginx
server {
  listen 80;
  server_name example.com;
  return 301 https://$host$request_uri;
}
\`\`\`

3. **Then add HSTS** so browsers never try HTTP again:
   \`Strict-Transport-Security: max-age=63072000; includeSubDomains\`

Add HSTS only once HTTPS works everywhere — it is cached by browsers and hard
to undo.`;

export const WEAK_TLS = `Disable TLS 1.0 and 1.1 and require 1.2 or higher.

**nginx:**
\`\`\`nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
\`\`\`

**Apache:**
\`\`\`apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
\`\`\`

Managed platforms (Cloudflare, Azure, Vercel) expose this as a "minimum TLS
version" setting — set it to 1.2. Reload the server and re-scan.`;

export const CERT_EXPIRING = `Renew the certificate before it lapses — an expired certificate blocks all
visitors with a full-page browser warning.

- **Let's Encrypt / certbot:** confirm the renewal timer is running with
  \`systemctl list-timers | grep certbot\`, then test with \`certbot renew --dry-run\`.
- **Managed hosts:** renewal is usually automatic; check the dashboard for a
  failed-renewal warning, most often caused by a DNS or domain-validation change.

Set a calendar reminder 14 days before expiry as a backstop.`;

export const SELF_SIGNED = `Replace the self-signed certificate with one from a trusted CA. Every visitor
currently sees a full-page security warning.

Let's Encrypt is free and automated:

\`\`\`bash
sudo certbot --nginx -d example.com -d www.example.com
\`\`\`

Self-signed certificates are fine for internal or development environments, but
never for a site the public reaches.`;

export const HSTS_MISSING = `Add the HSTS header so browsers refuse to connect over plain HTTP:

\`\`\`
Strict-Transport-Security: max-age=31536000; includeSubDomains
\`\`\`

Roll this out carefully: start with a short \`max-age\` (e.g. 300), confirm every
subdomain works over HTTPS, then raise it to a year. Add \`preload\` only when
you are certain — preloaded domains are hard-coded into browsers and removal
takes months.`;

export const HSTS_SHORT = `Raise \`max-age\` to at least 15552000 (180 days); a year is standard:

\`\`\`
Strict-Transport-Security: max-age=31536000; includeSubDomains
\`\`\`

A short window leaves users unprotected once the policy expires between visits.`;

export const CSP_MISSING = `Add a Content-Security-Policy header. This is the single most effective control
against cross-site scripting.

Start in report-only mode so nothing breaks:

\`\`\`
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
\`\`\`

Watch the browser console and your report endpoint for violations, add the
origins you genuinely use (CDN, analytics, payment scripts), then switch the
header name to \`Content-Security-Policy\` to enforce.

Avoid \`'unsafe-inline'\` in \`script-src\` — it removes most of the protection.
Use a per-request nonce instead if you need inline scripts.`;

export const CSP_WEAK = `Tighten the existing policy. The issues listed above each weaken it materially:

- **\`'unsafe-inline'\` in \`script-src\`** — defeats most XSS protection. Replace
  with a per-request nonce: \`script-src 'nonce-{random}'\`.
- **\`'unsafe-eval'\`** — remove unless a dependency genuinely requires it.
- **Wildcard (\`*\`) sources** — replace with explicit origins.
- **Missing \`object-src\`/\`base-uri\`** — add \`object-src 'none'; base-uri 'self'\`.

Test changes with \`Content-Security-Policy-Report-Only\` before enforcing.`;

export const COOKIE_FLAGS = `Set the missing attributes when the cookie is issued:

\`\`\`
Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/
\`\`\`

- **Secure** — never sent over plain HTTP.
- **HttpOnly** — unreadable from JavaScript, so XSS cannot steal the session.
- **SameSite=Lax** (or \`Strict\`) — blocks the cookie on cross-site requests,
  which stops most CSRF.

Omit \`HttpOnly\` only for cookies your front-end genuinely must read. If you set
\`SameSite=None\` for a cross-site integration, \`Secure\` becomes mandatory.`;

export const CORS_WILDCARD = `Replace the wildcard with an explicit allow-list. \`Access-Control-Allow-Origin: *\`
lets any website on the internet read responses from this origin.

\`\`\`js
const ALLOWED = new Set(["https://app.example.com", "https://admin.example.com"]);
const origin = req.headers.origin;
if (origin && ALLOWED.has(origin)) {
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
}
\`\`\`

The \`Vary: Origin\` header is required — without it a CDN can cache one origin's
response and serve it to another.`;

export const CORS_REFLECTED = `Stop reflecting the \`Origin\` header. Echoing it back is equivalent to a wildcard,
but also works with credentials — which is why this is scored higher.

Validate against a fixed allow-list instead:

\`\`\`js
const ALLOWED = new Set(["https://app.example.com"]);
const origin = req.headers.origin;
if (origin && ALLOWED.has(origin)) {
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Vary", "Origin");
}
\`\`\`

Never build the allow-list with a substring or regex match —
\`origin.endsWith("example.com")\` also matches \`evil-example.com\`.`;

export const SPF_MISSING = `Publish an SPF record so receiving servers can reject forged mail from your
domain. Add one TXT record at the domain root:

\`\`\`
Type: TXT
Name: @
Value: v=spf1 include:_spf.google.com -all
\`\`\`

Replace the \`include:\` with your actual sending provider:

| Provider   | include |
|------------|---------|
| Google     | \`_spf.google.com\` |
| Microsoft  | \`spf.protection.outlook.com\` |
| SendGrid   | \`sendgrid.net\` |
| Mailgun    | \`mailgun.org\` |
| Resend     | \`_spf.resend.com\` |

End with \`-all\` (hard fail) once you are sure every sender is listed; use
\`~all\` (soft fail) while testing. Only one SPF record per domain is permitted.`;

export const SPF_ISSUES = `Correct the SPF record — the issues above will cause it to be ignored or to fail
open.

- **More than one SPF record** — merge into a single TXT record; multiple
  records are a permanent error and receivers ignore all of them.
- **More than 10 DNS lookups** — flatten or reduce \`include:\` chains, otherwise
  evaluation fails with \`permerror\`.
- **Ends with \`+all\`** — this authorises the entire internet to send as you.
  Change it to \`-all\`.

Verify with \`dig TXT example.com +short\` after the change.`;

export const DMARC_MISSING = `Publish a DMARC record to tell receivers what to do with mail that fails SPF or
DKIM, and to start receiving reports.

Begin in monitor mode so no legitimate mail is affected:

\`\`\`
Type: TXT
Name: _dmarc
Value: v=DMARC1; p=none; rua=mailto:dmarc@example.com; pct=100
\`\`\`

Review the aggregate reports for a few weeks, confirm all your legitimate
senders pass, then tighten to \`p=quarantine\` and finally \`p=reject\`.

DMARC requires a working SPF or DKIM record first — publish those before
enforcing.`;

export const DMARC_NONE = `Move DMARC from monitoring to enforcement. With \`p=none\`, spoofed mail is
reported but still delivered.

\`\`\`
v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; pct=100
\`\`\`

Check your aggregate reports first — every legitimate sender must be passing SPF
or DKIM, or their mail will start going to spam. Once clean, move to \`p=reject\`.
You can ease in with \`pct=25\` to apply the policy to a quarter of failing mail.`;

export const CAA_MISSING = `Add CAA records so only your chosen certificate authorities can issue
certificates for the domain:

\`\`\`
example.com. IN CAA 0 issue "letsencrypt.org"
example.com. IN CAA 0 issuewild ";"
example.com. IN CAA 0 iodef "mailto:security@example.com"
\`\`\`

The \`issuewild ";"\` line forbids wildcard certificates; drop it if you use them.
The \`iodef\` address is notified when an unauthorised issuance is attempted.`;

export const DNSSEC_MISSING = `DNSSEC signs your DNS records so resolvers can detect tampering. Without it, an
attacker positioned to poison DNS can point your domain anywhere.

Most managed DNS providers (Cloudflare, Route 53, Azure DNS) enable it with a
single toggle, then give you a DS record to add at your registrar.

This is a defence-in-depth measure — lower priority than SPF/DMARC or missing
headers.`;

export const EXPOSED_FILE = `Block public access to this path immediately, then rotate anything it revealed.

**1. Block it.**

\`\`\`nginx
location ~ /\\.(git|env|htpasswd) { deny all; return 404; }
\`\`\`

Better still, remove the file from the web root entirely — deployments should
never place \`.env\` files or repository metadata inside the served directory.

**2. Assume it was read.** Rotate every credential it contained: database
passwords, API keys, signing secrets, session keys. Search access logs for prior
requests to the path.

**3. Prevent recurrence.** Add the path to \`.gitignore\` and your deploy
ignore-file, and re-scan to confirm it now returns 404.`;

export const SECURITY_TXT_MISSING = `Publish \`/.well-known/security.txt\` so researchers know where to report
vulnerabilities instead of disclosing them publicly:

\`\`\`
Contact: mailto:security@example.com
Expires: 2027-01-01T00:00:00.000Z
Preferred-Languages: en
Canonical: https://example.com/.well-known/security.txt
\`\`\`

\`Contact\` and \`Expires\` are required by RFC 9116. Set a reminder to update
\`Expires\` before it passes.`;

export const OUTDATED_LIBRARY = `Upgrade to a currently supported version.

1. Check the advisory for the affected version range and the first fixed release.
2. Read the migration guide before a major-version jump.
3. Upgrade, run your test suite, and re-scan.

\`\`\`bash
npm audit
npm audit fix
npm outdated
\`\`\`

If the library is loaded from a CDN, bump the version in the \`<script>\` tag and
update the \`integrity\` hash to match.

Where an upgrade is genuinely blocked, confirm whether the vulnerable code path
is reachable in your usage and document the decision.`;

export const OPEN_PORT = `Close the port or restrict who can reach it. Administrative services should
never be exposed to the whole internet.

\`\`\`bash
# Allow only your office/VPN range
sudo ufw allow from 203.0.113.0/24 to any port 22
sudo ufw deny 22
\`\`\`

On a cloud provider, do this in the security group or network ACL rather than
the host firewall. Databases (3306, 5432, 27017, 6379) should listen on a
private interface only — bind to \`127.0.0.1\` or a VPC address, never \`0.0.0.0\`.

If the service must stay reachable, put it behind a VPN or bastion host.`;

export const SHODAN_CVES = `Identify the software behind each CVE and patch it.

1. Look up each CVE to confirm it applies to your installed version — Shodan
   infers these from service banners, so false positives happen.
2. Apply vendor patches, or upgrade the affected package.
3. If a patch is unavailable, restrict network access to the service while you
   wait.

Banner-based detection also means your service is advertising its exact version
to the internet. Suppressing version strings in banners reduces automated
targeting.`;

export const MIXED_CONTENT = `Load every subresource over HTTPS. Browsers block mixed active content, so parts
of the page are already broken for visitors.

1. Change the offending \`http://\` URLs to \`https://\`, or to protocol-relative
   paths if the host supports both.
2. Add \`upgrade-insecure-requests\` to your CSP as a safety net:

\`\`\`
Content-Security-Policy: upgrade-insecure-requests
\`\`\`

3. For third-party resources with no HTTPS option, host the asset yourself.`;

export const DANGEROUS_METHODS = `Disable the HTTP methods you do not use. \`PUT\`, \`DELETE\`, and \`TRACE\` are rarely
needed by a website and can allow file modification or aid session theft.

\`\`\`nginx
if ($request_method !~ ^(GET|HEAD|POST|OPTIONS)$) { return 405; }
\`\`\`

If you run a REST API that legitimately uses \`PUT\`/\`DELETE\`, restrict them to
the API paths and confirm each is behind authentication and authorisation
checks.`;

export const ERROR_DISCLOSURE = `Replace the default error pages with custom ones. Stack traces and framework
banners tell an attacker exactly what to target.

- Disable debug mode in production (\`APP_DEBUG=false\`, \`DEBUG=False\`,
  \`NODE_ENV=production\`).
- Configure custom 404 and 500 pages that show a generic message.
- Log the full detail server-side where only you can read it.`;

export const INFO_DISCLOSURE = `Remove version details from response headers. This does not stop a determined
attacker but does remove you from automated scans for specific versions.

\`\`\`nginx
server_tokens off;
more_clear_headers "X-Powered-By";
\`\`\`

**Express:** \`app.disable("x-powered-by")\`
**PHP:** \`expose_php = Off\` in \`php.ini\`
**Next.js:** \`poweredByHeader: false\` in \`next.config.js\``;

export const WP_XMLRPC = `Disable XML-RPC unless a plugin needs it. It allows hundreds of password guesses
in a single request via \`system.multicall\`.

\`\`\`nginx
location = /xmlrpc.php { deny all; return 404; }
\`\`\`

Or in \`functions.php\`:

\`\`\`php
add_filter('xmlrpc_enabled', '__return_false');
\`\`\`

The Jetpack plugin and the classic WordPress mobile apps rely on XML-RPC —
verify before disabling.`;

export const WP_USER_ENUM = `Block the REST users endpoint so usernames cannot be harvested for brute-force
attacks:

\`\`\`php
add_filter('rest_endpoints', function ($endpoints) {
  unset($endpoints['/wp/v2/users']);
  unset($endpoints['/wp/v2/users/(?P<id>[\\d]+)']);
  return $endpoints;
});
\`\`\`

Also block \`/?author=1\` enumeration, and make sure display names differ from
login names. Pair this with a login rate-limiter.`;

export const WP_DEBUG_LOG = `Delete the debug log and stop writing it to a public directory. It commonly
contains database credentials, file paths, and full stack traces.

\`\`\`php
// wp-config.php
define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);
define('WP_DEBUG_DISPLAY', false);
\`\`\`

Remove the existing file, then rotate any credential that appeared in it — treat
the contents as public.`;

export const WP_README = `Delete \`readme.html\` from the WordPress root. It states the exact version, which
is what automated scanners use to select an exploit.

\`\`\`bash
rm /var/www/html/readme.html /var/www/html/license.txt
\`\`\`

WordPress recreates it on upgrade — remove it again as a post-deploy step, or
block it in your server config.`;

export const WP_CRON = `\`wp-cron.php\` runs on visitor requests and can be called repeatedly by anyone,
making it a cheap denial-of-service lever.

Disable the web trigger and use a real cron job:

\`\`\`php
// wp-config.php
define('DISABLE_WP_CRON', true);
\`\`\`

\`\`\`bash
*/5 * * * * curl -s https://example.com/wp-cron.php?doing_wp_cron >/dev/null
\`\`\`

Low priority unless the site is under load.`;

export const CONSOLE_ERRORS = `Console errors are not vulnerabilities, but they often mark a broken CSP rule, a
failed subresource, or an unhandled exception path worth checking.

Open DevTools, reproduce, and confirm none of them leak internal URLs, tokens,
or stack traces to the browser.`;

export const UNHEALTHY_STATUS = `The page did not return a healthy status to a headless browser. Confirm the site
is reachable and not blocking automated clients.

If a WAF or bot filter returned this deliberately, allow-list the scanner or
verify domain ownership so future scans reflect real content rather than the
challenge page.`;

export const ROBOTS_PATHS = `\`robots.txt\` is public, so listing sensitive paths there advertises them. It
controls crawling, never access.

Remove admin and internal paths from the file and protect them with
authentication instead. Anything that must stay unindexed but reachable should
use \`X-Robots-Tag: noindex\` on the response.`;

export const SUBDOMAINS_FOUND = `Certificate Transparency logs make every subdomain you hold a certificate for
public. This is informational, but worth an inventory pass:

- Decommission subdomains you no longer use — stale ones are a common entry
  point.
- Check for dangling DNS records pointing at deprovisioned cloud resources,
  which allow subdomain takeover.
- Confirm staging and development hosts are not publicly reachable.`;

export const TECH_DETECTED = `Informational — no action required. Knowing what a scanner can fingerprint about
your stack is useful context when triaging the findings above.`;

export const NO_ISSUES = `Automated checks found nothing. That covers configuration, headers, TLS, DNS,
and known-vulnerable versions — it does not cover business logic, access
control, or authorisation flaws, which need manual testing.

Keep scanning on a schedule so regressions surface early.`;
