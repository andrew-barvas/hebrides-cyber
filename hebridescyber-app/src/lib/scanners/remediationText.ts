// Copy-pasteable fix guidance attached to findings at the point they are
// created (see summariseResults in ./index.ts), where the full check result is
// still in scope. Keeping the text here rather than inline keeps
// summariseResults readable, and keeping it attached to the Finding rather than
// re-derived later means the report never has to string-match a title to work
// out which fix applies.
//
// Each entry is Markdown. The report UI renders it as plain text with fenced
// blocks styled as code, so keep lines short and avoid nested formatting.

// Every header headers.ts's OWASP_HEADERS list can report missing must have
// an entry here — a gap falls back to the literal, useless "<value>"
// placeholder below rather than a real header value. This previously
// happened for the three cross-origin-* headers and cache-control (only
// the 6 originally-"critical" headers were covered), so a "recommended
// headers" finding for any of those four rendered an unusable snippet.
// Deliberately NOT derived from OWASP_HEADERS's own `recommendation`
// field — that field is human-readable guidance for the report's header
// table ("DENY (or SAMEORIGIN if framing needed)", "Define explicit
// allow-lists; avoid 'unsafe-inline'/'unsafe-eval'"), not always a literal
// value that's valid to paste into a `key: value` header directive.
export const HEADER_VALUES: Record<string, string> = {
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "content-security-policy":
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "geolocation=(), microphone=(), camera=()",
  "cross-origin-embedder-policy": "require-corp",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "cache-control": "no-store",
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

export const DKIM_NOT_DETECTED = `DKIM signs outgoing mail with a private key so receivers can verify it really
came from you and was not altered in transit. Together with SPF it is what
DMARC enforcement depends on.

**This check is not conclusive.** DKIM keys live at \`<selector>._domainkey\`,
and the selector name is chosen freely — it cannot be discovered from DNS. We
probed the defaults used by the common providers (Google, Microsoft 365,
Mailchimp, SendGrid and similar). If you sign with a custom selector, DKIM is
working and there is nothing to fix here.

To confirm for yourself, send a message to any address you control and look for
\`dkim=pass\` in the received message's \`Authentication-Results\` header.

If DKIM genuinely is not set up, enable it in your mail provider's admin
console — they generate the key pair and give you the TXT record to publish:

| Provider | Where |
|----------|-------|
| Google Workspace | Admin console → Apps → Gmail → Authenticate email |
| Microsoft 365 | Defender portal → Policies → Email authentication → DKIM |
| SendGrid / Mailgun | Sender authentication → domain setup |

Use a 2048-bit key where offered.`;

export const DKIM_ISSUES = `A DKIM key was found, but its configuration weakens or disables the protection
it is meant to provide.

- **Revoked key (empty \`p=\`)** — this is the RFC-defined way to retire a key.
  Mail still signed with this selector will fail verification. Either republish
  the public key or move signing to a live selector.
- **Testing mode (\`t=y\`)** — tells receivers to ignore verification failures,
  so the signature provides no real protection. Remove \`t=y\` once you have
  confirmed signing works.
- **Short key** — 1024-bit RSA keys are considered weak. Regenerate at 2048-bit
  in your provider's console and publish the new record.

After changing a key, keep the old selector published for a few days so mail
already in flight can still be verified.`;

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

export const MTA_STS_MISSING = `MTA-STS (RFC 8461) lets other mail servers require TLS when delivering mail
to this domain, closing the STARTTLS-downgrade gap that plain opportunistic
TLS leaves open. Two pieces are required:

**1. Publish the DNS record:**

\`\`\`
_mta-sts.example.com. IN TXT "v=STSv1; id=20260101000000Z"
\`\`\`

The \`id\` is any string you bump whenever the policy file changes — receivers
use it to know when to re-fetch.

**2. Serve the policy file** over HTTPS at
\`https://mta-sts.example.com/.well-known/mta-sts.txt\`:

\`\`\`
version: STSv1
mode: testing
mx: mail.example.com
max_age: 604800
\`\`\`

Start with \`mode: testing\` (failures are reported, nothing is rejected),
confirm delivery still works normally, then switch to \`mode: enforce\`.`;

export const MTA_STS_ISSUES = `The _mta-sts DNS record exists but the policy behind it isn't fully working —
see the specific issue reported for this finding. A published-but-broken
policy is worse than no policy at all if it's ever switched to \`mode:
enforce\` without being fixed first, since receivers that see \`mode: none\` or
\`testing\` simply don't enforce anything, and a 404/unreachable policy file
is a dangling pointer some receivers may treat as \`mode: none\` too.

Fetch \`https://mta-sts.<your-domain>/.well-known/mta-sts.txt\` yourself and
confirm it returns a 200 with a valid \`mode:\` line before relying on it.`;

export const TLS_RPT_MISSING = `TLS-RPT (RFC 8460) is pure visibility — it doesn't enforce anything on its
own, but without it you have no way to know if inbound mail delivery is
silently being downgraded to plaintext by a receiving server that ignores
STARTTLS. Add:

\`\`\`
_smtp._tls.example.com. IN TXT "v=TLSRPTv1; rua=mailto:tls-reports@example.com"
\`\`\`

Reports arrive as periodic JSON summaries from participating mail providers
(Google, Microsoft, and others send these). Worth pairing with MTA-STS —
TLS-RPT is how you'd notice an MTA-STS policy is misbehaving in practice.`;

export const TLS_RPT_ISSUES = `The _smtp._tls TXT record exists but is missing a \`rua=\` reporting address,
so any provider that would otherwise send TLS failure reports has nowhere to
send them. Add one:

\`\`\`
_smtp._tls.example.com. IN TXT "v=TLSRPTv1; rua=mailto:tls-reports@example.com"
\`\`\`

A mailbox is simplest to start; some providers also accept \`rua=https://...\`
for automated ingestion once report volume makes that worthwhile.`;

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

export const DIRECTORY_LISTING = `Turn off autoindexing so this directory's contents can't be browsed without
knowing individual file names — any file inside is currently listed and
one click away, including ones never meant to be linked from the site.

**nginx:**
\`\`\`nginx
location /uploads/ { autoindex off; }
\`\`\`

**Apache:**
\`\`\`apache
<Directory "/var/www/html/uploads">
  Options -Indexes
</Directory>
\`\`\`

Or add an empty \`index.html\` to the directory, which most servers prefer over
generating a listing.

**2. Check what was exposed.** Review the listing for anything that shouldn't
be public — backups, exports, old versions of uploaded files — and remove or
relocate it. Treat anything sensitive as compromised and rotate accordingly.`;

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

export function sriRemediation(kind: "script" | "stylesheet", url: string): string {
  const tag = kind === "script" ? "script" : "link";
  const attr = kind === "script" ? "src" : "href";

  return `Add a Subresource Integrity hash to this ${kind}, so the browser refuses to
run/apply it if the third-party origin ever serves something different from
what you expect:

\`\`\`bash
curl -s ${url} | openssl dgst -sha384 -binary | openssl base64 -A
\`\`\`

\`\`\`html
<${tag} ${attr}="${url}" integrity="sha384-<hash from above>" crossorigin="anonymous"></${tag}>
\`\`\`

\`crossorigin="anonymous"\` is required alongside \`integrity\` — without it the
browser won't apply the check at all. Most CDNs (jsDelivr, cdnjs, unpkg)
publish the correct \`integrity\` value directly on their site; copying theirs
is safer than hand-computing it, since it's pinned to the exact file they
serve. If you control the third-party resource yourself, consider serving it
same-origin instead, which needs no SRI hash at all.`;
}

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

export const JOOMLA_VERSION_DISCLOSED = `Restrict access to the administrator manifest so the core version can't be
read remotely:

\`\`\`apache
<Files "joomla.xml">
  Require all denied
</Files>
\`\`\`

This doesn't replace patching — keep Joomla core updated regardless — but it
removes the easiest way for an automated scanner to pick a matching exploit
for your exact version.`;

export const JOOMLA_INSTALL_FILES = `Remove or rename the leftover installer files:

\`\`\`bash
rm htaccess.txt web.config.txt
\`\`\`

\`htaccess.txt\` is meant to be renamed to \`.htaccess\` (Apache) as part of
hardening the install; \`web.config.txt\` is its IIS equivalent. Their presence
in the default state usually means the site was never hardened after install —
worth a full configuration review, not just deleting these two files.`;

export const DRUPAL_VERSION_DISCLOSED = `Block CHANGELOG.txt and core/CHANGELOG.txt so the exact core version can't be
read remotely:

\`\`\`nginx
location ~ /(CHANGELOG|core/CHANGELOG)\\.txt$ { deny all; return 404; }
\`\`\`

Keep Drupal core patched regardless — this only removes the easiest way to
pick a matching exploit for your exact version.`;

export const DRUPAL_UPDATE_PHP = `Restrict update.php to trusted IPs or require authentication at the web
server, on top of Drupal's own \`update_free_access\` setting (confirm it's
\`FALSE\` in \`settings.php\`):

\`\`\`nginx
location = /update.php {
  allow 203.0.113.0/24;
  deny all;
}
\`\`\`

Only re-open it when you're actually about to run an update, then close it
again.`;

export const DRUPAL_JSONAPI_EXPOSED = `Confirm this is intentional. If nothing consumes the public JSON:API, disable
the module:

\`\`\`bash
drush pm:uninstall jsonapi
\`\`\`

If it's needed, restrict which resource types and fields are exposed via
JSON:API's resource-type configuration, and check per-entity access controls —
the endpoint inherits normal Drupal permissions, so exposure here usually means
a permission was set more broadly than intended.`;

export const DRUPAL_UID1_ENUMERABLE = `Restrict anonymous access to user profile pages, or at minimum to uid 1
specifically, in **Configuration → People → Permissions** (\`View user
information\` for the Anonymous role). Consider also renaming the uid 1
account away from an obvious username — many Drupal hardening guides recommend
creating a separate named admin account and disabling uid 1's direct login.`;

export const CLOUD_STORAGE_PUBLIC = `Remove public list access from the bucket/container. Anyone who finds the URL
can currently browse its full contents.

**S3:** Block public access at the bucket (or account) level unless a specific
prefix genuinely needs to be public:

\`\`\`bash
aws s3api put-public-access-block --bucket BUCKET_NAME \\
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
\`\`\`

**Azure Blob:** Set the container's public access level to **Private**:

\`\`\`bash
az storage container set-permission --name CONTAINER_NAME --public-access off
\`\`\`

**GCS:** Remove \`allUsers\`/\`allAuthenticatedUsers\` from the bucket's IAM
bindings:

\`\`\`bash
gsutil iam ch -d allUsers gs://BUCKET_NAME
\`\`\`

Then check what was listed — if any of it was meant to be private, treat it as
exposed and rotate/replace accordingly. If genuinely public assets (product
images, downloads) need serving, put them behind a CDN or signed-URL flow
instead of a fully public, listable bucket.`;

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

// ---------------------------------------------------------------------------
// Deep TLS (src/lib/scanners/deepTls.ts, testssl.sh) — moved here from being
// kept local in that file's first draft, per the convention at the top of
// this file.
// ---------------------------------------------------------------------------

export const DEEP_TLS_PROTOCOL = `Disable the obsolete protocol version on the server and require TLS 1.2 or
higher.

**nginx:**
\`\`\`nginx
ssl_protocols TLSv1.2 TLSv1.3;
\`\`\`

**Apache:**
\`\`\`apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
\`\`\`

Managed platforms (Cloudflare, Azure, AWS ALB) expose this as a "minimum TLS
version" setting. Reload the server and re-scan to confirm.`;

export const DEEP_TLS_CIPHERS = `Restrict the server to modern AEAD cipher suites with forward secrecy and
remove the weak categories listed above.

**nginx:**
\`\`\`nginx
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
\`\`\`

The Mozilla SSL Configuration Generator produces a correct config for your
exact server and version — use its "intermediate" profile unless you have a
documented need to support legacy clients.`;

export const DEEP_TLS_VULNERABILITY = `This is a known, named weakness in the server's TLS stack. The fix is almost
always one of:

1. **Update the TLS library** (OpenSSL, LibreSSL, or the load balancer /
   platform firmware) to a current supported release.
2. **Disable the feature the attack relies on** — the obsolete protocol
   version, TLS compression, or the affected cipher suites.

Re-scan afterwards: these checks are direct probes, so a clean result is
positive confirmation that the fix landed.`;

export const DEEP_TLS_FORWARD_SECRECY = `Enable forward secrecy so that a future compromise of the server's private key
cannot decrypt traffic captured today. Prefer ECDHE key exchange and drop
static RSA key exchange entirely.

If a Diffie-Hellman group was flagged as weak, generate a strong one:

\`\`\`bash
openssl dhparam -out /etc/ssl/dhparam.pem 4096
\`\`\`

then point \`ssl_dhparam\` (nginx) or \`SSLOpenSSLConfCmd DHParameters\`
(Apache) at it. TLS 1.3 gives forward secrecy unconditionally.`;

export const DEEP_TLS_CERTIFICATE = `Fix the certificate itself rather than the protocol configuration.

- **Chain of trust / incomplete chain:** serve the full chain, not just the
  leaf. Most issuers publish a "fullchain" bundle — use it.
- **Hostname or SAN mismatch:** reissue the certificate with every hostname
  the site is reached by listed in the subject alternative names.
- **Weak key or signature algorithm:** reissue with at least RSA 2048 (or
  ECDSA P-256) and a SHA-256 signature.

Managed issuers (Let's Encrypt, ACM, Cloudflare) get all of this right by
default, so a flagged certificate usually means a manual install to redo.`;

// ---------------------------------------------------------------------------
// Extended tool suite (src/lib/scanExecution.ts's runExtendedTools) —
// nuclei/sqlmap/nmap findings are built inline there rather than in a
// dedicated scanner module (unlike everything above), but the same rule
// applies: remediation prose lives here, not inline at the finding site.
// ZAP is the one exception — ZAP's own `alert.solution` is real, specific,
// evidenced guidance from its own knowledge base, so it's used directly as
// the Finding's remediation rather than duplicated here.
// ---------------------------------------------------------------------------

/**
 * nuclei covers thousands of templates spanning wildly different issue
 * classes, so a single static string would be either too vague to help or
 * (worse) confidently wrong for a chunk of them. Categorising by the
 * template-id's path prefix — nuclei's own directory taxonomy in
 * https://github.com/projectdiscovery/nuclei-templates — is the honest
 * middle ground: specific enough to be useful, general enough to never claim
 * evidence a category name doesn't actually give us.
 */
export function nucleiRemediation(templateId: string): string {
  const category = templateId.split(/[:/]/)[0] ?? "";

  const base = `nuclei matched this against a known vulnerability template
(\`${templateId || "unknown template"}\`). Look the template ID up at
https://github.com/projectdiscovery/nuclei-templates for the exact advisory
it's based on — that page names the specific CVE or issue and usually links
the vendor's own fix.`;

  const byCategory: Record<string, string> = {
    cves: `${base}\n\nThis is a known CVE. Update the affected software to the
version the advisory names as fixed — check the vendor's changelog for the
CVE number in the template ID.`,
    "exposed-panels": `${base}\n\nAn admin or management interface is
reachable from the public internet. Put it behind a VPN, IP allowlist, or at
minimum strong authentication + rate limiting — these panels are a common
first foothold in real attacks specifically because they're easy to find.`,
    exposures: `${base}\n\nSomething that shouldn't be publicly readable is —
a config file, backup, credential, or debug endpoint. Remove or restrict
access to the exposed path, then rotate anything it revealed (keys, tokens,
passwords).`,
    misconfiguration: `${base}\n\nThis is a configuration weakness rather
than a code vulnerability — check the affected service's hardening guide for
the specific setting nuclei flagged.`,
    "default-logins": `${base}\n\nA service is reachable with vendor-default
credentials still active. Change them immediately — default credentials are
one of the most automated attack vectors that exist, scanned for constantly
and not just by security researchers.`,
    takeovers: `${base}\n\nA DNS record points at a service (cloud storage,
a SaaS platform, a deprovisioned app) that no longer owns that hostname.
Remove the dangling DNS record, or reclaim the resource it points to —
otherwise anyone can claim it and serve content under your domain.`,
    vulnerabilities: `${base}\n\nUpdate the affected software to a current
version; check its changelog for the specific issue nuclei's template
targets.`,
  };

  return byCategory[category] ?? base;
}

export const SQLMAP_SQLI_BASE = `sqlmap confirmed this parameter accepts attacker-controlled SQL — the
database can very likely be read, modified, or used as a foothold into the
rest of the network. Treat this as urgent.

**The fix is always the same: stop building queries by string concatenation.**

- Use parameterised queries / prepared statements everywhere this parameter
  reaches the database — never string-interpolate user input into SQL.
- If an ORM is available (Prisma, Sequelize, ActiveRecord, Django ORM,
  Entity Framework...), use its query builder rather than raw SQL for this
  code path.
- Apply least privilege to the database account the application connects
  with — it should not be able to read tables or run commands it has no
  legitimate reason to touch, so a successful injection here does less
  damage even before the code fix ships.
- Add input validation as defence in depth, not as the primary fix —
  allowlisting expected formats (numeric IDs, known enum values) helps, but
  parameterisation is what actually closes this class of bug.`;

/** Same as SQLMAP_SQLI_BASE, with DBMS-specific prepared-statement syntax appended when sqlmap identified one. */
export function sqlmapRemediation(dbms: string | null): string {
  const snippets: Record<string, string> = {
    mysql: "\n\n**MySQL / MariaDB (mysqli):**\n```php\n$stmt = $mysqli->prepare(\"SELECT * FROM users WHERE id = ?\");\n$stmt->bind_param(\"i\", $id);\n```",
    postgresql: "\n\n**PostgreSQL (node-postgres):**\n```js\nawait pool.query(\"SELECT * FROM users WHERE id = $1\", [id]);\n```",
    "microsoft sql server": "\n\n**SQL Server (mssql):**\n```js\nawait pool.request().input(\"id\", sql.Int, id).query(\"SELECT * FROM users WHERE id = @id\");\n```",
    sqlite: "\n\n**SQLite (better-sqlite3):**\n```js\ndb.prepare(\"SELECT * FROM users WHERE id = ?\").get(id);\n```",
    oracle: "\n\n**Oracle (node-oracledb):**\n```js\nawait connection.execute(\"SELECT * FROM users WHERE id = :id\", [id]);\n```",
  };
  const key = (dbms ?? "").toLowerCase();
  const match = Object.keys(snippets).find((k) => key.includes(k));
  return SQLMAP_SQLI_BASE + (match ? snippets[match] : "");
}

export const XSSER_XSS_BASE = `XSSer confirmed this parameter reflects attacker-controlled markup or
script back into the page unescaped — an attacker can run arbitrary
JavaScript in another user's browser session (steal cookies/session tokens,
act as that user, deface the page). Treat this as urgent.

**The fix is always the same: never trust user input to become HTML/JS.**

- Escape output for the context it lands in — HTML-entity-encode for HTML
  body content, JS-string-encode for inline scripts, attribute-encode for
  HTML attributes. Use your framework's built-in escaping (React/Vue/Angular
  all escape by default) rather than hand-rolled string building.
- Never use \`dangerouslySetInnerHTML\`, \`v-html\`, \`innerHTML\`, or
  equivalents on anything derived from user input without passing it through
  a sanitiser (e.g. DOMPurify) first.
- Add a Content-Security-Policy that restricts \`script-src\` — even a
  successful reflection is far less exploitable without inline-script
  execution allowed.
- Set cookies \`HttpOnly\` so a successful XSS still can't read the session
  cookie directly.`;

/** Same as XSSER_XSS_BASE — XSS remediation doesn't vary by target the way sqlmap's DBMS-specific syntax does, so this is a plain export with no per-target variant function. */
export function xsserRemediation(): string {
  return XSSER_XSS_BASE;
}

export const COMMIX_COMMAND_INJECTION_BASE = `commix confirmed this parameter reaches a shell command on the server —
an attacker can run arbitrary operating-system commands with the
application's own privileges. This is typically a direct path to full
server compromise. Treat this as critical.

**The fix is always the same: stop passing user input to a shell.**

- Avoid shell execution of user-controlled input entirely where possible —
  use a language-native API instead of \`exec\`/\`system\`/backticks (e.g. a
  library for the specific task rather than shelling out to a CLI tool).
- If shelling out is unavoidable, use the array/argument-list form of your
  language's process-spawning API (e.g. Node's \`execFile\` with an args
  array, Python's \`subprocess.run([...])\` with \`shell=False\`) so arguments
  are never concatenated into a single shell string, which is what makes
  injection possible.
- Never build a shell command via string concatenation or template
  literals with user input, even with manual escaping — allowlisting exact
  expected values (not blocklisting characters) is the only reliable
  defence when shell execution truly can't be avoided.
- Apply least privilege to the account the application process runs as, so
  a successful injection here does less damage even before the code fix
  ships.`;

/** Same as COMMIX_COMMAND_INJECTION_BASE — no per-target variant, matching xsserRemediation()'s reasoning. */
export function commixRemediation(): string {
  return COMMIX_COMMAND_INJECTION_BASE;
}

/**
 * The small fixed set of ports scanExecution.ts's DANGEROUS_TOOL_PORTS
 * escalates to critical regardless of nmap's service-guess — each one is
 * dangerous for a specific, well-known reason, so per-port text is both
 * cheap to write correctly (six ports, not nmap's whole 1000-port sweep) and
 * more useful than one generic "close this port" paragraph.
 */
export function nmapDangerousPortRemediation(port: number): string {
  const byPort: Record<number, string> = {
    2375: `Port 2375 is the Docker Engine API over plain HTTP — no
authentication, no encryption. Anyone reaching it can run arbitrary
containers with root-equivalent access to the host. Bind the Docker daemon
to localhost only, or if remote access is genuinely needed, use port 2376
with TLS client-certificate authentication (\`--tlsverify\`) instead.`,
    2376: `Port 2376 is the Docker Engine API over TLS. It being open isn't
itself the problem — check that \`--tlsverify\` is actually enforced and
that client certificates are required, not just offered. A misconfigured
TLS listener here still grants root-equivalent container access.`,
    6379: `Port 6379 is Redis. By default Redis has no authentication and no
encryption, so anyone reaching this port can read every key, and depending
on configuration can write files to the host via \`CONFIG SET\` /
\`SAVE\` — a known path to full remote code execution. Set \`requirepass\`,
bind to a private network only, and never expose Redis directly to the
internet.`,
    9200: `Port 9200 is Elasticsearch's HTTP API. Without security enabled
(disabled by default in older versions), anyone reaching this port can read,
modify, or delete every index — a very common source of large public data
leaks. Enable Elasticsearch Security (authentication + TLS) or put it behind
a private network / VPN, never expose it directly.`,
    27017: `Port 27017 is MongoDB. Older defaults bind to 0.0.0.0 with no
authentication, meaning anyone reaching this port has full read/write access
to every database. Enable authentication (\`--auth\`), bind to a private
network only, and confirm the exposed instance isn't one of the many
publicly-indexed unauthenticated MongoDB instances attackers actively scan
for.`,
    2379: `Port 2379 is etcd's client API — the coordination/config store
behind most Kubernetes clusters. Unauthenticated access here can expose
every secret and config value the cluster stores, including credentials for
other systems. Enable etcd's client authentication (RBAC or mutual TLS) and
restrict network access to cluster-internal traffic only.`,
  };
  return (
    byPort[port] ??
    `This port runs a service (${port}) that's dangerous to expose without
authentication — confirm it requires credentials, and restrict network
access to it if it doesn't need to be public.`
  );
}

// ---------------------------------------------------------------------------
// Dependency manifest scanning (src/lib/scanners/dependencyManifest.ts) —
// real npm/package.json CVE scanning via OSV.dev, as opposed to webapp.ts's
// client-side JS library *detection*. Function, not a constant, for the same
// reason sqlmapRemediation/nmapDangerousPortRemediation are: the fix names a
// specific package, and a static string can't do that.
// ---------------------------------------------------------------------------

/**
 * OSV.dev doesn't return one canonical "fixed version" in a shape safe to
 * quote across every advisory, so this stays generic rather than fabricating
 * a specific target version we haven't independently verified.
 */
const DEPENDENCY_ECOSYSTEM_COMMANDS: Record<
  "npm" | "pip" | "composer",
  { manifest: string; checkInstalled: (pkg: string) => string; commands: (pkg: string) => string }
> = {
  npm: {
    manifest: "package.json",
    checkInstalled: (pkg) => `npm ls ${pkg}`,
    commands: (pkg) =>
      `npm view ${pkg} versions --json   # see what's available\nnpm update ${pkg}\n# or pin a specific patched version directly:\nnpm install ${pkg}@<fixed-version>`,
  },
  pip: {
    manifest: "requirements.txt",
    checkInstalled: (pkg) => `pip show ${pkg}`,
    commands: (pkg) => `pip install --upgrade ${pkg}\n# then pin the resolved version back into requirements.txt:\npip freeze | grep -i ${pkg}`,
  },
  composer: {
    manifest: "composer.json",
    checkInstalled: (pkg) => `composer show ${pkg}`,
    commands: (pkg) => `composer update ${pkg}\n# or pin a specific patched version directly:\ncomposer require ${pkg}:^<fixed-version>`,
  },
};

export function dependencyVulnerableRemediation(packageName: string, ecosystem: "npm" | "pip" | "composer" = "npm"): string {
  const cfg = DEPENDENCY_ECOSYSTEM_COMMANDS[ecosystem];
  const auditNote =
    ecosystem === "npm"
      ? " — `npm audit fix` applies it automatically when the fix doesn't require a major-version bump"
      : "";

  return `Update **${packageName}** to a patched version.

\`\`\`bash
${cfg.commands(packageName)}
\`\`\`

Check the advisory OSV.dev matched (search \`${packageName}\` at
https://osv.dev) for the exact patched range${auditNote}.

The version checked here comes from the range declared in \`${cfg.manifest}\`,
not a lockfile, so it is an approximation of what's actually installed — run
\`${cfg.checkInstalled(packageName)}\` to confirm the real installed version
before deciding whether this is already fixed.

After upgrading, run your test suite and re-scan to confirm the finding
clears.`;
}

// ---------------------------------------------------------------------------
// Google Safe Browsing (src/lib/scanners/safeBrowsing.ts) — the site itself
// is currently on Google's malware/phishing/unwanted-software threat list.
// Unlike most findings above, the fix isn't "configure something" — it's
// "your site is very likely compromised" (or a redirect on your domain is
// being abused), plus the delisting process once it's actually clean.
// ---------------------------------------------------------------------------

export const SAFE_BROWSING_FLAGGED = `Google has flagged this exact URL on its Safe Browsing threat list. Chrome,
Firefox, and Safari all consult this list before loading a page — visitors
may already be seeing a full-page red warning, or being blocked outright,
without you knowing anything is wrong.

**This is not a configuration issue like the other findings in this report.**
A URL only ends up flagged for one of two reasons:

1. **Your site was compromised** and is now serving malicious content —
   injected JavaScript, a drive-by download, or a hidden redirect to a
   malicious site — without your knowledge. This is the far more common case.
2. **A URL shortener, open redirect, or user-generated-content area on your
   domain** is being abused to point at someone else's malicious page, and
   Google flagged your domain because the malicious content is reachable
   through it.

**Investigate before you try to get delisted — delisting a still-compromised
site just gets it flagged again within hours:**

1. Compare live files against a known-good backup or your git history for
   unexpected changes, especially in theme/plugin files, \`.htaccess\`,
   \`web.config\`, or anywhere your CMS stores executable templates.
2. Search page source and templates for injected \`<script>\` tags, obfuscated
   \`eval(\`/\`atob(\` JavaScript, or iframes pointing at unfamiliar domains —
   these are frequently appended right before \`</body>\`.
3. Check for admin/user accounts you don't recognise, and rotate every
   credential with access to the server, database, and hosting/DNS control
   panel — not just the CMS admin password.
4. Check web server and application logs around the time the compromise
   likely started for the initial entry point (an outdated plugin, an
   exposed admin panel, a leaked credential) so the same hole doesn't let the
   attacker back in after cleanup.
5. If your site includes a redirect, URL-shortening, or user-submitted-link
   feature, confirm it can't be pointed at arbitrary external URLs by an
   anonymous visitor.

**Once you're confident the site is genuinely clean:**

1. In [Google Search Console](https://search.google.com/search-console),
   verify ownership of the domain if you haven't already.
2. Open **Security Issues** in the left sidebar — Google lists the specific
   pages and threat type it detected, which is often more precise than what
   this scan alone can tell you.
3. After remediation, use the **Request a Review** action on that page.
   Google re-crawls and, if clean, lifts the flag — this typically takes
   anywhere from a few hours to a few days, not instantly.
4. Keep monitoring: re-run this scan and keep Search Console's email alerts
   on, since a reinfection through the same hole will flag the site again.`;

// ---------------------------------------------------------------------------
// WordPress plugin version detection (src/lib/scanners/webapp.ts,
// checkWordPress() → detectPlugins()) — informational only. This finding
// reports a plugin name + version read from the plugin's own public
// readme.txt; it is not itself a vulnerability claim. OSV.dev has no
// "WordPress" ecosystem (verified against its published ecosystem list), so
// unlike the npm-backed JS library findings above, no automated CVE id can be
// attached here — forcing one would risk a false match, which the appendix
// convention in docs/PLATFORM-ROADMAP.md explicitly rules out.
// ---------------------------------------------------------------------------

export const WP_PLUGIN_DETECTED = `This is an informational finding, not a vulnerability report — a WordPress
plugin and its version were readable from the plugin's own public
\`readme.txt\` file. No automated CVE match is attached to *this* finding
because OSV.dev (this scanner's default vulnerability data source) does not
cover the WordPress plugin ecosystem — if WPScan's vulnerability database is
configured and finds a real match for this version, it appears as its own,
separate finding rather than being folded into this one.

**What to do with this:**

1. Compare the detected version against the plugin's changelog on
   [wordpress.org/plugins](https://wordpress.org/plugins/) to see how far
   behind current it is.
2. Cross-check the exact version against
   [WPScan's vulnerability database](https://wpscan.com/) or the
   [National Vulnerability Database](https://nvd.nist.gov/vuln/search) —
   both index WordPress-plugin-specific CVEs that OSV.dev does not.
3. If the plugin is out of date, update it from the WordPress admin dashboard
   (**Plugins → Update Available**) after taking a backup.

**Reduce exposure regardless of version**, since the readme.txt itself being
world-readable is what made this detection possible in the first place:

\`\`\`nginx
location ~ /wp-content/plugins/.*/readme\\.(txt|html)$ { deny all; return 404; }
\`\`\`

\`\`\`apache
<FilesMatch "readme\\.(txt|html)$">
  Require all denied
</FilesMatch>
\`\`\`

This doesn't replace keeping the plugin updated — it only removes one of the
easiest ways for an automated scanner (including this one) to fingerprint the
exact version remotely.`;

/**
 * A real, WPScan-confirmed CVE match against the detected plugin version —
 * distinct from WP_PLUGIN_DETECTED above, which is purely informational.
 * fixedIn null means still unpatched upstream, which changes the advice
 * from "update" to "there is nothing to update to yet."
 */
export function wpPluginVulnerabilityRemediation(pluginName: string, fixedIn: string | null, referenceUrl?: string): string {
  const parts: string[] = [];

  if (fixedIn) {
    parts.push(
      `Update **${pluginName}** to version **${fixedIn}** or later from the WordPress admin dashboard ` +
        `(**Plugins → Update Available**) after taking a backup. This is a confirmed, disclosed vulnerability ` +
        `in the specific version detected — not a general "keep plugins updated" reminder.`
    );
  } else {
    parts.push(
      `WPScan's vulnerability database shows no patched version yet for this issue in **${pluginName}** — updating ` +
        `to the latest available release may still help if the maintainer has silently patched it since this ` +
        `database entry was last updated, but is not guaranteed to close this specific vulnerability. Consider ` +
        `whether the plugin's functionality is worth the current exposure, and watch the plugin's changelog for a ` +
        `fix. A web application firewall rule may reduce risk in the meantime, depending on the vulnerability type.`
    );
  }

  if (referenceUrl) {
    parts.push(`Full advisory: ${referenceUrl}`);
  }

  return parts.join("\n\n");
}

// ---------------------------------------------------------------------------
// Wayback historical path discovery (src/lib/scanners/waybackDiscovery.ts)
// ---------------------------------------------------------------------------

export const WAYBACK_LIVE_PATH = `Confirm this path is meant to be publicly reachable, then either secure it or
remove it.

This wasn't found on a generic wordlist — it was found in the Wayback
Machine's own archive of this domain, meaning it genuinely existed here at
some point and still responds today. That combination (old + forgotten + still
live) is exactly the profile of things nobody remembers to decommission:
retired admin panels, one-off debug pages, deprecated API versions still
running alongside their replacement.

1. **Identify what it is.** Check the response directly and search your
   deployment history/commit log for the path.
2. **If it's not meant to be public**, remove the route or block it at the
   server/CDN, the same as any other unintended exposure:

\`\`\`nginx
location = /path { deny all; return 404; }
\`\`\`

3. **If it's an old API version or admin surface still in active use**, that's
   a bigger conversation than this one finding — put it behind authentication
   and confirm it's on your team's radar for eventual retirement rather than
   living on indefinitely because nothing broke yet.
4. **Rotate anything it could have exposed** if it turns out to serve data or
   functionality that shouldn't have been reachable — the same rule as any
   other exposed-endpoint finding.`;

// ---------------------------------------------------------------------------
// HIBP domain breach search (src/lib/scanners/hibp.ts) — a positive match
// here is evidence that email addresses on this domain appeared in a known
// third-party breach dump. It is NOT a claim that this site is currently
// compromised — say so explicitly, since it's easy to conflate with the
// Safe Browsing finding above. Function, not a constant, because the useful
// advice differs a lot depending on which data classes HIBP actually
// reported (a breach with just email addresses needs different next steps
// than one with plaintext passwords or financial data).
// ---------------------------------------------------------------------------

export function hibpBreachRemediation(dataClasses: string[]): string {
  const classes = dataClasses.map((c) => c.toLowerCase());
  const hasPasswords = classes.some((c) => c.includes("password"));
  const hasFinancial = classes.some((c) =>
    ["credit card", "bank account", "financ", "social security", "passport", "national id"].some((s) => c.includes(s))
  );

  const parts: string[] = [
    `This is a record that email addresses on this domain appeared in a third-party breach dump — it is not a claim that this site is currently compromised. The exposure happened on the breached service, not here.`,
    ``,
    `1. **Identify who's actually affected.** Cross-reference the affected aliases against active accounts — some may be shared inboxes, former employees, or aliases no longer in use, which need no action.`,
  ];

  if (hasPasswords) {
    parts.push(
      ``,
      `2. **Force a password reset** for every affected account that may have reused the breached password anywhere else, and enable MFA where it isn't already required. Leaked passwords are the single biggest driver of credential-stuffing attacks — attackers replay them against unrelated services, not just the one that was breached.`
    );
  } else {
    parts.push(
      ``,
      `2. **No password was in this particular breach**, but treat the exposed addresses as a phishing/spam target list. Confirm SPF, DKIM, and DMARC are enforced (see the DNS findings above if any are missing) so a spoofed message impersonating these addresses is rejected rather than delivered.`
    );
  }

  if (hasFinancial) {
    parts.push(
      ``,
      `3. **Financial or government-ID data was included.** Check whether this triggers a breach-notification obligation in your jurisdiction (e.g. GDPR Article 33/34) and consider proactively notifying affected account holders.`
    );
  }

  parts.push(
    ``,
    `Ongoing: re-run this check periodically rather than once. HIBP indexes newly-published breach dumps continuously, so a domain that's clean today can show a new match after the next one surfaces — that's expected, not a sign this check is unreliable.`
  );

  return parts.join("\n");
}

// ---------------------------------------------------------------------------
// Dockerfile base-image freshness (src/lib/scanners/dockerBaseImage.ts) — see
// that file's header for why this is an end-of-life-tag check against
// https://endoflife.date rather than an OSV.dev CVE match: OSV.dev's OS
// ecosystems are real, but querying them needs the exact OS package versions
// baked into the image, which a Dockerfile's FROM line doesn't give us.
// ---------------------------------------------------------------------------

/** Static because the fix is identical regardless of which image is affected. */
export const DOCKER_BASE_IMAGE_UNPINNED = `Pin the base image to an explicit version tag (and ideally a digest) instead
of \`latest\` or no tag at all.

\`\`\`dockerfile
# Before
FROM node

# After — explicit tag
FROM node:20-alpine

# Stronger still — tag *and* digest, so the build is byte-for-byte
# reproducible even if the tag is later moved or the registry is compromised
FROM node:20-alpine@sha256:<digest>
\`\`\`

Get the current digest for a tag with:

\`\`\`bash
docker pull node:20-alpine
docker inspect --format='{{index .RepoDigests 0}}' node:20-alpine
\`\`\`

Without a pinned tag, the exact contents of the base image can change between
builds with no corresponding change to the Dockerfile — a dependency update
upstream can break or silently alter your build, and there's no way to tell
from the file alone which version actually shipped. Bump the pinned
version/digest deliberately, as its own reviewed change, rather than
inheriting whatever \`latest\` happens to resolve to on build day.`;

/**
 * Function, not a constant, for the same reason
 * dependencyVulnerableRemediation is: the fix names the specific image,
 * tag, and the real EOL date that was actually looked up — a static string
 * can't do that, and fabricating a "latest supported version" we haven't
 * verified would violate the same evidence rule the finding itself follows.
 */
export function dockerBaseImageOutdatedRemediation(repoPath: string, tag: string, cycle: string, eolDate: string, endoflifeProduct: string): string {
  return `Upgrade **${repoPath}:${tag}** to a currently supported release. endoflife.date
records ${repoPath} ${cycle} as end-of-life since ${eolDate} — no further
security patches are published for it upstream, so any vulnerability found in
it from this point on stays unpatched for as long as it's in use.

1. Check the currently supported cycles for **${repoPath}** at
   https://endoflife.date/${endoflifeProduct} — pick a cycle that is not past its own EOL date, ideally one with long support remaining.
2. Update the tag in the Dockerfile:

\`\`\`dockerfile
FROM ${repoPath}:${tag}
# becomes, e.g.
FROM ${repoPath}:<current-supported-tag>
\`\`\`

3. Rebuild and run your test suite — a major-version bump on the base image
   can change installed tooling, default users/permissions, or libc
   (glibc vs musl on Alpine), so treat this like any other major dependency
   upgrade rather than a drop-in swap.
4. Re-scan to confirm the finding clears, and consider pinning the new tag by
   digest too (see the unpinned-tag remediation) so the next upgrade is a
   deliberate, reviewed change rather than a silent drift.`;
}
