import type { SastCategory } from "./sastCatalog";
import type { WorkflowSecurityCategory } from "./workflowSecurityCatalog";

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

export const CERT_EXPIRED = `Renew the certificate now — until you do, visitors see a browser warning
instead of your site.

- **Let's Encrypt / certbot:** run \`sudo certbot renew\`, then reload the web
  server (\`sudo systemctl reload nginx\` or \`apache2\`). If renewal fails, the
  error usually names the cause — most often a DNS change or a firewall
  blocking port 80 for the validation request.
- **Managed hosts and CDNs:** look for a failed-renewal warning in the
  dashboard; re-validating the domain normally triggers a new certificate.

Then find out why automatic renewal stopped, or this will happen again in
90 days, and set a calendar reminder 14 days before the next expiry.`;

export const SUBDOMAIN_CERT_EXPIRED = `First decide whether each listed hostname is still needed.

- **No longer used:** delete its DNS record (an A or CNAME at your DNS
  provider). That removes the warning and a forgotten system someone could
  probe or take over.
- **Still used:** renew the certificate on whatever serves that hostname —
  \`sudo certbot renew\` on your own server, or re-validate the domain at the
  hosting provider or CDN it points to. Then find out why automatic renewal
  stopped.

A wildcard certificate (\`*.example.com\`) covers every listed host at once,
so one renewal fixes them all.`;

export const SUBDOMAIN_CERT_EXPIRING = `Make sure the certificate renews before it expires.

- **Your own server:** confirm automatic renewal works with
  \`sudo certbot renew --dry-run\`.
- **Hosting provider or CDN:** check its dashboard for a renewal warning;
  renewal usually fails because the hostname's DNS no longer points there.
- **Not used any more:** delete the hostname's DNS record instead of renewing.`;

export const CERT_NAME_MISMATCH = `Serve a certificate that includes this exact hostname.

1. Check which names the current certificate covers (shown in the finding).
   A common cause is a certificate for \`example.com\` served on
   \`www.example.com\`, or the reverse.
2. Reissue it with every hostname you serve, e.g. with certbot:

\`\`\`bash
sudo certbot --nginx -d example.com -d www.example.com
\`\`\`

3. If the hostname points at a hosting provider or CDN, add it as a custom
   domain there so the provider issues a certificate for it. If you no longer
   use the hostname, delete its DNS record instead.`;

export const CERT_CHAIN_INCOMPLETE = `Configure the server to send the intermediate certificate along with your own.

- **nginx:** \`ssl_certificate\` must point at the *full chain* file
  (certbot's \`fullchain.pem\`, not \`cert.pem\`).
- **Apache 2.4.8+:** \`SSLCertificateFile\` should be the full chain file.
- **Other servers / control panels:** paste the CA bundle ("intermediate" or
  "chain" certificate) your certificate provider supplied.

Reload the server, then confirm with
\`openssl s_client -connect example.com:443 -servername example.com\` — the
output should show at least two certificates.`;

export const CERT_UNTRUSTED = `Replace the certificate with one issued by a publicly trusted certificate authority.

Certificates from a private or internal CA are fine for internal systems, but
browsers don't trust them on a public site. Let's Encrypt is free and
automated; most hosts and CDNs also issue trusted certificates automatically
once the domain is added. If the certificate was revoked, find out why
(often a key compromise) before reissuing it with a new key.`;

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

export const SMUGGLING_SURFACE = `A response should carry exactly one of Content-Length or Transfer-Encoding,
never both — RFC 7230 §3.3.3. When a front-end proxy/load balancer and the
back-end server it forwards to disagree on which one to trust, an attacker
can craft a request whose framing is read differently by each hop, splitting
one connection's traffic to smuggle a second, hidden request past the
front-end's security controls (request smuggling, CL.TE/TE.CL/TE.TE desync).

This finding does not prove a desync is exploitable — it means the response
shape that makes that class of attack possible exists somewhere in your
stack. Fix it at the source:
- Configure your back-end application/framework to send only one of the two
  headers (chunked transfer OR a precomputed Content-Length, never both).
- If a proxy, CDN or load balancer sits in front, check its own
  request-smuggling mitigations (most major providers — Cloudflare, AWS
  ALB/CloudFront, nginx 1.21+ — reject or normalise ambiguous framing by
  default; confirm this is actually enabled).
- For a thorough audit beyond this read-only check, use a dedicated tool
  designed for it (e.g. Burp Suite's HTTP Request Smuggler) against
  infrastructure you fully control end-to-end, coordinated with your CDN/
  proxy operator — a naive probe can corrupt a connection shared with other
  tenants of the same front end.`;

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

export const MAGENTO_ENV_PHP_EXPOSED = `Treat this as an active incident, not routine hardening — the database
credentials and crypt key are both out and should be assumed compromised.

1. Rotate the database password immediately and run \`bin/magento setup:config:set\`
   to update it, then rotate every encrypted value (payment credentials, API keys) with
   \`bin/magento setup:rollback\` or Magento's official key-rotation tooling.
2. Fix the web server config so \`app/etc/\` is never served directly — this usually
   means the vhost root points at \`pub/\` rather than the store root, or an \`.htaccess\`/
   nginx rule explicitly denies \`app/etc/\`.
3. Review access logs for any request to this path before you found it.`;

export const MAGENTO_DOWNLOADER_ACCESSIBLE = `Remove or block public access to the \`/downloader/\` directory — it is
deprecated and not needed for a production store. Delete the directory, or add a
server-level rule (nginx \`location\`/Apache \`<Directory>\` block) that denies it.`;

export const MAGENTO_DEFAULT_ADMIN_PATH = `Move the admin panel to a custom path: set \`admin/url/custom_path\` via
\`bin/magento config:set\`, or the Admin Base URL options in **Stores → Configuration →
Advanced → Admin**. Pair this with 2FA on every admin account and an IP allowlist if
your team works from fixed locations.`;

export const SHOPIFY_ADMIN_TOKEN_EXPOSED = `Revoke the exposed token immediately in Shopify Admin → **Apps and sales
channels → Develop apps** (or the custom/private app that issued it), then issue a new
one. Find where the leaking code puts it into a page or script the browser loads —
admin-level tokens must stay server-side (a backend proxy endpoint, or a serverless
function) and never be embedded in theme Liquid/JS. The public Storefront API token is
fine to expose; this format never is.`;

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

export const DOM_XSS = `A script on this page reads data from the URL — most likely \`location.hash\` or
\`location.search\` — and writes it into the page without sanitising it first. Unlike a
reflected-XSS finding, this never touches your server: an attacker only needs to send
someone a crafted link to this page.

1. Find where the page reads \`location.hash\`/\`location.search\`/\`document.URL\`/
   \`document.referrer\` and writes the result into the DOM (\`innerHTML\`, \`outerHTML\`,
   \`document.write\`, \`insertAdjacentHTML\`, a templating call that doesn't escape its
   input, or a router library's \`dangerouslySetInnerHTML\`-style API).
2. Use a text-only sink (\`textContent\`, \`setAttribute\`) instead, or run the value
   through a sanitiser (e.g. DOMPurify) before it ever reaches markup.
3. A Content-Security-Policy without \`'unsafe-inline'\` in \`script-src\` limits what an
   injected \`<script>\` can do, but does not fix the underlying unsanitised write.`;

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

export const LIVE_HOST_DISCOVERED = `A discovered hostname is serving a live web application. This is inventory, not
a vulnerability — but every live host is attack surface, so confirm it is one
you mean to expose:

- Is this host meant to be public? Staging, admin, and internal apps that end up
  internet-reachable are a common breach entry point.
- Does the detected technology need patching or hardening? Match it against the
  version findings in this report.
- If the host is no longer used, take it offline and remove its DNS record.`;

export const CONTENT_DISCOVERY_FOUND = `A path that is not linked from the site answered a request. Content discovery
probes a curated list of common directories and files, so a hit here is a
reachable endpoint an attacker could also find:

- Confirm this path is meant to be reachable. Admin panels, backups, config
  files, and ".git"/".env"-style paths are the classic accidental exposures.
- If it should not be public, remove it or put it behind authentication / an IP
  allow-list — "unlinked" is not "hidden".
- A 401/403 here is good (the path exists but is protected); a 200 on something
  sensitive is the one to act on.`;

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
export type SqlmapContext = { place?: string; techniques?: string[] };

/** Where the injected value arrives changes where the fix goes. */
const SQLMAP_PLACE_NOTES: Record<string, string> = {
  GET: "The value comes from the URL query string. Check every handler behind this URL, not just the one that renders the page.",
  POST: "The value comes from a form or request body. Parameterise it where the handler builds the query; client-side validation doesn't help, since attackers send requests directly.",
  COOKIE: "The value comes from a cookie, which the browser treats as trusted and developers often forget to parameterise. Treat every cookie as user input.",
  URI: "The value is part of the URL path (a REST-style id or slug). Parameterise it like any other input, and validate its type (an integer id should be parsed as an integer).",
  "USER-AGENT": "The value comes from the User-Agent header, usually from logging or analytics code that builds a query from it. Parameterise those writes too.",
  REFERER: "The value comes from the Referer header, usually from logging or analytics code. Parameterise those writes too.",
  HOST: "The value comes from the Host header, which an attacker controls. Never put it in a query.",
};

const SQLMAP_TECHNIQUE_NOTES: Array<[RegExp, string]> = [
  [/error-based/i, "Error-based injection worked, so database error messages reach the response: turn off verbose errors as well as fixing the query."],
  [/time-based/i, "Time-based injection worked, which needs no visible output at all, so hiding results or errors isn't a fix: only parameterised queries are."],
  [/union/i, "UNION injection worked, meaning an attacker can read other tables through this parameter. Run the application's database account with the least privilege it needs."],
  [/stacked/i, "Stacked queries worked: an attacker can run extra statements, not just read. Check what the application's database account is allowed to modify."],
];

export function sqlmapRemediation(dbms: string | null, context: SqlmapContext = {}): string {
  const snippets: Record<string, string> = {
    mysql: "\n\n**MySQL / MariaDB (mysqli):**\n```php\n$stmt = $mysqli->prepare(\"SELECT * FROM users WHERE id = ?\");\n$stmt->bind_param(\"i\", $id);\n```",
    postgresql: "\n\n**PostgreSQL (node-postgres):**\n```js\nawait pool.query(\"SELECT * FROM users WHERE id = $1\", [id]);\n```",
    "microsoft sql server": "\n\n**SQL Server (mssql):**\n```js\nawait pool.request().input(\"id\", sql.Int, id).query(\"SELECT * FROM users WHERE id = @id\");\n```",
    sqlite: "\n\n**SQLite (better-sqlite3):**\n```js\ndb.prepare(\"SELECT * FROM users WHERE id = ?\").get(id);\n```",
    oracle: "\n\n**Oracle (node-oracledb):**\n```js\nawait connection.execute(\"SELECT * FROM users WHERE id = :id\", [id]);\n```",
  };
  const key = (dbms ?? "").toLowerCase();
  const match = Object.keys(snippets).find((k) => key.includes(k));
  const notes: string[] = [];
  const place = context.place ? SQLMAP_PLACE_NOTES[context.place.toUpperCase()] : undefined;
  if (place) notes.push(place);
  for (const [pattern, note] of SQLMAP_TECHNIQUE_NOTES) {
    if ((context.techniques ?? []).some((t) => pattern.test(t))) notes.push(note);
  }
  const specific = notes.length > 0 ? `\n\n**For this finding:**\n${notes.map((n) => `- ${n}`).join("\n")}` : "";
  return SQLMAP_SQLI_BASE + (match ? snippets[match] : "") + specific;
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

/** Same as COMMIX_COMMAND_INJECTION_BASE — no per-target variant. */
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
export type DependencyEcosystemSlug = "npm" | "pip" | "composer" | "go" | "maven" | "ruby" | "cargo" | "nuget";

const DEPENDENCY_ECOSYSTEM_COMMANDS: Record<
  DependencyEcosystemSlug,
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
  go: {
    manifest: "go.mod",
    checkInstalled: (pkg) => `go list -m ${pkg}`,
    commands: (pkg) => `go get ${pkg}@latest\n# or pin a specific patched version directly:\ngo get ${pkg}@<fixed-version>\ngo mod tidy`,
  },
  maven: {
    manifest: "pom.xml",
    checkInstalled: (pkg) => `mvn dependency:tree -Dincludes=${pkg}`,
    commands: (pkg) =>
      `# ${pkg} is "groupId:artifactId" — update the <version> in pom.xml directly, then:\nmvn versions:display-dependency-updates -Dincludes=${pkg}\nmvn clean install`,
  },
  ruby: {
    manifest: "Gemfile",
    checkInstalled: (pkg) => `bundle info ${pkg}`,
    commands: (pkg) => `bundle update ${pkg} --conservative`,
  },
  cargo: {
    manifest: "Cargo.toml",
    checkInstalled: (pkg) => `cargo tree -i ${pkg}`,
    commands: (pkg) => `cargo update -p ${pkg}\n# or move to a specific patched version:\ncargo update -p ${pkg} --precise <fixed-version>`,
  },
  nuget: {
    manifest: "the .csproj file",
    checkInstalled: () => `dotnet list package --include-transitive`,
    commands: (pkg) => `dotnet add package ${pkg} --version <fixed-version>\ndotnet restore --force-evaluate   # refreshes packages.lock.json`,
  },
};

/** Where the vulnerable version came from, when the finding knows (dependencyManifest.ts sets it). */
export type DependencyRemediationContext = {
  /** "lockfile": the exact installed version; "manifest": the lowest version a declared range allows. */
  versionSource: "lockfile" | "manifest";
  /** The file the version was read from ("package-lock.json", "requirements.txt", ...). */
  file: string;
  /** A version OSV.dev names as fixing every advisory found, when it names one. */
  fixedVersion?: string | null;
  /** false when the package is only pulled in by another dependency. */
  direct?: boolean | null;
  /** Ancestors from the direct dependency down to the parent (name@version). */
  introducedVia?: string[];
};

// How to force a patched version of a dependency the project doesn't declare itself.
function transitiveOverride(slug: DependencyEcosystemSlug, file: string, pkg: string, fixed: string): string {
  switch (slug) {
    case "npm":
      if (file === "yarn.lock") return `Yarn: add \`"resolutions": { "${pkg}": "${fixed}" }\` to package.json, then \`yarn install\`.`;
      if (file === "pnpm-lock.yaml") return `pnpm: add \`"pnpm": { "overrides": { "${pkg}": "${fixed}" } }\` to package.json, then \`pnpm install\`.`;
      return `npm: add \`"overrides": { "${pkg}": "${fixed}" }\` to package.json, then \`npm install\`.`;
    case "pip":
      return `Add \`${pkg}>=${fixed}\` as a direct requirement (or a constraint), then re-lock.`;
    case "composer":
      return `\`composer update ${pkg} --with-dependencies\`, or \`composer require ${pkg}:^${fixed}\` to pin it directly.`;
    case "go":
      return `\`go get ${pkg}@v${fixed.replace(/^v/, "")}\` then \`go mod tidy\` — Go builds the highest version any module requires.`;
    case "maven":
      return `Pin it in \`<dependencyManagement>\` (Maven) or a \`constraints\` block (Gradle, then \`./gradlew dependencies --write-locks\`).`;
    case "ruby":
      return `\`bundle update ${pkg} --conservative\`, or add \`gem "${pkg}", ">= ${fixed}"\` to the Gemfile.`;
    case "cargo":
      return `\`cargo update -p ${pkg} --precise ${fixed}\`, if the crates that depend on it allow that version.`;
    case "nuget":
      return `\`dotnet add package ${pkg} --version ${fixed}\` adds a direct reference that overrides the transitive one.`;
  }
}

/**
 * Without `context` (findings from before lockfile scanning) this is the
 * original manifest-range text. With it, the text names the fixed version
 * when OSV.dev gives one, says whether the version is lockfile-exact, and
 * explains how to fix a transitive dependency.
 */
export function dependencyVulnerableRemediation(
  packageName: string,
  ecosystem: DependencyEcosystemSlug = "npm",
  context?: DependencyRemediationContext
): string {
  const cfg = DEPENDENCY_ECOSYSTEM_COMMANDS[ecosystem];
  const auditNote =
    ecosystem === "npm"
      ? " — `npm audit fix` applies it automatically when the fix doesn't require a major-version bump"
      : "";
  const fixed = context?.fixedVersion ?? null;
  const commands = fixed ? cfg.commands(packageName).replace(/<fixed-version>/g, fixed) : cfg.commands(packageName);
  const target = fixed ? `**${fixed}** or later (the version OSV.dev names as fixing every advisory found)` : "a patched version";

  let transitive = "";
  if (context?.direct === false) {
    const via = context.introducedVia ?? [];
    const chain = via.length ? ` It is pulled in by ${via.join(" > ")}.` : "";
    const parent = via.length ? ` (${via[0].replace(/@[^@]*$/, "")})` : "";
    transitive = `

**${packageName}** isn't declared by your project directly.${chain} Upgrading the
dependency that brings it in${parent} to a release that requires a patched
version is the cleanest fix. If there isn't one yet, force the patched version:
${transitiveOverride(ecosystem, context.file, packageName, fixed ?? "<fixed-version>")}`;
  }

  const versionNote =
    context?.versionSource === "lockfile"
      ? `The version checked here is the exact one recorded in \`${context.file}\` —
what your project actually installs — so update the lockfile, not just the
manifest.`
      : `The version checked here comes from the range declared in \`${context?.file ?? cfg.manifest}\`,
not a lockfile, so it is an approximation of what's actually installed — run
\`${cfg.checkInstalled(packageName)}\` to confirm the real installed version
before deciding whether this is already fixed.`;

  return `Update **${packageName}** to ${target}.

\`\`\`bash
${commands}
\`\`\`${transitive}

Check the advisory OSV.dev matched (search \`${packageName}\` at
https://osv.dev) for the exact patched range${auditNote}.

${versionNote}

After upgrading, run your test suite and re-scan to confirm the finding
clears.`;
}

/**
 * Typosquat/supply-chain risk (src/lib/scanners/typosquatRisk.ts) — the
 * fix is not "upgrade a version", it's "confirm whether this dependency
 * was ever intended" and, if not, treat it as a possible compromise.
 */
export function typosquatRiskRemediation(ecosystemLabel: string, packageName: string, resembles: string): string {
  return `**${packageName}** is one character away from the well-known ${ecosystemLabel} package **${resembles}**, and has far fewer releases than a real, actively-maintained package of that name — the pattern a typosquat (a malicious package published under a name a developer might mistype or misread) uses.

1. Check whether \`${packageName}\` was ever meant to be a dependency. Search your lockfile/manifest history (\`git log -p -- package-lock.json\` or the equivalent for your ecosystem) for when and how it was added — a manual edit, a copy-pasted install command with a typo, or a dependency someone else introduced.
2. If it was a typo: remove \`${packageName}\`, install \`${resembles}\` instead, and re-run your test suite. Before trusting the environment it ran in, review anything the package could have executed on install (npm \`postinstall\`/\`preinstall\` scripts, a PyPI \`setup.py\`) and rotate any credentials that environment had access to if you can't rule out it ran.
3. If \`${packageName}\` really is what you intended (an unrelated, legitimately small package that happens to be one character off), no action is needed beyond double-checking it is the package you expect at https://www.npmjs.com/package/${packageName} or https://pypi.org/project/${packageName}/.

This is a heuristic signal from name similarity plus registry release history, not a confirmed-malicious verdict — it will not catch every typosquat, and a small number of genuinely unrelated packages may be flagged. If this package is in fact malicious, consider reporting it to the registry's security team (npm: security@npmjs.com; PyPI: https://pypi.org/security/).`;
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
// attached here — forcing one would risk a false match, which
// docs/SCANNER-CONVENTIONS.md explicitly rules out.
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
// Software CVE DB (src/lib/scanners/softwareCveDb.ts, E-24) — real CVE
// matches for the three fingerprint.ts riskySoftware entries OSV.dev can't
// cover: WordPress core (via WPScan), PHP and Apache (via NVD's CPE-based
// lookup). Distinct from OUTDATED_LIBRARY above, which is used for the
// generic "no CVE data available, upgrade anyway" case across all of
// KNOWN_RISKY — these three carry real, matched CVE ids, so the guidance
// gets to be specific about it.
// ---------------------------------------------------------------------------

export const SOFTWARE_CVE_WORDPRESS_CORE = `Update WordPress core to the latest version. This is a confirmed CVE match
from WPScan's vulnerability database against the exact core version detected
— not the general "keep WordPress updated" reminder.

1. **Back up the site and database first** — files and database, not just
   one or the other.
2. Update from **Dashboard → Updates**, or via WP-CLI:

\`\`\`bash
wp core update
wp core update-db
\`\`\`

3. Re-scan afterwards to confirm the finding clears.

Core updates are usually low-risk compared to plugin/theme updates — WordPress
maintains backward compatibility carefully across minor and even major
releases — but test on staging first if the site has heavy custom
functionality or an old, unmaintained theme.`;

export const SOFTWARE_CVE_PHP = `Upgrade the server's PHP version. These are real CVEs from the National
Vulnerability Database matched against the exact PHP version this site is
running — an end-of-life PHP release accumulates unpatched vulnerabilities
with no vendor fix coming, ever.

1. **Check your current PHP support window** at
   [php.net/supported-versions](https://www.php.net/supported-versions.php) —
   only actively supported branches receive security patches.
2. Upgrade via your host's control panel, or directly:

\`\`\`bash
# Debian/Ubuntu
sudo apt install php8.3-fpm
sudo a2dismod php8.1 && sudo a2enmod php8.3   # Apache
sudo systemctl restart php8.3-fpm nginx        # nginx + php-fpm
\`\`\`

3. **Test before switching production traffic** — a major PHP version bump can
   break code relying on removed/deprecated functions (this is common enough
   that it's the main reason old PHP versions linger). Run your test suite,
   or at minimum smoke-test key flows, against the new version on staging.
4. Re-scan afterwards to confirm.

If you're on shared hosting with no version control, this is a conversation
with your host or a reason to move providers — there is no secure way to stay
on an end-of-life PHP branch indefinitely.`;

export const SOFTWARE_CVE_APACHE = `Upgrade Apache httpd to a current release. These are real CVEs from the
National Vulnerability Database matched against the exact Apache version this
server is advertising.

1. Upgrade via your OS package manager:

\`\`\`bash
# Debian/Ubuntu
sudo apt update && sudo apt install --only-upgrade apache2

# RHEL/CentOS/Alma
sudo dnf update httpd
\`\`\`

2. **Review the changelog for your version jump** — a config directive
   deprecated or changed behaviour between major Apache versions can break a
   site's \`.htaccess\`/vhost config if copied forward blindly. Test on staging
   first.
3. Restart (not just reload) after upgrading, and re-scan to confirm the
   version string changed.

If Apache is fronted by a managed platform or reverse proxy, confirm which
layer is actually advertising the outdated \`Server\` header — the fix may
belong to your hosting provider rather than a server you control directly.`;

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

/**
 * End-of-life software the site itself reveals (endOfLife.ts). Built from the
 * real cycle and date looked up, never a guessed "latest version".
 */
export function endOfLifeRemediation(label: string, cycle: string, eolDate: string | null, endoflifeProduct: string, packagedBy: string | null): string {
  const since = eolDate ? ` (end of life ${eolDate})` : "";
  const vendor = packagedBy
    ? `

**If ${label} came from ${packagedBy}'s own packages**, upstream end of life may
not apply: check your ${packagedBy} release's support status. If the release
itself is still supported and you install its updates, record that as your
evidence for Cyber Essentials; if the release is past its own support, upgrade
the operating system release.`
    : "";
  return `Move off ${label} ${cycle}${since} to a release line that still receives security fixes.

1. See which ${label} release lines are supported, and until when:
   https://endoflife.date/${endoflifeProduct} — pick one with plenty of support left.
2. Upgrade in a test environment first. A new major release can remove
   features or change defaults, so check the upgrade notes and run your tests.
3. Deploy, then re-scan to confirm this finding clears.
4. Put the next end-of-life date in your calendar so the following upgrade is
   planned, not forced. Cyber Essentials requires unsupported software to be
   removed or upgraded.${vendor}`;
}

/**
 * Function, not a constant, same reasoning as dockerBaseImageOutdatedRemediation:
 * names the actual package, versions, and image Trivy scanned. Deliberately
 * not folded into dependencyVulnerableRemediation's ecosystem-command shape
 * (npm/pip/composer/go/maven) — this is an OS package (apt/apk/yum) inside
 * someone else's base image, not a project dependency you can bump in your
 * own manifest. Unlike OSV.dev's dependency lookups, Trivy's own
 * `FixedVersion` field is a specific, directly-scanned fact when present, so
 * it's quoted directly rather than hedged.
 */
export function trivyImagePackageRemediation(
  pkgName: string,
  installedVersion: string,
  fixedVersion: string | undefined,
  imageRef: string
): string {
  const fixLine = fixedVersion
    ? `A fixed version is available: **${pkgName} ${fixedVersion}**.`
    : `No fixed version has been published for this package yet — track the CVE for an update rather than guessing at a workaround.`;

  return `The base image **${imageRef}** ships **${pkgName} ${installedVersion}**, which has a known vulnerability. ${fixLine}

You can't \`apt upgrade\`/\`apk upgrade\` this package directly in your own
Dockerfile and expect it to stick — the base image's own maintainers publish
the fix in a later build of the same tag family, so:

1. Check whether a newer build of **${imageRef.split(":")[0] ?? imageRef}** already bundles the fix (rebuild with \`--no-cache\` — image tags are mutable, so the same tag today may already differ from what was scanned) and re-scan.
2. If the fix isn't in the base image yet, add a stopgap layer that upgrades just this package:

\`\`\`dockerfile
FROM ${imageRef}
RUN apt-get update && apt-get install -y --only-upgrade ${pkgName} \\
    && rm -rf /var/lib/apt/lists/*
# (use apk upgrade ${pkgName}, or your distro's equivalent, on non-Debian bases)
\`\`\`

3. Re-scan to confirm the finding clears once the fix is in place. Remove the
   stopgap layer once a base image build that already includes the fix is
   available, so you're not carrying a manual patch indefinitely.`;
}

/**
 * Trivy's own `Resolution` field is already real, sourced remediation text —
 * this wraps it (per docs/SCANNER-CONVENTIONS.md's "remediation prose lives
 * in remediationText.ts, not inline at the push site") rather than
 * duplicating it, and falls back to a generic pointer for the older rego
 * checks that don't set Resolution.
 */
// ---------------------------------------------------------------------------
// WAF detection (src/worker/tools/whatwaf.ts)
// ---------------------------------------------------------------------------

export const WAF_NOT_DETECTED = `No Web Application Firewall (WAF) was detected in front of this application.
A WAF provides an additional layer of defence against common web attacks —
injection, cross-site scripting, and application-layer DDoS — buying time to
patch when a new vulnerability is disclosed.

**Options, roughly in order of deployment effort:**

1. **Managed CDN/WAF** (Cloudflare, AWS WAF, Azure Front Door, Akamai) —
   point DNS at the provider, enable the managed ruleset. Fastest path, and
   the WAF doubles as a CDN.
2. **ModSecurity + OWASP Core Rule Set** — open-source, self-hosted. Add the
   module to nginx or Apache, enable the CRS, and start in \`DetectionOnly\`
   mode while you tune false positives.
3. **Cloud-native WAF** (AWS WAF, Azure WAF, GCP Cloud Armor) — if you are
   already behind that provider's load balancer, the WAF is a configuration
   toggle, not a new deployment.

A WAF is defence in depth, not a replacement for fixing the underlying issues
in this report. Start with the critical and high findings above, and layer a
WAF on top.`;

export const WAF_BYPASS = `A WAF is present but WhatWaf identified a technique that bypasses it. This
means the WAF provides a false sense of security for some attack patterns.

1. **Update the WAF ruleset** — managed WAFs auto-update, but self-hosted ones
   (ModSecurity) need manual rule updates.
2. **Review the WAF mode** — ensure it is in blocking mode, not detection-only.
3. **Test the bypass** — reproduce the bypass technique in a staging
   environment and confirm the WAF blocks it after updating.
4. **Fix the underlying vulnerability** — a WAF bypass is only dangerous when
   there is a real vulnerability behind it. Prioritise the application-level
   fix.`;

// ---------------------------------------------------------------------------
// WPScan CLI (src/worker/tools/wpscan.ts)
// ---------------------------------------------------------------------------

export const WPSCAN_CONFIG_BACKUP = `A WordPress configuration backup file is publicly accessible. This file
typically contains database credentials, authentication keys, and other
secrets.

1. **Delete the backup immediately** — it should never exist in the web root.
2. **Rotate every credential** it contained: database password, AUTH_KEY,
   SECURE_AUTH_KEY, and all other salts in wp-config.php.
3. **Block access** to common backup patterns at the server level:

\`\`\`nginx
location ~* wp-config\\.php\\.(bak|old|orig|save|swp|txt)$ {
  deny all;
  return 404;
}
\`\`\`

4. **Audit how it was created** — a manual backup left by an admin, an editor
   plugin, or part of a compromised deployment pipeline. Remove the cause, not
   just the symptom.`;

export const WPSCAN_DB_EXPORT = `A database export file is publicly accessible. This is a **critical** exposure
— the file likely contains every user account, password hash, post, comment,
and option row in the WordPress database.

1. **Delete the file immediately.**
2. **Assume the data is compromised.** Force a password reset for every user,
   revoke all active sessions, and rotate every secret stored in the database
   (API keys, OAuth tokens, etc.).
3. **Block access** at the server level:

\`\`\`nginx
location ~* \\.(sql|sql\\.gz|sql\\.bz2|sql\\.zip)$ {
  deny all;
  return 404;
}
\`\`\`

4. **Never store database exports inside the web root.** Use a backup plugin
   that writes to a private storage location (S3, a local path outside the
   document root) instead.`;

export const WPSCAN_TIMTHUMB = `TimThumb is a PHP image-resizing script with a history of critical
remote-file-inclusion and remote-code-execution vulnerabilities.

1. **Remove TimThumb entirely** — modern WordPress has built-in image handling
   via \`add_image_size()\` and the media library.
2. If removal is not immediately possible, update to the latest TimThumb
   version and restrict the list of allowed domains.
3. Check for indicators of compromise: unexpected PHP files in the cache
   directory, unfamiliar cron jobs, or new admin accounts.`;

export function wpScanThemeVulnerabilityRemediation(slug: string, fixedIn: string | null): string {
  if (fixedIn) {
    return `Update the **${slug}** theme to version **${fixedIn}** or later from the WordPress admin
dashboard (**Appearance → Themes → Update**) after taking a backup. This is a
confirmed, disclosed vulnerability in the specific version detected.`;
  }
  return `The **${slug}** theme has a known vulnerability with no patched version available
yet. Consider switching to an alternative theme, or apply a web application
firewall rule to mitigate the specific vulnerability type while waiting for a
fix from the theme author.`;
}

export function cmsmapVulnerabilityRemediation(cmsType: string): string {
  return `CMSmap identified a vulnerability in this **${cmsType}** installation.

1. **Update** ${cmsType} core and all extensions to the latest versions.
2. **Review** the specific vulnerability details and check the vendor's
   advisory for the exact affected versions.
3. **Harden** the ${cmsType} installation following the official security
   checklist for your version.
4. **Re-scan** to confirm the finding clears after patching.`;
}

export function cmsmapMisconfigRemediation(cmsType: string): string {
  return `CMSmap identified a configuration weakness in this **${cmsType}** installation.
Review the ${cmsType} hardening guide and correct the specific misconfiguration
reported. Common issues include debug mode enabled in production, default
admin paths exposed, and unnecessary modules/plugins active.`;
}

export const METADATA_LEAK_EMAIL = `An email address was found in the metadata of a publicly accessible document.
Strip document metadata before publishing using your office suite's "Inspect
Document" feature, or run \`exiftool -all= <file>\` to remove all metadata.`;

export const METADATA_LEAK_INTERNAL_IP = `An internal/private IP address was found in a publicly accessible document's
metadata. This leaks information about your internal network topology. Strip
document metadata before publishing.`;

export const METADATA_LEAK_PATH = `A local filesystem path (e.g. \`C:\\Users\\...\` or \`/home/...\`) was found in a
publicly accessible document's metadata. This leaks internal usernames and
directory structure. Strip metadata before publishing.`;

export const METADATA_LEAK_AUTHOR = `An author name was found in a publicly accessible document's metadata.
While low-risk, this can be used in social engineering attacks. Strip
document metadata before publishing using your office suite's privacy tools.`;

export const METADATA_LEAK_SOFTWARE = `Software version information was found in a publicly accessible document's
metadata. This reveals the tools and versions used internally. Strip
document metadata before publishing.`;

export const HIDDEN_ENDPOINT_DISCOVERED = `A hidden endpoint was discovered via JavaScript-aware crawling (ZAP AJAX
Spider) that was not found by the traditional HTML spider. Review whether
this endpoint should be publicly accessible and ensure it enforces
appropriate authentication and authorization controls.`;

export function trivyConfigMisconfigRemediation(resolution: string | undefined, primaryUrl: string | undefined): string {
  const link = primaryUrl ? `\n\nSee ${primaryUrl} for the full rule rationale and background.` : "";
  if (resolution && resolution.trim()) {
    return `${resolution.trim()}${link}`;
  }
  return `Review this resource against Trivy's rule for this finding — no specific remediation text was published for it.${link}`;
}

// --- API scanning (Kiterunner / Arjun) ---

export const KITERUNNER_HIDDEN_ENDPOINT = `An API endpoint was discovered via contextual wordlist brute-forcing
(Kiterunner) that is not linked from the application's HTML or JavaScript.
Review whether this endpoint should be publicly accessible and ensure it
enforces appropriate authentication and authorization controls. Consider
adding the endpoint to your API documentation or removing it if it is
no longer needed.`;

export const ARJUN_HIDDEN_PARAMETER = `A hidden HTTP parameter was discovered that is not documented in the
application's public interface. Hidden parameters can be used to bypass
input validation or access restricted functionality. Review each
discovered parameter and ensure it is properly validated and authorised.
Remove any debug or internal-only parameters from production.`;

// --- Session / business logic ---

export const NO_RATE_LIMIT = `The login endpoint does not appear to enforce rate limiting. This
allows attackers to perform brute-force password guessing attacks at
high speed. Implement rate limiting (e.g. 5 attempts per minute per
IP/account) and consider adding CAPTCHA after repeated failures.
Most web frameworks have rate-limiting middleware available.`;

export const SESSION_FIXATION = `The server accepted a pre-set session cookie without issuing a new
session identifier. An attacker could set a victim's session cookie
(e.g. via a subdomain cookie or XSS) and then hijack the session once
the victim authenticates. Ensure your application always generates a
new session ID upon successful authentication, invalidating any
previously issued session tokens.`;

export const IDOR_INDICATOR = `An API endpoint returned data when accessed with a sequential numeric
ID without requiring authentication. This may indicate an Insecure
Direct Object Reference (IDOR) vulnerability where users can access
other users' data by changing the ID parameter. Implement proper
authentication and authorization checks on all data-access endpoints.
Use non-sequential identifiers (UUIDs) where possible.`;

// --- JWT security (src/worker/tools/jwtAnalysis.ts) ---

export const JWT_NONE_ALGORITHM = `A JWT issued by this site uses the "none" algorithm, or has no
signature at all. Any library that honours "none" (or fails to check
that a signature is present) will accept a token whose claims have
been edited by anyone who sees it — including role/permission claims.
Configure your JWT library to accept only the specific signing
algorithm you use (e.g. HS256 or RS256), and reject "none" and any
algorithm you did not explicitly allow.`;

export const JWT_NO_EXPIRATION = `A JWT issued by this site has no "exp" (expiration) claim, so once
issued it remains valid forever. A token that leaks — in a log, a
browser history entry, or a compromised device — stays usable
indefinitely. Set a short, explicit expiration on every token you
issue, and use a refresh-token flow for long-lived sessions instead
of a single never-expiring access token.`;

export const JWT_WEAK_SECRET = `A JWT issued by this site is signed with a secret from a short list of
publicly known, commonly used default or example secrets. Anyone who
finds this secret can forge a valid token for any user, including an
administrator. Generate a new, long, random secret (at least 32 bytes
from a cryptographically secure source) and rotate it — every token
signed with the old secret must be treated as compromised.`;

export const JWT_SENT_OVER_HTTP = `A JWT was observed on a plain HTTP response. Without TLS, a token in
transit can be read or captured by anyone on the network path between
the client and your server — a coffee-shop Wi-Fi network, a
compromised router, or an intermediate proxy. Serve the entire
application over HTTPS and redirect HTTP requests, so no credential
ever travels in clear text.`;

export const JWT_EXPOSED_IN_URL = `A JWT appears in a URL (a query string or path segment) rather than
only in a header or cookie. URLs are written to server access logs,
proxy logs, browser history, and the Referer header sent to any
third-party resource the page loads — so a token placed in a URL can
leak well after the original request completes. Send tokens only in
an Authorization header or an HttpOnly cookie, never as a URL
parameter.`;

// --- Cloud posture (E-32) ---

export const AWS_PUBLIC_S3_BUCKET = `This S3 bucket is missing one or more PublicAccessBlock settings, or
has no PublicAccessBlock at all. Enable all four settings on every
bucket:

\`\`\`
aws s3api put-public-access-block \\
  --bucket BUCKET_NAME \\
  --public-access-block-configuration \\
    BlockPublicAcls=true,IgnorePublicAcls=true,\\
    BlockPublicPolicy=true,RestrictPublicBuckets=true
\`\`\`

Also enable account-level S3 Block Public Access in the AWS console
under S3 > Block Public Access settings for this account.`;

export const AWS_PUBLIC_S3_POLICY = `This S3 bucket has a bucket policy that grants public access. Review
the bucket policy with:

\`\`\`
aws s3api get-bucket-policy --bucket BUCKET_NAME
\`\`\`

Remove any Statement with \`"Principal": "*"\` or
\`"Principal": {"AWS": "*"}\` unless the bucket genuinely needs to
serve public content. Even then, prefer CloudFront with an OAI/OAC
over direct public bucket access.`;

export const AWS_ACCOUNT_PUBLIC_ACCESS = `The AWS account does not have account-level S3 Block Public Access
fully enabled. This is a defence-in-depth control that prevents any
bucket in the account from being accidentally made public. Enable it:

**AWS Console:** S3 → Block Public Access settings for this account →
enable all four checkboxes.

**CLI:**
\`\`\`
aws s3control put-public-access-block \\
  --account-id ACCOUNT_ID \\
  --public-access-block-configuration \\
    BlockPublicAcls=true,IgnorePublicAcls=true,\\
    BlockPublicPolicy=true,RestrictPublicBuckets=true
\`\`\``;

export const AZURE_PUBLIC_BLOB = `This Azure Storage account has allowBlobPublicAccess enabled. Even
if no containers are currently public, any user with the right
permissions can create a public container. Disable it:

**Azure Portal:** Storage account → Configuration → Allow Blob
anonymous access → Disabled.

**CLI:**
\`\`\`
az storage account update \\
  --name ACCOUNT_NAME \\
  --resource-group RG_NAME \\
  --allow-blob-public-access false
\`\`\``;

export const AZURE_HTTP_TRAFFIC = `This Azure Storage account allows unencrypted HTTP traffic. Enforce
HTTPS-only:

**Azure Portal:** Storage account → Configuration → Secure transfer
required → Enabled.

**CLI:**
\`\`\`
az storage account update \\
  --name ACCOUNT_NAME \\
  --resource-group RG_NAME \\
  --https-only true
\`\`\``;

export const AZURE_WEAK_TLS = `This Azure Storage account allows TLS versions below 1.2. Set the
minimum to TLS 1.2:

**Azure Portal:** Storage account → Configuration → Minimum TLS
version → Version 1.2.

**CLI:**
\`\`\`
az storage account update \\
  --name ACCOUNT_NAME \\
  --resource-group RG_NAME \\
  --min-tls-version TLS1_2
\`\`\``;

export const GCP_PUBLIC_ACCESS_PREVENTION = `This GCS bucket does not have Public Access Prevention enforced. Without
it, an IAM binding or legacy ACL can grant public access without an
additional safety net catching it. Enforce it:

**Console:** Cloud Storage → bucket → Permissions → Public access
prevention → Enforce.

**CLI:**
\`\`\`
gcloud storage buckets update gs://BUCKET \\
  --public-access-prevention=enforced
\`\`\``;

export const GCP_UNIFORM_ACCESS = `This GCS bucket uses legacy per-object ACLs instead of uniform
bucket-level access. Legacy ACLs are harder to audit for public exposure
since they can be set per-object, independent of the bucket's IAM policy.
Switch to uniform access:

**Console:** Cloud Storage → bucket → Permissions → Access control →
Uniform.

**CLI:**
\`\`\`
gcloud storage buckets update gs://BUCKET \\
  --uniform-bucket-level-access
\`\`\`

This is a one-way switch within 90 days of enabling it — existing ACLs
stop being enforced in favour of the bucket's IAM policy, so confirm
nothing depends on a per-object ACL before switching.`;

export const GCP_PUBLIC_BUCKET = `This GCS bucket's IAM policy grants access to \`allUsers\` or
\`allAuthenticatedUsers\`, meaning anyone on the internet (or anyone with a
Google account) can access it. Review and remove the binding:

\`\`\`
gcloud storage buckets get-iam-policy gs://BUCKET
gcloud storage buckets remove-iam-policy-binding gs://BUCKET \\
  --member=allUsers --role=ROLE_FROM_ABOVE
gcloud storage buckets remove-iam-policy-binding gs://BUCKET \\
  --member=allAuthenticatedUsers --role=ROLE_FROM_ABOVE
\`\`\`

If the bucket genuinely needs to serve public content, prefer a signed URL
or Cloud CDN in front of it over a fully public, listable bucket.`;

// --- Cloud posture: IAM / encryption (SCALE-3) ---

export const AWS_IAM_PASSWORD_POLICY = `This AWS account has no IAM account
password policy, so console users can set weak passwords. Set one that meets
Cyber Essentials / CIS expectations:

\`\`\`
aws iam update-account-password-policy \\
  --minimum-password-length 14 \\
  --require-symbols --require-numbers \\
  --require-uppercase-characters --require-lowercase-characters \\
  --max-password-age 90 --password-reuse-prevention 24
\`\`\`

Better still, use IAM Identity Center (SSO) / federation and reserve long-lived
console passwords for break-glass accounts only, each with hardware MFA.`;

export const AWS_IAM_WEAK_PASSWORD_POLICY = `This AWS account has an IAM
password policy, but it is weaker than recommended (minimum length under 14,
no expiry, or no reuse-prevention). Strengthen it:

\`\`\`
aws iam update-account-password-policy \\
  --minimum-password-length 14 \\
  --require-symbols --require-numbers \\
  --require-uppercase-characters --require-lowercase-characters \\
  --max-password-age 90 --password-reuse-prevention 24
\`\`\``;

export const AZURE_STORAGE_INFRA_ENCRYPTION = `This Azure Storage account does
not have infrastructure (double) encryption enabled. Data at rest is encrypted
once by default, but regulated workloads often require a second,
infrastructure-level layer. It can only be set at account creation:

\`\`\`
az storage account create --name NAME --resource-group RG \\
  --require-infrastructure-encryption true ...
\`\`\`

Recreate the account with the flag, or confirm single-layer encryption is
acceptable for your compliance scope and accept this finding.`;

// --- Strix AI pentest (Sprint 18) ---

export function strixRemediation(vulnClass: string): string {
  const base = `Strix (AI pentest agent) validated this vulnerability with a
working proof-of-concept exploit. This is not a speculative detection —
the agent confirmed exploitability against the live target.`;

  const byClass: Record<string, string> = {
    sqli: `${base}\n\nSQL injection confirmed. Use parameterised queries or
prepared statements for all database access. Never concatenate user input
into SQL strings. Review the ORM/query builder configuration and enable
strict parameterisation.`,
    xss: `${base}\n\nCross-site scripting confirmed. Encode all user-supplied
output with context-appropriate escaping (HTML entity encoding for HTML
content, JavaScript encoding for script contexts). Implement a strict
Content Security Policy.`,
    ssrf: `${base}\n\nServer-side request forgery confirmed. Validate and
allowlist all URLs the application fetches. Block internal/private IP
ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254)
at the network level and in application code.`,
    rce: `${base}\n\nRemote code execution confirmed. This is the highest-
severity class of vulnerability. Patch the affected component immediately.
If no patch is available, take the affected service offline or restrict
network access to it until one is.`,
    "auth-bypass": `${base}\n\nAuthentication bypass confirmed. Review and
harden the authentication flow — ensure session tokens are validated on
every request, enforce re-authentication for sensitive operations, and
check that no debug/backdoor endpoints exist in production.`,
    idor: `${base}\n\nInsecure Direct Object Reference confirmed. Implement
server-side authorization checks on every data-access endpoint. Verify
the authenticated user has permission to access the requested resource,
not just that they hold a valid session.`,
    "path-traversal": `${base}\n\nPath traversal confirmed. Never use raw
user input to construct file paths. Use a allowlist of permitted files or
resolve the canonical path and verify it stays within the intended
directory before reading or serving it.`,
    "default-creds": `${base}\n\nDefault or weak credentials confirmed on a
live service. Change them immediately — this is one of the most automated
attack vectors, targeted by bots continuously.`,
  };

  return byClass[vulnClass] ?? base;
}

// --- Cairn autonomous exploitation (AGPL-3.0, subprocess-isolated) ---

// ---------------------------------------------------------------------------
// Business logic (src/lib/scanners/businessLogic.ts) — passive checks for
// common application-layer flaws: missing CSRF tokens, forms posting to
// external domains, autocomplete on sensitive fields, sequential workflow
// URLs, predictable resource IDs, open redirects, and absent rate limiting.
// ---------------------------------------------------------------------------

export const BUSINESS_LOGIC_CSRF_MISSING = `Add CSRF tokens to every form that performs a state-changing action (POST,
PUT, PATCH, DELETE). Without a token, an attacker-controlled page can submit
requests on behalf of a logged-in user.

Most frameworks handle this automatically:

**Django:** enabled by default — confirm \`{% csrf_token %}\` is inside every
\`<form>\` tag that uses \`method="post"\`.

**Rails:** enabled by default — \`protect_from_forgery with: :exception\` in
\`ApplicationController\`, and the meta tag \`csrf-token\` in the layout.

**Laravel:** add \`@csrf\` inside every Blade form.

**Express (csurf / csrf-csrf):**
\`\`\`js
const csrf = require("csurf");
app.use(csrf({ cookie: true }));
// then in the form: <input type="hidden" name="_csrf" value="<%= csrfToken %>">
\`\`\`

**Next.js / React SPA:** set a CSRF cookie on session creation and send it
back as a custom header (\`X-CSRF-Token\`) on every mutating fetch. The
server compares cookie to header — the same-origin policy guarantees only
your own code can read the cookie.

For AJAX-only forms, the \`SameSite=Lax\` cookie attribute is partial
protection, but a CSRF token is the proper defence.`;

export const BUSINESS_LOGIC_EXTERNAL_FORM_ACTION = `A form on this page sends data to a different domain. This may be
intentional (a payment processor, a third-party survey tool) or it may
indicate data exfiltration — either injected markup or a legitimate form
whose action was changed.

1. **Verify the target domain is expected.** If the form posts to a known
   third-party service you integrated, this is informational only.
2. **If it's unexpected**, inspect the page source or CMS template for
   injected or modified \`<form action="...">\` attributes. Compare against
   version control or a known-good backup.
3. **Protect against future injection** by tightening your CSP's
   \`form-action\` directive to allow only your own origin and any
   third-party targets you genuinely use:

\`\`\`
Content-Security-Policy: form-action 'self' https://checkout.stripe.com
\`\`\``;

export const BUSINESS_LOGIC_AUTOCOMPLETE = `Sensitive fields (passwords, credit card numbers, SSNs) should disable
browser autofill to reduce the risk of credentials being stored in
cleartext on shared or compromised devices.

Add \`autocomplete="off"\` or \`autocomplete="new-password"\` to these fields:

\`\`\`html
<input type="password" name="password" autocomplete="new-password">
<input type="text" name="cc-number" autocomplete="off">
\`\`\`

\`autocomplete="new-password"\` is the most reliably honoured value for
password fields — browsers treat \`off\` as a suggestion they may override,
but \`new-password\` tells them the user is creating (not reusing) a
credential.

PCI DSS explicitly requires that cardholder data is never stored
unnecessarily — browser autofill of card numbers is a form of local storage
the site can and should prevent.`;

export const BUSINESS_LOGIC_SEQUENTIAL_URL = `The page contains links with sequential URL patterns (step1, step2,
checkout/1, checkout/2) that suggest a multi-step workflow. Sequential steps
can sometimes be skipped by manipulating the URL directly — for example,
jumping from step 1 to step 5 to bypass validation or payment.

1. **Enforce server-side workflow state.** Each step should verify the
   previous step was completed before allowing access — check a session
   flag or database record, not just the URL.
2. **Use unpredictable step identifiers** (UUIDs or signed tokens) instead
   of bare sequence numbers, so steps can't be guessed or enumerated.
3. **Test manually** — try accessing later steps directly without completing
   earlier ones and confirm the server rejects the request.`;

export const BUSINESS_LOGIC_PREDICTABLE_IDS = `The page exposes links with small sequential numeric IDs (e.g. \`/user/1\`,
\`/order/2\`, \`/invoice/3\`). If these resources lack proper authorisation
checks, an attacker can enumerate every record by incrementing the ID —
an Insecure Direct Object Reference (IDOR) vulnerability.

1. **Add authorisation checks** on every endpoint that serves a resource by
   ID — verify the authenticated user is allowed to access that specific
   record, not just that they hold a valid session.
2. **Use non-sequential identifiers** (UUIDs, nanoids, or hashed IDs) for
   any resource that's referenced in client-visible URLs or API responses.
   This is defence in depth, not a replacement for authorisation.
3. **Rate-limit enumeration** — even with proper auth, a logged-in user
   iterating through every ID in a table is a data-scraping signal worth
   detecting.`;

export const BUSINESS_LOGIC_OPEN_REDIRECT = `A redirect parameter on this page accepts an arbitrary external URL. An
attacker can craft a link that starts at your trusted domain and lands the
victim on a phishing page — the browser's address bar shows your domain
right up until the redirect fires, which is why open redirects are a
standard building block in phishing campaigns.

1. **Validate redirect targets server-side.** Maintain an allow-list of
   permitted redirect destinations (or at minimum restrict to same-origin
   paths only):

\`\`\`js
const target = req.query.next;
const url = new URL(target, \`https://\${req.hostname}\`);
if (url.origin !== \`https://\${req.hostname}\`) {
  return res.redirect("/");
}
res.redirect(url.pathname + url.search);
\`\`\`

2. **Never pass a full URL in a query parameter** if a relative path
   (\`/dashboard\`, \`/account\`) would serve the same purpose.
3. **Log redirect-parameter abuse** — a spike in redirect attempts to
   unknown domains is an early indicator of a phishing campaign targeting
   your users.`;

export const BUSINESS_LOGIC_NO_RATE_LIMIT = `The login endpoint does not appear to enforce rate limiting — five rapid
requests all received normal responses with no 429 status, Retry-After
header, or rate-limit indicator. This allows brute-force password guessing
at high speed.

Implement rate limiting at the application or reverse-proxy level:

**Express (express-rate-limit):**
\`\`\`js
const rateLimit = require("express-rate-limit");
app.use("/login", rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: "Too many login attempts — try again in a minute.",
}));
\`\`\`

**nginx:**
\`\`\`nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
location /login {
  limit_req zone=login burst=3 nodelay;
}
\`\`\`

Also consider:
- Progressive delays (1s, 2s, 4s...) after each failure.
- CAPTCHA after 3–5 failed attempts.
- Account lockout after 10 failures (with a reset mechanism that doesn't
  allow denial-of-service via intentional lockout of another user's account).
- Alerting on brute-force patterns in your logs.`;

// --- API spec scanning (E-33, src/lib/scanners/apiSpec.ts) ---------------

export const API_SPEC_AUTH_BYPASS = `This API endpoint is documented as requiring authentication in the OpenAPI
spec but responded successfully without any credentials. This is a broken
access control vulnerability.

1. **Verify the endpoint's authentication middleware is actually applied** —
   not just documented. A common pattern is declaring \`security:\` in the spec
   but forgetting to wire the auth guard in the route registration.
2. **Add authentication enforcement** at the framework level (middleware/filter)
   rather than per-handler, so new endpoints are protected by default.
3. **Test with and without credentials** after the fix to confirm the endpoint
   now returns 401/403 for unauthenticated requests.

Re-scan to confirm the finding clears.`;

export const API_SPEC_METHOD_CONFUSION = `This endpoint accepted an HTTP method that is not documented in the API spec.
Undocumented methods can bypass access controls that are only applied to the
expected method, or trigger unintended side effects (e.g. a DELETE on a
path that only expects GET).

1. **Restrict allowed methods** on each route to only those documented in the
   spec — return 405 Method Not Allowed for anything else.
2. **Most frameworks support this natively:**

\`\`\`
// Express
router.route('/api/items').get(handler); // only GET allowed

// Next.js API route
if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });
\`\`\`

3. **Check your reverse proxy** — some (nginx, Apache) allow method restrictions
   at the server level too, which is defence in depth.`;

export const API_SPEC_SCHEMA_VIOLATION = `This API endpoint accepted a request with missing required fields without
returning a validation error. Missing server-side validation allows:

- **Data integrity issues** — records created without mandatory fields
- **Business logic bypass** — required-field checks in the frontend can be
  trivially skipped by calling the API directly
- **Injection attacks** — unexpected types/values reach processing code that
  assumes validated input

1. **Add server-side request validation** that enforces the same schema the
   spec documents. Most frameworks have middleware for this:

\`\`\`
// Express + express-openapi-validator
app.use(OpenApiValidator.middleware({ apiSpec: './openapi.yaml' }));

// Zod / joi / yup validation in any framework
const schema = z.object({ name: z.string(), email: z.string().email() });
const parsed = schema.safeParse(req.body);
if (!parsed.success) return res.status(400).json(parsed.error);
\`\`\`

2. **Return 400 Bad Request** with a clear error message for invalid input —
   never silently accept malformed data.`;

export const API_SPEC_EXCESSIVE_DATA = `This API endpoint returns fields in its response that are not documented in
the OpenAPI spec. Undocumented fields — especially ones with names suggesting
sensitive data (passwords, tokens, internal IDs) — are a potential data leak.

This is OWASP API Security Top 10 #3: Excessive Data Exposure.

1. **Review every field** the endpoint returns and confirm each one is intended
   for the consumer. Remove any that are not — especially internal IDs, hashed
   passwords, tokens, or debug fields.
2. **Use a serialisation layer** (a DTO / view model / GraphQL selection set)
   that explicitly lists the fields to return, rather than passing raw database
   records to the response.
3. **Keep the spec in sync** with what the API actually returns — if a field
   is intentionally returned, document it; if it's not documented, don't
   return it.`;

export const API_SPEC_SQLI = `SQL injection detected via API spec parameter testing. The server returned
a database error message when an injection payload was sent in a documented
API parameter.

**The fix is always the same: use parameterised queries.**

- Never concatenate user input into SQL strings — use prepared statements
  or your ORM's query builder.
- Add input validation as defence in depth: type-check and constrain
  parameter values to their documented types (numeric IDs should reject
  non-numeric input before reaching the database layer).
- Apply least privilege to the database user the API connects with.

Re-scan after fixing to confirm the error messages are no longer returned.`;

export const API_SPEC_XSS = `Cross-site scripting detected via API spec parameter testing. A script tag
payload sent in a documented API parameter was reflected unescaped in the
response body.

1. **HTML-encode all user-supplied output** — use your framework's built-in
   escaping (React, Vue, Angular all escape by default in templates).
2. **Set Content-Type: application/json** on API responses that return data,
   not HTML — browsers won't execute scripts in a JSON response.
3. **Add a Content-Security-Policy header** that restricts \`script-src\`.
4. **Validate input** against the documented parameter types — a numeric ID
   parameter should reject HTML tags before processing.`;

export function cairnRemediation(vulnClass: string): string {
  const base = `Cairn (autonomous exploitation engine) discovered and validated
this vulnerability through state-space exploration. The finding was
confirmed through an automated exploit chain, not a signature match.`;

  const byClass: Record<string, string> = {
    sqli: `${base}\n\nSQL injection confirmed via autonomous exploitation.
Use parameterised queries or prepared statements for all database
interactions. Never concatenate user input into SQL. Audit all query
construction paths in the affected endpoint.`,
    xss: `${base}\n\nCross-site scripting confirmed. Apply context-aware
output encoding — HTML-encode for HTML contexts, JavaScript-encode for
script contexts. Deploy a strict Content Security Policy.`,
    rce: `${base}\n\nRemote code execution confirmed. This is the highest
severity class. Patch or take offline immediately. Investigate for signs
of prior exploitation and rotate all credentials the affected service
can access.`,
    "privilege-escalation": `${base}\n\nPrivilege escalation confirmed.
Review the authorization model — ensure every privileged operation
checks the caller's actual role, not just session validity. Implement
principle of least privilege across all service accounts.`,
    "file-inclusion": `${base}\n\nFile inclusion (LFI/RFI) confirmed.
Never use user input to construct file paths without validation.
Allowlist permitted files, resolve canonical paths, and block traversal
sequences (../) at both the application and web server level.`,
    "auth-bypass": `${base}\n\nAuthentication bypass confirmed. Review the
authentication flow for logic errors — check that every protected
endpoint validates credentials, that session tokens cannot be predicted
or reused, and that no debug/test endpoints exist in production.`,
    ssrf: `${base}\n\nServer-side request forgery confirmed. Validate and
allowlist all URLs the application fetches. Block access to internal
IP ranges and cloud metadata endpoints at the network layer.`,
    "insecure-deserialization": `${base}\n\nInsecure deserialization
confirmed. Never deserialize untrusted data with language-native
serialization (Java ObjectInputStream, Python pickle, PHP unserialize).
Use safe formats like JSON with schema validation.`,
  };

  return byClass[vulnClass] ?? base;
}

// ---- Dangling DNS / subdomain takeover (takeover.ts) ------------------------

export function danglingCnameRemediation(host: string, cname: string, provider: string): string {
  return `\`${host}\` still points at \`${cname}\` on ${provider}, but that resource no
longer exists. Whoever next creates a ${provider} resource with that name
controls what \`${host}\` serves — a convincing phishing page on your own
domain, or scripts that can read cookies scoped to your parent domain.

Fix it today, in whichever order is quicker:

1. **Remove the record** if nothing should live at \`${host}\` any more:
   delete its CNAME at your DNS provider.
2. **Or reclaim the resource**: recreate the ${provider} resource with the
   name \`${cname.split(".")[0]}\` in your own account, so the record points at
   something you control.

Then make it a habit: when you delete a cloud app, bucket or site, delete its
DNS record in the same change. The next scan will confirm the fix.`;
}

// ---- Emerging-threat alerts (src/lib/emergingThreatAlerts.ts) ----------------

/**
 * What to do about a newly exploited CVE that matched a site's latest scan.
 * Plain-text steps rather than one Markdown block: the same list is rendered
 * as an email <ol> and as Slack/Teams lines. `reason` is the evidence tier's
 * reason (emergingThreats.ts's MatchReason) — the steps differ because "you
 * run an affected version" and "we can't see your version" need different
 * first moves.
 */
export function emergingThreatSteps(
  product: string,
  reason: "version_in_range" | "version_unknown" | "partial_version" | "distro_packaged" | "platform_specific",
  packagedBy: string | null = null
): string[] {
  const urgent = "Attackers are already exploiting this, so treat it as today's job, not this month's.";
  switch (reason) {
    case "version_in_range":
      return [
        `Upgrade ${product} to a release that fixes this vulnerability. The vendor advisory linked below names the fixed versions.`,
        "If you can't upgrade today, apply the vendor's workaround or take the affected feature offline until you can.",
        "Check your logs for signs of exploitation since the date CISA listed it.",
        "Run a new scan afterwards to confirm the version we see has changed.",
      ];
    case "distro_packaged": {
      const distro = packagedBy ?? "your Linux distribution";
      return [
        `Check ${distro}'s security advisory for this CVE. Distributions fix vulnerabilities by patching the version they ship, so the fixed package can keep the same version number.`,
        `Install ${distro}'s pending security updates for ${product} and restart the service.`,
        "If no fixed package exists yet, apply the vendor's workaround or limit access to the affected service.",
        urgent,
      ];
    }
    case "platform_specific":
      return [
        `Check whether your setup matches the conditions in the advisory linked below, such as the operating system ${product} runs on or a particular module.`,
        `If it does, upgrade ${product} to a fixed release straight away.`,
        "If you're not sure, upgrade anyway: the fix is normally a routine update.",
        urgent,
      ];
    case "partial_version":
    case "version_unknown":
      return [
        `Find out exactly which ${product} version the site runs, from your hosting control panel, the admin dashboard or the server's package list.`,
        "Compare it with the affected versions in the advisory linked below.",
        `If it's affected, upgrade ${product} to a fixed release. ${urgent}`,
      ];
  }
}

// ---- Domain registration (domainRegistration.ts) ----------------------------

export const DOMAIN_EXPIRING = `Renew the domain now, and turn on auto-renew with your registrar.

When a domain lapses, the website **and all email on it** stop working, and
after the registrar's grace period anyone can buy it — including someone who
wants to receive your customers' email or impersonate you.

- Log in to your registrar (named in the finding), renew for at least a year,
  and enable **auto-renew**.
- Check the payment card on file hasn't expired — that's the usual reason
  auto-renew silently fails.
- Make sure the registrar's reminder emails go to a mailbox someone reads,
  not to a former employee.`;

export const DOMAIN_TRANSFER_LOCK = `Turn on your registrar's **transfer lock** (sometimes called "registrar
lock" or "domain lock").

With the lock on, the registry refuses any request to move the domain to
another registrar until you switch it off yourself. Without it, a single
compromised registrar login or a social-engineered support request is enough
to take the domain — and your website and email with it.

It's a free setting in every major registrar's dashboard, usually under the
domain's security or transfer options. Leave it on except when you are
deliberately moving registrar.`;

// ---- Static code analysis (src/worker/tools/sast.ts) -------------------------
//
// One block per weakness category (SastCategory in sastCatalog.ts, derived
// from the rule's CWE), with the fix shown for the language of the file the
// rule fired in. The finding's own detail already names the file and line.

export type SastLanguage = "javascript" | "python" | "php" | "other";

const SAST_FIX_BY_CATEGORY: Record<SastCategory, { intro: string; examples: Partial<Record<SastLanguage, string>> }> = {
  "sql-injection": {
    intro: `Never build SQL text out of request values. Keep the SQL constant and pass
the values separately as bound parameters — the driver then sends them as data,
so quotes and keywords in the input can't change the query.`,
    examples: {
      javascript: `\`\`\`js
// mysql2 / pg
await db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);
await client.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
// Prisma: use the tagged template, never $queryRawUnsafe with input
await prisma.$queryRaw\`SELECT * FROM "User" WHERE email = \${email}\`;
\`\`\``,
      python: `\`\`\`python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
# Django
Person.objects.raw("SELECT * FROM people WHERE name = %s", [name])
\`\`\``,
      php: `\`\`\`php
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
$stmt->execute([$_POST['email']]);
// WordPress
$wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE post_author = %d", $author));
\`\`\``,
    },
  },
  "code-injection": {
    intro: `Remove the dynamic evaluation. Request input must be treated as data, never
as code: parse it (JSON, a number, an enum) and map it to behaviour through a
fixed lookup table of allowed operations. If users genuinely need to write
expressions, use a dedicated expression parser that cannot call functions or
reach the runtime.`,
    examples: {
      javascript: `\`\`\`js
const OPERATIONS = { sum: (a, b) => a + b, max: Math.max };
const op = OPERATIONS[req.query.op];
if (!op) return res.status(400).send("unknown operation");
\`\`\``,
      python: `\`\`\`python
import ast
value = ast.literal_eval(request.args["value"])  # literals only, no calls
\`\`\``,
      php: `\`\`\`php
$actions = ['list' => 'listItems', 'show' => 'showItem'];
$fn = $actions[$_GET['action']] ?? null;
if ($fn === null) { http_response_code(400); exit; }
$fn();
\`\`\``,
    },
  },
  "command-injection": {
    intro: `Don't hand request input to a shell. Call the program directly with an
argument list (no shell in between), and validate the value against an
allow-list or a strict pattern before using it at all.`,
    examples: {
      javascript: `\`\`\`js
const { execFile } = require("node:child_process");
if (!/^[a-z0-9.-]+$/i.test(host)) return res.status(400).end();
execFile("ping", ["-c", "1", host], (err, stdout) => res.send(stdout));
\`\`\``,
      python: `\`\`\`python
import subprocess
subprocess.run(["ping", "-c", "1", host], check=True, timeout=10)  # no shell=True
\`\`\``,
      php: `\`\`\`php
$out = shell_exec('ping -c 1 ' . escapeshellarg($host));
\`\`\``,
    },
  },
  "file-inclusion": {
    intro: `Never let the request choose a file path to include. Map the request value to
a fixed list of allowed templates and include only from that list. Also make
sure \`allow_url_include\` is Off in php.ini.`,
    examples: {
      php: `\`\`\`php
$pages = ['home' => 'home.php', 'about' => 'about.php'];
$page = $pages[$_GET['page'] ?? 'home'] ?? 'home.php';
include __DIR__ . '/pages/' . $page;
\`\`\``,
    },
  },
  deserialization: {
    intro: `Don't deserialise request data with a format that can create arbitrary objects
or run code (pickle, PyYAML's full loader, PHP unserialize, node-serialize).
Exchange request data as JSON. If you must keep the existing format, sign the
payload server-side (HMAC) and verify the signature before deserialising.`,
    examples: {
      javascript: `\`\`\`js
const profile = JSON.parse(req.cookies.profile);
\`\`\``,
      python: `\`\`\`python
data = json.loads(request.get_data())
config = yaml.safe_load(request.get_data())
\`\`\``,
      php: `\`\`\`php
$cart = json_decode($_COOKIE['cart'], true);
// or, if unserialize is unavoidable:
$cart = unserialize($data, ['allowed_classes' => false]);
\`\`\``,
    },
  },
  "open-redirect": {
    intro: `Only redirect to destinations you have checked. Accept relative paths that start
with a single "/" (not "//" or "/\\"), or compare the target host against an
explicit allow-list; otherwise fall back to a safe default page.`,
    examples: {
      javascript: `\`\`\`js
const next = String(req.query.next || "/");
const safe = next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\\\");
res.redirect(safe ? next : "/");
\`\`\``,
      python: `\`\`\`python
from django.utils.http import url_has_allowed_host_and_scheme
if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
    target = "/"
return redirect(target)
\`\`\``,
      php: `\`\`\`php
wp_safe_redirect($_GET['redirect_to']); // WordPress: only allowed hosts
\`\`\``,
    },
  },
  "tls-verification": {
    intro: `Turn certificate verification back on. Disabling it is usually a workaround for
a self-signed or privately issued certificate — the fix for that is to trust
that specific CA, not to trust everything.`,
    examples: {
      javascript: `\`\`\`js
const agent = new https.Agent({ ca: fs.readFileSync("/etc/ssl/private-ca.pem") });
// and remove any NODE_TLS_REJECT_UNAUTHORIZED=0
\`\`\``,
      python: `\`\`\`python
requests.get(url, verify="/etc/ssl/private-ca.pem")  # or just omit verify=
\`\`\``,
      php: `\`\`\`php
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
curl_setopt($ch, CURLOPT_CAINFO, '/etc/ssl/private-ca.pem');
\`\`\``,
    },
  },
  "debug-mode": {
    intro: `Make debug mode come from the environment and default to off, so a production
deployment can't ship with it enabled. Debug pages and debuggers expose source
code, configuration and secrets — and Flask's Werkzeug debugger allows running
code.`,
    examples: {
      python: `\`\`\`python
# Django settings.py
DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
# Flask
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG") == "1"
\`\`\``,
      php: `\`\`\`php
// config/app.php
'debug' => (bool) env('APP_DEBUG', false),
\`\`\``,
    },
  },
  "jwt-verification": {
    intro: `Always verify a token's signature before trusting any of its claims, and pin
the algorithms you accept — never include "none". Decoding without
verification is only safe for reading the header to choose a key.`,
    examples: {
      javascript: `\`\`\`js
const claims = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
\`\`\``,
      python: `\`\`\`python
claims = jwt.decode(token, key, algorithms=["HS256"])
\`\`\``,
    },
  },
};

const SAST_GENERIC_FIX = `Open the file at the line given and review how request data reaches this
code. The rule that fired describes the weakness in its message above; fix the
data flow rather than suppressing the match. If you are certain the match is a
false positive, add a \`// nosemgrep\` (or \`# nosemgrep\`) comment on that line
so future scans skip it — and tell us, so we can tighten the rule.`;

/** Language for remediation examples, from the matched file's extension. */
export function sastLanguageForPath(path: string): SastLanguage {
  const ext = path.toLowerCase().split(".").pop() ?? "";
  if (["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"].includes(ext)) return "javascript";
  if (ext === "py") return "python";
  if (["php", "phtml", "inc"].includes(ext)) return "php";
  return "other";
}

/**
 * Fix guidance for a SAST finding. `category` is null when the rule's CWE
 * doesn't map to a known category — the generic text is returned then, not
 * a guess.
 */
export function sastRemediation(category: SastCategory | null, language: SastLanguage): string {
  if (!category) return SAST_GENERIC_FIX;
  const entry = SAST_FIX_BY_CATEGORY[category];
  const example = entry.examples[language];
  const suppress = `If this specific match is a false positive (for example, the value was validated
somewhere the analyser can't see), add a \`nosemgrep\` comment on that line so
future scans skip it.`;
  return [entry.intro, example, suppress].filter(Boolean).join("\n\n");
}

// ---- GitHub Actions workflow security (src/worker/tools/workflowSecurity.ts) -
//
// One block per category (WorkflowSecurityCategory in
// workflowSecurityCatalog.ts), plus a link to zizmor's own documentation for
// the specific ident so the customer can read the exact rule's rationale.

const WORKFLOW_SECURITY_FIX_BY_CATEGORY: Record<WorkflowSecurityCategory, string> = {
  injection: `An expression like \${{ github.event.issue.title }} or \${{ github.event.pull_request.title }}
is attacker-controlled text, expanded directly into the step before the shell
ever runs — so a crafted title or comment becomes shell code, not just a
string argument. Never interpolate an untrusted \${{ ... }} expression
straight into a \`run:\` block. Pass it through an environment variable
instead, which the shell receives as data:

\`\`\`yaml
- name: Greet
  env:
    ISSUE_TITLE: \${{ github.event.issue.title }}
  run: echo "Hello $ISSUE_TITLE"
\`\`\`

The same applies to writes into \`$GITHUB_ENV\`/\`$GITHUB_PATH\` and to
\`ACTIONS_ALLOW_UNSECURE_COMMANDS\` — both let one step's untrusted input
control what a later step executes.`,

  "dangerous-triggers": `\`pull_request_target\` and \`workflow_run\` run with the BASE repository's
permissions and secrets, but can be configured to check out and execute code
from the PR's HEAD — attacker-controlled. If the workflow needs to build or
test the PR's code, use the plain \`pull_request\` trigger instead (no
secrets, read-only \`GITHUB_TOKEN\`); if it genuinely needs repository
permissions (e.g. to post a PR comment), keep \`pull_request_target\` but
never check out, build, or run anything from \`github.event.pull_request.head\`
inside it.`,

  "excessive-permissions": `Set an explicit, minimal \`permissions:\` block at the workflow or job level —
the GitHub default for a classic token is broad read/write across many
scopes, and \`permissions: write-all\` grants everything. Most workflows need
only \`contents: read\`; add \`write\` scopes one at a time, only for the job
that needs them. \`secrets: inherit\` on a called reusable workflow passes
every one of the caller's secrets to code you may not control — pass only
the specific secrets that workflow actually needs instead.`,

  "supply-chain-integrity": `Pin every third-party action to a full commit SHA, not a tag or branch
(\`uses: actions/checkout@v4\` → \`uses: actions/checkout@<40-char-sha> # v4\`)
— a tag can be moved to point at different code after you've reviewed it,
but a commit SHA cannot. Pin Docker images by digest
(\`image@sha256:...\`) for the same reason. Double-check the owner/repo name
against the action you intend to use — a typosquatted name
(\`actions/checkout\` vs a lookalike) runs whatever code its author pushes.`,

  "credential-exposure": `\`actions/checkout\` persists the \`GITHUB_TOKEN\` in the local git config by
default so later steps can push; a step that then uploads the full checkout
as a build artifact leaks that token to anyone who can download it. Add
\`persist-credentials: false\` to the checkout step unless a later step
genuinely needs to push. Never place a \`\${{ secrets.X }}\` expression
directly in a \`run:\` command or a \`with:\` input where it can appear in
process arguments or be echoed to the log — assign it to an \`env:\` variable
first, which GitHub Actions automatically redacts from log output.`,

  "unsound-logic": `A conditional written to gate a step on a condition it doesn't actually test
— an \`if:\` that's always true, a \`contains()\` substring check that a
crafted string can defeat, or a ternary-style expression with an inverted
branch — can silently skip a security check or run a privileged step when it
shouldn't. Rewrite the condition to test the exact value you mean, and add
a comment stating the intent so the next person doesn't reintroduce the bug.`,

  hygiene: `This is a best-practice or maintainability finding rather than a direct
vulnerability — add a \`concurrency:\` group to avoid overlapping runs
racing each other, document why a non-default permission is needed, remove
actions that duplicate another step's effect, and avoid defining a composite
action anonymously inline where a named, reviewable one would do.`,
};

/** zizmor's own documentation page for the specific audit ident. */
export function workflowSecurityDocsUrl(ident: string): string {
  return `https://docs.zizmor.sh/audits/#${ident}`;
}

export function workflowSecurityRemediation(category: WorkflowSecurityCategory, ident: string): string {
  return [WORKFLOW_SECURITY_FIX_BY_CATEGORY[category], `Rule documentation: ${workflowSecurityDocsUrl(ident)}`].join("\n\n");
}

// ---- Third-party script inventory (scriptInventory.ts) ------------------------

/**
 * List items are one line each: RemediationBody (ScanReportView.tsx) only
 * renders a block as a list when every line starts with a bullet.
 */
export function scriptInventoryRemediation(origin: string, paymentPage: boolean): string {
  const paymentNote = paymentPage
    ? `

On a payment page, the strongest fix is to take card entry off your page: use your payment provider's hosted fields or hosted payment page (an iframe or a redirect), so scripts on your page can't read what the customer types into the card form.`
    : "";

  return `Decide whether this page should load scripts from \`${origin}\`, then record the decision.

1. **Identify it.** Work out which service it belongs to (analytics, chat widget, payment provider, tag manager…) and who added it. If nobody knows, treat that as a warning sign: card-skimming attacks work by adding exactly this kind of script.
2. **Remove it** if the page doesn't need it. If it arrives through a tag manager, remove the tag there.
3. **Authorise it** if it is needed: use **Mark as accepted / authorised** on this finding and write the justification — what it does, why this page needs it, and who approved it. That record is its entry in your PCI DSS 6.4.3 script inventory. You can authorise several sources at once.
4. **Lock it down** so nothing else can join it unnoticed.

- Pin versioned files (a library from a CDN) with Subresource Integrity: \`integrity="sha384-…" crossorigin="anonymous"\`. Scripts that change by design, such as a payment provider's SDK or a tag manager, can't be pinned; rely on the allowlist below instead.
- Allow only the sources you have authorised in your Content-Security-Policy, and add a \`report-to\` (or \`report-uri\`) endpoint so the browser tells you when it blocks something new:

\`\`\`
Content-Security-Policy: script-src 'self' ${origin}
\`\`\`

- Limit who can publish in your tag manager: anyone who can publish a tag can add a script to every page.

Each scan compares this list with the previous one, so a new script source shows as **New** and one that disappears shows as **Fixed**. That catches sources being added or removed; it doesn't see changes inside a script's contents or to your security headers, which PCI DSS 11.6.1 also expects you to detect (weekly, or as your risk analysis sets). A Content-Security-Policy report endpoint or a client-side script-monitoring service covers that part.${paymentNote}`;
}

// ---- Crawler (E-70) --------------------------------------------------------------

export function crawlHeaderGapRemediation(header: string): string {
  const value = HEADER_VALUES[header] ?? "<value>";
  return `Send \`${header}\` on every page, not only the home page. Some pages are answered by a different route, template, reverse-proxy rule or CMS plugin that doesn't add it.

1. Set the header once at the outermost layer (the web server, CDN or framework middleware) so every response inherits it, rather than in individual page handlers.
2. Check the pages listed above after the change; the ones that still lack it are served by something that bypasses that layer (a static-file rule, a separate backend, a redirect target).

\`\`\`
${header}: ${value}
\`\`\``;
}

export const CRAWL_COOKIE_FLAGS = `Set the missing flags on this cookie where the page sets it. The home page doesn't set it, which is why the home-page cookie check didn't see it.

- \`Secure\` so it is never sent over plain HTTP.
- \`HttpOnly\` so scripts can't read it through \`document.cookie\` (skip only for cookies your own front-end code must read).
- \`SameSite=Lax\` (or \`Strict\`) to blunt cross-site request forgery.

\`\`\`
Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax; Path=/
\`\`\``;

export const CRAWL_MIXED_CONTENT = MIXED_CONTENT;

export const CRAWL_INSECURE_FORM = `Serve this page, and everything a form on it submits to, over HTTPS only.

1. Change any form \`action\` that starts with \`http://\` to \`https://\` (or a relative path).
2. Redirect all HTTP traffic to HTTPS and send \`Strict-Transport-Security\` so browsers stop trying HTTP at all.
3. A page with a password field must itself be served over HTTPS: on plain HTTP anyone on the network path can read the password and alter the page.`;

export const CRAWL_ERROR_DISCLOSURE = `Show a generic error page in production instead of the framework's own error output, which reveals file paths, library versions and sometimes code or configuration.

- Turn off debug mode (\`DEBUG=False\`, \`APP_DEBUG=false\`, \`display_errors=Off\`, \`customErrors mode="On"\`) and log the detail server-side instead.
- Make sure this applies to every route, not only the home page: error handling configured per route is the usual reason a deep page still leaks.`;

export function crawlSriRemediation(): string {
  return `Add a Subresource Integrity hash to each cross-origin script and stylesheet listed, so the browser refuses it if the third-party origin ever serves something different:

\`\`\`html
<script src="https://cdn.example.com/lib.js" integrity="sha384-<hash>" crossorigin="anonymous"></script>
\`\`\`

\`\`\`bash
curl -s https://cdn.example.com/lib.js | openssl dgst -sha384 -binary | openssl base64 -A
\`\`\`

\`crossorigin="anonymous"\` must accompany \`integrity\`. Scripts that change by design (tag managers, payment SDKs) can't be pinned; list them in your Content-Security-Policy instead. Resources you control are better served from your own origin, which needs no hash.`;
}

// ---- Supabase backend exposure ---------------------------------------------------

export const BACKEND_SERVICE_KEY = `A Supabase \`service_role\` key is visible in your site's public code. Treat it as already stolen.

1. **Rotate it now.** In the Supabase dashboard open *Project Settings → API* and generate a new JWT secret (this invalidates both keys), then update your server-side configuration. Until you do, anyone who has copied the key can read and change every table.
2. **Keep it out of the browser.** The \`service_role\` key belongs only in server code (API routes, edge functions, CI secrets) and must never be in a variable that is bundled for the client, such as one starting with \`NEXT_PUBLIC_\`, \`VITE_\` or \`REACT_APP_\`. The browser should only ever hold the \`anon\` key.
3. **Check for misuse.** Review the project's logs and tables for reads or writes you don't recognise, and rotate any other secrets stored in the database.`;

export function backendOpenTableRemediation(table: string): string {
  const name = /^[a-z_][a-z0-9_]*$/i.test(table) ? table : "your_table";
  return `Turn on row level security for \`${name}\` and add policies that only allow what each user should see. Without it, the public \`anon\` key (which every visitor's browser holds) can read the table.

\`\`\`sql
alter table public.${name} enable row level security;

-- Example: signed-in users can read only their own rows.
create policy "${name}: read own rows"
  on public.${name} for select
  to authenticated
  using (user_id = auth.uid());
\`\`\`

If the data is meant to be public, say so deliberately with a narrow policy (only the columns and rows that are public, ideally through a view), rather than leaving RLS off. After the change, check it as an anonymous visitor: a request with only the anon key should return no rows. Tables created through the SQL editor have RLS **off** by default, so check every table in the \`public\` schema.`;
}

export function backendStorageBucketRemediation(bucket: string): string {
  const name = /^[a-z0-9][a-z0-9._-]*$/.test(bucket) ? bucket : "your-bucket";
  return `Anyone with the public \`anon\` key can list the files in the \`${name}\` storage bucket. Listing is controlled by policies on \`storage.objects\`, separately from whether the bucket is "public" (public only means a file can be downloaded by its exact URL).

Remove the policy that lets \`anon\` (or everyone) select from this bucket, and allow listing only to the users who need it:

\`\`\`sql
-- Example: signed-in users can list only files in their own folder (<user id>/...).
create policy "${name}: list own files"
  on storage.objects for select
  to authenticated
  using (bucket_id = '${name}' and (storage.foldername(name))[1] = auth.uid()::text);
\`\`\`

If the files are meant to be public, keep the bucket public for downloads but drop the listing policy, so visitors can fetch a file whose URL they were given without being able to enumerate the rest. Afterwards, list the bucket with only the anon key and confirm it returns nothing.`;
}

// ---- Firebase exposure -----------------------------------------------------------

export const FIREBASE_RTDB_OPEN = `Your Firebase Realtime Database answers anyone who asks: its security rules allow reads from the root without signing in, so the whole database can be downloaded with one request.

Lock the root and open only the paths that need it, in *Realtime Database → Rules*:

\`\`\`json
{
  "rules": {
    ".read": false,
    ".write": false,
    "users": {
      "$uid": {
        ".read": "auth != null && auth.uid === $uid",
        ".write": "auth != null && auth.uid === $uid"
      }
    }
  }
}
\`\`\`

Rules cascade: a \`.read: true\` high up the tree can't be taken back further down, so check every level. Use the Rules Playground to test an unauthenticated read of \`/\` and confirm it is denied, then check what was exposed (and for how long) before deciding whether anyone needs to be told.`;

export const FIREBASE_STORAGE_OPEN = `Anyone can list the files in your Firebase Storage bucket without signing in. Listing needs only a rule that allows \`read\` (or \`list\`) at the bucket root.

Tighten the rules in *Storage → Rules*:

\`\`\`
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /users/{uid}/{allPaths=**} {
      allow read, write: if request.auth != null && request.auth.uid == uid;
    }
    // Public assets: downloadable by exact path, never listable.
    match /public/{file} {
      allow get: if true;
    }
  }
}
\`\`\`

\`get\` lets a visitor fetch a file whose path they already know; \`list\` lets them enumerate everything, which is rarely what you want. Test an unauthenticated list in the Rules Playground afterwards.`;

export function firestoreOpenRemediation(collection: string): string {
  const name = /^[A-Za-z][A-Za-z0-9_-]*$/.test(collection) ? collection : "yourCollection";
  return `Anyone can read documents in the \`${name}\` Firestore collection without signing in. Firestore's security rules decide who can read what; this collection currently allows unauthenticated reads.

Restrict it in *Firestore Database → Rules*:

\`\`\`
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /${name}/{docId} {
      allow read: if request.auth != null && request.auth.uid == resource.data.ownerId;
    }
  }
}
\`\`\`

If the collection is meant to be public (published articles, a product catalogue), keep public reads but make sure no document holds anything private, and allow \`get\` rather than \`list\` where visitors only need single documents. Test an unauthenticated query in the Rules Playground afterwards.`;
}

// ---- GraphQL exposure ------------------------------------------------------------

export const GRAPHQL_INTROSPECTION = `Turn introspection off in production unless the API is deliberately public. Anyone can currently list every type, query and mutation.

- **Apollo Server:** \`new ApolloServer({ introspection: process.env.NODE_ENV !== "production" })\`
- **graphql-yoga / Envelop:** use the \`useDisableIntrospection\` plugin.
- **Hasura:** set \`HASURA_GRAPHQL_ENABLE_CONSOLE=false\` and restrict introspection to admin roles.
- **Other servers:** look for an "introspection" or "NoSchemaIntrospectionCustomRule" option.

Switching introspection off hides the schema, it doesn't protect it. Authorisation still has to be enforced on every field and mutation. After the change, send \`{ __schema { types { name } } }\` yourself and confirm it is refused.`;

export const GRAPHQL_SUGGESTIONS = `Stop the server suggesting field names in error messages (the "Did you mean …" text). With introspection off, suggestions let an attacker rebuild the schema one guess at a time.

- **Apollo Server 4+:** use a plugin or \`formatError\` that strips the suggestion from validation errors.
- **graphql-js / Yoga:** the \`maskedErrors\` option or a custom \`formatError\` removing "Did you mean".

Production errors should say what failed, not what the schema contains.`;

export const GRAPHQL_IDE = `Remove or protect the GraphQL explorer in production. GraphiQL, Playground and Apollo Sandbox are development tools that make exploring the API trivial.

- **Apollo Server:** drop the landing-page plugin in production (\`ApolloServerPluginLandingPageDisabled()\`).
- **Yoga / Express GraphQL:** set \`graphiql: false\` (or \`graphiql: process.env.NODE_ENV !== "production"\`).
- **Hasura:** disable the console on the public endpoint.

If a team needs it, serve the explorer only behind your VPN or sign-in.`;
