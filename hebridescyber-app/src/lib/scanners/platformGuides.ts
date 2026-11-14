// Platform-specific steps added to a finding's remediation, chosen from what
// the scan already detected: the website platform (fingerprint.ts) and the
// email provider (the MX hosts dns.ts reads). Generic advice ("add this
// header to your server") is where small customers give up, and on hosted
// platforms it is often impossible: Shopify, Wix and Squarespace don't let a
// customer set security headers at all, and saying so saves them an evening.
//
// Applied as a last pass in summariseResults, after every finding has its
// generic remediation. Never changes severity, title or detail, and never
// invents a platform: with nothing detected, nothing is added.
import type { Finding } from "./index";

export type MailProvider = "microsoft365" | "google";
export type PlatformContext = { technologies: string[]; mailProvider: MailProvider | null };

/** The email provider, from MX host names. Null when it isn't one we have steps for. */
export function mailProviderFromMx(hosts: string[]): MailProvider | null {
  const names = hosts.map((h) => h.toLowerCase().replace(/\.$/, ""));
  if (names.some((h) => h.endsWith(".mail.protection.outlook.com"))) return "microsoft365";
  if (names.some((h) => h === "smtp.google.com" || h.endsWith(".google.com") || h.endsWith(".googlemail.com"))) return "google";
  return null;
}

const HOSTED_NO_HEADERS: Record<string, string> = {
  Shopify: "Shopify",
  Wix: "Wix",
  Squarespace: "Squarespace",
  Webflow: "Webflow",
};

const HEADER_CHECKS = ["headers.missing-critical", "headers.missing-recommended", "headers.csp-absent", "headers.csp-weak", "tls.hsts-missing", "tls.hsts-short"];
const SPF_CHECKS = ["dns.spf-missing", "dns.spf-issues"];
const DKIM_CHECKS = ["dns.dkim-not-detected", "dns.dkim-issues"];

function guideFor(checkId: string, ctx: PlatformContext): string | null {
  const base = checkId.split(":")[0];
  const has = (name: string) => ctx.technologies.includes(name);
  const hosted = Object.keys(HOSTED_NO_HEADERS).find(has);

  if (HEADER_CHECKS.includes(base)) {
    if (hosted) {
      return `**On ${HOSTED_NO_HEADERS[hosted]}:** the platform serves your site and sets these headers itself; there is no setting to add your own. You can't fix this from your account. If it matters for a customer or insurer, mark the finding as accepted risk with the reason "set by ${HOSTED_NO_HEADERS[hosted]}", and raise it with their support.`;
    }
    if (has("Cloudflare")) {
      return base.startsWith("tls.hsts")
        ? "**Behind Cloudflare:** Cloudflare dashboard → SSL/TLS → Edge Certificates → HTTP Strict Transport Security (HSTS) → Enable, with a max-age of 6 months or more. Turn on \"include subdomains\" only once every subdomain works over HTTPS."
        : "**Behind Cloudflare:** you can add the header without touching your server: Cloudflare dashboard → Rules → Transform Rules → Modify Response Header → Create rule, then \"Set static\" for each header and value.";
    }
    if (has("WordPress")) {
      return "**On WordPress:** your host's control panel may have a security headers setting. If not, add the headers in your server configuration (.htaccess on Apache or LiteSpeed hosting) or with a reputable security-headers plugin, then re-check. Test the site after adding a Content-Security-Policy, because it can block scripts your theme or plugins rely on.";
    }
    return null;
  }

  if (base === "tls.weak-protocol" && has("Cloudflare")) {
    return "**Behind Cloudflare:** Cloudflare dashboard → SSL/TLS → Edge Certificates → Minimum TLS Version → TLS 1.2.";
  }

  if (SPF_CHECKS.includes(base)) {
    if (ctx.mailProvider === "microsoft365") return '**With Microsoft 365:** the SPF record is a TXT record at your domain: `v=spf1 include:spf.protection.outlook.com -all`. Add the include of any other service that sends mail as you (your website, newsletter tool) before the `-all`.';
    if (ctx.mailProvider === "google") return "**With Google Workspace:** the SPF record is a TXT record at your domain: `v=spf1 include:_spf.google.com ~all`. Add the include of any other service that sends mail as you before the `~all`, and move to `-all` once your DMARC reports look clean.";
    return null;
  }

  if (DKIM_CHECKS.includes(base)) {
    if (ctx.mailProvider === "microsoft365") return "**With Microsoft 365:** Microsoft Defender portal → Email & collaboration → Policies & rules → Threat policies → Email authentication settings → DKIM → select your domain. Publish the two CNAME records it shows (selector1 and selector2), then turn on \"Sign messages for this domain with DKIM signatures\".";
    if (ctx.mailProvider === "google") return "**With Google Workspace:** Admin console → Apps → Google Workspace → Gmail → Authenticate email → Generate new record (2048-bit). Publish the TXT record it shows at `google._domainkey`, wait for DNS, then select Start authentication.";
    return null;
  }

  return null;
}

/** Appends the matching platform steps to each finding's remediation, in place. */
export function applyPlatformGuides(findings: Finding[], ctx: PlatformContext): void {
  for (const f of findings) {
    if (!f.checkId) continue;
    const guide = guideFor(f.checkId, ctx);
    if (!guide) continue;
    f.remediation = f.remediation ? `${f.remediation}\n\n${guide}` : guide;
  }
}
