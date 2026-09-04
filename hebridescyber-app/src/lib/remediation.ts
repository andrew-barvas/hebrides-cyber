// Turns scan findings into concrete, copy-pasteable fix content. Used by
// src/pages/api/generate-fix-pr.ts to build the file a remediation PR adds.
//
// Deliberately produces a *recommendations* file rather than silently
// rewriting the customer's actual source files (next.config.js, nginx
// conf, etc.). Automatically patching a stranger's config with regex/AST
// surgery is exactly the kind of thing that quietly breaks a production
// site — a PR a human reviews and merges is the responsible version of
// "automated fix," not a script that pushes straight to main.

import type { Finding } from "./scanners";

const HEADER_SNIPPETS: Record<string, string> = {
  "strict-transport-security":
    "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
  "content-security-policy":
    "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
  "x-frame-options": "X-Frame-Options: DENY",
  "x-content-type-options": "X-Content-Type-Options: nosniff",
  "referrer-policy": "Referrer-Policy: strict-origin-when-cross-origin",
};

const NEXTJS_HEADERS_SNIPPET = `// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          // TODO: tailor Content-Security-Policy to your actual script/style sources —
          // a too-strict CSP will silently break the page.
          // Tailor each directive to your actual origins — this starter blocks
          // all third-party scripts/styles by default. Add your CDN, analytics,
          // and payment script origins before enabling in production.
          { key: "Content-Security-Policy", value: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" },
        ],
      },
    ];
  },
};`;

/** Builds the full Markdown body for the remediation PR/file. */
export function buildRemediationMarkdown(targetUrl: string, findings: Finding[], score: number | null): string {
  const sections = findings
    .filter((f) => f.severity !== "info")
    .map((f) => `### [${f.severity.toUpperCase()}] ${f.title}\n\n${f.detail}\n\n${suggestFixSnippet(f)}`)
    .join("\n\n---\n\n");

  return `# Hebrides Cyber — Suggested Fixes

**Target:** ${targetUrl}
**Generated:** ${new Date().toISOString()}
${score !== null ? `**Score at time of scan:** ${score}/100\n` : ""}
This file was opened as a pull request by Hebrides Cyber's automated
remediation tool. Nothing in your existing code has been changed — review
each suggestion below and apply the ones that make sense for your app.

${sections || "No actionable findings — nice work."}

---

*Generated automatically from a Hebrides Cyber Security Score scan. See
https://hebridescyber.co.uk for details, or reply to your scan email with
questions.*
`;
}

function suggestFixSnippet(finding: Finding): string {
  // Findings produced by summariseResults carry their own fix text, built with
  // the full check result in scope. Prefer it over re-deriving anything here.
  if (finding.remediation) return finding.remediation;

  // Fallbacks below are for findings deserialised from scans stored before
  // Finding.remediation existed.
  if (finding.title.includes("security headers") || finding.title.includes("recommended headers")) {
    // Header names live in `detail` ("x-frame-options, referrer-policy"),
    // never in the title.
    const missing = finding.detail.split(",").map((h) => h.trim()).filter(Boolean);
    const lines = missing.map((h) => HEADER_SNIPPETS[h.toLowerCase()] ?? h).join("\n");
    return [
      "**Raw headers to add:**",
      "```",
      lines,
      "```",
      "**If this is a Next.js app**, add a `headers()` function to `next.config.js`:",
      "```js",
      NEXTJS_HEADERS_SNIPPET,
      "```",
    ].join("\n");
  }

  if (finding.title.includes("outdated") || finding.title.includes("front-end libraries")) {
    return "Upgrade the packages named above to their latest stable major version and re-run the scan. Check each project's migration guide for breaking changes before upgrading in production.";
  }

  if (finding.title.includes("TLS")) {
    return [
      "**nginx:**",
      "```nginx",
      "ssl_protocols TLSv1.2 TLSv1.3;",
      "```",
      "**Apache:**",
      "```apache",
      "SSLProtocol -all +TLSv1.2 +TLSv1.3",
      "```",
    ].join("\n");
  }

  if (finding.title.includes("not served over HTTPS")) {
    return "Obtain a TLS certificate (e.g. Let's Encrypt, or your host's managed SSL) and redirect all HTTP traffic to HTTPS.";
  }

  return "No automated fix snippet available for this finding yet — see src/lib/remediation.ts to add one.";
}
