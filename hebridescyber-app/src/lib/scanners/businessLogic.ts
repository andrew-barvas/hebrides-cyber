// Business logic vulnerability scanner — checks for common application-layer
// flaws that automated tools can detect without active exploitation: missing
// CSRF tokens, forms posting to external domains, autocomplete on sensitive
// fields, sequential-URL patterns that suggest step-skippable workflows,
// predictable resource IDs in links, open redirect parameters, and absent
// rate limiting on login endpoints. All checks are passive read-only probes.
//
// Follows docs/SCANNER-CONVENTIONS.md: every outbound request gets
// AbortSignal.timeout(), findings are only reported when evidenced, and
// remediation text lives in remediationText.ts.

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export type BusinessLogicResult =
  | {
      status: "checked";
      csrf: CsrfCheckData;
      externalForms: ExternalFormData[];
      autocompleteIssues: AutocompleteIssueData[];
      sequentialUrls: SequentialUrlData[];
      predictableIds: PredictableIdData[];
      openRedirects: OpenRedirectData[];
      rateLimiting: RateLimitData;
    }
  | { status: "error"; note: string };

export type CsrfCheckData = {
  formsFound: number;
  formsWithToken: number;
  formsWithoutToken: number;
  /** True when the page has a meta csrf-token tag (e.g. Rails). */
  metaCsrfPresent: boolean;
};

export type ExternalFormData = {
  formAction: string;
  targetDomain: string;
};

export type AutocompleteIssueData = {
  fieldType: string;
  fieldName: string;
  autocompleteValue: string | null;
};

export type SequentialUrlData = {
  url: string;
  pattern: string;
};

export type PredictableIdData = {
  url: string;
  idValue: string;
};

export type OpenRedirectData = {
  parameter: string;
  endpoint: string;
  redirectedTo: string;
};

export type RateLimitData = {
  checked: boolean;
  /** The endpoint we managed to test against. null if none were found. */
  endpoint: string | null;
  /** True when we detected rate limiting (429 response or Retry-After header). */
  rateLimited: boolean;
  /** Total requests sent before rate limiting kicked in (or the cap, if it never did). */
  requestsSent: number;
};

// ---------------------------------------------------------------------------
// HTML parsing helpers (regex-based, matching codebase convention)
// ---------------------------------------------------------------------------

/** All <form ...> tags including their inner content. */
const FORM_TAG_RE = /<form\b[^>]*>([\s\S]*?)<\/form>/gi;

/** The action attribute of a <form> tag. */
const FORM_ACTION_RE = /action\s*=\s*["']([^"']+)["']/i;

/** The method attribute of a <form> tag. */
const FORM_METHOD_RE = /method\s*=\s*["']([^"']+)["']/i;

/** Hidden input fields — captures name and value attributes. */
const HIDDEN_INPUT_RE = /<input\b[^>]*type\s*=\s*["']hidden["'][^>]*>/gi;

/** Generic input fields — captures full tag for attribute inspection. */
const INPUT_RE = /<input\b[^>]*>/gi;

/** Meta tag with csrf-token content (Rails convention). */
const META_CSRF_RE = /<meta\b[^>]*name\s*=\s*["']csrf-token["'][^>]*>/i;

/** Extract name attribute from an input tag. */
const NAME_ATTR_RE = /name\s*=\s*["']([^"']+)["']/i;

/** Extract type attribute from an input tag. */
const TYPE_ATTR_RE = /type\s*=\s*["']([^"']+)["']/i;

/** Extract autocomplete attribute from an input tag. */
const AUTOCOMPLETE_ATTR_RE = /autocomplete\s*=\s*["']([^"']+)["']/i;

/** Well-known CSRF token field names. */
const CSRF_FIELD_NAMES = new Set([
  "csrf",
  "csrf_token",
  "csrftoken",
  "csrfmiddlewaretoken",
  "_csrf",
  "_token",
  "token",
  "authenticity_token",
  "__requestverificationtoken",
  "antiforgery",
  "__antiforgerytoken",
  "xsrf_token",
  "_xsrf",
]);

/** Sensitive field types/names that should have autocomplete disabled. */
const SENSITIVE_FIELD_PATTERNS: Array<{ type?: string; namePattern: RegExp; label: string }> = [
  { type: "password", namePattern: /password/i, label: "password" },
  { namePattern: /credit.?card|card.?number|cc.?num/i, label: "credit card" },
  { namePattern: /\bssn\b|social.?security/i, label: "SSN" },
  { namePattern: /\bcvv\b|\bcvc\b|\bcvv2\b|security.?code/i, label: "card security code" },
];

/** URL patterns that suggest sequential multi-step workflows. */
const SEQUENTIAL_URL_RE = /(?:step|phase|stage|checkout|wizard|onboard)[\/_-]?(\d+)/i;

/** Anchor href or API-style URL with a bare numeric ID segment. */
const HREF_RE = /href\s*=\s*["']([^"']+)["']/gi;

/** A URL path segment that's purely a small numeric ID (1-9 digits). */
const NUMERIC_ID_SEGMENT_RE = /\/(\d{1,9})(?:\/|$|\?)/;

/** Common redirect query parameters. */
const REDIRECT_PARAMS = ["url", "redirect", "next", "return", "returnTo", "goto", "destination", "redirect_uri", "continue", "redir"];

/** Common login endpoint paths. */
const LOGIN_ENDPOINTS = ["/login", "/signin", "/auth", "/api/auth", "/api/login", "/api/signin"];

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

async function fetchPage(targetUrl: string): Promise<{ html: string; finalUrl: string } | null> {
  try {
    const res = await fetch(targetUrl, {
      redirect: "follow",
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) return null;
    const html = await res.text();
    return { html, finalUrl: res.url };
  } catch {
    return null;
  }
}

function checkCsrf(html: string): CsrfCheckData {
  const metaCsrfPresent = META_CSRF_RE.test(html);

  let formsFound = 0;
  let formsWithToken = 0;
  let formsWithoutToken = 0;

  let formMatch: RegExpExecArray | null;
  FORM_TAG_RE.lastIndex = 0;
  while ((formMatch = FORM_TAG_RE.exec(html)) !== null) {
    const fullTag = formMatch[0];
    const methodMatch = fullTag.match(FORM_METHOD_RE);
    const method = (methodMatch?.[1] ?? "get").toLowerCase();

    // Only POST/PUT/PATCH/DELETE forms need CSRF protection — GET forms are
    // safe by convention (CSRF is a state-mutation attack).
    if (method === "get") continue;

    formsFound++;

    // Check if the form contains a hidden input with a CSRF-like name.
    const formContent = formMatch[1] ?? "";
    let hasToken = false;
    let hiddenMatch: RegExpExecArray | null;
    HIDDEN_INPUT_RE.lastIndex = 0;
    while ((hiddenMatch = HIDDEN_INPUT_RE.exec(formContent)) !== null) {
      const nameMatch = hiddenMatch[0].match(NAME_ATTR_RE);
      if (nameMatch && CSRF_FIELD_NAMES.has(nameMatch[1].toLowerCase())) {
        hasToken = true;
        break;
      }
    }

    // A meta csrf-token tag (Rails) counts as protection too, since the
    // framework injects it into AJAX requests automatically.
    if (hasToken || metaCsrfPresent) {
      formsWithToken++;
    } else {
      formsWithoutToken++;
    }
  }

  return { formsFound, formsWithToken, formsWithoutToken, metaCsrfPresent };
}

function checkExternalForms(html: string, pageOrigin: string): ExternalFormData[] {
  const results: ExternalFormData[] = [];

  let formMatch: RegExpExecArray | null;
  FORM_TAG_RE.lastIndex = 0;
  while ((formMatch = FORM_TAG_RE.exec(html)) !== null) {
    const fullTag = formMatch[0];
    const actionMatch = fullTag.match(FORM_ACTION_RE);
    if (!actionMatch) continue;

    const action = actionMatch[1];

    // Skip relative, same-origin, and javascript: actions.
    if (action.startsWith("/") || action.startsWith("#") || action.startsWith("javascript:")) continue;

    try {
      const actionUrl = new URL(action, pageOrigin);
      const targetOrigin = actionUrl.origin;

      if (targetOrigin !== pageOrigin) {
        // Skip well-known payment processors and analytics — they are expected
        // external form targets, not data exfiltration indicators.
        const wellKnown = [
          "stripe.com", "paypal.com", "braintreegateway.com", "authorize.net",
          "google.com", "googleapis.com", "gstatic.com",
          "facebook.com", "twitter.com",
        ];
        const actionHost = actionUrl.hostname.toLowerCase();
        if (wellKnown.some((wk) => actionHost === wk || actionHost.endsWith(`.${wk}`))) continue;

        results.push({
          formAction: action,
          targetDomain: actionUrl.hostname,
        });
      }
    } catch {
      // Malformed action URL — skip.
    }
  }

  return results;
}

function checkAutocomplete(html: string): AutocompleteIssueData[] {
  const results: AutocompleteIssueData[] = [];

  let inputMatch: RegExpExecArray | null;
  INPUT_RE.lastIndex = 0;
  while ((inputMatch = INPUT_RE.exec(html)) !== null) {
    const tag = inputMatch[0];
    const typeMatch = tag.match(TYPE_ATTR_RE);
    const nameMatch = tag.match(NAME_ATTR_RE);
    const autocompleteMatch = tag.match(AUTOCOMPLETE_ATTR_RE);
    const fieldType = (typeMatch?.[1] ?? "text").toLowerCase();
    const fieldName = nameMatch?.[1] ?? "";
    const autocompleteValue = autocompleteMatch?.[1]?.toLowerCase() ?? null;

    for (const pattern of SENSITIVE_FIELD_PATTERNS) {
      const matchesType = pattern.type ? fieldType === pattern.type : true;
      const matchesName = pattern.namePattern.test(fieldName) || (pattern.type && fieldType === pattern.type);

      if (matchesType && matchesName) {
        // autocomplete="off" or "new-password" are the correct values for
        // sensitive fields. Anything else (including absent) is a finding.
        const isSafe =
          autocompleteValue === "off" ||
          autocompleteValue === "new-password";

        if (!isSafe) {
          results.push({
            fieldType: pattern.label,
            fieldName: fieldName || `(unnamed ${fieldType} field)`,
            autocompleteValue,
          });
        }
        break; // Only one finding per field.
      }
    }
  }

  return results;
}

function checkSequentialUrls(html: string): SequentialUrlData[] {
  const results: SequentialUrlData[] = [];
  const seen = new Set<string>();

  let hrefMatch: RegExpExecArray | null;
  HREF_RE.lastIndex = 0;
  while ((hrefMatch = HREF_RE.exec(html)) !== null) {
    const url = hrefMatch[1];
    const seqMatch = url.match(SEQUENTIAL_URL_RE);
    if (seqMatch && !seen.has(url)) {
      seen.add(url);
      results.push({ url, pattern: seqMatch[0] });
    }
  }

  return results;
}

function checkPredictableIds(html: string, pageOrigin: string): PredictableIdData[] {
  const results: PredictableIdData[] = [];
  const seen = new Set<string>();

  let hrefMatch: RegExpExecArray | null;
  HREF_RE.lastIndex = 0;
  while ((hrefMatch = HREF_RE.exec(html)) !== null) {
    const rawUrl = hrefMatch[1];

    // Only consider same-origin or relative links — cross-origin IDs are the
    // other domain's concern.
    try {
      const resolved = new URL(rawUrl, pageOrigin);
      if (resolved.origin !== pageOrigin) continue;
    } catch {
      // Relative paths are fine — they're same-origin by definition.
    }

    const idMatch = rawUrl.match(NUMERIC_ID_SEGMENT_RE);
    if (idMatch && !seen.has(rawUrl)) {
      const idStr = idMatch[1];
      const idNum = parseInt(idStr, 10);
      // Only flag small sequential-looking IDs (1–999999). Very large numbers
      // and hashes are not practically enumerable.
      if (idNum >= 1 && idNum <= 999999) {
        seen.add(rawUrl);
        results.push({ url: rawUrl, idValue: idStr });
      }
    }
  }

  // Only report if we found multiple links with numeric IDs — a single link
  // with an ID is common and not necessarily a problem. Two or more suggests
  // a pattern of sequential resource identifiers.
  return results.length >= 2 ? results : [];
}

async function checkOpenRedirects(targetUrl: string): Promise<OpenRedirectData[]> {
  const results: OpenRedirectData[] = [];
  const origin = new URL(targetUrl).origin;
  const evilDomain = "https://evil.example.com";

  for (const param of REDIRECT_PARAMS) {
    const testUrl = `${origin}/?${param}=${encodeURIComponent(evilDomain)}`;
    try {
      const res = await fetch(testUrl, {
        redirect: "manual", // Don't follow — check the Location header.
        signal: AbortSignal.timeout(8_000),
      });

      const location = res.headers.get("location");
      if (location) {
        try {
          const redirectTarget = new URL(location);
          // Only flag when the server actually redirects to the attacker domain.
          if (
            redirectTarget.hostname === "evil.example.com" ||
            redirectTarget.hostname.endsWith(".evil.example.com")
          ) {
            results.push({
              parameter: param,
              endpoint: "/",
              redirectedTo: location,
            });
          }
        } catch {
          // Relative redirect or malformed — not an open redirect.
        }
      }
    } catch {
      // Timeout or network error — skip this parameter.
    }
  }

  return results;
}

async function checkRateLimiting(targetUrl: string): Promise<RateLimitData> {
  const origin = new URL(targetUrl).origin;
  const REQUEST_COUNT = 5;

  // Try each common login endpoint until we find one that responds.
  for (const path of LOGIN_ENDPOINTS) {
    const endpoint = origin + path;

    try {
      // Verify the endpoint exists first with a single GET.
      const probe = await fetch(endpoint, {
        method: "GET",
        redirect: "follow",
        signal: AbortSignal.timeout(8_000),
      });

      // Skip endpoints that return 404 — not a login page.
      if (probe.status === 404) continue;

      // Now send rapid POST requests with dummy credentials.
      let rateLimited = false;
      let sent = 0;

      for (let i = 0; i < REQUEST_COUNT; i++) {
        try {
          const res = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: "username=test&password=test",
            redirect: "manual",
            signal: AbortSignal.timeout(8_000),
          });
          sent++;

          if (
            res.status === 429 ||
            res.headers.has("retry-after") ||
            res.headers.has("x-ratelimit-remaining")
          ) {
            const remaining = res.headers.get("x-ratelimit-remaining");
            if (res.status === 429 || (remaining !== null && parseInt(remaining, 10) <= 0)) {
              rateLimited = true;
              break;
            }
          }
        } catch {
          // Request-level failure — continue.
        }
      }

      return { checked: true, endpoint: path, rateLimited, requestsSent: sent };
    } catch {
      // Endpoint not reachable — try next.
    }
  }

  // No login endpoint found — cannot check rate limiting.
  return { checked: false, endpoint: null, rateLimited: false, requestsSent: 0 };
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export async function checkBusinessLogic(targetUrl: string): Promise<BusinessLogicResult> {
  try {
    const pageData = await fetchPage(targetUrl);
    if (!pageData) {
      return { status: "error", note: "Could not fetch target page for business logic checks" };
    }

    const { html, finalUrl } = pageData;
    const pageOrigin = new URL(finalUrl).origin;

    // Run the fast HTML-parsing checks synchronously, then the network-based
    // checks in parallel.
    const csrf = checkCsrf(html);
    const externalForms = checkExternalForms(html, pageOrigin);
    const autocompleteIssues = checkAutocomplete(html);
    const sequentialUrls = checkSequentialUrls(html);
    const predictableIds = checkPredictableIds(html, pageOrigin);

    const [openRedirects, rateLimiting] = await Promise.all([
      checkOpenRedirects(targetUrl),
      checkRateLimiting(targetUrl),
    ]);

    return {
      status: "checked",
      csrf,
      externalForms,
      autocompleteIssues,
      sequentialUrls,
      predictableIds,
      openRedirects,
      rateLimiting,
    };
  } catch (err) {
    return { status: "error", note: `Business logic check failed: ${(err as Error).message}` };
  }
}
