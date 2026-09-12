// Business logic / session management checks — no external binary.
//
// Probes the target for common session-management and business-logic
// issues: rate limiting detection, session fixation, and basic IDOR
// indicators. These are lightweight HTTP-based checks that complement
// the heavier active scanning tools.

export type SessionFinding = {
  type: "no-rate-limit" | "session-fixation" | "idor-indicator" | "session-no-rotation";
  detail: string;
  url: string;
};

export type SessionCheckResult =
  | { status: "completed"; findings: SessionFinding[] }
  | { status: "error"; note: string };

const FETCH_TIMEOUT_MS = 10_000;
const RATE_LIMIT_BURST_COUNT = 10;

async function checkRateLimiting(targetUrl: string): Promise<SessionFinding[]> {
  const findings: SessionFinding[] = [];
  const loginPaths = ["/login", "/api/login", "/api/auth/login", "/signin", "/api/signin"];

  for (const path of loginPaths) {
    try {
      const url = new URL(path, targetUrl).href;
      const firstRes = await fetch(url, {
        method: "HEAD",
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (firstRes.status === 404 || firstRes.status === 405) continue;

      let blocked = false;
      for (let i = 0; i < RATE_LIMIT_BURST_COUNT; i++) {
        const res = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: "test@example.com", password: "testpassword123" }),
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        });
        if (res.status === 429 || res.headers.has("retry-after") || res.headers.has("x-ratelimit-remaining")) {
          blocked = true;
          break;
        }
      }

      if (!blocked) {
        findings.push({
          type: "no-rate-limit",
          detail: `Login endpoint ${path} accepted ${RATE_LIMIT_BURST_COUNT} rapid requests without rate limiting. This could allow brute-force attacks.`,
          url: path,
        });
      }
      break;
    } catch {
      // Path unreachable — try next
    }
  }

  return findings;
}

async function checkSessionFixation(targetUrl: string): Promise<SessionFinding[]> {
  const findings: SessionFinding[] = [];

  try {
    const res1 = await fetch(targetUrl, {
      redirect: "follow",
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });

    const cookies1 = res1.headers.getSetCookie?.() ?? [];
    const sessionCookies1 = cookies1.filter((c) =>
      /^(session|sess|sid|jsessionid|phpsessid|asp\.net_sessionid)/i.test(c)
    );

    if (sessionCookies1.length > 0) {
      const res2 = await fetch(targetUrl, {
        redirect: "follow",
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        headers: {
          Cookie: sessionCookies1.map((c) => c.split(";")[0]).join("; "),
        },
      });

      const cookies2 = res2.headers.getSetCookie?.() ?? [];
      const sessionCookies2 = cookies2.filter((c) =>
        /^(session|sess|sid|jsessionid|phpsessid|asp\.net_sessionid)/i.test(c)
      );

      if (sessionCookies2.length === 0) {
        findings.push({
          type: "session-fixation",
          detail: "Server accepted a pre-set session cookie without issuing a new one. This may indicate session fixation vulnerability.",
          url: targetUrl,
        });
      }
    }
  } catch {
    // Can't reach the target
  }

  return findings;
}

async function checkIdorIndicators(targetUrl: string): Promise<SessionFinding[]> {
  const findings: SessionFinding[] = [];
  const idorPaths = [
    "/api/users/1",
    "/api/user/1",
    "/api/account/1",
    "/api/profile/1",
    "/api/v1/users/1",
  ];

  for (const path of idorPaths) {
    try {
      const url = new URL(path, targetUrl).href;
      const res = await fetch(url, {
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (res.status === 200) {
        const contentType = res.headers.get("content-type") ?? "";
        if (contentType.includes("json")) {
          findings.push({
            type: "idor-indicator",
            detail: `Endpoint ${path} returned JSON data with a sequential numeric ID without authentication. This may be an insecure direct object reference (IDOR).`,
            url: path,
          });
        }
      }
    } catch {
      // Path unreachable
    }
  }

  return findings;
}

export async function runSessionCheck(targetUrl: string): Promise<SessionCheckResult> {
  try {
    const [rateLimitFindings, sessionFixationFindings, idorFindings] = await Promise.allSettled([
      checkRateLimiting(targetUrl),
      checkSessionFixation(targetUrl),
      checkIdorIndicators(targetUrl),
    ]);

    const findings: SessionFinding[] = [
      ...(rateLimitFindings.status === "fulfilled" ? rateLimitFindings.value : []),
      ...(sessionFixationFindings.status === "fulfilled" ? sessionFixationFindings.value : []),
      ...(idorFindings.status === "fulfilled" ? idorFindings.value : []),
    ];

    return { status: "completed", findings };
  } catch (err) {
    return {
      status: "error",
      note: `Session check failed: ${(err as Error).message}`,
    };
  }
}
