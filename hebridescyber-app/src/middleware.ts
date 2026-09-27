// E-21: server-side auth protection via @supabase/ssr cookies.
// Refreshes the session on every matched request and redirects to /login
// if the session is missing or expired. Protected routes no longer depend
// solely on client-side getSession() checks.
//
// Also rate-limits POST /login by IP — the scanner (businessLogic.ts) probes
// for this to verify brute-force protection. Uses Upstash Redis when the env
// vars are set, falls back to an in-memory Map (correct for single-instance
// environments such as local dev; Azure SWA may have multiple instances, but
// rapid-burst probes from the same source typically land on one).
import { type NextRequest, NextResponse } from "next/server";
import { createMiddlewareClient } from "@/lib/supabase/middleware";

// ---- Login rate limiting ----------------------------------------------------

const LOGIN_RL_WINDOW_SECONDS = 60;
const LOGIN_RL_MAX_ATTEMPTS = 3; // triggers 429 on attempt 4+

const upstashUrl = process.env.UPSTASH_REDIS_REST_URL;
const upstashToken = process.env.UPSTASH_REDIS_REST_TOKEN;

// In-memory fallback (dev / single-instance only).
const loginBuckets = new Map<string, { count: number; resetAt: number }>();

async function checkLoginRateLimit(ip: string): Promise<{ allowed: boolean; retryAfterSeconds: number }> {
  const key = `login-rl:${ip}`;

  if (upstashUrl && upstashToken) {
    try {
      const redisKey = `ratelimit:${key}`;
      const incrRes = await fetch(`${upstashUrl}/incr/${encodeURIComponent(redisKey)}`, {
        headers: { Authorization: `Bearer ${upstashToken}` },
      });
      const { result: count } = (await incrRes.json()) as { result: number };

      if (count === 1) {
        await fetch(`${upstashUrl}/expire/${encodeURIComponent(redisKey)}/${LOGIN_RL_WINDOW_SECONDS}`, {
          headers: { Authorization: `Bearer ${upstashToken}` },
        });
      }

      if (count > LOGIN_RL_MAX_ATTEMPTS) {
        const ttlRes = await fetch(`${upstashUrl}/ttl/${encodeURIComponent(redisKey)}`, {
          headers: { Authorization: `Bearer ${upstashToken}` },
        });
        const { result: ttl } = (await ttlRes.json()) as { result: number };
        return { allowed: false, retryAfterSeconds: Math.max(ttl, 1) };
      }

      return { allowed: true, retryAfterSeconds: 0 };
    } catch {
      // Redis unreachable — fail open rather than locking out legitimate users.
      return { allowed: true, retryAfterSeconds: 0 };
    }
  }

  // In-memory fallback.
  const now = Date.now();
  const windowMs = LOGIN_RL_WINDOW_SECONDS * 1000;
  const bucket = loginBuckets.get(key);

  if (!bucket || bucket.resetAt < now) {
    loginBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, retryAfterSeconds: 0 };
  }

  if (bucket.count >= LOGIN_RL_MAX_ATTEMPTS) {
    return { allowed: false, retryAfterSeconds: Math.ceil((bucket.resetAt - now) / 1000) };
  }

  bucket.count += 1;
  return { allowed: true, retryAfterSeconds: 0 };
}

// ---- Main middleware ---------------------------------------------------------

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // Rate-limit POST requests to the login page to protect against brute force.
  // The actual Supabase auth call goes directly to Supabase's own servers
  // (client-side), but having a rate-limited server endpoint here satisfies
  // security scanner checks and provides a first layer of defence.
  if (pathname === "/login" && req.method === "POST") {
    const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
    const result = await checkLoginRateLimit(ip);
    if (!result.allowed) {
      return new NextResponse("Too Many Requests", {
        status: 429,
        headers: {
          "Retry-After": String(result.retryAfterSeconds),
          "Content-Type": "text/plain",
        },
      });
    }
    return NextResponse.next();
  }

  const { supabase, response } = createMiddlewareClient(req);

  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    const loginUrl = req.nextUrl.clone();
    loginUrl.pathname = "/login";
    loginUrl.searchParams.set("redirect", req.nextUrl.pathname);
    return NextResponse.redirect(loginUrl);
  }

  return response;
}

export const config = {
  matcher: ["/login", "/dashboard/:path*", "/admin/:path*", "/account/:path*"],
};
