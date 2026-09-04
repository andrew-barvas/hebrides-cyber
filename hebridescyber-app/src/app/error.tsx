"use client";

import { useEffect } from "react";
import Link from "next/link";
import * as Sentry from "@sentry/nextjs";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // E-03 (docs/ENHANCEMENTS.md): was console.error-only with a comment
    // saying "wire to Application Insights / Sentry here later" — this is
    // that wiring. captureException is a safe no-op when SENTRY_DSN isn't
    // configured (see sentry.server.config.ts), so console.error stays as
    // a genuine fallback, not dead code.
    console.error("[global error]", error);
    Sentry.captureException(error);
  }, [error]);

  return (
    <div className="mx-auto max-w-md px-6 py-32 text-center">
      <p className="mb-2 font-mono text-4xl font-bold text-atlantic/20">500</p>
      <h1 className="mb-4 text-2xl font-bold text-atlantic">Something went wrong</h1>
      <p className="text-sm text-slatedark/70">
        An unexpected error occurred. If this keeps happening, please{" "}
        <Link href="/contact" className="underline">
          get in touch
        </Link>
        .
      </p>
      {error.digest && (
        <p className="mt-3 font-mono text-xs text-slatedark/40">ref: {error.digest}</p>
      )}
      <div className="mt-8 flex justify-center gap-4">
        <button
          onClick={reset}
          className="rounded-md bg-atlantic px-5 py-2 text-sm font-semibold text-white hover:opacity-90"
        >
          Try again
        </button>
        <Link
          href="/"
          className="rounded-md border border-slate-200 px-5 py-2 text-sm font-semibold text-slatedark hover:border-atlantic"
        >
          Go home
        </Link>
      </div>
    </div>
  );
}
