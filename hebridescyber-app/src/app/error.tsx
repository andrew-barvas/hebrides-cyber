"use client";

import { useEffect } from "react";
import Link from "next/link";
import * as Sentry from "@sentry/nextjs";

export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("[route error]", error);
    Sentry.captureException(error);
  }, [error]);

  return (
    <div className="bg-cyberbg min-h-screen flex items-center justify-center px-6">
      <div className="max-w-lg w-full bg-cyberpanel border border-cyberborder rounded-xl p-10">
        <p className="mb-3 font-mono text-xs tracking-widest text-neon">// 500 — server error</p>
        <h1 className="text-2xl font-bold text-cybertext mb-3 leading-snug">
          Something went wrong
        </h1>
        <p className="text-sm text-cybertext/50 leading-relaxed mb-8">
          The page hit an unexpected error. Try refreshing — if it keeps
          happening, contact us and we&apos;ll investigate.
        </p>
        <div className="flex gap-3 flex-wrap">
          <button
            onClick={reset}
            className="px-5 py-2.5 rounded-md bg-neon text-cyberbg text-sm font-semibold hover:opacity-80 transition-opacity"
          >
            Try again
          </button>
          <Link
            href="/"
            className="px-5 py-2.5 rounded-md border border-cyberborder text-neon text-sm font-semibold hover:opacity-80 transition-opacity"
          >
            Go to homepage
          </Link>
        </div>
        {error.digest && (
          <p className="mt-6 font-mono text-xs text-cybertext/20">
            ref: {error.digest}
          </p>
        )}
      </div>
    </div>
  );
}
