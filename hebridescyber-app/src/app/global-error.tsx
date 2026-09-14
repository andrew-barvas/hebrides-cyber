"use client";

import { useEffect } from "react";
import * as Sentry from "@sentry/nextjs";

// Next.js's specific mechanism for root-layout errors — replaces the layout
// entirely, so must render a full <html>/<body> rather than a page fragment.
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("[root layout error]", error);
    Sentry.captureException(error);
  }, [error]);

  return (
    <html lang="en">
      <body style={{ margin: 0, background: "#070B14", color: "#fff", fontFamily: "ui-monospace, monospace", minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: "2rem" }}>
        <div style={{ maxWidth: 520, background: "#0D1524", border: "1px solid #1C2940", borderRadius: 12, padding: "2.5rem" }}>
          <p style={{ fontSize: "0.75rem", color: "#39FFC0", letterSpacing: "0.08em", marginBottom: "1.25rem" }}>// 500 — server error</p>
          <h1 style={{ fontSize: "1.5rem", fontWeight: 700, marginBottom: "0.75rem", lineHeight: 1.3 }}>Something went wrong</h1>
          <p style={{ fontSize: "0.875rem", color: "rgba(255,255,255,0.5)", lineHeight: 1.6, marginBottom: "2rem" }}>
            The application hit an unexpected error. Try refreshing or return to the homepage.
          </p>
          <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
            <button
              onClick={reset}
              style={{ padding: "0.625rem 1.25rem", borderRadius: 6, background: "#39FFC0", color: "#070B14", fontSize: "0.8125rem", fontWeight: 600, border: "none", cursor: "pointer" }}
            >
              Try again
            </button>
            <a
              href="/"
              style={{ padding: "0.625rem 1.25rem", borderRadius: 6, background: "transparent", color: "#39FFC0", fontSize: "0.8125rem", fontWeight: 600, border: "1px solid #1C2940", textDecoration: "none" }}
            >
              Go to homepage
            </a>
          </div>
          {error.digest && (
            <p style={{ marginTop: "1.5rem", fontSize: "0.75rem", color: "rgba(255,255,255,0.2)" }}>ref: {error.digest}</p>
          )}
        </div>
      </body>
    </html>
  );
}
