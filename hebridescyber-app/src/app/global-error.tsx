"use client";

// E-03 (docs/ENHANCEMENTS.md): error.tsx (this folder) only catches errors
// inside a route segment — an error thrown in the root layout itself
// (Header/Footer/CookieConsent in src/app/layout.tsx, or layout.tsx's own
// LocalBusinessJsonLd) bypasses it entirely and would previously go
// completely unreported. This file is Next.js's specific mechanism for
// that case, and per its own requirement must render a full <html>/<body>
// — it replaces the root layout, not just the page, when it triggers.
import { useEffect } from "react";
import * as Sentry from "@sentry/nextjs";

export default function GlobalError({
  error,
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
      <body>
        <div style={{ maxWidth: 420, margin: "8rem auto", padding: "0 1.5rem", textAlign: "center", fontFamily: "sans-serif" }}>
          <h1 style={{ fontSize: "1.5rem", fontWeight: 700, marginBottom: "1rem" }}>Something went wrong</h1>
          <p style={{ fontSize: "0.875rem", opacity: 0.7 }}>
            An unexpected error occurred loading this page. Please try refreshing, or get in touch at{" "}
            <a href="mailto:hello@hebridescyber.co.uk">hello@hebridescyber.co.uk</a> if this keeps happening.
          </p>
          {error.digest && <p style={{ marginTop: "0.75rem", fontSize: "0.75rem", opacity: 0.4 }}>ref: {error.digest}</p>}
        </div>
      </body>
    </html>
  );
}
