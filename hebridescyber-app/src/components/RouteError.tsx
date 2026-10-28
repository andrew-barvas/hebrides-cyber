"use client";

import { useEffect } from "react";
import * as Sentry from "@sentry/nextjs";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

/**
 * Body for a section-level error.tsx. Renders inside the section's layout, so
 * the app shell (nav, session) survives a crash in one page instead of the
 * whole screen being replaced by the root error page.
 */
export default function RouteError({
  error,
  reset,
  section,
}: {
  error: Error & { digest?: string };
  reset: () => void;
  section: string;
}) {
  useEffect(() => {
    console.error(`[${section} error]`, error);
    Sentry.captureException(error);
  }, [error, section]);

  return (
    <div className="mx-auto max-w-xl px-4 py-12">
      <Alert variant="danger" title="Something went wrong">
        This part of {section} hit an unexpected error. Your data is safe — try again, and contact us if it keeps happening.
        {error.digest && <span className="mt-2 block font-mono text-xs text-cybermuted">ref: {error.digest}</span>}
      </Alert>
      <Button className="mt-4" onClick={reset}>
        Try again
      </Button>
    </div>
  );
}
