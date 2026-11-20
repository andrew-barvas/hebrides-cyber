"use client";

// The "what to do" for one lookalike domain (lookalikeResponse.ts): steps and
// a ready-written registrar report the owner can copy. Used on the Assets page
// and in the Lookout report.
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { buildLookalikeResponse, type LookalikeInput } from "@/lib/lookalikeResponse";

export function LookalikeResponseKit(props: LookalikeInput) {
  const kit = buildLookalikeResponse(props);
  const [copied, setCopied] = useState<"ok" | "failed" | null>(null);
  const reportText = `Subject: ${kit.abuseReport.subject}\n\n${kit.abuseReport.body}`;

  async function copy() {
    try {
      await navigator.clipboard.writeText(reportText);
      setCopied("ok");
    } catch {
      setCopied("failed");
    }
  }

  return (
    <div className="space-y-3 text-sm">
      <p className="text-cybertext/80">{kit.summary}</p>
      <ol className="list-decimal space-y-2 pl-5">
        {kit.steps.map((s) => (
          <li key={s.title}>
            <span className="font-semibold text-cybertext">{s.title}.</span> <span className="text-cybertext/80">{s.body}</span>
            {s.link && (
              <>
                {" "}
                <a href={s.link.href} target="_blank" rel="noopener noreferrer" className="text-neon hover:underline">
                  {s.link.label}
                  <span className="sr-only"> (opens in a new tab)</span>
                </a>
              </>
            )}
          </li>
        ))}
      </ol>
      <div className="rounded-lg border border-cyberborder bg-cyberbg/50 p-3">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <p className="font-semibold text-cybertext">Report for the registrar</p>
          <Button variant="secondary" size="sm" onClick={copy}>
            Copy report
          </Button>
        </div>
        <pre className="whitespace-pre-wrap break-words font-sans text-xs text-cybertext/80">{reportText}</pre>
        {copied && (
          <p role="status" className="mt-2 text-xs text-cybermuted">
            {copied === "ok" ? "Copied. Fill in the bracketed parts before sending." : "Couldn't copy automatically; select the text above instead."}
          </p>
        )}
      </div>
    </div>
  );
}
