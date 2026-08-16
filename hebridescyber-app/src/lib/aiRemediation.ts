// On-demand, per-finding AI-tailored remediation. Distinct from
// generateAiSummary (src/lib/scanners/index.ts), which runs automatically on
// every scan for a 2-3 sentence executive summary and has a non-AI fallback
// baked in. This is explicitly user-triggered (a "Get AI-tailored fix" button
// on one finding), so it deliberately has no silent fallback — if Azure
// OpenAI isn't configured or the call fails, the caller needs to know that
// plainly, rather than quietly receiving back the same static remediation
// text it already had with no indication anything ran.
import type { Finding } from "./scanners";
import type { DetectedTech } from "./scanners/fingerprint";

export type AiRemediationResult =
  | { status: "ok"; guidance: string }
  | { status: "not_configured" }
  | { status: "error"; message: string };

export async function generateAiRemediation(
  finding: Pick<Finding, "title" | "detail" | "remediation">,
  technologies: DetectedTech[]
): Promise<AiRemediationResult> {
  const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
  const apiKey = process.env.AZURE_OPENAI_KEY;
  const deployment = process.env.AZURE_OPENAI_DEPLOYMENT;
  if (!endpoint || !apiKey || !deployment) return { status: "not_configured" };

  const stackList =
    technologies.length > 0
      ? technologies.map((t) => `${t.name}${t.version ? ` ${t.version}` : ""} (${t.category})`).join(", ")
      : "not detected — give general guidance covering the most common platforms";

  try {
    const res = await fetch(
      `${endpoint}/openai/deployments/${deployment}/chat/completions?api-version=2024-02-15-preview`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "api-key": apiKey },
        signal: AbortSignal.timeout(20_000),
        body: JSON.stringify({
          messages: [
            {
              role: "system",
              content:
                "You are a security engineer writing precise, actionable remediation steps for a single " +
                "vulnerability finding, tailored to the specific technology stack detected on the target " +
                "site. Reference exact file names, config locations, and commands for the detected " +
                "platform(s) — do not give generic multi-platform advice when the stack is known. Keep it " +
                "under 200 words. Markdown, with a fenced code block for any config or command snippet. No " +
                "preamble — start directly with the fix.",
            },
            {
              role: "user",
              content:
                `Finding: ${finding.title}\n` +
                `Detail: ${finding.detail}\n` +
                (finding.remediation ? `Generic remediation already on file:\n${finding.remediation}\n\n` : "") +
                `Detected technology stack: ${stackList}\n\n` +
                "Give remediation steps specific to this exact stack.",
            },
          ],
          max_tokens: 400,
          temperature: 0.2,
        }),
      }
    );

    if (!res.ok) {
      return { status: "error", message: `Azure OpenAI returned ${res.status}` };
    }
    const body = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
    const guidance = body.choices?.[0]?.message?.content?.trim();
    if (!guidance) return { status: "error", message: "Azure OpenAI returned an empty response" };
    return { status: "ok", guidance };
  } catch (err) {
    return { status: "error", message: (err as Error).message };
  }
}
