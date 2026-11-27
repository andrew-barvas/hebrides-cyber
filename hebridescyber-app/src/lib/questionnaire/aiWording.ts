// Optional AI phrasing on top of the rule-based drafts, through the app's
// existing Azure OpenAI deployment (the same env vars as aiRemediation.ts;
// no new provider or secret).
//
// The model only rewords. It receives the question, the rule-based draft and
// the evidence lines that draft cites, nothing else: no customer name, no
// hostnames beyond what the draft already says, no other answers. A reworded
// answer that changes the draft's yes/no/partly, or comes back empty or
// overlong, is thrown away and the rule-based draft stands. When Azure OpenAI
// isn't configured or the call fails, every draft stands unchanged.

export type WordingItem = { id: string; question: string; draft: string; evidence: string[] };
export type WordingResult = { status: "ok"; worded: Map<string, string> } | { status: "not_configured" } | { status: "error"; message: string };

export const MAX_ITEMS_PER_CALL = 10;
const MAX_ANSWER_CHARS = 1200;

export function isAiWordingConfigured(): boolean {
  return Boolean(process.env.AZURE_OPENAI_ENDPOINT && process.env.AZURE_OPENAI_KEY && process.env.AZURE_OPENAI_DEPLOYMENT);
}

/** Pure: the leading yes/no/partly of an answer, or null when it has none. */
export function polarity(text: string): "yes" | "no" | "partly" | null {
  const m = /^\s*(yes|no|not|partly|partially)\b/i.exec(text);
  if (!m) return null;
  const w = m[1].toLowerCase();
  return w === "yes" ? "yes" : w === "no" || w === "not" ? "no" : "partly";
}

/** Pure: keep a reworded answer only if it is usable and says the same thing. */
export function acceptWording(draft: string, worded: unknown): string | null {
  if (typeof worded !== "string") return null;
  const text = worded.trim();
  if (!text || text.length > MAX_ANSWER_CHARS) return null;
  if (polarity(draft) !== polarity(text)) return null;
  return text;
}

const SYSTEM_PROMPT =
  "You reword draft answers to a security questionnaire for a small UK business. " +
  "Each item has a question, a draft answer and the evidence behind it. Rewrite each draft so it reads as a " +
  "clear, professional first-person answer (\"we\", \"our\") to that exact question, in UK English, in at most " +
  "three sentences. Rules: never add a fact, product, number, date or claim that is not in the draft or its " +
  "evidence; never change whether the answer is yes, no or partly, and keep that word first; never mention " +
  "Hebrides Cyber unless the draft does; no preamble. Reply with JSON only: " +
  '{"answers":[{"id":"<id>","answer":"<text>"}]}.';

/** Reword up to MAX_ITEMS_PER_CALL drafts in one call. Never throws. */
export async function wordAnswers(items: WordingItem[]): Promise<WordingResult> {
  const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
  const apiKey = process.env.AZURE_OPENAI_KEY;
  const deployment = process.env.AZURE_OPENAI_DEPLOYMENT;
  if (!endpoint || !apiKey || !deployment) return { status: "not_configured" };
  const batch = items.slice(0, MAX_ITEMS_PER_CALL);
  if (!batch.length) return { status: "ok", worded: new Map() };

  const payload = batch.map((i) => ({ id: i.id, question: i.question.slice(0, 1000), draft: i.draft, evidence: i.evidence.slice(0, 6).map((e) => e.slice(0, 400)) }));
  try {
    const res = await fetch(`${endpoint}/openai/deployments/${deployment}/chat/completions?api-version=2024-02-15-preview`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "api-key": apiKey },
      signal: AbortSignal.timeout(25_000),
      body: JSON.stringify({
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: JSON.stringify({ items: payload }) },
        ],
        max_tokens: 250 * batch.length,
        temperature: 0.2,
        response_format: { type: "json_object" },
      }),
    });
    if (!res.ok) return { status: "error", message: `Azure OpenAI returned ${res.status}` };
    const body = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
    const content = body.choices?.[0]?.message?.content;
    if (!content) return { status: "error", message: "Azure OpenAI returned an empty response" };
    let parsed: { answers?: Array<{ id?: unknown; answer?: unknown }> };
    try {
      parsed = JSON.parse(content);
    } catch {
      return { status: "error", message: "Azure OpenAI returned something that isn't JSON" };
    }
    const byId = new Map(batch.map((i) => [i.id, i]));
    const worded = new Map<string, string>();
    for (const a of parsed.answers ?? []) {
      const item = typeof a.id === "string" ? byId.get(a.id) : undefined;
      const text = item ? acceptWording(item.draft, a.answer) : null;
      if (item && text) worded.set(item.id, text);
    }
    return { status: "ok", worded };
  } catch (err) {
    return { status: "error", message: (err as Error).message };
  }
}
