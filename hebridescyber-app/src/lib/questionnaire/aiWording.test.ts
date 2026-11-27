// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { acceptWording, isAiWordingConfigured, polarity, wordAnswers, MAX_ITEMS_PER_CALL } from "./aiWording";

const item = (id: string, draft = "Yes. MFA is in place.") => ({ id, question: "Is MFA enforced?", draft, evidence: ["Microsoft 365 check (2026-11-21): no accounts without MFA"] });
const reply = (content: unknown, ok = true, status = 200) =>
  Promise.resolve({ ok, status, json: () => Promise.resolve({ choices: [{ message: { content: typeof content === "string" ? content : JSON.stringify(content) } }] }) } as Response);

describe("aiWording", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.stubEnv("AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com");
    vi.stubEnv("AZURE_OPENAI_KEY", "test-key");
    vi.stubEnv("AZURE_OPENAI_DEPLOYMENT", "gpt");
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("reads polarity", () => {
    expect(polarity("Yes, in transit.")).toBe("yes");
    expect(polarity("No. Not yet.")).toBe("no");
    expect(polarity("Not fully.")).toBe("no");
    expect(polarity("Partially, on servers")).toBe("partly");
    expect(polarity("Our scan found nothing")).toBeNull();
  });

  it("keeps only usable rewordings that say the same thing", () => {
    expect(acceptWording("Yes. MFA on.", "Yes, we enforce MFA.")).toBe("Yes, we enforce MFA.");
    expect(acceptWording("No. Gaps found.", "Yes, MFA is on.")).toBeNull();
    expect(acceptWording("Our scan found no open ports.", "Yes, our firewall blocks everything.")).toBeNull();
    expect(acceptWording("Yes.", "")).toBeNull();
    expect(acceptWording("Yes.", 42)).toBeNull();
    expect(acceptWording("Yes.", `Yes ${"x".repeat(1300)}`)).toBeNull();
  });

  it("does nothing without configuration", async () => {
    vi.stubEnv("AZURE_OPENAI_KEY", "");
    expect(isAiWordingConfigured()).toBe(false);
    expect(await wordAnswers([item("a")])).toEqual({ status: "not_configured" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("sends only the question, draft and evidence, and keeps valid rewordings", async () => {
    expect(isAiWordingConfigured()).toBe(true);
    fetchMock.mockReturnValue(reply({ answers: [{ id: "a", answer: "Yes, we enforce MFA for all accounts." }, { id: "b", answer: "Yes, all good." }, { id: "zzz", answer: "Yes" }, { answer: "Yes" }] }));
    const res = await wordAnswers([item("a"), item("b", "No. Two accounts lack MFA.")]);
    expect(res.status).toBe("ok");
    if (res.status !== "ok") return;
    expect([...res.worded]).toEqual([["a", "Yes, we enforce MFA for all accounts."]]);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://example.openai.azure.com/openai/deployments/gpt/chat/completions?api-version=2024-02-15-preview");
    const sent = JSON.parse(JSON.parse(init.body).messages[1].content);
    expect(Object.keys(sent.items[0]).sort()).toEqual(["draft", "evidence", "id", "question"]);
  });

  it("caps a batch and skips an empty one", async () => {
    fetchMock.mockReturnValue(reply({ answers: [] }));
    await wordAnswers(Array.from({ length: MAX_ITEMS_PER_CALL + 5 }, (_, i) => item(String(i))));
    expect(JSON.parse(JSON.parse(fetchMock.mock.calls[0][1].body).messages[1].content).items).toHaveLength(MAX_ITEMS_PER_CALL);
    expect(await wordAnswers([])).toEqual({ status: "ok", worded: new Map() });
    fetchMock.mockReturnValue(reply({}));
    expect(await wordAnswers([item("a")])).toEqual({ status: "ok", worded: new Map() });
  });

  it("reports failures so the rule-based drafts stand", async () => {
    fetchMock.mockReturnValueOnce(reply({}, false, 429));
    expect(await wordAnswers([item("a")])).toEqual({ status: "error", message: "Azure OpenAI returned 429" });
    fetchMock.mockReturnValueOnce(Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ choices: [] }) } as unknown as Response));
    expect(await wordAnswers([item("a")])).toEqual({ status: "error", message: "Azure OpenAI returned an empty response" });
    fetchMock.mockReturnValueOnce(reply("not json"));
    expect(await wordAnswers([item("a")])).toEqual({ status: "error", message: "Azure OpenAI returned something that isn't JSON" });
    fetchMock.mockRejectedValueOnce(new Error("timeout"));
    expect(await wordAnswers([item("a")])).toEqual({ status: "error", message: "timeout" });
  });
});
