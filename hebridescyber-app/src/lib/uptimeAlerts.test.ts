import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";

const m = vi.hoisted(() => ({ slack: vi.fn(), teams: vi.fn(), email: vi.fn() }));
vi.mock("./slack", () => ({ sendSlackNotice: m.slack }));
vi.mock("./msTeams", () => ({ sendTeamsNotice: m.teams }));
vi.mock("./email", async (orig) => ({ ...(await orig<typeof import("./email")>()), sendEmail: m.email }));

import { buildUptimeMessage, sendUptimeAlert } from "./uptimeAlerts";

function db(sub: Record<string, unknown> | null, user: Record<string, unknown> | null) {
  return {
    from: (table: string) => {
      const b: Record<string, unknown> = {};
      b.select = () => b;
      b.eq = () => b;
      b.maybeSingle = () => Promise.resolve({ data: table === "subscriptions" ? sub : user });
      return b;
    },
  } as unknown as SupabaseClient;
}

beforeEach(() => {
  m.slack.mockReset().mockResolvedValue(undefined);
  m.teams.mockReset().mockResolvedValue(undefined);
  m.email.mockReset().mockResolvedValue({ ok: true });
});

describe("buildUptimeMessage", () => {
  it("names the host for down and recovered", () => {
    expect(buildUptimeMessage("down", "https://shop.example.co.uk/")).toMatchObject({ subject: "shop.example.co.uk is down", title: "Site down: shop.example.co.uk" });
    expect(buildUptimeMessage("recovered", "https://shop.example.co.uk")).toMatchObject({ subject: "shop.example.co.uk is back up" });
  });
  it("falls back to the raw value for a malformed target", () => {
    expect(buildUptimeMessage("down", "not a url").subject).toBe("not a url is down");
  });
});

describe("sendUptimeAlert", () => {
  it("sends to every configured channel", async () => {
    await sendUptimeAlert(db({ slack_webhook_url: "https://hooks.slack.com/x", ms_teams_webhook_url: "https://example.webhook.office.com/y" }, { email: "me@example.co.uk" }), "o1", "down", "https://shop.example.co.uk");
    expect(m.slack).toHaveBeenCalledTimes(1);
    expect(m.teams).toHaveBeenCalledTimes(1);
    expect(m.email).toHaveBeenCalledWith(expect.objectContaining({ to: "me@example.co.uk", subject: "shop.example.co.uk is down" }));
  });

  it("sends only email when no chat webhooks are set", async () => {
    await sendUptimeAlert(db({}, { email: "me@example.co.uk" }), "o1", "recovered", "https://shop.example.co.uk");
    expect(m.slack).not.toHaveBeenCalled();
    expect(m.email).toHaveBeenCalledTimes(1);
  });

  it("still sends the other channels when one fails, and never throws", async () => {
    m.slack.mockRejectedValue(new Error("slack down"));
    await expect(sendUptimeAlert(db({ slack_webhook_url: "https://hooks.slack.com/x" }, { email: "me@example.co.uk" }), "o1", "down", "https://shop.example.co.uk")).resolves.toBeUndefined();
    expect(m.email).toHaveBeenCalledTimes(1);
  });

  it("escapes the host in the email body", async () => {
    await sendUptimeAlert(db(null, { email: "me@example.co.uk" }), "o1", "down", "https://x.example/<script>");
    const html = m.email.mock.calls[0][0].html as string;
    expect(html).not.toContain("<script>");
  });

  it("does nothing, quietly, when there is nowhere to send", async () => {
    await expect(sendUptimeAlert(db(null, null), "o1", "down", "https://shop.example.co.uk")).resolves.toBeUndefined();
    expect(m.email).not.toHaveBeenCalled();
  });
});
