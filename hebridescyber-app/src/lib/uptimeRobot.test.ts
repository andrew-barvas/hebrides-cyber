import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  UPTIMEROBOT_API_BASE,
  UPTIMEROBOT_DEFAULT_INTERVAL_SECONDS,
  isUptimeRobotApiUrl,
  mapUptimeRobotStatus,
  parseUptimeRobotMonitor,
  uptimeRobotProvider,
} from "./uptimeRobot";
import { normaliseMonitorUrl } from "./uptimeProvider";

const KEY = "ur-test-key";

function json(body: unknown, init: { status?: number; headers?: Record<string, string> } = {}): Response {
  return new Response(JSON.stringify(body), { status: init.status ?? 200, headers: { "content-type": "application/json", ...init.headers } });
}

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("mapUptimeRobotStatus", () => {
  it.each([
    ["UP", "up"],
    ["up", "up"],
    ["DOWN", "down"],
    ["LOOKS_DOWN", "seems_down"],
    ["PAUSED", "paused"],
    ["STARTED", "unknown"],
    ["SOMETHING_NEW", "unknown"],
    ["", "unknown"],
    [undefined, "unknown"],
    [1, "unknown"],
  ])("%j -> %s", (raw, expected) => {
    expect(mapUptimeRobotStatus(raw)).toBe(expected);
  });
});

describe("parseUptimeRobotMonitor", () => {
  it("parses a monitor, stringifying the numeric id", () => {
    expect(
      parseUptimeRobotMonitor({ id: 801234, friendlyName: "Hebrides: shop.example.co.uk", url: "https://shop.example.co.uk", status: "UP", currentStateDuration: 3600.7 }),
    ).toEqual({
      externalId: "801234",
      name: "Hebrides: shop.example.co.uk",
      url: "https://shop.example.co.uk",
      status: "up",
      stateDurationSeconds: 3600,
    });
  });

  it("tolerates missing optional fields, and never reports up for them", () => {
    expect(parseUptimeRobotMonitor({ id: 1 })).toEqual({ externalId: "1", name: "", url: null, status: "unknown", stateDurationSeconds: null });
  });

  it.each([[null], ["x"], [{}], [{ id: null }], [{ friendlyName: "no id" }]])("rejects %j", (raw) => {
    expect(parseUptimeRobotMonitor(raw)).toBeNull();
  });

  it("ignores a negative or non-numeric duration", () => {
    expect(parseUptimeRobotMonitor({ id: 1, currentStateDuration: -5 })?.stateDurationSeconds).toBeNull();
    expect(parseUptimeRobotMonitor({ id: 1, currentStateDuration: "9" })?.stateDurationSeconds).toBeNull();
  });
});

describe("isUptimeRobotApiUrl", () => {
  it("accepts only https URLs on UptimeRobot's API host", () => {
    expect(isUptimeRobotApiUrl(`${UPTIMEROBOT_API_BASE}/monitors?cursor=5`)).toBe(true);
    expect(isUptimeRobotApiUrl("https://evil.example/v3/monitors")).toBe(false);
    expect(isUptimeRobotApiUrl("http://api.uptimerobot.com/v3/monitors")).toBe(false);
    expect(isUptimeRobotApiUrl("https://api.uptimerobot.com.evil.example/v3")).toBe(false);
    expect(isUptimeRobotApiUrl("not a url")).toBe(false);
  });
});

describe("validate", () => {
  it("sends the key as a bearer token to /user/me and succeeds on 200", async () => {
    fetchMock.mockResolvedValue(json({ email: "a@b.c" }));
    expect(await uptimeRobotProvider(KEY).validate()).toEqual({ ok: true, value: true });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(`${UPTIMEROBOT_API_BASE}/user/me`);
    expect(init.headers.Authorization).toBe(`Bearer ${KEY}`);
    expect(init.redirect).toBe("manual");
  });

  it.each([401, 403])("reports a rejected key for %i", async (status) => {
    fetchMock.mockResolvedValue(json({ code: "x" }, { status }));
    expect(await uptimeRobotProvider(KEY).validate()).toMatchObject({ ok: false, kind: "auth" });
  });

  it("reports rate limiting with Retry-After", async () => {
    fetchMock.mockResolvedValue(json({}, { status: 429, headers: { "retry-after": "42" } }));
    expect(await uptimeRobotProvider(KEY).validate()).toMatchObject({ ok: false, kind: "rate_limited", retryAfterSeconds: 42 });
  });

  it("defaults the retry delay when Retry-After is missing or junk", async () => {
    fetchMock.mockResolvedValue(json({}, { status: 429, headers: { "retry-after": "soon" } }));
    expect(await uptimeRobotProvider(KEY).validate()).toMatchObject({ kind: "rate_limited", retryAfterSeconds: 60 });
  });

  it("maps 5xx and network failures to unavailable, 4xx to invalid", async () => {
    fetchMock.mockResolvedValueOnce(json({}, { status: 503 }));
    expect(await uptimeRobotProvider(KEY).validate()).toMatchObject({ kind: "unavailable" });
    fetchMock.mockResolvedValueOnce(json({}, { status: 422 }));
    expect(await uptimeRobotProvider(KEY).validate()).toMatchObject({ kind: "invalid" });
    fetchMock.mockRejectedValueOnce(new Error("ECONNRESET"));
    expect(await uptimeRobotProvider(KEY).validate()).toMatchObject({ ok: false, kind: "unavailable" });
  });

  it("does not include the key in an error message", async () => {
    fetchMock.mockRejectedValue(new Error("boom"));
    const r = await uptimeRobotProvider(KEY).validate();
    expect(JSON.stringify(r)).not.toContain(KEY);
  });
});

describe("listMonitors", () => {
  const dto = (id: number, status: string, url = `https://s${id}.example`) => ({ id, friendlyName: `m${id}`, url, status });

  it("returns parsed monitors from one page", async () => {
    fetchMock.mockResolvedValue(json({ data: [dto(1, "UP"), dto(2, "DOWN")], nextLink: null }));
    const r = await uptimeRobotProvider(KEY).listMonitors();
    expect(r.ok && r.value.map((m) => [m.externalId, m.status])).toEqual([
      ["1", "up"],
      ["2", "down"],
    ]);
    expect(fetchMock.mock.calls[0][0]).toBe(`${UPTIMEROBOT_API_BASE}/monitors?limit=200`);
  });

  it("follows a bare cursor and a same-host absolute nextLink, capped at three pages", async () => {
    fetchMock
      .mockResolvedValueOnce(json({ data: [dto(1, "UP")], nextLink: "123" }))
      .mockResolvedValueOnce(json({ data: [dto(2, "UP")], nextLink: `${UPTIMEROBOT_API_BASE}/monitors?cursor=456` }))
      .mockResolvedValueOnce(json({ data: [dto(3, "UP")], nextLink: "789" }))
      .mockResolvedValueOnce(json({ data: [dto(4, "UP")], nextLink: null }));
    const r = await uptimeRobotProvider(KEY).listMonitors();
    expect(r.ok && r.value).toHaveLength(3);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[1][0]).toContain("cursor=123");
    expect(fetchMock.mock.calls[2][0]).toBe(`${UPTIMEROBOT_API_BASE}/monitors?cursor=456`);
  });

  it("refuses to follow a nextLink to another host, so the key is never sent there", async () => {
    fetchMock.mockResolvedValue(json({ data: [dto(1, "UP")], nextLink: "https://evil.example/steal" }));
    const r = await uptimeRobotProvider(KEY).listMonitors();
    expect(r).toMatchObject({ ok: false, kind: "unavailable" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("is an error, not an empty list, when the body is malformed", async () => {
    fetchMock.mockResolvedValue(json({ nope: true }));
    expect(await uptimeRobotProvider(KEY).listMonitors()).toMatchObject({ ok: false, kind: "unavailable" });
    fetchMock.mockResolvedValue(new Response("<html>", { status: 200 }));
    expect(await uptimeRobotProvider(KEY).listMonitors()).toMatchObject({ ok: false, kind: "unavailable" });
  });

  it("skips malformed entries but keeps the good ones", async () => {
    fetchMock.mockResolvedValue(json({ data: [dto(1, "UP"), { friendlyName: "no id" }, null], nextLink: null }));
    const r = await uptimeRobotProvider(KEY).listMonitors();
    expect(r.ok && r.value).toHaveLength(1);
  });

  it("returns the error from a failing later page rather than a partial list", async () => {
    fetchMock.mockResolvedValueOnce(json({ data: [dto(1, "UP")], nextLink: "9" })).mockResolvedValueOnce(json({}, { status: 429 }));
    expect(await uptimeRobotProvider(KEY).listMonitors()).toMatchObject({ ok: false, kind: "rate_limited" });
  });
});

describe("createMonitor", () => {
  it("posts an HTTP monitor with a 5-minute interval and returns it", async () => {
    fetchMock.mockResolvedValue(json({ id: 77, friendlyName: "Hebrides: shop.example.co.uk", url: "https://shop.example.co.uk", status: "STARTED" }, { status: 201 }));
    const r = await uptimeRobotProvider(KEY).createMonitor({ url: "https://shop.example.co.uk", name: "Hebrides: shop.example.co.uk" });
    expect(r.ok && r.value).toMatchObject({ externalId: "77", status: "unknown" });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(`${UPTIMEROBOT_API_BASE}/monitors`);
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual({
      type: "HTTP",
      friendlyName: "Hebrides: shop.example.co.uk",
      url: "https://shop.example.co.uk",
      interval: UPTIMEROBOT_DEFAULT_INTERVAL_SECONDS,
      timeout: 30,
    });
  });

  it("surfaces a plan-limit style refusal as invalid", async () => {
    fetchMock.mockResolvedValue(json({ code: "x", message: "monitor limit reached" }, { status: 400 }));
    expect(await uptimeRobotProvider(KEY).createMonitor({ url: "https://a.example", name: "n" })).toMatchObject({ ok: false, kind: "invalid" });
  });

  it("errors when the response has no id", async () => {
    fetchMock.mockResolvedValue(json({ status: "UP" }, { status: 201 }));
    expect(await uptimeRobotProvider(KEY).createMonitor({ url: "https://a.example", name: "n" })).toMatchObject({ ok: false, kind: "unavailable" });
  });

  it("truncates a very long name", async () => {
    fetchMock.mockResolvedValue(json({ id: 1 }, { status: 201 }));
    await uptimeRobotProvider(KEY).createMonitor({ url: "https://a.example", name: "x".repeat(500) });
    expect(JSON.parse(fetchMock.mock.calls[0][1].body).friendlyName).toHaveLength(120);
  });
});

describe("normaliseMonitorUrl", () => {
  it("compares URLs the way a person would", () => {
    expect(normaliseMonitorUrl("https://Shop.Example.co.uk/")).toBe("https://shop.example.co.uk");
    expect(normaliseMonitorUrl("https://shop.example.co.uk")).toBe("https://shop.example.co.uk");
    expect(normaliseMonitorUrl("https://shop.example.co.uk/path/#frag")).toBe("https://shop.example.co.uk/path");
    expect(normaliseMonitorUrl("http://a.example:8080/x?y=1")).toBe("http://a.example:8080/x?y=1");
  });
  it("rejects non-http(s) and junk", () => {
    expect(normaliseMonitorUrl("ftp://a.example")).toBeNull();
    expect(normaliseMonitorUrl("javascript:alert(1)")).toBeNull();
    expect(normaliseMonitorUrl("nope")).toBeNull();
  });
});
