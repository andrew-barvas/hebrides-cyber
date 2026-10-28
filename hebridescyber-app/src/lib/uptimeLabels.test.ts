import { describe, expect, it } from "vitest";
import { uptimeStatusLabel } from "./uptimeLabels";

describe("uptimeStatusLabel", () => {
  it.each([
    ["up", "Up"],
    ["down", "Down"],
    ["seems_down", "Seems down"],
    ["paused", "Paused"],
    ["unknown", "Waiting for first check"],
  ] as const)("%s reads as %s", (status, text) => {
    expect(uptimeStatusLabel(status).text).toBe(text);
  });

  it("treats no status, or one it does not recognise, as waiting rather than up", () => {
    expect(uptimeStatusLabel(null).text).toBe("Waiting for first check");
    expect(uptimeStatusLabel(undefined).text).toBe("Waiting for first check");
    expect(uptimeStatusLabel("sideways" as never).text).toBe("Waiting for first check");
  });

  it("never shows a stale status for a monitor the last sync did not find", () => {
    expect(uptimeStatusLabel("up", true)).toEqual({ text: "Not found in UptimeRobot", className: "text-warning" });
    expect(uptimeStatusLabel("down", true).text).toBe("Not found in UptimeRobot");
  });
});
