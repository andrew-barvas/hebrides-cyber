import { describe, it, expect, vi } from "vitest";
import type { HttpProbeRecord } from "./scanners/hostProbe";
import { captureEstateScreenshots, isScreenshotFileName, screenshotBlobName, selectScreenshotTargets } from "./estateScreenshots";

const rec = (host: string, statusCode = 200, url = `https://${host}/`): HttpProbeRecord =>
  ({ input: host, url, host, port: "443", scheme: "https", statusCode, contentLength: 1, title: null } as HttpProbeRecord);

describe("selectScreenshotTargets", () => {
  it("takes live hosts once each, sorted, skipping the scanned host and error pages, up to the cap", () => {
    const targets = selectScreenshotTargets(
      [rec("www.example.com"), rec("b.example.com"), rec("a.example.com"), rec("a.example.com"), rec("down.example.com", 503), rec("redir.example.com", 301), rec("odd.example.com", 200, "ftp://odd")],
      "https://www.example.com/",
      10
    );
    expect(targets.map((t) => t.host)).toEqual(["a.example.com", "b.example.com", "redir.example.com"]);
    expect(selectScreenshotTargets([rec("a.x"), rec("b.x"), rec("c.x")], "https://y", 2)).toHaveLength(2);
  });
});

describe("blob names and file names", () => {
  it("files each screenshot under the owner and scan, with a safe host name", () => {
    expect(screenshotBlobName("owner-1", "scan-1", "Shop.Example.com")).toBe("owner-1/scan-1/shop.example.com.jpg");
    expect(screenshotBlobName("o", "s", "weird/../host:8443")).toBe("o/s/weird-..-host-8443.jpg");
  });

  it("serves only plain .jpg names, never a path", () => {
    expect(isScreenshotFileName("shop.example.com.jpg")).toBe(true);
    for (const bad of ["../other/x.jpg", "a/b.jpg", "x.png", "..jpg", "A.JPG", ""]) expect(isScreenshotFileName(bad), bad).toBe(false);
  });
});

describe("captureEstateScreenshots", () => {
  it("uploads each capture under its blob name and counts failures without stopping", async () => {
    const upload = vi.fn(async () => undefined);
    const capture = vi.fn(async (url: string) => {
      if (url.includes("broken")) throw new Error("timeout");
      if (url.includes("huge")) return Buffer.alloc(300_000);
      return Buffer.from([0xff, 0xd8]);
    });
    const result = await captureEstateScreenshots("o", "s", [
      { host: "a.example.com", url: "https://a.example.com/" },
      { host: "broken.example.com", url: "https://broken.example.com/" },
      { host: "huge.example.com", url: "https://huge.example.com/" },
    ], { capture, upload });
    expect(result).toEqual({ captured: ["a.example.com"], failed: 2 });
    expect(upload).toHaveBeenCalledTimes(1);
    expect(upload).toHaveBeenCalledWith("o/s/a.example.com.jpg", expect.any(Buffer));
  });
});
