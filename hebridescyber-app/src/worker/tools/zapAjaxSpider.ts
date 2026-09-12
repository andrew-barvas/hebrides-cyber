// ZAP AJAX Spider integration — JavaScript-aware crawling for SPAs.
//
// The traditional ZAP spider (zap.ts) follows HTML links but misses
// client-side-rendered routes and API calls made by JavaScript. The
// AJAX spider uses a headless browser to discover these. Results are
// merged with the traditional spider's URL list and fed into the
// active scan phase.
//
// Requires the same running ZAP daemon as zap.ts. When ZAP_API_URL
// is not set, returns { status: "not_configured" }.

const ZAP_AJAX_SPIDER_POLL_MS = 10_000;
const ZAP_AJAX_SPIDER_TIMEOUT_MS = 300_000;

export type AjaxSpiderResult =
  | { status: "completed"; urls: string[] }
  | { status: "not_configured" }
  | { status: "error"; note: string };

async function zapGet<T>(
  base: string,
  path: string,
  apiKey: string
): Promise<T> {
  const sep = path.includes("?") ? "&" : "?";
  const res = await fetch(
    `${base}${path}${sep}apikey=${encodeURIComponent(apiKey)}`,
    { signal: AbortSignal.timeout(15_000) }
  );
  if (!res.ok) {
    throw new Error(`ZAP responded ${res.status} for ${path}`);
  }
  return res.json() as Promise<T>;
}

async function zapPost<T>(
  base: string,
  path: string,
  body: Record<string, string>,
  apiKey: string
): Promise<T> {
  const params = new URLSearchParams({ ...body, apikey: apiKey });
  const res = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) {
    throw new Error(`ZAP responded ${res.status} for ${path}`);
  }
  return res.json() as Promise<T>;
}

export async function runZapAjaxSpider(targetUrl: string): Promise<AjaxSpiderResult> {
  const zapApiUrl = process.env.ZAP_API_URL;
  const zapApiKey = process.env.ZAP_API_KEY ?? "changeme";

  if (!zapApiUrl) {
    return { status: "not_configured" };
  }

  try {
    await zapPost<{ scan: string }>(
      zapApiUrl,
      "/JSON/ajaxSpider/action/scan/",
      { url: targetUrl, inScope: "true" },
      zapApiKey
    );

    const deadline = Date.now() + ZAP_AJAX_SPIDER_TIMEOUT_MS;
    while (Date.now() < deadline) {
      const statusResp = await zapGet<{ status: string }>(
        zapApiUrl,
        "/JSON/ajaxSpider/view/status/",
        zapApiKey
      );
      if (statusResp.status === "stopped") break;
      await new Promise((r) => setTimeout(r, ZAP_AJAX_SPIDER_POLL_MS));
    }

    const resultsResp = await zapGet<{ results: Array<{ requestHeader?: string; url?: string }> }>(
      zapApiUrl,
      "/JSON/ajaxSpider/view/results/?start=0&count=500",
      zapApiKey
    );

    const urls = new Set<string>();
    for (const result of resultsResp.results ?? []) {
      if (result.url) urls.add(result.url);
    }

    return { status: "completed", urls: [...urls] };
  } catch (err) {
    return {
      status: "error",
      note: `ZAP AJAX Spider failed: ${(err as Error).message}`,
    };
  }
}
