// Browser side of the executive report: calls GET /api/generate-report, which
// answers with the PDF bytes, or (when Azure Blob Storage is configured) a JSON
// body holding a one-hour download URL. Kept apart from the page component so
// both shapes and the failure path are unit-tested.

export type ExecutiveReportDownload = { kind: "pdf"; blob: Blob } | { kind: "url"; url: string };

export async function fetchExecutiveReport(scanId: string, token: string): Promise<ExecutiveReportDownload> {
  const res = await fetch(`/api/generate-report?scan_id=${encodeURIComponent(scanId)}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) {
    const message = res.status === 429 ? "Too many report requests — try again in a few minutes." : `The report could not be generated (${res.status}).`;
    throw new Error(message);
  }
  if ((res.headers.get("content-type") ?? "").includes("application/json")) {
    const body = (await res.json()) as { url?: string };
    if (!body.url) throw new Error("The report service returned no download link.");
    return { kind: "url", url: body.url };
  }
  return { kind: "pdf", blob: await res.blob() };
}
