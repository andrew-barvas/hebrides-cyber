// GET /api/findings — every open finding across the caller's sites (E-74),
// filterable, groupable by check and paginated. Session or API key; always
// the caller's own account. All logic is in src/lib/findingsView.ts.
//
//   ?view=grouped|rows  (default grouped: one entry per checkId base)
//   &site=<host> &severity=critical,high &kev=1 &epssMin=0.1 &category=headers
//   &triage=open|triaged|all|accepted_risk|false_positive|snoozed (default open)
//   &sla=breached|due_soon|on_track &minAgeDays=30 &page=1 &pageSize=50
//   &format=csv  — the whole filtered list as a download (no paging)
//
// Triage is written through the existing bulk PUT /api/findings/triage, not
// here. Before migration 043 this answers { available: false }; before 046
// nothing is triaged and `triageAvailable` is false.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import {
  applyFilters,
  buildFacets,
  compareFindings,
  findingsToCsv,
  groupFindings,
  loadFindingsView,
  paginate,
  parseFindingsQuery,
} from "@/lib/findingsView";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Unauthorized" });

  const loaded = await loadFindingsView(supabaseAdmin, caller.ownerId);
  if (!loaded.ok) return res.status(500).json({ error: loaded.error });
  const { data } = loaded;

  const query = parseFindingsQuery(req.query);
  const filtered = applyFilters(data.rows, query.filters).sort(compareFindings);

  if (query.format === "csv") {
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="open-findings.csv"');
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(findingsToCsv(filtered));
  }

  const common = {
    available: data.available,
    triageAvailable: data.triageAvailable,
    slaEnabled: data.slaEnabled,
    detailComplete: data.detailComplete,
    truncated: data.truncated,
    facets: buildFacets(data.rows),
    view: query.view,
    totalFindings: filtered.length,
  };

  if (query.view === "rows") {
    const page = paginate(filtered, query.page, query.pageSize);
    return res.status(200).json({ ...common, ...page, groups: [] });
  }
  const groups = groupFindings(filtered);
  const page = paginate(groups, query.page, query.pageSize);
  return res.status(200).json({ ...common, ...page, items: [], groups: page.items });
}
