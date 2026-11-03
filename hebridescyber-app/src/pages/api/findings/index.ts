// GET /api/findings — every open finding across the caller's sites (E-74),
// filterable, groupable by check and paginated. Session or API key; always
// the caller's own account. All logic is in src/lib/findingsView.ts.
//
//   ?view=grouped|rows  (default grouped: one entry per checkId base)
//   &site=<host> &severity=critical,high &kev=1 &epssMin=0.1 &category=headers
//   &triage=open|triaged|all|accepted_risk|false_positive|snoozed (default open)
//   &sla=breached|due_soon|on_track &minAgeDays=30 &page=1 &pageSize=50
//   &format=csv  — the whole filtered list as a download (no paging)
//   &sort=priority  — the estate "fix this first" rank (estatePriority.ts):
//                 open, untriaged, non-info findings only, most urgent first,
//                 each row carrying `priority` { rank, score, factors, reason }.
//                 Defaults to view=rows. Also served as GET /api/v1/findings.
//
// Triage is written through the existing bulk PUT /api/findings/triage, not
// here. Before migration 043 this answers { available: false }; before 046
// nothing is triaged and `triageAvailable` is false.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { buildHostSignals, loadTargetContexts, rankFindings, type PrioritisedFinding } from "@/lib/estatePriority";
import {
  applyFilters,
  buildFacets,
  compareFindings,
  findingsToCsv,
  groupFindings,
  type FindingRow,
  loadFindingsView,
  paginate,
  parseFindingsQuery,
} from "@/lib/findingsView";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Unauthorized" });

  return respondWithFindings(req, res, caller.ownerId);
}

/** The list itself, for an already-authenticated owner — shared with
 *  GET /api/v1/findings so the two paths can't drift. */
export async function respondWithFindings(req: NextApiRequest, res: NextApiResponse, ownerId: string) {
  const query = parseFindingsQuery(req.query);
  const [loaded, targets] = await Promise.all([
    loadFindingsView(supabaseAdmin, ownerId),
    query.sort === "priority" ? loadTargetContexts(supabaseAdmin, ownerId) : null,
  ]);
  if (!loaded.ok) return res.status(500).json({ error: loaded.error });
  const { data } = loaded;

  const matching = applyFilters(data.rows, query.filters);
  // Ranked rows keep every findingsView field, so CSV, grouping and paging
  // below work on either order.
  const filtered: Array<FindingRow | PrioritisedFinding> = targets
    ? rankFindings(matching, targets.contexts, buildHostSignals(data.detailByHost))
    : matching.sort(compareFindings);

  if (query.format === "csv") {
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="open-findings.csv"');
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(findingsToCsv(filtered, { priority: targets !== null }));
  }

  const common = {
    available: data.available,
    triageAvailable: data.triageAvailable,
    slaEnabled: data.slaEnabled,
    detailComplete: data.detailComplete,
    truncated: data.truncated,
    facets: buildFacets(data.rows),
    sort: query.sort,
    // Priority only: false before migration 067 (every site ranks as normal
    // criticality); priorityComplete false if criticality or scan detail
    // couldn't be read.
    ...(targets ? { criticalityAvailable: targets.available, priorityComplete: targets.complete && data.detailComplete } : {}),
    view: query.view,
    totalFindings: filtered.length,
  };

  if (query.view === "rows") {
    const page = paginate(filtered, query.page, query.pageSize);
    return res.status(200).json({ ...common, ...page, groups: [] });
  }
  const groups = groupFindings(filtered);
  if (targets) {
    // Most urgent group = the one holding the best-ranked finding.
    const best = (g: (typeof groups)[number]) => Math.min(...g.rows.map((r) => (r as PrioritisedFinding).priority.rank));
    groups.sort((a, b) => best(a) - best(b));
  }
  const page = paginate(groups, query.page, query.pageSize);
  return res.status(200).json({ ...common, ...page, items: [], groups: page.items });
}
