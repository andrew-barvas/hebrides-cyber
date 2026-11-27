// The customer's own evidence, gathered once per questionnaire draft. Every
// source is the customer's: their scans and open findings, their Microsoft
// 365 / Google Workspace checks, their Cyber Essentials self-assessment, their
// enrolled devices, and the documents on their public security profile.
// Nothing here is shared between customers.
//
// Each source degrades to "absent" when its table doesn't exist yet or the
// read fails, so a missing source leaves questions as "Needs your answer"
// rather than failing the whole draft. A failed read is never "clean"
// (CLAUDE.md rule 7): absent evidence can't produce a "Yes".
import type { SupabaseClient } from "@supabase/supabase-js";
import type { CeAnswerValue } from "../ceSelfAssessment";
import { displayStatus } from "../deviceAgent/patchRule";
import { hostOf } from "../findingLifecycle";
import { loadFindingsView, type FindingRow } from "../findingsView";
import type { DocumentKind } from "../trustDocumentKinds";

export type EvidenceFinding = Pick<FindingRow, "host" | "checkId" | "title" | "knownExploited">;

/** One scanned site's latest completed scan. `evaluated` says which checks actually ran. */
export type SiteEvidence = {
  host: string;
  lastScanAt: string;
  score: number | null;
  evaluated: { tls: boolean; dns: boolean; ports: boolean; hibp: boolean };
};

export type DeclaredAnswer = { questionKey: string; answer: CeAnswerValue; updatedAt: string | null };

export type DeviceEvidence = {
  /** Active (not revoked) devices. */
  total: number;
  /** Reported within the staleness window. */
  reporting: number;
  passes: number;
  atRisk: number;
  fails: number;
  /** Devices whose operating system is past its end of life. */
  unsupportedOs: number;
  lastSeenAt: string | null;
};

export type DocumentEvidence = { kind: DocumentKind; title: string; uploadedAt: string; host: string };

export type EvidenceFacts = {
  /** Open findings across every site, false positives left out. */
  findings: EvidenceFinding[];
  /** Newest first. */
  sites: SiteEvidence[];
  m365CheckedAt: string | null;
  workspaceCheckedAt: string | null;
  declared: DeclaredAnswer[];
  devices: DeviceEvidence | null;
  documents: DocumentEvidence[];
  /** Hosts with a published public security profile. */
  profileHosts: string[];
};

export const EMPTY_FACTS: EvidenceFacts = {
  findings: [],
  sites: [],
  m365CheckedAt: null,
  workspaceCheckedAt: null,
  declared: [],
  devices: null,
  documents: [],
  profileHosts: [],
};

const MAX_SITES = 10;

type DeviceRow = { revoked_at: string | null; last_seen_at: string | null; patch_status: string; last_match: { osEol?: { state?: string } | null } | null };

/** Pure: the device summary from agent_devices rows. Null when no device was ever enrolled. */
export function summariseDevices(rows: DeviceRow[], now: Date): DeviceEvidence | null {
  const active = rows.filter((r) => !r.revoked_at);
  if (!active.length) return null;
  const out: DeviceEvidence = { total: active.length, reporting: 0, passes: 0, atRisk: 0, fails: 0, unsupportedOs: 0, lastSeenAt: null };
  for (const r of active) {
    const status = displayStatus(r.patch_status, r.last_seen_at, now);
    if (status === "never_reported" || status === "stale") continue;
    out.reporting++;
    if (status === "passes") out.passes++;
    else if (status === "at_risk") out.atRisk++;
    else if (status === "fails") out.fails++;
    if (r.last_match?.osEol?.state === "unsupported") out.unsupportedOs++;
    if (r.last_seen_at && (!out.lastSeenAt || r.last_seen_at > out.lastSeenAt)) out.lastSeenAt = r.last_seen_at;
  }
  return out;
}

type ResultRow = { scan_id: string; score: number | null; created_at: string; tls: string | null; dns: string | null; ports: string | null; hibp: string | null };

/** Load the customer's evidence. Never throws; a source that can't be read is left out. */
export async function loadEvidenceFacts(supabaseAdmin: SupabaseClient, ownerId: string, now: Date = new Date()): Promise<EvidenceFacts> {
  const [view, scans, m365, workspace, declared, devices, documents, profiles] = await Promise.all([
    loadFindingsView(supabaseAdmin, ownerId, now).catch(() => null),
    supabaseAdmin.from("scans").select("id, target_url, created_at").eq("owner", ownerId).eq("status", "completed").order("created_at", { ascending: false }).limit(200),
    supabaseAdmin.from("m365_tenants").select("last_checked_at").eq("owner", ownerId).order("last_checked_at", { ascending: false }).limit(1).maybeSingle(),
    supabaseAdmin.from("workspace_connections").select("last_checked_at").eq("owner", ownerId).maybeSingle(),
    supabaseAdmin.from("ce_self_assessment").select("question_key, answer, updated_at").eq("owner", ownerId),
    supabaseAdmin.from("agent_devices").select("revoked_at, last_seen_at, patch_status, last_match").eq("owner", ownerId),
    supabaseAdmin.from("trust_documents").select("kind, title, uploaded_at, target_host").eq("owner", ownerId).is("deleted_at", null),
    supabaseAdmin.from("security_profiles").select("target_host").eq("owner", ownerId),
  ]);

  // Latest completed scan per host, newest hosts first.
  const latest = new Map<string, { id: string; created_at: string }>();
  for (const s of (scans.error ? [] : (scans.data ?? [])) as Array<{ id: string; target_url: string; created_at: string }>) {
    const host = hostOf(s.target_url);
    if (host && !latest.has(host) && latest.size < MAX_SITES) latest.set(host, { id: s.id, created_at: s.created_at });
  }
  let sites: SiteEvidence[] = [];
  if (latest.size) {
    const { data, error } = await supabaseAdmin
      .from("scan_results")
      .select("scan_id, score, created_at, tls:results->tls->>status, dns:results->dns->>status, ports:results->ports->>status, hibp:results->hibp->>status")
      .in("scan_id", [...latest.values()].map((s) => s.id));
    const byScan = new Map(((error ? [] : (data ?? [])) as unknown as ResultRow[]).map((r) => [r.scan_id, r]));
    sites = [...latest].flatMap(([host, scan]) => {
      const r = byScan.get(scan.id);
      if (!r) return [];
      return [{
        host,
        lastScanAt: scan.created_at,
        score: typeof r.score === "number" ? r.score : null,
        evaluated: { tls: r.tls === "checked", dns: r.dns === "checked", ports: r.ports === "checked", hibp: r.hibp === "checked" },
      }];
    });
  }

  const findings: EvidenceFinding[] =
    view && view.ok
      ? view.data.rows.filter((r) => r.triage?.state !== "false_positive").map((r) => ({ host: r.host, checkId: r.checkId, title: r.title, knownExploited: r.knownExploited }))
      : [];
  const lastChecked = (res: { data: unknown; error: unknown }) => (res.error ? null : ((res.data as { last_checked_at?: string | null } | null)?.last_checked_at ?? null));

  return {
    findings,
    sites,
    m365CheckedAt: lastChecked(m365),
    workspaceCheckedAt: lastChecked(workspace),
    declared: declared.error
      ? []
      : ((declared.data ?? []) as Array<{ question_key: string; answer: CeAnswerValue; updated_at: string | null }>).map((a) => ({ questionKey: a.question_key, answer: a.answer, updatedAt: a.updated_at })),
    devices: devices.error ? null : summariseDevices((devices.data ?? []) as DeviceRow[], now),
    documents: documents.error
      ? []
      : ((documents.data ?? []) as Array<{ kind: DocumentKind; title: string; uploaded_at: string; target_host: string }>).map((d) => ({ kind: d.kind, title: d.title, uploadedAt: d.uploaded_at, host: d.target_host })),
    profileHosts: profiles.error ? [] : ((profiles.data ?? []) as Array<{ target_host: string }>).map((p) => p.target_host),
  };
}
