// Admin: per-tool kill switches. GET lists every extended-scan tool with
// its current enabled/disabled state (an absent row means enabled — the
// default); PATCH flips one tool. The scan worker reads the same
// tool_kill_switches table (migration 055) and skips any disabled tool on
// every scan — see src/lib/toolKillSwitch.ts. Every change is audited.
import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { logAuditEvent } from "@/lib/audit";
import { EXTENDED_TOOL_NAMES } from "@/lib/scanProfiles";
import { parseDisabledTools, type KillSwitchRow } from "@/lib/toolKillSwitch";

const TOOL_NAME_SET = new Set<string>(EXTENDED_TOOL_NAMES);

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin.from("tool_kill_switches").select("tool_name, disabled");
    if (error) return res.status(500).json({ error: error.message });
    const disabled = parseDisabledTools((data as KillSwitchRow[] | null) ?? []);
    // One entry per known tool, so the UI shows the full list; an absent row
    // is reported as enabled (the default).
    const tools = EXTENDED_TOOL_NAMES.map((name) => ({ tool: name, disabled: disabled.has(name) }));
    return res.status(200).json({ tools });
  }

  if (req.method === "PATCH") {
    const tool = typeof req.body?.tool === "string" ? req.body.tool : "";
    const disabled = req.body?.disabled;
    if (!TOOL_NAME_SET.has(tool)) return res.status(400).json({ error: "Unknown tool" });
    if (typeof disabled !== "boolean") return res.status(400).json({ error: "disabled must be a boolean" });

    const { error } = await supabaseAdmin.from("tool_kill_switches").upsert(
      { tool_name: tool, disabled, updated_by: adminId, updated_at: new Date().toISOString() },
      { onConflict: "tool_name" }
    );
    if (error) return res.status(500).json({ error: error.message });

    await logAuditEvent(supabaseAdmin, {
      actorId: adminId,
      action: disabled ? "admin.tool_disabled" : "admin.tool_enabled",
      resourceType: "scan_tool",
      resourceId: tool,
    });
    return res.status(200).json({ ok: true });
  }

  res.setHeader("Allow", "GET, PATCH");
  return res.status(405).end();
}
