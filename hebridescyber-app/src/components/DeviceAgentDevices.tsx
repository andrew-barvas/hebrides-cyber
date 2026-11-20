"use client";

import { useCallback, useEffect, useId, useState } from "react";
import { Laptop } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { Alert } from "@/components/ui/alert";
import { EmptyState } from "@/components/ui/empty-state";
import { cn } from "@/lib/utils";

type PatchItem = {
  kind: string;
  key: string;
  title: string;
  severity: string | null;
  since: string | null;
  sinceBasis: string | null;
  dueBy: string | null;
  overdue: boolean;
  detail: string | null;
};

type Device = {
  id: string;
  name: string;
  token_prefix: string;
  created_at: string;
  revoked_at: string | null;
  last_seen_at: string | null;
  hostname: string | null;
  os: { family: string | null; name: string | null; version: string | null };
  agent_version: string | null;
  status: "passes" | "at_risk" | "fails" | "unknown" | "stale" | "never_reported" | "revoked";
  evaluation: { summary?: string; overdue?: PatchItem[]; dueSoon?: PatchItem[]; gaps?: string[] } | null;
  match: { cve_count: number; os_eol: { cycle: string; state: string; eolDate: string | null } | null; coverage: { softwareTotal: number; softwareChecked: number } | null } | null;
  matched_at: string | null;
};

export const STATUS_LABELS: Record<Device["status"], { label: string; tone: string }> = {
  fails: { label: "Misses 14-day rule", tone: "border-danger/40 bg-danger/10 text-danger" },
  at_risk: { label: "Updates due", tone: "border-warning/40 bg-warning/10 text-warning" },
  passes: { label: "Meets 14-day rule", tone: "border-neon/40 bg-neon/10 text-neon" },
  unknown: { label: "Not enough evidence", tone: "border-cyberborder text-cybermuted" },
  stale: { label: "No recent report", tone: "border-warning/40 text-warning" },
  never_reported: { label: "Waiting for first report", tone: "border-cyberborder text-cybermuted" },
  revoked: { label: "Revoked", tone: "border-cyberborder text-cybermuted" },
};

const BASIS: Record<string, string> = {
  vendor_release: "released",
  first_reported: "first reported by this device",
  cve_published: "CVE published",
  end_of_life: "end of support",
};

function date(iso: string | null) {
  return iso ? new Date(iso).toLocaleDateString("en-GB") : "never";
}

/** Install commands for a freshly issued token. */
export function installCommands(token: string): { label: string; command: string }[] {
  return [
    { label: "Windows (PowerShell, as Administrator)", command: `.\\hebrides-agent.exe enrol --token ${token}; .\\hebrides-agent.exe report` },
    { label: "macOS / Linux (as root)", command: `sudo ./hebrides-agent enrol --token ${token} && sudo ./hebrides-agent report` },
  ];
}

function ItemList({ items, heading }: { items: PatchItem[]; heading: string }) {
  if (items.length === 0) return null;
  return (
    <div>
      <p className="mb-1 font-mono text-xs uppercase tracking-wide text-cybermuted">{heading}</p>
      <ul className="space-y-1 text-xs">
        {items.slice(0, 20).map((i) => (
          <li key={i.key} className="leading-relaxed">
            <span className={i.overdue ? "text-danger" : "text-cybertext"}>{i.title}</span>
            {i.severity && <span className="text-cybermuted"> · {i.severity}</span>}
            {i.since && (
              <span className="text-cybermuted">
                {" "}
                · {BASIS[i.sinceBasis ?? ""] ?? "since"} {i.since}
                {i.dueBy && i.kind !== "unsupported_os" ? `, due by ${i.dueBy}` : ""}
              </span>
            )}
            {i.detail && <span className="block text-cybermuted">{i.detail}</span>}
          </li>
        ))}
        {items.length > 20 && <li className="text-cybermuted">…and {items.length - 20} more</li>}
      </ul>
    </div>
  );
}

function DeviceRow({ device, onRevoke }: { device: Device; onRevoke: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const s = STATUS_LABELS[device.status];
  const ev = device.evaluation;
  const os = [device.os.name, device.os.version].filter(Boolean).join(" ");
  return (
    <li className="rounded-lg border border-cyberborder bg-cyberbg p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-medium text-cybertext">{device.name}</p>
          <p className="text-xs text-cybermuted">
            {device.hostname ?? "—"} · {os || "OS not reported yet"} · last report {date(device.last_seen_at)}
          </p>
          {ev?.summary && device.status !== "revoked" && <p className="mt-1 text-xs text-cybertext">{ev.summary}</p>}
        </div>
        <div className="flex items-center gap-2">
          <span className={cn("rounded-full border px-2 py-0.5 text-xs font-medium", s.tone)}>{s.label}</span>
          {ev && (
            <Button size="sm" variant="ghost" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
              {open ? "Hide" : "Details"}
            </Button>
          )}
          {!device.revoked_at && (
            <Button size="sm" variant="danger" onClick={() => onRevoke(device.id)}>
              Revoke
            </Button>
          )}
        </div>
      </div>
      {open && ev && (
        <div className="mt-3 space-y-3 border-t border-cyberborder pt-3">
          <ItemList items={ev.overdue ?? []} heading="Overdue" />
          <ItemList items={ev.dueSoon ?? []} heading="Due within 14 days" />
          {(ev.gaps?.length ?? 0) > 0 && (
            <div>
              <p className="mb-1 font-mono text-xs uppercase tracking-wide text-cybermuted">What&apos;s missing</p>
              <ul className="list-disc space-y-0.5 pl-4 text-xs text-cybermuted">
                {ev.gaps!.map((g) => (
                  <li key={g}>{g}</li>
                ))}
              </ul>
            </div>
          )}
          {device.match && (
            <p className="text-xs text-cybermuted">
              {device.match.cve_count} known CVE{device.match.cve_count === 1 ? "" : "s"} in installed software
              {device.match.coverage ? ` (${device.match.coverage.softwareChecked} of ${device.match.coverage.softwareTotal} packages and programs could be checked)` : ""}
              {device.match.os_eol ? ` · OS cycle ${device.match.os_eol.cycle}: ${device.match.os_eol.state}` : ""} · matched {date(device.matched_at)}
            </p>
          )}
          <p className="text-xs text-cybermuted">
            Agent {device.agent_version ?? "—"} · token {device.token_prefix}… · added {date(device.created_at)}
          </p>
        </div>
      )}
    </li>
  );
}

export default function DeviceAgentDevices({ token }: { token: string | null }) {
  const fieldId = useId();
  const [devices, setDevices] = useState<Device[]>([]);
  const [enabled, setEnabled] = useState(true);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Held in state only: the server can't return it again.
  const [fresh, setFresh] = useState<{ name: string; token: string } | null>(null);
  const [showRevoked, setShowRevoked] = useState(false);

  const load = useCallback(async () => {
    if (!token) return;
    try {
      const res = await fetch("/api/agent/devices", { headers: { Authorization: `Bearer ${token}` } });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not load devices");
      setDevices(body.devices ?? []);
      setEnabled(body.enabled !== false);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    load();
  }, [load]);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!token) return;
    setCreating(true);
    setError(null);
    try {
      const res = await fetch("/api/agent/devices", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not add the device");
      setFresh({ name: body.name, token: body.token });
      setName("");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setCreating(false);
    }
  }

  async function revoke(id: string) {
    if (!token) return;
    setError(null);
    try {
      const res = await fetch("/api/agent/devices", {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not revoke the device");
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const active = devices.filter((d) => !d.revoked_at);
  const revoked = devices.filter((d) => d.revoked_at);
  const failing = active.filter((d) => d.status === "fails").length;

  return (
    <div className="space-y-5">
      {!enabled && <Alert variant="warning" title="Not enabled yet">Device reporting needs a database update on this server.</Alert>}
      {error && <Alert variant="danger">{error}</Alert>}

      <form onSubmit={create} className="flex flex-wrap items-end gap-2 rounded-xl border border-cyberborder bg-cyberpanel p-4">
        <div className="min-w-56 flex-1">
          <Label htmlFor={fieldId}>Device name</Label>
          <Input id={fieldId} value={name} onChange={(e) => setName(e.target.value)} maxLength={80} placeholder="Reception PC" />
        </div>
        <Button type="submit" disabled={creating || !name.trim() || !token}>
          {creating ? "Adding…" : "Add device"}
        </Button>
      </form>

      {fresh && (
        <Alert variant="success" title={`Token for ${fresh.name}: shown once`}>
          <p className="text-xs text-cybermuted">Copy it now. It isn&apos;t stored, so it can&apos;t be shown again; revoke the device and add it again if it&apos;s lost.</p>
          <code className="mt-2 block break-all rounded-md border border-cyberborder bg-cyberbg p-2 font-mono text-xs text-neon">{fresh.token}</code>
          {installCommands(fresh.token).map((c) => (
            <div key={c.label} className="mt-2">
              <p className="text-xs text-cybermuted">{c.label}</p>
              <code className="block break-all rounded-md border border-cyberborder bg-cyberbg p-2 font-mono text-xs text-cybertext">{c.command}</code>
            </div>
          ))}
          <Button size="sm" variant="ghost" className="mt-2" onClick={() => setFresh(null)}>
            I&apos;ve copied it
          </Button>
        </Alert>
      )}

      {loading ? (
        <p className="text-sm text-cybermuted">Loading devices…</p>
      ) : active.length === 0 ? (
        <EmptyState
          icon={<Laptop />}
          title="No devices yet"
          description="Add a device, then run the agent on it. It reports the OS version, installed software and pending updates once a day, and never scans your network."
        />
      ) : (
        <section aria-label="Devices">
          <p className="mb-2 text-sm text-cybermuted">
            {active.length} device{active.length === 1 ? "" : "s"}
            {failing > 0 ? `, ${failing} missing the 14-day patch rule` : ""}.
          </p>
          <ul className="space-y-2">
            {active.map((d) => (
              <DeviceRow key={d.id} device={d} onRevoke={revoke} />
            ))}
          </ul>
        </section>
      )}

      {revoked.length > 0 && (
        <div>
          <Button size="sm" variant="ghost" onClick={() => setShowRevoked((v) => !v)} aria-expanded={showRevoked}>
            {showRevoked ? "Hide" : "Show"} {revoked.length} revoked
          </Button>
          {showRevoked && (
            <ul className="mt-2 space-y-2">
              {revoked.map((d) => (
                <DeviceRow key={d.id} device={d} onRevoke={revoke} />
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
