"use client";

// The agency "current client" picker in the app shell header. A native
// <select> keeps it keyboard- and screen-reader-friendly with many clients.

import { cn } from "@/lib/utils";
import { SCOPE_ALL, SCOPE_UNASSIGNED, type ClientScope, type ClientSummary } from "@/lib/clientRollup";

type Props = {
  clients: ClientSummary[];
  value: ClientScope;
  onChange: (scope: ClientScope) => void;
  className?: string;
};

export default function ClientSwitcher({ clients, value, onChange, className }: Props) {
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <label htmlFor="client-switcher" className="font-mono text-xs uppercase tracking-wide text-cybermuted">
        // client
      </label>
      <select
        id="client-switcher"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-md border border-cyberborder bg-cyberpanel px-2.5 py-1.5 text-sm text-cybertext focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-neon"
      >
        <option value={SCOPE_ALL}>All clients</option>
        {clients.map((c) => (
          <option key={c.id} value={c.id}>
            {c.name}
          </option>
        ))}
        <option value={SCOPE_UNASSIGNED}>Unassigned</option>
      </select>
    </div>
  );
}
