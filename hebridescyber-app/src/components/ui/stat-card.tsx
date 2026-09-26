import * as React from "react";
import { cn } from "@/lib/utils";

const TONE = {
  default: "text-cybertext",
  brand: "text-neon",
  danger: "text-danger",
  warning: "text-warning",
  muted: "text-cybermuted",
} as const;

type StatCardProps = {
  label: string;
  value: React.ReactNode;
  /** Unit or denominator shown small after the value, e.g. "/100". */
  suffix?: string;
  hint?: React.ReactNode;
  tone?: keyof typeof TONE;
  className?: string;
};

export function StatCard({ label, value, suffix, hint, tone = "default", className }: StatCardProps) {
  return (
    <div className={cn("rounded-xl border border-cyberborder bg-cyberpanel p-5", className)}>
      <p className="font-mono text-[11px] uppercase tracking-wider text-cybermuted">{label}</p>
      <p className={cn("mt-2 text-3xl font-bold tabular-nums", TONE[tone])}>
        {value}
        {suffix && <span className="ml-1 text-sm font-medium text-cybermuted">{suffix}</span>}
      </p>
      {hint && <p className="mt-1 text-xs text-cybermuted">{hint}</p>}
    </div>
  );
}
