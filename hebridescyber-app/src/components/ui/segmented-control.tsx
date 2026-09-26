"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

type Option<T extends string> = { value: T; label: React.ReactNode };

type SegmentedControlProps<T extends string> = {
  value: T;
  onChange: (value: T) => void;
  options: readonly Option<T>[];
  /** Required — the group needs a name for screen readers ("Filter findings"). */
  "aria-label": string;
  className?: string;
};

/** A row of mutually exclusive toggle buttons for filtering a view in place.
 *  aria-pressed exposes which one is active; without it, the selected state
 *  was conveyed by colour alone. */
export function SegmentedControl<T extends string>({ value, onChange, options, className, ...rest }: SegmentedControlProps<T>) {
  return (
    <div role="group" aria-label={rest["aria-label"]} className={cn("inline-flex flex-wrap gap-1.5", className)}>
      {options.map((o) => {
        const selected = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            aria-pressed={selected}
            onClick={() => onChange(o.value)}
            className={cn(
              "rounded-md border px-2.5 py-1 text-xs font-medium transition-colors",
              "focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-neon",
              selected
                ? "border-neon bg-neon/10 text-neon"
                : "border-cyberborder text-cybermuted hover:border-cybertext/30 hover:text-cybertext"
            )}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
