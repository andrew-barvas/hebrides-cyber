import * as React from "react";
import { cn } from "@/lib/utils";

type PageHeaderProps = {
  /** Terminal-style prompt above the title, e.g. "$ ./dashboard". Decorative. */
  eyebrow?: string;
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
};

export function PageHeader({ eyebrow, title, description, actions, className }: PageHeaderProps) {
  return (
    <div className={cn("flex flex-wrap items-end justify-between gap-4", className)}>
      <div className="min-w-0">
        {eyebrow && (
          <p className="font-mono text-xs text-neon/70" aria-hidden="true">
            {eyebrow}
          </p>
        )}
        <h1 className="text-2xl font-bold tracking-tight text-cybertext sm:text-3xl">{title}</h1>
        {description && <p className="mt-1 max-w-2xl text-sm text-cybermuted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}
