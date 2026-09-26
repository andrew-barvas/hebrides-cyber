import * as React from "react";
import { cn } from "@/lib/utils";

type EmptyStateProps = {
  icon?: React.ReactNode;
  title: string;
  description?: React.ReactNode;
  action?: React.ReactNode;
  as?: "h2" | "h3";
  className?: string;
};

/** What a view shows when it has nothing to show yet — always paired with the
 *  next step, so a new account never lands on a blank page. */
export function EmptyState({ icon, title, description, action, as: Heading = "h2", className }: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center rounded-xl border border-dashed border-cyberborder bg-cyberpanel/50 px-6 py-12 text-center",
        className
      )}
    >
      {icon && (
        <div
          className="mb-4 flex size-12 items-center justify-center rounded-full border border-cyberborder bg-cyberbg text-neon [&_svg]:size-5"
          aria-hidden="true"
        >
          {icon}
        </div>
      )}
      <Heading className="text-base font-semibold text-cybertext">{title}</Heading>
      {description && <p className="mt-1 max-w-sm text-sm text-cybermuted">{description}</p>}
      {action && <div className="mt-6">{action}</div>}
    </div>
  );
}
