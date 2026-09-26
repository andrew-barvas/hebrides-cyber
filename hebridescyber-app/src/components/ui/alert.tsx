import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { CircleCheck, Info, OctagonAlert, TriangleAlert } from "lucide-react";
import { cn } from "@/lib/utils";

const alertVariants = cva("flex gap-3 rounded-lg border p-4 text-sm text-cybertext", {
  variants: {
    variant: {
      info: "border-cyberborder bg-cyberpanel",
      success: "border-neon/30 bg-neon/10",
      warning: "border-warning/30 bg-warning/10",
      danger: "border-danger/30 bg-danger/10",
    },
  },
  defaultVariants: { variant: "info" },
});

const ICONS = { info: Info, success: CircleCheck, warning: TriangleAlert, danger: OctagonAlert } as const;
const ACCENT = { info: "text-cybermuted", success: "text-neon", warning: "text-warning", danger: "text-danger" } as const;

type AlertProps = Omit<React.HTMLAttributes<HTMLDivElement>, "title"> &
  VariantProps<typeof alertVariants> & { title?: React.ReactNode };

/** Colour carries on the icon and title only — body text stays cybertext, so
 *  a paragraph of warning copy is as readable as any other paragraph.
 *  Danger announces assertively (role=alert); everything else politely. */
export function Alert({ variant, title, className, children, role, ...props }: AlertProps) {
  const v = variant ?? "info";
  const Icon = ICONS[v];
  return (
    <div role={role ?? (v === "danger" ? "alert" : "status")} className={cn(alertVariants({ variant: v }), className)} {...props}>
      <Icon className={cn("mt-0.5 size-4 shrink-0", ACCENT[v])} aria-hidden="true" />
      <div className="min-w-0 space-y-1">
        {title && <p className={cn("font-semibold", ACCENT[v])}>{title}</p>}
        {children && <div>{children}</div>}
      </div>
    </div>
  );
}
