import * as React from "react";
import { cn } from "@/lib/utils";

export const Card = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("rounded-xl border border-cyberborder bg-cyberpanel p-5", className)} {...props} />
  )
);
Card.displayName = "Card";

export function CardHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("mb-4 flex flex-wrap items-start justify-between gap-3", className)} {...props} />;
}

type CardTitleProps = React.HTMLAttributes<HTMLHeadingElement> & { as?: "h2" | "h3" };

/** The brand's `// section` overline. The `//` is decoration, hidden from
 *  screen readers so headings aren't announced as "slash slash …". */
export function CardTitle({ as: Tag = "h2", className, children, ...props }: CardTitleProps) {
  return (
    <Tag className={cn("font-mono text-xs uppercase tracking-wide text-cybermuted", className)} {...props}>
      <span aria-hidden="true">{"// "}</span>
      {children}
    </Tag>
  );
}

export function CardDescription({ className, ...props }: React.HTMLAttributes<HTMLParagraphElement>) {
  return <p className={cn("text-sm text-cybermuted", className)} {...props} />;
}
