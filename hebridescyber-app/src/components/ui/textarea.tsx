import * as React from "react";
import { cn } from "@/lib/utils";

/** Multi-line sibling of Input — same surface, border and focus treatment. */
export const Textarea = React.forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...props }, ref) => (
    <textarea
      ref={ref}
      className={cn(
        "flex min-h-20 w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext transition-colors placeholder:text-cybermuted/70",
        "focus-visible:border-neon focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-neon/40",
        "disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-danger",
        className
      )}
      {...props}
    />
  )
);
Textarea.displayName = "Textarea";
