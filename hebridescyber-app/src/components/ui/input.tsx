import * as React from "react";
import { cn } from "@/lib/utils";

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, type = "text", ...props }, ref) => (
    <input
      ref={ref}
      type={type}
      className={cn(
        "flex h-10 w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext transition-colors placeholder:text-cybermuted/70",
        "focus-visible:border-neon focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-neon/40",
        "disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-danger",
        className
      )}
      {...props}
    />
  )
);
Input.displayName = "Input";

export function Label({ className, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return <label className={cn("text-sm font-medium text-cybertext", className)} {...props} />;
}
