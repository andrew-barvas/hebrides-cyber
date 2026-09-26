import { cn } from "@/lib/utils";

/** Loading placeholder shaped like the content it stands in for. The pulse is
 *  neutralised by globals.css under prefers-reduced-motion. */
export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden="true" className={cn("animate-pulse rounded-md bg-cyberborder/60", className)} />;
}
