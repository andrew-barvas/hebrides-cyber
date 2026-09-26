import Link from "next/link";
import { Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardTitle } from "@/components/ui/card";

/** Stands in for a plan-gated feature the current plan doesn't include.
 *  Hiding gated features entirely (the previous behaviour) meant a Basic
 *  customer had no way to discover that Slack alerts or cloud posture
 *  scanning existed at all. */
export default function LockedFeature({
  title,
  description,
  availableOn,
}: {
  title: string;
  description: string;
  availableOn: string;
}) {
  return (
    <Card className="border-dashed">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <CardTitle>{title}</CardTitle>
        <span className="inline-flex items-center gap-1 rounded-full border border-cyberborder px-2 py-0.5 text-[11px] font-medium text-cybermuted">
          <Lock className="size-3" aria-hidden="true" />
          {availableOn}
        </span>
      </div>
      <CardDescription className="mt-2">{description}</CardDescription>
      <Button asChild variant="secondary" size="sm" className="mt-4">
        <Link href="/pricing">Compare plans</Link>
      </Button>
    </Card>
  );
}
