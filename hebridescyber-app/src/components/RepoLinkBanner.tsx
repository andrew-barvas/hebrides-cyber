"use client";

// Dashboard overview: a notice when a connected repository isn't linked to a
// site (migration 077). Since #248 an unlinked repository is never scanned,
// so its code checks silently stop until the owner picks its site. Renders
// nothing when every repository is linked or none is connected.
import { useEffect, useState } from "react";
import Link from "next/link";
import { supabase } from "@/lib/supabaseClient";

export default function RepoLinkBanner({ ownerId }: { ownerId: string | null }) {
  const [unlinked, setUnlinked] = useState<string[]>([]);

  useEffect(() => {
    if (!ownerId) return;
    let cancelled = false;
    // RLS scopes repo_connections to the owner; the explicit filter keeps a
    // team member's shared view from listing someone else's repositories.
    supabase
      .from("repo_connections")
      .select("github_repo, target_host")
      .eq("owner", ownerId)
      .is("target_host", null)
      .then(
        ({ data }) => {
          if (!cancelled) setUnlinked(((data ?? []) as Array<{ github_repo: string }>).map((r) => r.github_repo));
        },
        () => {},
      );
    return () => {
      cancelled = true;
    };
  }, [ownerId]);

  if (unlinked.length === 0) return null;
  return (
    <div role="status" className="rounded-lg border border-warning/40 bg-warning/10 p-4 text-sm">
      <p className="text-cybertext">
        {unlinked.length === 1 ? (
          <>
            Your repository <code className="font-mono">{unlinked[0]}</code> isn&apos;t linked to a site, so its code checks are paused.
          </>
        ) : (
          <>{unlinked.length} of your repositories aren&apos;t linked to a site, so their code checks are paused.</>
        )}{" "}
        <Link href="/dashboard/integrations#connect-repo" className="font-semibold text-neon underline-offset-2 hover:underline">
          Choose its site
        </Link>
      </p>
    </div>
  );
}
