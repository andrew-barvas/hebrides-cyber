-- Migration 077: link each connected repository to the site it belongs to.
--
-- Before this, every non-safe scan used the owner's most recently connected
-- repository whatever site it scanned (scanExecution.ts), so repository
-- findings (SAST, Trivy, secrets, dependencies, workflows, Scorecard) were
-- recorded against unrelated sites. src/lib/repoTargets.ts now uses a
-- repository only for the site in target_host; an unlinked one is never used.
--
-- 1. target_host: the linked site's hostname, set by connect-repo.ts.
-- 2. Backfill: an owner with exactly one monitored site gets their existing
--    repositories linked to it, since that was the only site they could
--    have meant.
-- 3. Cleanup: repository findings recorded against a site that no
--    repository is linked to were misattributed, so they are removed from
--    finding_lifecycle. They come back on the right site at its next scan
--    once the repository is linked to it.
--
-- 4. SAST findings in the scanner's own deliberately vulnerable rule examples
--    (sast-rules/), recorded before sast.ts excluded that folder (#88), are
--    removed wherever they are; the title carries the file path.
--
-- Idempotent — safe to re-run.

alter table public.repo_connections add column if not exists target_host text;

with single_site as (
  select owner, min(lower(substring(target_url from '^[a-zA-Z]+://([^/:?#]+)'))) as host
  from public.monitored_targets
  group by owner
  having count(distinct lower(substring(target_url from '^[a-zA-Z]+://([^/:?#]+)'))) = 1
)
update public.repo_connections rc
set target_host = s.host
from single_site s
where rc.owner = s.owner
  and rc.target_host is null
  and s.host is not null;

delete from public.finding_lifecycle fl
where (
    fl.check_id like 'sast.%'
    or fl.check_id like 'trivy-config.%'
    or fl.check_id like 'trivy-image.%'
    or fl.check_id like 'secretScan.%'
    or fl.check_id like 'dependency-manifest.%'
    or fl.check_id like 'docker-base-image.%'
    or fl.check_id like 'workflow-security.%'
    or fl.check_id like 'scorecard.%'
  )
  and not exists (
    select 1 from public.repo_connections rc
    where rc.owner = fl.owner
      and rc.target_host is not null
      and regexp_replace(rc.target_host, '^www\.', '') = regexp_replace(fl.target_host, '^www\.', '')
  );

delete from public.finding_lifecycle
where check_id like 'sast.%'
  and title like '%sast-rules/%';
