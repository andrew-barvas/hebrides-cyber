-- Fixes a real bug: the dashboard's ScanList "Delete" button has always
-- called supabase.from("scans").delete().eq("id", scanId) from the browser
-- (anon key, RLS-enforced), but 001_init.sql's scans table only ever
-- shipped SELECT and INSERT policies — its own comment even says "TODO: add
-- an UPDATE policy scoped to owner" and never got around to DELETE either.
-- With no matching policy, Postgres RLS silently filters the DELETE down to
-- zero rows: no error is raised (PostgREST returns 200 with nothing
-- deleted), so the row was never actually removed — only for it to still be
-- sitting there next time the dashboard reloads scans, including scans
-- stuck at "running" that a user has no other way to clear.
--
-- Owner-scoped, matching the existing select/insert policies' pattern
-- exactly — no status restriction, same as those. scan_results.scan_id
-- already has `on delete cascade` (001_init.sql), so deleting a scans row
-- here also cleans up its scan_results row automatically; the dashboard's
-- separate manual scan_results delete call becomes redundant once this
-- ships (harmless either way, but worth knowing why it's now a no-op).
--
-- All statements are safe to re-run, matching the convention established in
-- 002_improvements.sql onward.
drop policy if exists "Users can delete their own scans" on public.scans;
create policy "Users can delete their own scans"
  on public.scans for delete
  using (owner = auth.uid());
