-- Optional lead-qualification fields on the contact form — company name,
-- team size, and budget range. All nullable: the existing name/email/
-- message-only submission must keep working unchanged. Bucketed as
-- check-constrained enums (matching subscriptions.plan's style in
-- 001_init.sql) rather than free text, so the admin UI can filter/sort on
-- them later without normalising messy input.
--
-- Must be applied before the updated src/pages/api/contact.ts ships — that
-- route's insert will fail with "column does not exist" otherwise.
--
-- No RLS policy change needed: contact_enquiries has none (003_contact_enquiries.sql)
-- — service-role-only access already covers these new columns too.
--
-- Safe to re-run, matching the convention established in 002_improvements.sql onward.
alter table public.contact_enquiries
  add column if not exists company text,
  add column if not exists team_size text
    check (team_size in ('solo', '2_10', '11_50', '51_200', '200_plus')),
  add column if not exists budget_range text
    check (budget_range in ('unsure', 'under_300', '300_800', '800_1800', '1800_plus'));
