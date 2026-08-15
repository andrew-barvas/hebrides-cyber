-- Migration 003: tag the seeded blog posts + ensure scan_results has a findings column
-- Run in Supabase SQL editor. Idempotent.

-- 1. Add tags to existing blog posts
-- (tags column already exists from migration 002; these rows just have '{}')

update public.blog_posts set tags = '{ransomware,data-breach,enterprise,hr-security}'
where slug = 'hyundai-turkiye-ransomware-recruitment-data';

update public.blog_posts set tags = '{ransomware,uk,sme,statistics}'
where slug = 'uk-ransomware-2026-sme-stats';

update public.blog_posts set tags = '{supply-chain,data-breach,third-party-risk,credentials}'
where slug = 'klue-supply-chain-breach-third-party-risk';

update public.blog_posts set tags = '{healthcare,data-breach,vendor-liability,gdpr}'
where slug = 'conduent-healthcare-breach-vendor-liability';

update public.blog_posts set tags = '{data-breach,telecoms,extortion}'
where slug = 'charter-communications-breach-42-million';

update public.blog_posts set tags = '{mfa,guide,best-practices,quick-win}'
where slug = 'mfa-best-value-security-upgrade';

update public.blog_posts set tags = '{http-headers,guide,quick-win,web}'
where slug = 'security-headers-five-minute-fix';

-- 2. Ensure scan_results has a findings column for structured report display
-- (The existing run-scan.ts stores findings inside the results JSONB blob;
--  this adds a top-level column so the report page can query it directly
--  without parsing the whole blob client-side.)
alter table public.scan_results
    add column if not exists findings jsonb not null default '[]';
