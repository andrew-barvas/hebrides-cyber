# Changelog: 18 to 20 November 2026

Everything merged to `master` from 2026-11-18 to 2026-11-20, in plain
English, grouped by product. Each entry links to its pull request. Product
summaries: [`PRODUCTS.md`](PRODUCTS.md). Current plan:
[`NEXT-STEPS.md`](NEXT-STEPS.md).

## Scanner

- **Repository findings only appear on the right site.**
  [#248](https://github.com/andrew-barvas/hebrides-cyber/pull/248)
  Each connected GitHub repository is now linked to one of the owner's sites,
  and only that site's scans use it. Before, every deeper scan used the
  owner's newest repository whatever site it was scanning, so one
  repository's findings showed up on an unrelated site. Connecting a
  repository now asks which site it belongs to. Existing repositories were
  linked automatically for owners with one site; misplaced repository
  findings were removed. A storage-network finding on our own Azure
  configuration was accepted with the reason recorded.
- **Prompt to link older repositories.**
  [#267](https://github.com/andrew-barvas/hebrides-cyber/pull/267)
  A repository that isn't linked to a site is no longer scanned, so the
  dashboard now shows a banner naming it, the Integrations page opens the
  Link control, and a manually run workflow emails each affected owner once
  (dry run by default).
- **Assign findings to a person.**
  [#249](https://github.com/andrew-barvas/hebrides-cyber/pull/249)
  The Findings Explorer has an "Assign to" picker in the bulk bar, an
  "Assigned to" filter and a badge on each finding. Assignments hold across
  scans, are audited, and the assignee gets one email listing what was
  assigned.
- **Team members can see the owner's findings.**
  [#250](https://github.com/andrew-barvas/hebrides-cyber/pull/250)
  Someone on a team can switch to the owner's account in the Findings
  Explorer and read its findings, read-only, filtered to what is assigned to
  them. The assignment email links straight there.
- **Weekly "one thing to fix" email.**
  [#255](https://github.com/andrew-barvas/hebrides-cyber/pull/255)
  Every Monday each active subscriber gets one email naming their single most
  urgent finding, how to fix it, roughly how long it takes and a link to
  check it's fixed, plus whether last week's suggestion was fixed. On by
  default, with a switch under notification preferences. Never sent twice in
  six days; nothing is sent when nothing needs fixing.
- **Security evidence pack.**
  [#264](https://github.com/andrew-barvas/hebrides-cyber/pull/264)
  Pro customers can download one PDF for an insurer, a supplier questionnaire
  or a Cyber Essentials application. Each answer says where it comes from:
  seen by our checks, a gap our checks found, the customer's own
  self-assessment, or something only their own records can show. It is
  supporting evidence, not a certification.
- **Estate map.**
  [#265](https://github.com/andrew-barvas/hebrides-cyber/pull/265)
  The Assets page lists every known host, grouped by domain, with its web
  status, certificate expiry, exposed services, open issues and a link to its
  latest report. Anything we haven't checked says so rather than looking
  fine.
- **Fewer false "fixed" results and a cleaner ranking.**
  [#259](https://github.com/andrew-barvas/hebrides-cyber/pull/259)
  When the Wayback Machine lookup fails, earlier findings from it stay open
  instead of being marked fixed. Findings from a tool a site no longer runs
  drop out of the "fix this first" ranking, the weekly email and Lookout
  drafts, while staying in the full list.
- **Continue with Google.**
  [#273](https://github.com/andrew-barvas/hebrides-cyber/pull/273)
  Login and sign-up pages have a Google button that keeps the chosen plan or
  link through sign-in. It stays hidden until the owner sets up the Google
  provider (OT-63).
- **Smaller UX fixes.**
  [#247](https://github.com/andrew-barvas/hebrides-cyber/pull/247)
  One audience in the homepage headline ("Professional security for UK small
  businesses"), a proper browser-tab title on every dashboard and account
  page, a one-line cookie bar on phones, and the first-scan message now says
  it usually takes 3 to 5 minutes.

## Lookout

- **The report as a dated PDF, with an estate gallery.**
  [#252](https://github.com/andrew-barvas/hebrides-cyber/pull/252)
  Customers can download each published report as a PDF named for its period.
  The report page and PDF show up to 12 screenshots of the customer's sites
  from the period's latest scan. Analysts can preview a draft as a PDF.
- **Lookalike domains in the report.**
  [#253](https://github.com/andrew-barvas/hebrides-cyber/pull/253)
  The report lists lookalike domains our weekly sweep spotted during the
  period, how each differs from the real one and when we found it. New drafts
  get a summary sentence about them.
- **Analysts find the customer by email.**
  [#256](https://github.com/andrew-barvas/hebrides-cyber/pull/256)
  Starting a report takes the customer's sign-up email instead of a user id
  copied from the database. The report list shows each customer's email.
- **Breached email accounts in the report.**
  [#258](https://github.com/andrew-barvas/hebrides-cyber/pull/258)
  Each site shows known data breaches that included addresses on its domain:
  the breach, its date, how many addresses and what kind of data. Only counts
  and breach names are used. The section stays hidden until the owner buys a
  breach-data key (OT-17) and each domain is verified with that service.

## Exploit (not launched; do not market)

- **Authorisations expire within 30 days.**
  [#280](https://github.com/andrew-barvas/hebrides-cyber/pull/280)
  Recording a Tier A authorisation for the offensive scan profile now
  requires an expiry no more than 30 days away, and every existing open-ended
  authorisation was given one. Consent to that kind of testing is never
  open-ended. The same PR removed the default password from the demo-account
  seed script.

## Platform and operations

- **Database back under its size limit.**
  [#268](https://github.com/andrew-barvas/hebrides-cyber/pull/268)
  The database had grown to 629 MB against the Supabase Free plan's 500 MB,
  almost all of it the CVE lookup index. The index now lives as compressed
  files in Supabase Storage (bucket `cve-index`), and the database is about
  17 MB. Matching works exactly as before. A new daily check reports the
  database size, emails a warning from 70% of the limit and fails from 85%.
- **Scheduled scans fixed after a GitHub runner change.**
  [#277](https://github.com/andrew-barvas/hebrides-cyber/pull/277)
  GitHub's default runner moved to a newer Ubuntu with Python 3.14, which one
  of our scan tools refuses, so scheduled scans failed while installing
  tools. The scan jobs are pinned to Ubuntu 24.04 until the tool catches up.
- **Alert when tool updates can't be pushed.**
  [#259](https://github.com/andrew-barvas/hebrides-cyber/pull/259)
  If the weekly scanner tool update can't push its branch, the run now opens
  or comments on one GitHub issue with the run link.
- **Dependency updates.**
  [#215](https://github.com/andrew-barvas/hebrides-cyber/pull/215),
  [#244](https://github.com/andrew-barvas/hebrides-cyber/pull/244)
  Dependabot bumped two pinned GitHub Actions (the Docker login action and
  the Terraform security scan action).

## Site, marketing and docs

- **Location references removed.**
  [#246](https://github.com/andrew-barvas/hebrides-cyber/pull/246)
  The site, legal pages, structured data, footer and marketing copy no longer
  name a town or island; structured data now says Scotland. Grant
  applications and local press material keep their addresses on purpose.
- **Launch pack, advertising plan, social images and link previews.**
  [#257](https://github.com/andrew-barvas/hebrides-cyber/pull/257)
  New marketing documents covering launch steps, an advertising plan with
  rules (claims must match built features; Exploit is not advertised), social
  profile images and a default link-preview image for shared pages and blog
  posts.
- **Phishing awareness design.**
  [#251](https://github.com/andrew-barvas/hebrides-cyber/pull/251)
  A design for simulated phishing and staff training. Nothing is built; owner
  decisions are OT-59 to OT-61.
- **Competitor analysis against enterprise vendors.**
  [#262](https://github.com/andrew-barvas/hebrides-cyber/pull/262)
  What each product ships compared with large global vendors, with ranked
  ideas. Not for marketing until each fact is re-checked.
- **Owner to-do updates.**
  [#254](https://github.com/andrew-barvas/hebrides-cyber/pull/254)
  Email sending (OT-02) recorded as done with proof.

## Database migrations in this period

| Migration | PR | Change |
|---|---|---|
| 077 | [#248](https://github.com/andrew-barvas/hebrides-cyber/pull/248) | Repository linked to a site (`repo_connections.target_host`) |
| 078 | [#249](https://github.com/andrew-barvas/hebrides-cyber/pull/249) | `finding_assignments` table |
| 079 | [#255](https://github.com/andrew-barvas/hebrides-cyber/pull/255) | Weekly fix email switch and last-sent fields on `subscriptions` |
| 080 | [#267](https://github.com/andrew-barvas/hebrides-cyber/pull/267) | `repo_connections.link_reminder_sent_at` |
| 081 | [#268](https://github.com/andrew-barvas/hebrides-cyber/pull/268) | Drops the CVE index tables (now in object storage) |
| 082 | [#280](https://github.com/andrew-barvas/hebrides-cyber/pull/280) | 30-day expiry on open-ended offensive authorisations |

Migrations 075 (Lookout reports) and 076 (Google Workspace connections) landed
on 2026-11-14 in [#242](https://github.com/andrew-barvas/hebrides-cyber/pull/242)
and [#243](https://github.com/andrew-barvas/hebrides-cyber/pull/243).
