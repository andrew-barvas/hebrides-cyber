# Supabase Backup & Restore Runbook

> E-13 (docs/ENHANCEMENTS.md): documented RPO/RTO, PITR configuration,
> and a tested restore procedure.

## Current backup posture

Supabase provides **daily automatic backups** on the Free/Pro plan and
**Point-in-Time Recovery (PITR)** on Pro/Enterprise (when enabled). This
project runs on the Free plan by default — which means daily backups only,
no continuous WAL archival.

**RPO (Recovery Point Objective)**: up to 24 hours of data loss on the Free
plan (last daily backup). With PITR enabled on Pro: seconds.

**RTO (Recovery Time Objective)**: minutes once the restore is initiated.

## Checking current backup status

1. Open the Supabase Dashboard → **Database → Backups**.
2. Verify "Daily backups" shows recent completion timestamps.
3. If on Pro: verify PITR is enabled under **Database → Backups → PITR**.

## Upgrading to PITR (recommended for production)

1. Upgrade the Supabase project to **Pro** ($25/mo per project).
2. Enable PITR: Dashboard → Database → Backups → Enable PITR.
3. Verify WAL archiving is active (the page will show retention window).

## Restore from a daily backup

1. Dashboard → Database → Backups.
2. Click **Restore** next to the desired backup timestamp.
3. Confirm — this replaces the current database state entirely.
4. Wait for the restore to complete (progress shown in Dashboard).
5. Verify: run the migration schema check from CI manually:
   ```bash
   cd hebridescyber-app
   # Check key columns exist
   curl -s "$SUPABASE_URL/rest/v1/subscriptions?select=notify_email&limit=0" \
     -H "apikey: $SUPABASE_ANON_KEY" -o /dev/null -w "%{http_code}"
   # Should return 200
   ```
6. Smoke test: log into the dashboard and verify scans/subscriptions load.

## Restore from PITR (Pro plan only)

1. Dashboard → Database → Backups → PITR.
2. Select the target recovery timestamp.
3. Click **Restore** and confirm.
4. Same verification steps as above.

## Testing the restore procedure

Run this against a **scratch Supabase project** (free tier), not
production, to prove the procedure works without risk.

1. Create a free Supabase project for testing.
2. Apply all migrations with the project's runner (which records them in the
   `schema_migrations` ledger, as production does):
   ```bash
   cd hebridescyber-app
   DATABASE_URL="$TEST_DATABASE_URL" npx tsx src/scripts/apply-migrations.ts apply
   ```
3. Seed some test data (a user, a subscription, a scan).
4. Take note of the data state.
5. Wait for a daily backup to complete (or trigger one if on Pro).
6. Mutate or delete the test data.
7. Restore from the backup.
8. Verify the data matches the pre-mutation state.

## Migrations are forward-only

There are no `down` migration scripts. A restore brings back the
`schema_migrations` ledger with the data, so the ledger and the schema stay
consistent. Restoring to a point before a migration was applied means that
migration is now pending: apply it with the project's runner (not
`supabase db push`, which does not know the ledger):

```bash
cd hebridescyber-app
export DATABASE_URL='<direct postgres connection string>'
npx tsx src/scripts/apply-migrations.ts status   # applied, pending, drift
npx tsx src/scripts/apply-migrations.ts apply
```

Migrations are written to re-apply safely (`create or replace`,
`if not exists`); the few documented exceptions are listed in
`migrations.db.test.ts`. The full incident and disaster-recovery procedures,
including what to reconcile after a restore, are in `RUNBOOK.md` section 8.

## Emergency contacts

- **Supabase status**: https://status.supabase.com
- **Supabase support**: Dashboard → Support (Pro plan gets priority)
- **This project's owner**: check the Supabase Dashboard for project owner
