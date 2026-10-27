# Data model & tenant isolation

The **visual** companion to the authoritative per-table prose in
[`../CLAUDE.md`](../CLAUDE.md) ("Database schema") and the gating detail in
[`FUNCTIONALITY-MATRIX.md`](FUNCTIONALITY-MATRIX.md). This file owns the diagrams
only — it does not restate what those files say; where a table's behaviour is in
question, they are the arbiter. Canonical diagram sources:
[`diagrams/er-core.mmd`](diagrams/er-core.mmd),
[`diagrams/er-rls-tiers.mmd`](diagrams/er-rls-tiers.mmd).

Migrations `sql/migrations/001`–`062` (the sequence skips 023). Every user-data table has RLS enabled;
the only bypass is server-side code using the service-role key. Isolation is
tested on real Postgres in `tests/db/rls.db.test.ts`.

## Entity-relationship (core)

```mermaid
erDiagram
    users ||--o| subscriptions : has
    users ||--o{ scans : owns
    users ||--o{ monitored_targets : owns
    users ||--o{ verifications : owns
    users ||--o{ repo_connections : owns
    users ||--o{ api_keys : owns
    users ||--o{ clients : owns
    clients ||--o{ monitored_targets : groups
    clients ||--o{ verifications : groups
    users ||--o{ webhooks : owns
    users ||--o{ teams : owns
    users ||--o{ cloud_credentials : owns
    users ||--o{ ticket_integrations : owns
    users ||--o{ finding_lifecycle : owns
    users ||--o{ finding_triage : owns
    users ||--o{ asset_inventory : owns
    users ||--o{ deletion_requests : requests
    scans ||--|| scan_results : produces
    scans ||--o{ scan_jobs : queued_as
    scans ||--o{ report_shares : shared_via
    monitored_targets ||--o| target_auth_credentials : "authed cred"
    monitored_targets ||--o{ scan_jobs : scheduled_as
    teams ||--o{ team_members : contains
    ticket_integrations ||--o{ ticket_links : "finding->issue ledger"
    finding_lifecycle ||--o| sla_policies : "measured against"
    users {
        uuid id PK "= auth.users.id"
        bool is_admin "self-grant blocked by migration 017"
    }
    subscriptions {
        text plan "basic|pro|agency|tier_a"
        text status "active|past_due|cancelled"
        text source "stripe|admin override (052)"
    }
    scans {
        text status
        int score "severity penalties weighted by CVSS/KEV/EPSS, floors at 0"
    }
    scan_jobs {
        uuid scan_id FK "null => scheduled"
        text scan_profile "safe|full|offensive"
        uuid client_id FK "nullable = Unassigned; ON DELETE SET NULL (064)"
    }
    clients {
        uuid id PK
        uuid owner FK
        text name "unique per owner, case-insensitive (064)"
        text notes
        text brand_name "per-client override of the account brand"
        text brand_logo_url "https only"
    }
    api_keys {
        text key_hash "sha-256 only; plaintext shown once at creation"
        text_array allowed_cidrs "IP allowlist (042)"
        text_array scopes "scans:read|scans:write|dependency:check (063)"
    }
    cloud_credentials {
        text provider "aws|azure|gcp"
        jsonb credentials_encrypted "PLAINTEXT - FINDING S-1"
    }
    blog_posts {
        text status "draft|published|scheduled"
        text meta_description "collected, NOT persisted - CMS bug"
    }
```

## RLS / credential-sensitivity tiers

```mermaid
flowchart TB
    classDef t1 fill:#2d6a4f,stroke:#1b4332,color:#fff
    classDef t2 fill:#1168bd,stroke:#0b4884,color:#fff
    classDef t3 fill:#5a189a,stroke:#3c096c,color:#fff
    classDef t4 fill:#6a040f,stroke:#370617,color:#fff
    T1[Tier 1 - owner read + owner write via RLS:<br/>scans, monitored_targets, verifications, repo_connections,<br/>api_keys, webhooks, subscriptions webhook URLs]:::t1
    T2[Tier 2 - owner read, SERVICE-ROLE write only:<br/>scan_results, scan_jobs, finding_lifecycle, finding_triage,<br/>asset_inventory, dns_snapshots, emerging_threat_alerts,<br/>lookalike_domains, ticket_links, deletion_requests]:::t2
    T3[Tier 3 - validate-before-save, service-role write:<br/>ticket_integrations, oncall, siem_integrations,<br/>cloud_credentials, target_auth_credentials]:::t3
    T4[Tier 4 - no client policy at all:<br/>audit_logs, contact_enquiries,<br/>report_shares no public SELECT - token-match route only]:::t4
    N1["Secrets at rest: Tier-3 tokens, keys and session cookies are PLAINTEXT.<br/>cloud_credentials column is named credentials_encrypted but is NOT encrypted - FINDING S-1 and S-2"]:::t3
    N2["Dead schema: organizations, org_members, rbac, sso_providers<br/>migrations 034-036 - zero code importers. No multi-org/MSP tenancy exists."]:::t4
    T3 -.-> N1
```

> **Review findings referenced:** S-1/S-2 (plaintext credentials-at-rest) and the
> dead org/RBAC/SSO schema are detailed in
> [`PRODUCT-REVIEW-2026-10.md`](PRODUCT-REVIEW-2026-10.md) (Phase 6 / Phase 1).
