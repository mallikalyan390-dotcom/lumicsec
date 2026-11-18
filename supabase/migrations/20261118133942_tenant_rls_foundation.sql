-- LumicSec tenant/RLS foundation, 2026-11-18.
-- No customer scanner execution or payment capability is enabled by this migration.
-- Supabase PostgreSQL and Supabase Auth remain the only data and identity services.

create schema if not exists lumicsec_private;
revoke all on schema lumicsec_private from public, anon, authenticated;

create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  display_name text not null check (char_length(btrim(display_name)) between 1 and 160),
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now()
);

create table public.organization_memberships (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  member_role text not null check (member_role in ('owner', 'admin', 'analyst', 'viewer')),
  member_status text not null default 'active'
    check (member_status in ('active', 'suspended')),
  created_at timestamptz not null default now(),
  primary key (organization_id, user_id)
);

create index organization_memberships_user_active_idx
  on public.organization_memberships (user_id, organization_id)
  where member_status = 'active';

create table public.assets (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  asset_kind text not null check (asset_kind in ('website', 'api')),
  display_name text not null check (char_length(btrim(display_name)) between 1 and 160),
  canonical_origin text not null
    check (
      char_length(canonical_origin) between 9 and 253
      and canonical_origin ~ '^https://[a-z0-9.-]+(:443)?$'
    ),
  verification_status text not null default 'pending'
    check (verification_status in ('pending', 'verified', 'revoked')),
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  verified_at timestamptz,
  unique (id, organization_id),
  unique (organization_id, canonical_origin)
);
create index assets_organization_idx on public.assets (organization_id, created_at desc);

create table public.assessment_jobs (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  asset_id uuid not null,
  requested_by uuid not null references auth.users(id) on delete restrict,
  assessment_kind text not null
    check (assessment_kind in ('web_passive', 'api_spec_offline')),
  job_state text not null default 'queued'
    check (job_state in ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  scope_hash text check (scope_hash is null or scope_hash ~ '^[0-9a-f]{64}$'),
  requested_at timestamptz not null default now(),
  started_at timestamptz,
  completed_at timestamptz,
  unique (id, organization_id),
  foreign key (asset_id, organization_id)
    references public.assets (id, organization_id)
);
create index assessment_jobs_organization_idx
  on public.assessment_jobs (organization_id, requested_at desc);

-- Observations are not automatic verified vulnerabilities.
create table public.assessment_observations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  job_id uuid not null,
  rule_id text not null check (char_length(rule_id) between 1 and 100),
  title text not null check (char_length(title) between 1 and 240),
  summary text not null check (char_length(summary) between 1 and 3000),
  severity_estimate text not null check (severity_estimate in ('info', 'low', 'medium', 'high')),
  review_state text not null default 'review_required'
    check (review_state in ('review_required', 'dismissed', 'needs_evidence')),
  created_at timestamptz not null default now(),
  foreign key (job_id, organization_id)
    references public.assessment_jobs (id, organization_id)
);
create index assessment_observations_organization_idx
  on public.assessment_observations (organization_id, created_at desc);

create table public.audit_events (
  id bigint generated always as identity primary key,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  actor_id uuid references auth.users(id) on delete set null,
  action text not null check (char_length(action) between 2 and 100),
  event_summary text not null check (char_length(event_summary) between 1 and 500),
  created_at timestamptz not null default now()
);
create index audit_events_organization_idx on public.audit_events (organization_id, created_at desc);

alter table public.organizations enable row level security;
alter table public.organization_memberships enable row level security;
alter table public.assets enable row level security;
alter table public.assessment_jobs enable row level security;
alter table public.assessment_observations enable row level security;
alter table public.audit_events enable row level security;

-- No anonymous access. Expose strictly limited column privileges to signed-in users.
revoke all on table public.organizations, public.organization_memberships,
  public.assets, public.assessment_jobs, public.assessment_observations,
  public.audit_events from public, anon, authenticated;

grant select on table public.organizations, public.organization_memberships,
  public.assets, public.assessment_jobs, public.assessment_observations,
  public.audit_events to authenticated;

grant insert (display_name, created_by) on public.organizations to authenticated;
grant update (display_name) on public.organizations to authenticated;

grant insert (organization_id, asset_kind, display_name, canonical_origin, created_by)
  on public.assets to authenticated;
grant update (display_name) on public.assets to authenticated;

-- Memberships cannot be directly invited, escalated or suspended by a browser.
-- Server-controlled membership administration is a separate audited milestone.
create policy membership_self_read on public.organization_memberships
  for select to authenticated
  using (
    user_id = (select auth.uid())
    and (auth.jwt() ->> 'aal') = 'aal2'
    and (auth.jwt() -> 'app_metadata' ->> 'provider') = 'google'
  );

create policy organization_member_read on public.organizations
  for select to authenticated
  using (
    exists (
      select 1 from public.organization_memberships m
      where m.organization_id = organizations.id
        and m.user_id = (select auth.uid())
        and m.member_status = 'active'
    )
  );

create policy organization_google_aal2_create on public.organizations
  for insert to authenticated
  with check (
    created_by = (select auth.uid())
    and (auth.jwt() ->> 'aal') = 'aal2'
    and (auth.jwt() -> 'app_metadata' ->> 'provider') = 'google'
  );

create policy organization_manager_rename on public.organizations
  for update to authenticated
  using (
    exists (
      select 1 from public.organization_memberships m
      where m.organization_id = organizations.id
        and m.user_id = (select auth.uid())
        and m.member_status = 'active'
        and m.member_role in ('owner', 'admin')
    )
  )
  with check (
    exists (
      select 1 from public.organization_memberships m
      where m.organization_id = organizations.id
        and m.user_id = (select auth.uid())
        and m.member_status = 'active'
        and m.member_role in ('owner', 'admin')
    )
  );

create policy asset_member_read on public.assets
  for select to authenticated
  using (
    exists (
      select 1 from public.organization_memberships m
      where m.organization_id = assets.organization_id
        and m.user_id = (select auth.uid())
        and m.member_status = 'active'
    )
  );

create policy asset_authorized_pending_create on public.assets
  for insert to authenticated
  with check (
    verification_status = 'pending'
    and verified_at is null
    and created_by = (select auth.uid())
    and exists (
      select 1 from public.organization_memberships m
      where m.organization_id = assets.organization_id
        and m.user_id = (select auth.uid())
        and m.member_status = 'active'
        and m.member_role in ('owner', 'admin', 'analyst')
    )
  );

create policy asset_editor_rename on public.assets
  for update to authenticated
  using (
    exists (
      select 1 from public.organization_memberships m
      where m.organization_id = assets.organization_id
        and m.user_id = (select auth.uid())
        and m.member_status = 'active'
        and m.member_role in ('owner', 'admin', 'analyst')
    )
  )
  with check (
    exists (
      select 1 from public.organization_memberships m
      where m.organization_id = assets.organization_id
        and m.user_id = (select auth.uid())
        and m.member_status = 'active'
        and m.member_role in ('owner', 'admin', 'analyst')
    )
  );

-- Jobs and observations are written only by future bounded, trusted workers.
-- No direct browser INSERT/UPDATE/DELETE grants exist for these tables.
create policy assessment_job_member_read on public.assessment_jobs
  for select to authenticated
  using (
    exists (
      select 1 from public.organization_memberships m
      where m.organization_id = assessment_jobs.organization_id
        and m.user_id = (select auth.uid())
        and m.member_status = 'active'
    )
  );

create policy assessment_observation_member_read on public.assessment_observations
  for select to authenticated
  using (
    exists (
      select 1 from public.organization_memberships m
      where m.organization_id = assessment_observations.organization_id
        and m.user_id = (select auth.uid())
        and m.member_status = 'active'
    )
  );

create policy audit_event_manager_read on public.audit_events
  for select to authenticated
  using (
    exists (
      select 1 from public.organization_memberships m
      where m.organization_id = audit_events.organization_id
        and m.user_id = (select auth.uid())
        and m.member_status = 'active'
        and m.member_role in ('owner', 'admin')
    )
  );

-- Internal-only trigger: owner membership is provisioned atomically at organization creation.
-- The function is not in a Data-API-exposed schema and EXECUTE is revoked from users.
create function lumicsec_private.bootstrap_owner()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (select auth.uid()) is distinct from new.created_by then
    raise exception 'organization creator identity mismatch' using errcode = '42501';
  end if;

  insert into public.organization_memberships
    (organization_id, user_id, member_role, member_status)
  values (new.id, new.created_by, 'owner', 'active');
  return new;
end;
$$;

revoke all on function lumicsec_private.bootstrap_owner()
  from public, anon, authenticated;

create trigger organization_bootstrap_owner_after_insert
after insert on public.organizations
for each row execute function lumicsec_private.bootstrap_owner();

-- No public function, table view, storage bucket or scheduled job is created.
