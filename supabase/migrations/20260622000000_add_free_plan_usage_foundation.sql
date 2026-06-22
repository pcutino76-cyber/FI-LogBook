-- Free-plan backend foundation: durable historical usage ledger,
-- server-side entitlement mirror, and read-only account access state RPC.

create table if not exists public.account_entitlements (
  user_id uuid primary key references auth.users(id) on delete cascade,
  plan_tier text not null default 'free',
  subscription_status text,
  stripe_customer_id text,
  stripe_subscription_id text,
  updated_at timestamptz not null default now(),
  constraint account_entitlements_plan_tier_check check (plan_tier in ('free', 'premium'))
);

create table if not exists public.session_usage_ledger (
  user_id uuid not null references auth.users(id) on delete cascade,
  session_id text not null,
  client_id text not null,
  consumed_at timestamptz not null default now(),
  source text not null default 'session_create',
  migration_metadata jsonb not null default '{}'::jsonb,
  primary key (user_id, session_id),
  constraint session_usage_ledger_session_id_not_blank check (btrim(session_id) <> ''),
  constraint session_usage_ledger_client_id_not_blank check (btrim(client_id) <> ''),
  constraint session_usage_ledger_source_not_blank check (btrim(source) <> '')
);

create index if not exists session_usage_ledger_user_client_idx
  on public.session_usage_ledger (user_id, client_id);

create or replace function public.set_account_entitlements_updated_at()
returns trigger
language plpgsql
set search_path = pg_catalog
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists set_account_entitlements_updated_at on public.account_entitlements;
create trigger set_account_entitlements_updated_at
  before update on public.account_entitlements
  for each row
  execute function public.set_account_entitlements_updated_at();

alter table public.account_entitlements enable row level security;
alter table public.session_usage_ledger enable row level security;

revoke all on table public.account_entitlements from public;
revoke all on table public.account_entitlements from anon;
revoke all on table public.account_entitlements from authenticated;

revoke all on table public.session_usage_ledger from public;
revoke all on table public.session_usage_ledger from anon;
revoke all on table public.session_usage_ledger from authenticated;

grant select, insert, update on table public.account_entitlements to service_role;

revoke all on function public.set_account_entitlements_updated_at() from public;
revoke all on function public.set_account_entitlements_updated_at() from anon;
revoke all on function public.set_account_entitlements_updated_at() from authenticated;

-- Service-role webhook writes use explicit table privileges and bypass RLS.
-- Browser clients receive entitlement and
-- usage only through get_account_access_state().

insert into public.account_entitlements (
  user_id,
  plan_tier,
  subscription_status,
  stripe_customer_id,
  stripe_subscription_id,
  updated_at
)
select
  u.id,
  case when u.raw_app_meta_data->>'plan_tier' = 'premium' then 'premium' else 'free' end,
  nullif(u.raw_app_meta_data->>'subscription_status', ''),
  nullif(u.raw_app_meta_data->>'stripe_customer_id', ''),
  nullif(u.raw_app_meta_data->>'stripe_subscription_id', ''),
  now()
from auth.users u
on conflict (user_id) do update set
  plan_tier = excluded.plan_tier,
  subscription_status = excluded.subscription_status,
  stripe_customer_id = excluded.stripe_customer_id,
  stripe_subscription_id = excluded.stripe_subscription_id,
  updated_at = now();

insert into public.session_usage_ledger (
  user_id,
  session_id,
  client_id,
  consumed_at,
  source,
  migration_metadata
)
select
  s.user_id,
  s.id::text,
  s."clientId"::text,
  now(),
  'migration_existing_session',
  jsonb_build_object('migration', '20260622000000_add_free_plan_usage_foundation')
from public.sessions s
where s.user_id is not null
  and nullif(pg_catalog.btrim(s.id::text), '') is not null
  and nullif(pg_catalog.btrim(s."clientId"::text), '') is not null
on conflict (user_id, session_id) do nothing;

create or replace function public.get_account_access_state()
returns table (
  plan_tier text,
  plan_state text,
  distinct_clients_used integer,
  sessions_created_total integer,
  max_sessions_created_per_client integer,
  free_client_limit integer,
  free_sessions_per_client_limit integer,
  free_total_sessions_limit integer
)
language sql
security definer
stable
set search_path = pg_catalog
as $$
  with current_user_id as (
    select auth.uid() as user_id
  ), entitlement as (
    select coalesce(e.plan_tier, 'free') as plan_tier
    from current_user_id cu
    left join public.account_entitlements e on e.user_id = cu.user_id
  ), per_client as (
    select l.client_id, pg_catalog.count(*)::integer as session_count
    from current_user_id cu
    join public.session_usage_ledger l on l.user_id = cu.user_id
    group by l.client_id
  ), usage as (
    select
      coalesce(pg_catalog.count(*)::integer, 0) as distinct_clients_used,
      coalesce(pg_catalog.sum(session_count)::integer, 0) as sessions_created_total,
      coalesce(pg_catalog.max(session_count)::integer, 0) as max_sessions_created_per_client
    from per_client
  )
  select
    entitlement.plan_tier,
    case
      when entitlement.plan_tier = 'premium' then 'premium_operational'
      when usage.distinct_clients_used > 7
        or usage.sessions_created_total > 35
        or usage.max_sessions_created_per_client > 5
        then 'free_read_only'
      else 'free_normal'
    end as plan_state,
    usage.distinct_clients_used,
    usage.sessions_created_total,
    usage.max_sessions_created_per_client,
    7 as free_client_limit,
    5 as free_sessions_per_client_limit,
    35 as free_total_sessions_limit
  from entitlement, usage;
$$;

revoke all on function public.get_account_access_state() from public;
revoke all on function public.get_account_access_state() from anon;
grant execute on function public.get_account_access_state() to authenticated;
