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
        or usage.max_sessions_created_per_client > 7
        then 'free_read_only'
      else 'free_normal'
    end as plan_state,
    usage.distinct_clients_used,
    usage.sessions_created_total,
    usage.max_sessions_created_per_client,
    7 as free_client_limit,
    7 as free_sessions_per_client_limit,
    35 as free_total_sessions_limit
  from entitlement, usage;
$$;

revoke execute on function public.get_account_access_state() from public;
revoke execute on function public.get_account_access_state() from anon;
grant execute on function public.get_account_access_state() to authenticated;
