revoke all on table public.account_entitlements from service_role;
grant select, insert, update on table public.account_entitlements to service_role;

revoke all on table public.session_usage_ledger from service_role;

revoke all on function public.set_account_entitlements_updated_at() from service_role;
revoke all on function public.record_session_usage_ledger_insert() from service_role;
revoke all on function public.get_account_access_state() from service_role;
