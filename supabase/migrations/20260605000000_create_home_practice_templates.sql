-- Cloud-backed Home Practice Library foundation.
-- Schema/RLS/GRANTs only: frontend CRUD, UI, and local template migration are
-- intentionally deferred to later PRs.

create extension if not exists pgcrypto;

create table if not exists public.home_practice_templates (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  suggestion text not null,
  frequency text not null default '',
  notes text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint home_practice_templates_name_not_blank check (btrim(name) <> ''),
  constraint home_practice_templates_suggestion_not_blank check (btrim(suggestion) <> '')
);

create or replace function public.set_home_practice_templates_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists set_home_practice_templates_updated_at on public.home_practice_templates;
create trigger set_home_practice_templates_updated_at
  before update on public.home_practice_templates
  for each row
  execute function public.set_home_practice_templates_updated_at();

alter table public.home_practice_templates enable row level security;

-- Do not expose saved templates to anonymous users. Authenticated access is
-- still constrained per row by the RLS policies below.
revoke all on table public.home_practice_templates from public;
revoke all on table public.home_practice_templates from anon;
grant select, insert, update, delete on table public.home_practice_templates to authenticated;

create policy "home_practice_templates_select_own"
  on public.home_practice_templates
  for select
  to authenticated
  using (user_id = auth.uid());

create policy "home_practice_templates_insert_own"
  on public.home_practice_templates
  for insert
  to authenticated
  with check (user_id = auth.uid());

create policy "home_practice_templates_update_own"
  on public.home_practice_templates
  for update
  to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

create policy "home_practice_templates_delete_own"
  on public.home_practice_templates
  for delete
  to authenticated
  using (user_id = auth.uid());
