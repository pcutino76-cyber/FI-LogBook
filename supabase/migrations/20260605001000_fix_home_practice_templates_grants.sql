-- Align Home Practice Library table privileges with the intended Data API surface.
-- The table should be usable by authenticated users only for normal CRUD, with
-- no REFERENCES, TRIGGER, TRUNCATE, anon, or public table privileges.

revoke all privileges on table public.home_practice_templates from authenticated;
revoke all privileges on table public.home_practice_templates from anon;
revoke all privileges on table public.home_practice_templates from public;

grant select, insert, update, delete on table public.home_practice_templates to authenticated;
