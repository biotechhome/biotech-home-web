-- =============================================================================
-- 0003_service_role_grants.sql  --  Biotech Home: privileges for trusted server code
--
-- Why this exists
--   "Automatic API grants" are OFF in this project, so the role "service_role"
--   (used ONLY by our own Edge Functions, never by the browser or the app) has
--   no table privileges. 0001 wrongly assumed it would. service_role bypasses
--   RLS but still needs plain GRANTs.
--
-- Rules
--   * service_role is a server-side secret role. It is never exposed to clients.
--   * payments: no DELETE, to keep the audit trail even for trusted code.
--
-- Safe to re-run (GRANT is idempotent).
-- =============================================================================

grant usage on schema public to service_role;

grant select, insert, update, delete on public.profiles        to service_role;
grant select, insert, update, delete on public.batches         to service_role;
grant select, insert, update, delete on public.batch_members   to service_role;
grant select, insert, update, delete on public.courses         to service_role;
grant select, insert, update, delete on public.course_access   to service_role;
grant select, insert, update, delete on public.comments        to service_role;
grant select, insert, update, delete on public.active_sessions to service_role;
grant select, insert, update         on public.payments        to service_role;  -- no delete: audit trail

-- =============================================================================
-- End of 0003_service_role_grants.sql
-- =============================================================================
