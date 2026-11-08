-- REVIEW TEMPLATE ONLY. Never applied by this tool.
-- Test on staging; export existing policies/grants for rollback first.
-- RLS may block legitimate app traffic. Broad existing policies can still grant access.
-- CHANGE user_id to the actual ownership column.
-- Check column type (UUID), tenant model, existing policies and application flows.
BEGIN;
ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;
-- Example only; review/remove broad existing policies before enabling this policy.
-- CREATE POLICY "audit_owner_access" ON "public"."profiles"
--   FOR ALL TO authenticated
--   USING ((SELECT auth.uid()) = user_id)
--   WITH CHECK ((SELECT auth.uid()) = user_id);
ALTER TABLE "public"."todos" ENABLE ROW LEVEL SECURITY;
-- Example only; review/remove broad existing policies before enabling this policy.
-- CREATE POLICY "audit_owner_access" ON "public"."todos"
--   FOR ALL TO authenticated
--   USING ((SELECT auth.uid()) = user_id)
--   WITH CHECK ((SELECT auth.uid()) = user_id);
-- Review every other finding manually; do not infer fixes from names alone.
-- Owner: self-check write access using SQL on staging, including two-user isolation.
ROLLBACK; -- Deliberate dry run. Change to COMMIT only after review and staging tests.
