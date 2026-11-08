-- PostgreSQL 15+, Supabase SQL Editor. Read-only, one exportable result set.
-- Export ALL rows as CSV or JSON. Only catalog metadata, never customer rows.
-- Customize this sensitive-table heuristic for your application.
WITH findings AS (
  SELECT 'rls_disabled'::text AS rule, n.nspname::text AS schema_name,
         c.relname::text AS object_name, ''::text AS policy_name
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relrowsecurity
  UNION ALL
  SELECT 'policy_true', schemaname::text, tablename::text, policyname::text
  FROM pg_catalog.pg_policies
  WHERE schemaname = 'public' AND (
    regexp_replace(coalesce(qual, ''), '[()[:space:]]', '', 'g') = 'true'
    OR regexp_replace(coalesce(with_check, ''), '[()[:space:]]', '', 'g') = 'true')
  UNION ALL
  SELECT 'sensitive_anon_policy', schemaname::text, tablename::text, policyname::text
  FROM pg_catalog.pg_policies
  WHERE schemaname = 'public'
    AND roles && ARRAY['anon', 'public']::name[]
    AND tablename ~* '(user|profile|order|payment|invoice|customer|patient|secret|token|document)'
  UNION ALL
  SELECT 'definer_search_path', n.nspname::text,
         p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')', ''
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'public' AND p.prosecdef AND p.prokind = 'f'
    AND NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) cfg WHERE cfg LIKE 'search_path=%')
  UNION ALL
  -- Definer functions the anon role can EXECUTE via /rest/v1/rpc (trigger functions excluded).
  SELECT 'definer_anon_exec', n.nspname::text,
         p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')', ''
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'public' AND p.prosecdef AND p.prokind = 'f'
    AND p.prorettype <> 'pg_catalog.trigger'::pg_catalog.regtype
    AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = 'anon')
    AND pg_catalog.has_function_privilege('anon', p.oid, 'EXECUTE')
  UNION ALL
  SELECT 'view_not_invoker', n.nspname::text, c.relname::text, ''
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind = 'v'
    AND NOT EXISTS (SELECT 1 FROM unnest(c.reloptions) opt
                    WHERE opt IN ('security_invoker=true', 'security_invoker=on', 'security_invoker=1'))
  UNION ALL
  SELECT 'public_bucket', 'storage', name, '' FROM storage.buckets WHERE public = true
  UNION ALL
  SELECT 'public_extension', n.nspname::text, e.extname::text, ''
  FROM pg_catalog.pg_extension e
  JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
  WHERE n.nspname = 'public'
)
SELECT rule, schema_name, object_name, policy_name FROM findings
ORDER BY rule, schema_name, object_name, policy_name;
