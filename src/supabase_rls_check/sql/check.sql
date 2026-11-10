-- PostgreSQL 15+, Supabase SQL Editor. Read-only, one exportable result set.
-- Export ALL rows as CSV or JSON. Only catalog metadata, never customer rows.
-- Customize this sensitive-table heuristic for your application.
WITH policy_expressions AS (
  -- Keep USING and WITH CHECK separate so each expression is checked independently.
  SELECT p.schemaname, p.tablename, p.policyname, c.relrowsecurity, e.expression
  FROM pg_catalog.pg_policies p
  JOIN pg_catalog.pg_namespace n ON n.nspname = p.schemaname
  JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid AND c.relname = p.tablename
  CROSS JOIN LATERAL (VALUES (p.qual), (p.with_check)) e(expression)
  WHERE p.schemaname = 'public' AND e.expression IS NOT NULL
), findings AS (
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
  SELECT 'sensitive_anon_policy', p.schemaname::text, p.tablename::text, p.policyname::text
  FROM pg_catalog.pg_policies p
  JOIN pg_catalog.pg_namespace n ON n.nspname = p.schemaname
  JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid AND c.relname = p.tablename
  WHERE p.schemaname = 'public'
    AND p.roles && ARRAY['anon', 'public']::name[]
    AND (
      p.tablename ~* '(user|profile|order|payment|invoice|customer|patient|secret|token|document)'
      OR pg_catalog.obj_description(c.oid, 'pg_class') ~* '\mpii\M'
    )
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
  UNION ALL
  SELECT DISTINCT 'policy_user_metadata', schemaname::text, tablename::text, policyname::text
  FROM policy_expressions
  -- Allow deparsed casts, parentheses and SELECT aliases between the JWT and its key.
  -- Do not confuse a separate user_metadata literal with a key read from the JWT.
  WHERE expression ~* $re$\m(auth[.]jwt[[:space:]]*\([[:space:]]*\)|(?:pg_catalog[.])?current_setting[[:space:]]*\([[:space:]]*'request[.]jwt[.]claims'[^)]*\))([[:space:]()]|::[[:space:]]*(jsonb?|text)|AS[[:space:]]+[[:alnum:]_]+)*(->>?|#>>?)[[:space:]]*'(user_metadata|\{user_metadata(,[^']*)?\})'$re$
  UNION ALL
  SELECT DISTINCT 'policy_auth_per_row', schemaname::text, tablename::text, policyname::text
  FROM policy_expressions
  WHERE relrowsecurity
    -- Ignore strings, then remove each directly SELECT-wrapped call's prefix.
    -- Check what remains: one wrapped call must not hide another unwrapped call.
    AND regexp_replace(
          regexp_replace(expression, $re$'(?:[^']|'')*'$re$, '', 'g'),
          $re$\([[:space:]]*SELECT[[:space:]]+\(*[[:space:]]*(auth[.](uid|jwt|role)|(?:pg_catalog[.])?current_setting)[[:space:]]*\($re$,
          '', 'gi'
        ) ~* $re$\m(auth[.](uid|jwt|role)|(?:pg_catalog[.])?current_setting)[[:space:]]*\($re$
  UNION ALL
  SELECT 'auth_users_exposed', n.nspname::text, c.relname::text, ''
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind IN ('v', 'm')
    AND (c.relkind = 'm' OR NOT EXISTS (
      SELECT 1 FROM unnest(c.reloptions) opt
      WHERE opt IN ('security_invoker=true', 'security_invoker=on', 'security_invoker=1')
    ))
    AND EXISTS (
      SELECT 1 FROM pg_catalog.pg_roles r
      WHERE r.rolname IN ('anon', 'authenticated')
        AND pg_catalog.has_table_privilege(r.oid, c.oid, 'SELECT')
    )
    AND EXISTS (
      -- Resolve auth.users through catalogs: no failing regclass cast if auth is absent.
      -- EXISTS also avoids duplicate findings for dependencies on multiple columns.
      SELECT 1
      FROM pg_catalog.pg_rewrite rw
      JOIN pg_catalog.pg_depend d
        ON d.classid = 'pg_catalog.pg_rewrite'::pg_catalog.regclass AND d.objid = rw.oid
      JOIN pg_catalog.pg_class base
        ON d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass AND d.refobjid = base.oid
      JOIN pg_catalog.pg_namespace bn ON bn.oid = base.relnamespace
      WHERE rw.ev_class = c.oid AND bn.nspname = 'auth' AND base.relname = 'users'
    )
  UNION ALL
  SELECT 'matview_api_exposed', n.nspname::text, c.relname::text, ''
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind IN ('m', 'f')
    AND EXISTS (
      SELECT 1 FROM pg_catalog.pg_roles r
      WHERE r.rolname IN ('anon', 'authenticated')
        AND pg_catalog.has_table_privilege(r.oid, c.oid, 'SELECT')
    )
  UNION ALL
  SELECT DISTINCT 'public_bucket_listable', 'storage', b.name, p.policyname::text
  FROM storage.buckets b
  JOIN pg_catalog.pg_policies p
    ON p.schemaname = 'storage'
   AND p.tablename = 'objects'
   AND p.cmd IN ('SELECT', 'ALL')
   AND p.roles && ARRAY['anon', 'public']::name[]
   AND (
     position('''' || b.id || '''' in coalesce(p.qual, '')) > 0
     OR regexp_replace(coalesce(p.qual, ''), '[()[:space:]]', '', 'g') = 'true'
   )
  WHERE b.public = true
  UNION ALL
  SELECT DISTINCT 'policy_any_authenticated', schemaname::text, tablename::text, policyname::text
  FROM policy_expressions
  WHERE lower(
          regexp_replace(
            regexp_replace(
              regexp_replace(
                regexp_replace(expression, '::[[:space:]]*text\M', '', 'gi'),
                '\mSELECT[[:space:]]+',
                '',
                'gi'
              ),
              '[[:space:]]+AS[[:space:]]+[[:alnum:]_]+\M',
              '',
              'gi'
            ),
            '[()[:space:]]',
            '',
            'g'
          )
        -- Parentheses are stripped above, so auth.role() becomes auth.role here.
        ) IN ('auth.role=''authenticated''', 'auth.uidisnotnull')
)
SELECT rule, schema_name, object_name, policy_name FROM findings
ORDER BY rule, schema_name, object_name, policy_name;
