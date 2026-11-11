"""Rule definitions, metadata sanitization, export loading, and rule explanations."""
from __future__ import annotations

import csv
from importlib import resources
import json
from pathlib import Path
import re
from typing import Any

# severity, English title/remedy, Vietnamese title/remedy
RULES: dict[str, tuple[str, str, str, str, str]] = {
    'rls_disabled': (
        'High',
        'Row security is disabled',
        'Enable RLS and review grants and ownership policies before release.',
        'Chưa bật bảo mật cấp dòng',
        'Bật RLS, rà quyền truy cập và policy chủ sở hữu trước khi phát hành.',
    ),
    'policy_true': (
        'High',
        'Unconditional policy expression',
        'Review command, roles and permissive/restrictive policy combinations; replace overly broad policies.',
        'Policy có điều kiện luôn đúng',
        'Rà lệnh, role và tổ hợp policy; thay policy cấp quyền quá rộng.',
    ),
    'policy_true_writable': (
        'Critical',
        'Unconditional write policy on a writable table',
        'Drop the write policy or tie it to the row owner (using ((select auth.uid()) = user_id)), and revoke UPDATE/DELETE from anon if the API should never write that table.',
        'Policy cho phép sửa hoặc xóa mọi dòng trên bảng có quyền ghi',
        'Xóa policy ghi hoặc gắn với chủ sở hữu dòng (using ((select auth.uid()) = user_id)), đồng thời thu hồi quyền UPDATE/DELETE của anon nếu API không cần ghi bảng này.',
    ),
    'sensitive_anon_policy': (
        'High',
        'Anonymous role on a potentially sensitive table',
        'Confirm sensitivity and effective access; restrict policies to intended users.',
        'Role ẩn danh trên bảng có thể nhạy cảm',
        'Xác nhận tính nhạy cảm và quyền thực tế; giới hạn policy cho đúng người dùng.',
    ),
    'definer_anon_exec': (
        'High',
        'Definer function callable with the anon key',
        'Check the function verifies auth.uid() before acting; otherwise REVOKE EXECUTE FROM PUBLIC, anon (and authenticated if not needed).',
        'Hàm definer gọi được bằng anon key',
        'Kiểm hàm có kiểm auth.uid() trước khi làm; nếu không thì REVOKE EXECUTE FROM PUBLIC, anon (và authenticated nếu không cần).',
    ),
    'definer_search_path': (
        'High',
        'Definer function has no fixed search_path',
        'Review function body and EXECUTE grants; qualify object names and set a safe search_path.',
        'Hàm definer chưa cố định search_path',
        'Rà thân hàm, quyền EXECUTE; chỉ rõ schema và đặt search_path an toàn.',
    ),
    'view_not_invoker': (
        'High',
        'View does not use caller permissions',
        'Review underlying grants and use security_invoker on PostgreSQL 15+.',
        'View không dùng quyền người gọi',
        'Rà quyền bảng gốc và bật security_invoker trên PostgreSQL 15+.',
    ),
    'public_bucket': (
        'Medium',
        'Storage bucket is public',
        'Confirm public delivery is intentional; make private if sensitive and review storage.objects policies.',
        'Bucket Storage công khai',
        'Xác nhận mục đích công khai; chuyển riêng tư nếu nhạy cảm và rà policy storage.objects.',
    ),
    'public_extension': (
        'Low',
        'Extension installed in public',
        'Review extension relocatability and dependencies before moving to an extensions schema.',
        'Extension cài trong public',
        'Rà khả năng di chuyển và phụ thuộc trước khi chuyển sang schema extensions.',
    ),
    'policy_user_metadata': (
        'High',
        'Policy trusts user-editable JWT metadata',
        'Use server-managed app_metadata or an authorization table that users cannot write to.',
        'Policy phân quyền dựa trên metadata người dùng có thể tự sửa',
        'Dùng app_metadata do máy chủ quản lý hoặc bảng phân quyền mà người dùng không có quyền ghi.',
    ),
    'policy_auth_per_row': (
        'Low',
        'Policy evaluates authentication functions per row',
        'Wrap row-independent calls in a sub-select, for example (select auth.uid()), and compare query plans.',
        'Policy gọi hàm xác thực cho từng dòng',
        'Bọc lời gọi không phụ thuộc vào dòng trong truy vấn con, ví dụ (select auth.uid()), rồi so sánh kế hoạch thực thi.',
    ),
    'auth_users_exposed': (
        'Critical',
        'Public view exposes auth.users',
        'Drop the view or enable security_invoker on a regular view and revoke SELECT from anon/authenticated, including inherited grants. Expose only needed columns from a profiles table instead.',
        'View trong schema public làm lộ bảng auth.users',
        'Xóa view hoặc bật security_invoker cho view thường và thu hồi quyền SELECT của anon/authenticated, kể cả quyền kế thừa. Chỉ công khai các cột cần thiết từ bảng hồ sơ người dùng riêng.',
    ),
    'matview_api_exposed': (
        'High',
        'Materialized view or foreign table exposed to API roles',
        'Revoke SELECT from anon/authenticated and serve the data through a regular view with security_invoker = true, or move it to a schema the API does not expose.',
        'Materialized view hoặc bảng ngoại trong public cho phép role API đọc',
        'Thu hồi quyền SELECT của anon/authenticated và cung cấp dữ liệu qua view thường có security_invoker = true, hoặc chuyển sang schema không công khai qua API.',
    ),
    'public_bucket_listable': (
        'Medium',
        'Public Storage bucket allows listing all objects',
        'Drop the broad SELECT policy on storage.objects; public files stay reachable by URL, and if listing is needed, restrict it to authenticated owners.',
        'Bucket công khai có policy cho phép liệt kê toàn bộ tệp',
        'Xóa policy SELECT quá rộng trên storage.objects; tệp trong bucket công khai vẫn tải được qua URL, và nếu cần liệt kê thì chỉ giới hạn cho chủ sở hữu đã xác thực.',
    ),
    'policy_any_authenticated': (
        'Medium',
        'Policy allows any authenticated user',
        'Tie the row to the caller (for example (select auth.uid()) = user_id) or to a membership table; if every signed-in user really should see the table, say so in a table comment and accept the finding.',
        'Policy cho phép mọi người dùng đã đăng nhập',
        'Gắn dòng dữ liệu với người gọi (ví dụ (select auth.uid()) = user_id) hoặc bảng thành viên; nếu mọi người dùng đã đăng nhập thực sự được phép xem bảng, hãy ghi rõ trong comment của bảng và chấp nhận phát hiện.',
    ),
    'secret_column_exposed': (
        'Medium',
        'Secret-like column readable by API roles',
        'Move secrets to Supabase Vault, a private schema, or a server-only Edge Function, and revoke column SELECT (REVOKE SELECT (col) ON public.t FROM anon, authenticated).',
        'Cột nghi chứa khóa bí mật cho phép role API đọc',
        'Chuyển khóa bí mật sang Supabase Vault, schema riêng tư hoặc Edge Function phía máy chủ, đồng thời thu hồi quyền SELECT trên cột (REVOKE SELECT (col) ON public.t FROM anon, authenticated).',
    ),
    'definer_trusts_id_arg': (
        'Medium',
        'Definer function takes an ID argument without referencing auth.uid() or auth.jwt() (review needed)',
        'Review needed: verify the function checks caller identity with auth.uid() or auth.jwt() instead of trusting a caller-supplied ID argument, or revoke EXECUTE from anon/authenticated.',
        'Hàm definer nhận tham số ID nhưng không kiểm tra auth.uid() hoặc auth.jwt() (cần rà soát)',
        'Cần rà soát: xác minh hàm kiểm tra danh tính người gọi bằng auth.uid() hoặc auth.jwt() thay vì tin tưởng tham số ID do client truyền vào, hoặc thu hồi quyền EXECUTE của anon/authenticated.',
    ),
    'anon_readable': (
        'High',
        'Rows readable without login',
        'Confirm these rows are intended for the public; review RLS, policies and grants.',
        'Đọc được dòng dữ liệu không cần đăng nhập',
        'Xác nhận dữ liệu được phép công khai; rà RLS, policy và quyền truy cập.',
    ),
    'service_role_exposed': (
        'Critical',
        'Frontend contains a service_role JWT',
        'Treat as exposed: rotate/revoke the key, remove it from frontend bundles and review access logs. Signature and validity were not verified.',
        'Frontend chứa JWT service_role',
        'Xử lý như khóa đã lộ: thu hồi/đổi khóa, xóa khỏi frontend và rà nhật ký. Chưa xác minh chữ ký hoặc hiệu lực.',
    ),
    'public_env_service_role': (
        'Critical',
        'Public environment variable contains a Supabase service_role or secret key',
        'Move the secret to server-side code (Edge Function / API route), rotate the leaked key now, and keep only the anon/publishable key in the client.',
        'Biến môi trường công khai chứa khóa service_role hoặc khóa bí mật Supabase',
        'Chuyển khóa bí mật sang mã phía máy chủ (Edge Function / API route), đổi/xoay vòng khóa đã lộ ngay lập tức và chỉ giữ khóa anon/publishable ở phía client.',
    ),
    'public_env_secret_key': (
        'High',
        'Public environment variable exposes a secret key',
        'Move the secret to server-side code (Edge Function / API route), rotate the leaked key now, and keep only the anon/publishable key in the client.',
        'Biến môi trường công khai làm lộ khóa bí mật',
        'Chuyển khóa bí mật sang mã phía máy chủ (Edge Function / API route), đổi/xoay vòng khóa đã lộ ngay lập tức và chỉ giữ khóa anon/publishable ở phía client.',
    ),
    'service_role_in_client_code': (
        'Critical',
        'Client source code contains a Supabase service_role or secret key literal',
        'Move the secret to server-side code (Edge Function / API route), rotate the leaked key now, and keep only the anon/publishable key in the client.',
        'Mã nguồn client chứa trực tiếp khóa service_role hoặc khóa bí mật Supabase',
        'Chuyển khóa bí mật sang mã phía máy chủ (Edge Function / API route), đổi/xoay vòng khóa đã lộ ngay lập tức và chỉ giữ khóa anon/publishable ở phía client.',
    ),
    'db_url_in_client_code': (
        'Critical',
        'Client or app config contains a Postgres connection string with a password',
        'Remove the connection string from the app, rotate the database password now, and reach the database only from server-side code or through the Supabase API with the anon/publishable key.',
        'Mã nguồn hoặc cấu hình app chứa chuỗi kết nối Postgres kèm mật khẩu',
        'Xóa chuỗi kết nối khỏi app, đổi mật khẩu cơ sở dữ liệu ngay lập tức và chỉ truy cập cơ sở dữ liệu từ mã phía máy chủ hoặc qua Supabase API với khóa anon/publishable.',
    ),
    'agent_config_secret': (
        'Critical',
        'AI coding agent or MCP config file contains a database or Supabase secret',
        'Remove hardcoded secrets from agent/MCP config files, rotate the leaked credential immediately, and pass secrets via unversioned environment variables or OS keychain references.',
        'Tệp cấu hình AI agent hoặc MCP chứa khóa bí mật Supabase hoặc mật khẩu cơ sở dữ liệu',
        'Xóa khóa bí mật ghi cứng khỏi tệp cấu hình agent/MCP, xoay vòng/đổi thông tin xác thực đã lộ ngay lập tức và truyền bí mật qua biến môi trường không đưa vào git hoặc keychain hệ điều hành.',
    ),
}

SQL_RULES: tuple[str, ...] = (
    'rls_disabled',
    'policy_true',
    'policy_true_writable',
    'sensitive_anon_policy',
    'definer_anon_exec',
    'definer_search_path',
    'view_not_invoker',
    'public_bucket',
    'public_extension',
    'policy_user_metadata',
    'policy_auth_per_row',
    'auth_users_exposed',
    'matview_api_exposed',
    'public_bucket_listable',
    'policy_any_authenticated',
    'secret_column_exposed',
    'definer_trusts_id_arg',
)

ENV_RULES: tuple[str, ...] = (
    'public_env_service_role',
    'public_env_secret_key',
    'service_role_in_client_code',
    'db_url_in_client_code',
    'agent_config_secret',
)

SEVERITIES: list[str] = ['Critical', 'High', 'Medium', 'Low']
VI_SEVERITIES: list[str] = ['Nghiêm trọng', 'Cao', 'Trung bình', 'Thấp']
JWT = re.compile(r'eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}')

NOTES: dict[str, tuple[str, str]] = {
    'discovery_failed': (
        'OpenAPI discovery unavailable. Supply --tables from owner-approved inventory; coverage is incomplete.',
        'Không lấy được OpenAPI. Dùng --tables từ danh sách chủ dự án cung cấp; phạm vi chưa đầy đủ.',
    ),
    'site_incomplete': (
        'Frontend scan incomplete: blocked/failed resource, external script or scan limit. Only HTML and directly linked same-origin scripts are inspected.',
        'Quét frontend chưa đầy đủ: tài nguyên lỗi/bị chặn, script ngoài miền hoặc giới hạn quét. Chỉ đọc HTML và script liên kết trực tiếp cùng nguồn.',
    ),
    'probe_incomplete': (
        'Some table reads/counts failed or returned invalid responses; inspect observations.',
        'Một số lần đọc/đếm bảng lỗi hoặc phản hồi không hợp lệ; xem kết quả kiểm tra.',
    ),
}

RULE_GUIDES: dict[str, dict[str, str]] = {
    'rls_disabled': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'Tables in the public schema are exposed through Supabase PostgREST (/rest/v1/) by default. '
            'When Row Level Security (RLS) is disabled, any role holding table grants—often including '
            'anon and authenticated—can read or write rows without per-row ownership checks.'
        ),
        'caveat': (
            'Occasionally intentional for read-only public lookup tables, though enabling RLS with an '
            'explicit SELECT policy is safer against accidental write grants. When the table belongs to an '
            'extension (for example PostGIS spatial_ref_sys), basis reads "owned by extension <name>": the '
            'exposure is still reported, but ENABLE ROW LEVEL SECURITY fails there with "must be owner" on '
            'Supabase, so the guidance is to move the extension out of public into an extensions schema. '
            'Detection relies on pg_depend and only covers tables that are direct members of an extension.'
        ),
        'example': (
            'ALTER TABLE public.your_table ENABLE ROW LEVEL SECURITY;\n'
            '-- Replace user_id with the actual ownership column after reviewing existing policies:\n'
            'CREATE POLICY "owner_access" ON public.your_table\n'
            '  FOR ALL TO authenticated\n'
            '  USING ((SELECT auth.uid()) = user_id)\n'
            '  WITH CHECK ((SELECT auth.uid()) = user_id);'
        ),
    },
    'policy_true': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'A policy whose USING or WITH CHECK expression evaluates unconditionally to true grants access '
            'to every row for the targeted command and roles. Because permissive policies combine with OR, '
            'leaving a broad USING (true) policy active overrides stricter policies on the same command.'
        ),
        'caveat': (
            'Commonly intentional for FOR SELECT policies on genuinely public content (for example, '
            'published blog posts or product catalogs), but dangerous on user-owned data or write commands.'
        ),
        'example': (
            'DROP POLICY IF EXISTS "allow_everyone" ON public.your_table;\n'
            'CREATE POLICY "authenticated_own_rows" ON public.your_table\n'
            '  FOR SELECT TO authenticated\n'
            '  USING ((SELECT auth.uid()) = user_id);'
        ),
    },
    'policy_true_writable': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'A permissive policy in public for UPDATE, DELETE, or ALL has an unconditional USING (true) '
            'expression on a table where anon or authenticated holds UPDATE or DELETE privileges. '
            'Anyone with that role can change or delete every row through the Data API, which is worse '
            'than the read leak policy_true already reports.'
        ),
        'caveat': (
            'Almost never intentional on API-exposed tables. policy_true also fires for the same policy; '
            'that overlap is intentional so unconditional write policies are highlighted at Critical severity.'
        ),
        'example': (
            '-- Drop the write policy or tie it to the row owner:\n'
            '-- DROP POLICY IF EXISTS "your_write_policy" ON public.your_table;\n'
            '-- CREATE POLICY "owner_update" ON public.your_table\n'
            '--   FOR UPDATE TO authenticated\n'
            '--   USING ((select auth.uid()) = user_id)\n'
            '--   WITH CHECK ((select auth.uid()) = user_id);\n'
            '-- Revoke UPDATE/DELETE from anon if the API should never write that table:\n'
            '-- REVOKE UPDATE, DELETE ON public.your_table FROM anon;'
        ),
    },
    'sensitive_anon_policy': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'A policy granted to anon or PUBLIC exists on a table whose name matches common sensitive '
            'patterns (users, profiles, orders, payments, invoices, customers, patients, secrets, tokens, '
            'documents) or whose table comment contains the word "pii". Unauthenticated callers holding '
            'the public anon key may reach rows matched by the policy.'
        ),
        'caveat': (
            'Name-based heuristic plus explicit COMMENT ON TABLE ... IS \'pii\' tagging. Public profile cards '
            'or public storefront documents may be intentional; verify which columns and rows are actually exposed.'
        ),
        'example': (
            'ALTER POLICY "your_policy" ON public.profiles TO authenticated;\n'
            '-- Or split public columns into a dedicated table/view with explicit column grants.'
        ),
    },
    'definer_anon_exec': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'PostgreSQL grants EXECUTE on new functions to PUBLIC by default, and SECURITY DEFINER functions '
            'run with the privileges of the function owner (typically bypassing caller RLS). Non-trigger '
            'functions in public are callable without login via POST /rest/v1/rpc/<function_name> using the anon key.'
        ),
        'caveat': (
            'Safe only if the function is intentionally public and validates all inputs and authorization '
            'explicitly inside its body.'
        ),
        'example': (
            'REVOKE EXECUTE ON FUNCTION public.your_function(uuid) FROM PUBLIC, anon;\n'
            '-- Grant only to the role that actually needs RPC access:\n'
            'GRANT EXECUTE ON FUNCTION public.your_function(uuid) TO authenticated;'
        ),
    },
    'definer_search_path': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'A SECURITY DEFINER function without a fixed search_path inherits the caller search_path at '
            'execution time. If any writable schema precedes target schemas or unqualified object names are '
            'used, callers may hijack function resolution under elevated owner privileges.'
        ),
        'caveat': (
            'Even when schemas are not writable by end users, PostgreSQL security guidance recommends '
            'pinning search_path on every SECURITY DEFINER function.'
        ),
        'example': (
            'ALTER FUNCTION public.your_function()\n'
            '  SET search_path = pg_catalog, public;'
        ),
    },
    'view_not_invoker': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'In PostgreSQL, views default to security_invoker = false, meaning queries against underlying '
            'tables execute with the view owner permissions and can bypass RLS on the base tables when the '
            'view is exposed in public via PostgREST.'
        ),
        'caveat': (
            'Sometimes used intentionally as a controlled projection over a private table; if so, verify '
            'exact column list, row filter, and view grants.'
        ),
        'example': (
            'ALTER VIEW public.your_view SET (security_invoker = true);'
        ),
    },
    'public_bucket': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'Objects inside a Supabase Storage bucket marked public = true can be downloaded without '
            'authentication or signed URLs by anyone who knows or guesses the object path.'
        ),
        'caveat': (
            'Expected for public avatars, marketing images, or public downloads; inappropriate for '
            'invoices, identity documents, or private user uploads.'
        ),
        'example': (
            'UPDATE storage.buckets SET public = false WHERE name = \'your_bucket\';\n'
            '-- Then enforce per-user policies on storage.objects and serve private files via signed URLs.'
        ),
    },
    'public_extension': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'Installing PostgreSQL extensions directly into public mixes extension functions, operators, and '
            'tables into the PostgREST-exposed schema and complicates privilege management.'
        ),
        'caveat': (
            'Low severity hygiene finding. Some extensions are not relocatable after installation or are '
            'referenced without schema qualification by existing queries.'
        ),
        'example': (
            'CREATE SCHEMA IF NOT EXISTS extensions;\n'
            'ALTER EXTENSION pg_trgm SET SCHEMA extensions;'
        ),
    },
    'policy_user_metadata': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'A public policy reads user_metadata from auth.jwt() or request.jwt.claims. '
            'End users can edit this metadata, so trusting its roles or permissions for authorization '
            'can let them bypass the policy.'
        ),
        'caveat': (
            'Expression matching is a heuristic, not a SQL parser or a proof of effective access. '
            'Review USING and WITH CHECK, including any other predicates. app_metadata is server-managed, '
            'but JWT claims may remain stale until the token is refreshed.'
        ),
        'example': (
            '-- Review the full policy and keep existing ownership/tenant checks.\n'
            '-- Use a server-managed claim, for example:\n'
            "-- ((SELECT auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin'\n"
            '-- Or query a separate authorization table that end users cannot modify.'
        ),
    },
    'policy_auth_per_row': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'An RLS-enabled public table has a policy with an unwrapped auth.uid(), auth.jwt(), '
            'auth.role(), or current_setting() call. Evaluating these calls for every row can slow '
            'queries on large tables. A scalar sub-select lets PostgreSQL evaluate a row-independent '
            'call once per statement through an initPlan. This is a performance finding, not a vulnerability.'
        ),
        'caveat': (
            'The check recognizes directly SELECT-wrapped calls in deparsed policy expressions; '
            'more complex subqueries may require manual review. Only cache calls whose arguments '
            'and results do not depend on the current row. Compare EXPLAIN plans and timings.'
        ),
        'example': (
            '-- In both USING and WITH CHECK, replace auth.uid() = user_id with:\n'
            '-- (select auth.uid()) = user_id\n'
            '-- Apply the same pattern to row-independent auth.jwt(), auth.role(), and current_setting().'
        ),
    },
    'auth_users_exposed': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'A public view or materialized view directly depends on auth.users and anon or authenticated '
            'has SELECT privileges. A regular view without security_invoker can expose Auth data with '
            'owner privileges; a materialized view exposes its stored snapshot.'
        ),
        'caveat': (
            'Review the selected columns and effective grants, including PUBLIC and inherited roles. '
            'Materialized views cannot be hardened with security_invoker. This check follows direct '
            'catalog dependencies, not chains of views; an unflagged view is not proof of safety.'
        ),
        'example': (
            '-- Drop the exposed view if it is not required. For a regular view retained after review:\n'
            '-- ALTER VIEW public.your_view SET (security_invoker = true);\n'
            '-- REVOKE SELECT ON public.your_view FROM PUBLIC, anon, authenticated;\n'
            '-- Also remove inherited access where necessary.\n'
            '-- For materialized views, revoke access or drop the materialized view.\n'
            '-- Publish only needed profile columns from a separate table with appropriate RLS.'
        ),
    },
    'matview_api_exposed': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'A materialized view or foreign table in public grants SELECT to anon or authenticated. '
            'Row Level Security does not apply to materialized views or foreign tables, so every row '
            'is readable through the Data API (/rest/v1/).'
        ),
        'caveat': (
            'Public precomputed aggregates may be intentional, but any underlying sensitive columns or rows '
            'stored in the materialized view or foreign table are readable in full by API callers. '
            'Materialized views over auth.users also trigger auth_users_exposed.'
        ),
        'example': (
            '-- Revoke direct API access and expose filtered rows through an invoker view, or move schemas:\n'
            '-- REVOKE SELECT ON public.your_matview FROM PUBLIC, anon, authenticated;\n'
            '-- ALTER MATERIALIZED VIEW public.your_matview SET SCHEMA private;'
        ),
    },
    'public_bucket_listable': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'A Storage bucket marked public = true also has a SELECT or ALL policy on storage.objects '
            'for anon or PUBLIC whose USING expression mentions that bucket id or is unconditionally true. '
            'Public buckets serve files by URL without any policy; such a SELECT policy additionally lets '
            'anyone list every file name in the bucket through the Storage API.'
        ),
        'caveat': (
            'Intentional only if callers are meant to browse and enumerate all objects in the bucket without '
            'authentication. Note that public_bucket also fires for the same bucket.'
        ),
        'example': (
            '-- Drop the broad SELECT policy; public files stay reachable by direct URL:\n'
            '-- DROP POLICY IF EXISTS "your_select_policy" ON storage.objects;\n'
            '-- If listing is needed, restrict SELECT on storage.objects to authenticated owners.'
        ),
    },
    'policy_any_authenticated': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'A policy in public has a USING or WITH CHECK expression that only checks whether the caller '
            'is signed in (auth.role() = \'authenticated\' or auth.uid() IS NOT NULL). Because email signup '
            'is enabled by default in Supabase projects, any signed-in account receives the same access to '
            'every row matched by the policy.'
        ),
        'caveat': (
            'Intentional only when every signed-in user should see or modify the table. If so, document '
            'that intent in a table comment and accept the finding.'
        ),
        'example': (
            '-- Tie the row to the caller or to a membership table:\n'
            '-- ALTER POLICY "your_policy" ON public.your_table\n'
            '--   USING ((select auth.uid()) = user_id)\n'
            '--   WITH CHECK ((select auth.uid()) = user_id);\n'
            '-- Or document intentional shared access in a table comment and accept the finding:\n'
            "-- COMMENT ON TABLE public.your_table IS 'shared across all authenticated users';"
        ),
    },
    'secret_column_exposed': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'A table in public has a column whose name matches or ends with a secret token '
            '(api_key, apikey, secret, client_secret, access_token, refresh_token, private_key, '
            'or password) and anon or authenticated holds SELECT privileges on the table or that column. '
            'RLS can limit rows to the owner, but the client still receives the plaintext secret whenever '
            'SELECT * or that column is queried through the Data API.'
        ),
        'caveat': (
            'Column-name heuristic (basis reports the column name). RLS can limit rows to the owner, '
            'but the client still receives the plaintext secret. If a column stores a non-secret value, '
            'rename it or accept the finding after review.'
        ),
        'example': (
            '-- Move third-party API keys and secrets to Supabase Vault, a private schema, or a server-only Edge Function.\n'
            '-- Or revoke SELECT on the secret column from API roles (requires column-level SELECT grants on remaining columns):\n'
            '-- REVOKE SELECT ON public.t FROM PUBLIC, anon, authenticated;\n'
            '-- GRANT SELECT (id, user_id) ON public.t TO authenticated;\n'
            '-- REVOKE SELECT (col) ON public.t FROM anon, authenticated;'
        ),
    },
    'definer_trusts_id_arg': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'A SECURITY DEFINER function in public is executable by anon or authenticated, accepts '
            'an argument whose name ends with _id or equals uid, user, org, or tenant, and its body '
            '(prosrc) does not mention auth.uid() or auth.jwt(). Because SECURITY DEFINER runs with '
            'owner privileges and bypasses RLS, trusting a caller-supplied user or tenant ID without '
            'verifying the caller can let one user access another user\'s data via /rest/v1/rpc/*.'
        ),
        'caveat': (
            'Review needed: this static prosrc heuristic has honest limits. It misses functions that '
            'call a helper which reads auth.uid(), and may flag functions that check the id against '
            'a membership table.'
        ),
        'example': (
            '-- Derive the caller from auth.uid() inside the function or verify ownership explicitly:\n'
            '-- IF p_user_id IS DISTINCT FROM auth.uid() THEN\n'
            "--   RAISE EXCEPTION 'permission denied';\n"
            '-- END IF;\n'
            '-- Or revoke RPC execution if clients should not call the function directly:\n'
            '-- REVOKE EXECUTE ON FUNCTION public.get_user_orders(uuid) FROM PUBLIC, anon, authenticated;'
        ),
    },
    'anon_readable': {
        'source': 'Anonymous HTTP probe (probe)',
        'why': (
            'An unauthenticated GET/HEAD request to PostgREST using only the public anon or publishable key '
            'returned at least one visible row. Anyone inspecting browser network traffic can read these '
            'columns and rows.'
        ),
        'caveat': (
            'Public catalogs, landing-page content, or announcements are meant to be readable without login. '
            'Review exposed column names and row count to confirm no private attributes leak.'
        ),
        'example': (
            'ALTER TABLE public.your_table ENABLE ROW LEVEL SECURITY;\n'
            '-- Remove or tighten policies granted to anon / PUBLIC, and verify column-level grants.'
        ),
    },
    'service_role_exposed': {
        'source': 'Frontend bundle scan (probe --site)',
        'why': (
            'A JWT whose payload decodes to role = "service_role" was detected in public HTML or a same-origin '
            'JavaScript bundle. The service_role key bypasses all Row Level Security policies across the project.'
        ),
        'caveat': (
            'JWT signatures and active validity are not verified by this scanner, but any service_role token '
            'shipped to browsers must be treated as compromised immediately.'
        ),
        'example': (
            '1. Rotate/revoke the exposed service_role / secret API key in Supabase Dashboard immediately.\n'
            '2. Move privileged operations to server-side backends or Edge Functions using environment secrets.\n'
            '3. Redeploy frontend assets, purge CDN caches, and audit database/storage logs.'
        ),
    },
    'public_env_service_role': {
        'source': 'Local public-env scan (scan-env)',
        'why': (
            'A variable with a client-bundled prefix (EXPO_PUBLIC_, NEXT_PUBLIC_, VITE_, REACT_APP_, '
            'PUBLIC_, or NUXT_PUBLIC_) contains a Supabase service_role JWT or sb_secret_ key. Build tools '
            'inline these variables directly into browser or mobile bundles, giving every user full '
            'RLS-bypassing privileges.'
        ),
        'caveat': (
            'Local static scan only; token signatures and live validity are not checked over the network. '
            'Any real service_role or sb_secret_ key in a public env file must be rotated immediately.'
        ),
        'example': (
            '1. Move the secret to server-side code (Edge Function or API route) without a public prefix.\n'
            '2. Rotate the leaked service_role / sb_secret_ key in the Supabase Dashboard now.\n'
            '3. Keep only the anon JWT or sb_publishable_ key in client environment variables.'
        ),
    },
    'public_env_secret_key': {
        'source': 'Local public-env scan (scan-env)',
        'why': (
            'A public-prefixed environment variable (EXPO_PUBLIC_, NEXT_PUBLIC_, VITE_, REACT_APP_, '
            'PUBLIC_, or NUXT_PUBLIC_) either starts with a known secret key prefix (sk_live_, rk_live_, '
            'sk-proj-, sk-ant-) or has a name containing SERVICE_ROLE, SECRET, or PRIVATE_KEY. These '
            'variables are bundled into client apps and readable by end users.'
        ),
        'caveat': (
            'Name-only matches ("name suggests a secret") are a naming heuristic; verify whether the value '
            'is sensitive or rename the variable if it stores a non-secret public value.'
        ),
        'example': (
            '1. Move the secret to server-side code (Edge Function or API route) using server-only env vars.\n'
            '2. Rotate the leaked key in the provider dashboard now.\n'
            '3. Keep only the anon/publishable key in the client.'
        ),
    },
    'service_role_in_client_code': {
        'source': 'Local public-env scan (scan-env)',
        'why': (
            'A hardcoded Supabase service_role JWT or sb_secret_ literal was found in a client-side source '
            'file outside server/Edge Function directories. Shipping a service_role or sb_secret_ key in '
            'client code bypasses all Row Level Security policies for anyone who inspects the app bundle.'
        ),
        'caveat': (
            'Files under supabase/functions/, server/, api/, scripts/, and backend/ are excluded by path '
            'heuristic. Secrets in server code should still be read from environment variables. The scan '
            'also covers app.json, app.config.* and eas.json. The anon/publishable key is expected in a '
            'client app and is not reported. Detection is pattern-based and can miss obfuscated or '
            'split-up keys.'
        ),
        'example': (
            '1. Move the secret and privileged logic to server-side code (Edge Function or API route).\n'
            '2. Rotate the leaked service_role / sb_secret_ key in the Supabase Dashboard now.\n'
            '3. Keep only the anon/publishable key in the client.'
        ),
    },
    'db_url_in_client_code': {
        'source': 'Local public-env scan (scan-env)',
        'why': (
            'A postgres:// or postgresql:// connection string with an inline password was found in a '
            'client-bundled file (React Native / Expo source, app.json, app.config.*, or eas.json). '
            'Anything shipped in an app bundle can be extracted, and the database password grants direct '
            'database access that bypasses PostgREST and Row Level Security.'
        ),
        'caveat': (
            'Pattern-based: only literal URLs with a user:password@ part on a single line are matched, '
            'and obfuscated, concatenated, or encoded values can be missed. Placeholders such as '
            '${DB_PASSWORD} are ignored. Files under supabase/functions/, server/, api/, scripts/, and '
            'backend/ are excluded by path heuristic.'
        ),
        'example': (
            '1. Remove the connection string from the app source and config.\n'
            '2. Reset the database password in the Supabase Dashboard now.\n'
            '3. Query data through supabase-js with the anon/publishable key and RLS, or from server-side code.'
        ),
    },
    'agent_config_secret': {
        'source': 'Local public-env scan (scan-env)',
        'why': (
            'An AI coding agent or MCP configuration file (.claude/settings.json, '
            '.claude/settings.local.json, .cursor/mcp.json, .mcp.json, or .vscode/mcp.json) '
            'contains a Supabase sb_secret_ key, a service_role JWT, or a PostgreSQL connection '
            'string with an inline password. These workspace files are frequently committed to '
            'repositories or shared in bug reports by mistake.'
        ),
        'caveat': (
            'Even when a local settings file is listed in .gitignore, storing plaintext service_role '
            'keys or database passwords on disk exposes them to other local processes and accidental commits.'
        ),
        'example': (
            '1. Remove the secret from .claude/settings*.json, .cursor/mcp.json, .mcp.json, or .vscode/mcp.json.\n'
            '2. Rotate the leaked Supabase secret key or database password in the Supabase Dashboard immediately.\n'
            '3. Add local agent config files to .gitignore and reference runtime environment variables instead of inline credentials.'
        ),
    },
}


EXTENSION_BASIS_PREFIX = 'owned by extension '

# Remediation for rls_disabled findings on tables owned by an extension (English, Vietnamese).
EXTENSION_REMEDY: tuple[str, str] = (
    'The table belongs to an extension, so ENABLE ROW LEVEL SECURITY fails with "must be owner" on '
    'Supabase. Move the extension out of public into an extensions schema (for example a new "extensions" '
    'schema) so PostgREST no longer exposes its tables. Check that the extension is relocatable first.',
    'Bảng thuộc một extension nên ENABLE ROW LEVEL SECURITY sẽ lỗi "must be owner" trên Supabase. '
    'Chuyển extension khỏi public sang schema extensions để PostgREST không còn lộ bảng này. '
    'Kiểm tra trước xem extension có di chuyển được (relocatable) không.',
)


def extension_owner(item: dict[str, Any]) -> str:
    """Return the extension name for an rls_disabled finding owned by an extension, else ''."""
    if item.get('rule') != 'rls_disabled':
        return ''
    basis = item.get('basis') or ''
    return basis[len(EXTENSION_BASIS_PREFIX):] if basis.startswith(EXTENSION_BASIS_PREFIX) else ''


def clean(value: str) -> str:
    """Retain bounded metadata; never persist JWT strings in metadata."""
    if not isinstance(value, str):
        raise ValueError('Metadata must be text')
    return JWT.sub('[REDACTED]', ''.join(c for c in value if c.isprintable()))[:500]


def finding(
    rule: str,
    schema_name: str = '',
    object_name: str = '',
    policy_name: str = '',
    basis: str = '',
    **extra: Any,
) -> dict[str, Any]:
    """Build a normalized finding dictionary without raw row values."""
    if rule not in RULES:
        raise ValueError('Unknown finding rule')
    result: dict[str, Any] = {
        'rule': rule,
        'schema_name': clean(schema_name),
        'object_name': clean(object_name),
        'policy_name': clean(policy_name),
        'basis': clean(basis or ''),
    }
    if rule == 'anon_readable':
        result['columns'] = sorted({clean(c) for c in extra.get('columns', [])})
        count = extra.get('row_count')
        result['row_count'] = count if type(count) is int and count >= 0 else None
    elif rule in ENV_RULES:
        result['severity'] = RULES[rule][0]
        if extra.get('file') is not None:
            result['file'] = clean(str(extra['file']))
        line = extra.get('line')
        if type(line) is int and line > 0:
            result['line'] = line
        if extra.get('variable') is not None:
            result['variable'] = clean(str(extra['variable']))
        if extra.get('masked_value') is not None:
            result['masked_value'] = clean(str(extra['masked_value']))
        if extra.get('reason') is not None:
            result['reason'] = clean(str(extra['reason']))
    return result


def load_result(path: str | Path) -> dict[str, Any]:
    """Accept SQL export or our result envelope, dropping unknown/raw fields."""
    path = Path(path)
    with path.open(encoding='utf-8-sig', newline='') as stream:
        if path.suffix.lower() == '.csv':
            reader = csv.DictReader(stream)
            if not {'rule', 'schema_name', 'object_name'}.issubset(reader.fieldnames or []):
                raise ValueError('Missing CSV metadata headers')
            data: Any = list(reader)
        else:
            data = json.load(stream)
    notes: list[str] = []
    observations: list[dict[str, str]] = []
    if isinstance(data, dict):
        if not isinstance(data.get('notes', []), list) or not isinstance(data.get('observations', []), list):
            raise ValueError('Invalid result envelope')
        notes = [n for n in data.get('notes', []) if n in NOTES]
        for item in data.get('observations', []):
            if not isinstance(item, dict):
                raise ValueError('Invalid observation')
            status = item.get('status')
            if status not in ('readable', 'empty', 'denied', 'error'):
                raise ValueError('Invalid observation')
            observations.append({'table': clean(item['table']), 'status': status})
        data = data.get('findings')
    if not isinstance(data, list):
        raise ValueError('Expected JSON array or findings envelope')
    rows: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict) or not all(k in item for k in ('rule', 'schema_name', 'object_name')):
            raise ValueError('Expected rule, schema_name, object_name columns')
        if not isinstance(item.get('columns', []), list):
            raise ValueError('Columns must be a list')
        rows.append(
            finding(
                item['rule'],
                item['schema_name'],
                item['object_name'],
                item.get('policy_name') or '',
                item.get('basis') or '',
                columns=item.get('columns', []),
                row_count=item.get('row_count'),
                file=item.get('file'),
                line=item.get('line'),
                variable=item.get('variable'),
                masked_value=item.get('masked_value'),
                reason=item.get('reason'),
            )
        )
    return {'findings': rows, 'notes': notes, 'observations': observations}


def explain_rule(rule: str, lang: str = 'en') -> str:
    """Return a detailed explanation and remediation guide for a single rule."""
    if lang not in ('en', 'vi'):
        raise ValueError("Language must be 'en' or 'vi'")
    if not isinstance(rule, str):
        raise ValueError(f"Unknown rule. Available rules: {', '.join(RULES)}")
    key = rule.strip().lower()
    if key not in RULES:
        safe = clean(rule.strip())[:80]
        raise ValueError(f"Unknown rule '{safe}'. Available rules: {', '.join(RULES)}")
    severity, en_title, en_remedy, vi_title, vi_remedy = RULES[key]
    guide = RULE_GUIDES[key]
    if lang == 'vi':
        vi_sev = VI_SEVERITIES[SEVERITIES.index(severity)]
        return (
            f'Luật / Rule: {key}\n'
            f'Mức độ / Severity: {vi_sev} ({severity})\n'
            f'Tiêu đề / Title: {vi_title}\n'
            f'Nguồn / Source: {guide["source"]}\n\n'
            f'Giải thích (EN):\n{guide["why"]}\n\n'
            f'Lưu ý ngữ cảnh:\n{guide["caveat"]}\n\n'
            f'Cách sửa:\n{vi_remedy}\n\n'
            f'Ví dụ minh họa (rà soát trên staging trước khi áp dụng):\n{guide["example"]}'
        )
    return (
        f'Rule: {key}\n'
        f'Severity: {severity}\n'
        f'Title: {en_title}\n'
        f'Source: {guide["source"]}\n\n'
        f'Why it matters:\n{guide["why"]}\n\n'
        f'When it may be intentional:\n{guide["caveat"]}\n\n'
        f'How to fix:\n{en_remedy}\n\n'
        f'Example remediation (review and test on staging first):\n{guide["example"]}'
    )


def get_check_sql_path() -> Path:
    """Return filesystem path to the bundled check.sql file."""
    return Path(__file__).resolve().parent / 'sql' / 'check.sql'


def read_check_sql() -> str:
    """Read the bundled read-only check.sql query text."""
    try:
        return resources.files('supabase_rls_check.sql').joinpath('check.sql').read_text(encoding='utf-8')
    except (FileNotFoundError, ModuleNotFoundError, TypeError):
        return get_check_sql_path().read_text(encoding='utf-8')
