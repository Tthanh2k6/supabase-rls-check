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
}

SQL_RULES: tuple[str, ...] = (
    'rls_disabled',
    'policy_true',
    'sensitive_anon_policy',
    'definer_anon_exec',
    'definer_search_path',
    'view_not_invoker',
    'public_bucket',
    'public_extension',
)

SEVERITIES: list[str] = ['Critical', 'High', 'Medium', 'Low']
VI_SEVERITIES: list[str] = ['Nghiêm trọng', 'Cao', 'Trung bình', 'Thấp']
JWT = re.compile(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

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
            'explicit SELECT policy is safer against accidental write grants.'
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
    'sensitive_anon_policy': {
        'source': 'SQL catalog check (check.sql)',
        'why': (
            'A policy granted to anon or PUBLIC exists on a table whose name matches common sensitive '
            'patterns (users, profiles, orders, payments, invoices, customers, patients, secrets, tokens, '
            'documents). Unauthenticated callers holding the public anon key may reach rows matched by the policy.'
        ),
        'caveat': (
            'Name-based heuristic. Public profile cards or public storefront documents may be intentional; '
            'verify which columns and rows are actually exposed.'
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
}


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
    }
    if rule == 'anon_readable':
        result['columns'] = sorted({clean(c) for c in extra.get('columns', [])})
        count = extra.get('row_count')
        result['row_count'] = count if type(count) is int and count >= 0 else None
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
                item.get('policy_name', ''),
                columns=item.get('columns', []),
                row_count=item.get('row_count'),
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
