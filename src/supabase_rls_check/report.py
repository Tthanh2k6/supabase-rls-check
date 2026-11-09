"""Standalone HTML/Markdown report rendering and rollback-first fix.sql generation."""
from __future__ import annotations

import base64
from collections.abc import Sequence
import html
from importlib import resources
import json
from pathlib import Path
from typing import Any

from .rules import NOTES, RULES, SEVERITIES, VI_SEVERITIES, clean


def quote_identifier(value: str) -> str:
    """Safely quote a PostgreSQL identifier."""
    return '"' + value.replace('"', '""') + '"'


def deduplicate_and_sort_findings(results: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate findings across inputs and sort by severity, object, and rule."""
    unique = {json.dumps(f, sort_keys=True): f for r in results for f in r['findings']}
    return sorted(
        unique.values(),
        key=lambda f: (SEVERITIES.index(RULES[f['rule']][0]), f['object_name'], f['rule']),
    )


def fix_sql(findings: Sequence[dict[str, Any]], lang: str = 'en') -> str:
    """Generate a dry-run SQL review template ending in ROLLBACK."""
    ownership_comment = (
        '-- SỬA cột user_id cho đúng / CHANGE user_id to the actual ownership column.'
        if lang == 'vi'
        else '-- CHANGE user_id to the actual ownership column.'
    )
    lines = [
        '-- REVIEW TEMPLATE ONLY. Never applied by this tool.',
        '-- Test on staging; export existing policies/grants for rollback first.',
        '-- RLS may block legitimate app traffic. Broad existing policies can still grant access.',
        ownership_comment,
        '-- Check column type (UUID), tenant model, existing policies and application flows.',
        'BEGIN;',
    ]
    tables = sorted(
        {
            (f['schema_name'], f['object_name'])
            for f in findings
            if f['rule'] in ('rls_disabled', 'policy_true', 'sensitive_anon_policy')
        }
    )
    for schema, table in tables:
        target = quote_identifier(schema) + '.' + quote_identifier(table)
        lines += [
            f'ALTER TABLE {target} ENABLE ROW LEVEL SECURITY;',
            '-- Example only; review/remove broad existing policies before enabling this policy.',
            f'-- CREATE POLICY "audit_owner_access" ON {target}',
            '--   FOR ALL TO authenticated',
            '--   USING ((SELECT auth.uid()) = user_id)',
            '--   WITH CHECK ((SELECT auth.uid()) = user_id);',
        ]
    for f in findings:
        if f['rule'] in ('policy_user_metadata', 'policy_auth_per_row', 'auth_users_exposed'):
            target = clean(f['schema_name']) + '.' + clean(f['object_name'])
            policy = ': ' + clean(f['policy_name']) if f['policy_name'] else ''
            remedy = RULES[f['rule']][4 if lang == 'vi' else 2]
            lines += [f"-- {f['rule']}: {target}{policy}", f'-- {remedy}']
    lines += [
        '-- Review every other finding manually; do not infer fixes from names alone.',
        '-- Owner: self-check write access using SQL on staging, including two-user isolation.',
        'ROLLBACK; -- Deliberate dry run. Change to COMMIT only after review and staging tests.',
    ]
    return '\n'.join(lines) + '\n'


def _load_font_bytes(filename: str) -> bytes | None:
    """Load embedded report font bytes from package resources or repository assets."""
    try:
        return resources.files('supabase_rls_check.assets').joinpath(filename).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, TypeError):
        pass
    here = Path(__file__).resolve()
    for candidate_dir in (here.parent / 'assets', here.parents[2] / 'assets'):
        candidate = candidate_dir / filename
        if candidate.is_file():
            return candidate.read_bytes()
    return None


def report(
    results: Sequence[dict[str, Any]],
    output: str | Path,
    lang: str = 'en',
    project: str = 'Supabase app',
) -> None:
    """Write standalone report.md, report.html, and fix.sql into output directory."""
    vi = lang == 'vi'
    pick = lambda en, vn: vn if vi else en
    findings = deduplicate_and_sort_findings(results)
    notes = sorted({n for r in results for n in r['notes']})
    project = clean(project)
    title = pick('Supabase security review', 'Kiểm tra bảo mật Supabase')
    summary = pick(
        f'{len(findings)} findings need review. Address critical and high risks first. Configuration flags do not by themselves prove data exposure or write access.',
        f'Có {len(findings)} phát hiện cần rà soát. Ưu tiên mức nghiêm trọng và cao. Cảnh báo cấu hình không tự chứng minh việc lộ dữ liệu hoặc quyền ghi.',
    )
    scope = pick(
        'Limited review of supplied metadata and/or anonymous read probes. No security certification. An empty result is not proof of safety. Public data may be intentional. Row values and keys are not saved.',
        'Kiểm tra giới hạn trên metadata được cung cấp và/hoặc phép đọc ẩn danh. Không chứng nhận bảo mật. Kết quả rỗng không chứng minh an toàn. Dữ liệu công khai có thể là chủ đích. Không lưu giá trị dòng hoặc khóa.',
    )
    next_steps = pick(
        'Review fix.sql on staging; export current policies/grants for rollback. The owner should self-check write access using SQL and test isolation between two users. Re-run checks after changes. No write tests were performed.',
        'Rà fix.sql trên staging; xuất policy/quyền hiện tại để khôi phục. Khuyến nghị chủ dự án tự kiểm ghi bằng SQL và kiểm tra cách ly hai người dùng. Chạy lại sau khi sửa. Công cụ không thực hiện kiểm ghi.',
    )
    headings = [
        pick('Severity', 'Mức độ'),
        pick('Finding / object', 'Phát hiện / đối tượng'),
        pick('Evidence', 'Bằng chứng'),
        pick('Remediation', 'Cách sửa'),
    ]
    table_rows = []
    for f in findings:
        rule = RULES[f['rule']]
        severity = VI_SEVERITIES[SEVERITIES.index(rule[0])] if vi else rule[0]
        evidence = f['rule'] + (': ' + f['policy_name'] if f['policy_name'] else '')
        if f['rule'] == 'anon_readable':
            evidence += pick('; columns: ', '; cột: ') + ', '.join(f['columns'])
            evidence += pick('; visible row count: ', '; số dòng thấy được: ') + str(
                f['row_count'] if f['row_count'] is not None else '?'
            )
        target = '.'.join(x for x in (f['schema_name'], f['object_name']) if x)
        table_rows.append([severity, rule[3 if vi else 1] + ' — ' + target, evidence, rule[4 if vi else 2]])
    counts = ' / '.join(
        f'{(VI_SEVERITIES if vi else SEVERITIES)[i]}: {sum(RULES[f["rule"]][0] == s for f in findings)}'
        for i, s in enumerate(SEVERITIES)
    )
    coverage = [NOTES[n][1 if vi else 0] for n in notes]
    status_labels = {
        'readable': pick('readable', 'đọc được'),
        'empty': pick('empty; inconclusive', 'rỗng; chưa kết luận'),
        'denied': pick('denied for this request', 'bị từ chối với yêu cầu này'),
        'error': pick('error; inconclusive', 'lỗi; chưa kết luận'),
    }
    coverage += [o['table'] + ': ' + status_labels[o['status']] for r in results for o in r['observations']]
    coverage = list(dict.fromkeys(coverage)) or [
        pick(
            'Only the supplied inputs are covered; untested areas remain unknown.',
            'Chỉ bao phủ đầu vào được cung cấp; phần chưa kiểm tra vẫn chưa rõ.',
        )
    ]
    esc = lambda s: html.escape(str(s), quote=True)
    md = (
        lambda s: esc(s)
        .replace('|', '&#124;')
        .replace('\n', ' ')
        .replace('`', '&#96;')
        .replace('*', '&#42;')
        .replace('[', '&#91;')
        .replace(']', '&#93;')
    )
    section = pick('Findings', 'Các phát hiện')
    coverage_title = pick('Coverage and limitations', 'Phạm vi và giới hạn')
    next_title = pick('Next steps', 'Bước tiếp theo')
    markdown = f'# {title}\n\n{md(project)}\n\n{summary}\n\n{counts}\n\n{scope}\n\n## {section}\n\n'
    markdown += '| ' + ' | '.join(headings) + ' |\n|' + ' --- |' * 4 + '\n'
    markdown += ''.join('| ' + ' | '.join(md(c) for c in row) + ' |\n' for row in table_rows)
    markdown += f'\n## {coverage_title}\n\n' + '\n'.join('- ' + md(n) for n in coverage)
    markdown += f'\n\n## {next_title}\n\n{next_steps}\n'
    css = (
        'body{margin:0;background:#F4F3EF;color:#141413;font:16px/1.6 "Segoe UI",sans-serif}'
        'main{max-width:1120px;margin:40px auto;padding:40px;background:white;border-top:6px solid #E03E1A}'
        'h1{font-size:38px;line-height:1.15;max-width:700px}'
        'h2{font-size:23px;margin-top:36px}'
        '.summary{max-width:76ch;font-size:19px}'
        '.score{padding:16px 0;border-block:1px solid #D8D5CD;font-weight:600}'
        'table{border-collapse:collapse;width:100%;font-size:14px;table-layout:fixed}'
        'th,td{padding:12px 8px;text-align:left;vertical-align:top;border-bottom:1px solid #D8D5CD;overflow-wrap:anywhere}'
        'th:first-child{width:10%}'
        'thead{background:#F4F3EF}'
        'p,li{max-width:80ch;overflow-wrap:anywhere}'
        'footer{border-top:1px solid #D8D5CD;margin-top:32px;padding-top:12px}'
        '@media(max-width:700px){main{margin:0;padding:18px}h1{font-size:30px}table{font-size:12px}th,td{padding:6px 3px}}'
        '@page{size:A4 landscape;margin:14mm}'
        '@media print{body{background:white;font-size:11pt}main{margin:0;padding:0;max-width:none}'
        'h1{font-size:26pt}table{font-size:9pt}thead{display:table-header-group}'
        'tr{break-inside:avoid}h2{break-after:avoid}.score{break-inside:avoid}}'
    )
    embedded_fonts = False
    for weight, filename in [(400, 'BricolageGrotesque-Regular.ttf'), (700, 'BricolageGrotesque-Bold.ttf')]:
        raw_font = _load_font_bytes(filename)
        if raw_font is not None:
            encoded = base64.b64encode(raw_font).decode('ascii')
            css += f'@font-face{{font-family:Audit;src:url(data:font/ttf;base64,{encoded}) format("truetype");font-weight:{weight};font-display:swap}}'
            embedded_fonts = True
    if embedded_fonts:
        css += 'body{font-family:Audit,"Segoe UI",sans-serif}'
    markup = f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)} — {esc(project)}</title><style>{css}</style></head><body><main>'
    markup += f'<header><p>{esc(project)}</p><h1>{esc(title)}</h1></header><p class="summary">{esc(summary)}</p><p class="score">{esc(counts)}</p><p>{esc(scope)}</p><h2>{section}</h2>'
    markup += '<table><thead><tr>' + ''.join(f'<th scope="col">{h}</th>' for h in headings) + '</tr></thead><tbody>'
    markup += ''.join('<tr>' + ''.join('<td>' + esc(c) + '</td>' for c in row) + '</tr>' for row in table_rows)
    markup += f'</tbody></table><h2>{coverage_title}</h2><ul>' + ''.join('<li>' + esc(n) + '</li>' for n in coverage) + '</ul>'
    markup += f'<footer><h2>{next_title}</h2><p>{esc(next_steps)}</p></footer></main></body></html>'
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for name, content in [('report.md', markdown), ('report.html', markup), ('fix.sql', fix_sql(findings, lang=lang))]:
        (output / name).write_text(content, encoding='utf-8')
