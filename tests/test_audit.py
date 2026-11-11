import base64
import json
from pathlib import Path
import sys

import pytest
import requests

import supabase_rls_check as audit
from supabase_rls_check import mcp_server


FIXTURE = Path(__file__).parent / 'fixtures' / 'all_findings.csv'


def token(role):
    payload = base64.urlsafe_b64encode(json.dumps({'role': role}).encode()).decode().rstrip('=')
    return 'eyJhbGciOiJIUzI1NiJ9.' + payload + '.fake_signature'


class Response:
    def __init__(self, data=None, status=200, headers=None, raw=None):
        self.status_code = status
        self.headers = headers or {}
        self.body = raw if raw is not None else json.dumps(data).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def iter_content(self, size):
        yield self.body


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError('Real network forbidden')

    monkeypatch.setattr(requests.Session, 'request', deny)


def mock_http(monkeypatch, responses):
    calls = []
    responses = iter(responses)

    def request(self, method, url, **kwargs):
        calls.append((method, url, kwargs))
        assert method in ('GET', 'HEAD')
        assert kwargs['allow_redirects'] is False
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(requests.Session, 'request', request)
    return calls


def test_all_sql_checks_csv_json(tmp_path):
    result = audit.load_result(FIXTURE)
    assert len(audit.SQL_RULES) == 17
    assert {f['rule'] for f in result['findings']} == set(audit.SQL_RULES)
    assert {f['rule'] for f in result['findings']} == set(audit.RULES) - {
        'anon_readable',
        'service_role_exposed',
        *audit.ENV_RULES,
    }
    by_rule_obj = {(f['rule'], f['object_name']): f['basis'] for f in result['findings']}
    assert by_rule_obj[('sensitive_anon_policy', 'payments')] == "table name matches pattern 'payment'"
    assert by_rule_obj[('sensitive_anon_policy', 'journal_entries')] == "table comment tag 'pii'"
    assert by_rule_obj[('secret_column_exposed', 'user_api_keys')] == 'openai_api_key'
    assert by_rule_obj[('definer_trusts_id_arg', 'get_user_orders(p_user_id uuid)')] == 'p_user_id'
    assert by_rule_obj[('rls_disabled', 'todos')] == ''
    path = tmp_path / 'export.json'
    path.write_text(json.dumps(result['findings']), encoding='utf-8')
    assert audit.load_result(path) == result

    # Backward compatibility: old JSON results without a 'basis' key treat basis as ''
    legacy_path = tmp_path / 'legacy.json'
    legacy_path.write_text(
        json.dumps([{'rule': 'rls_disabled', 'schema_name': 'public', 'object_name': 'todos', 'policy_name': ''}]),
        encoding='utf-8',
    )
    legacy_loaded = audit.load_result(legacy_path)
    assert legacy_loaded['findings'][0]['basis'] == ''


@pytest.mark.parametrize(
    'mode,extra',
    [
        ('sql', ['--from', 'missing.csv']),
        ('probe', ['--url', 'https://app.test', '--anon-key', 'bad']),
        ('report', ['--from', 'missing.json']),
    ],
)
def test_consent_before_io(mode, extra):
    with pytest.raises(SystemExit) as exc:
        audit.main([mode] + extra)
    assert exc.value.code == 2


def test_probe_redacts_values_and_counts(monkeypatch):
    calls = mock_http(
        monkeypatch,
        [
            Response({'paths': {'/todos': {'get': {}}, '/rpc/danger': {'post': {}}, '/': {'get': {}}}}),
            Response([{'id': 'private-id', 'email': 'secret@private.test'}]),
            Response(headers={'Content-Range': '0-0/42'}),
        ],
    )
    result = audit.probe('https://app.test', token('anon'))
    assert result['findings'][0]['row_count'] == 42
    assert result['findings'][0]['columns'] == ['email', 'id']
    assert 'private' not in json.dumps(result)
    assert len(calls) == 3
    assert calls[1][2]['params'] == {'select': '*', 'limit': 1}
    assert calls[2][0] == 'HEAD'


@pytest.mark.parametrize(
    'response,expected',
    [
        (Response([]), 'empty'),
        (Response(status=403), 'denied'),
        (Response(status=500), 'error'),
        (Response(raw=b'not-json'), 'error'),
        (requests.Timeout('SECRET'), 'error'),
    ],
)
def test_probe_states(monkeypatch, response, expected):
    responses = [Response({'paths': {'/todos': {'get': {}}}}), response]
    if expected == 'empty':
        responses.append(Response(headers={'Content-Range': '*/0'}))
    mock_http(monkeypatch, responses)
    result = audit.probe('https://app.test', token('anon'))
    assert result['observations'][0]['status'] == expected
    assert not result['findings']
    assert 'SECRET' not in json.dumps(result)


def test_openapi_blocked_fallback_and_unknown_count(monkeypatch):
    mock_http(monkeypatch, [Response(status=403), Response([{'id': 99}]), requests.Timeout()])
    result = audit.probe('https://app.test', token('anon'), tables=['owner_table'])
    assert result['findings'][0]['row_count'] is None
    assert set(result['notes']) == {'discovery_failed', 'probe_incomplete'}


def test_frontend_scan_never_saves_or_sends_privileged_key(monkeypatch):
    secret = token('service_role')
    calls = mock_http(
        monkeypatch,
        [
            Response({'paths': {'/rpc/f': {'post': {}}}}),
            Response(raw=b'<script src="/app.js?secret=query"></script><script src="https://other.test/a.js"></script>'),
            Response(raw=('const key="' + secret + '";').encode()),
        ],
    )
    result = audit.probe('https://app.test', token('anon'), site='https://site.test')
    assert result['findings'][0]['rule'] == 'service_role_exposed'
    assert secret not in json.dumps(result)
    assert 'query' not in json.dumps(result)
    assert 'site_incomplete' in result['notes']
    assert len(calls) == 3
    assert all('headers' not in c[2] for c in calls[1:])


@pytest.mark.parametrize('key', [token('service_role'), token('authenticated'), 'sb_secret_bad', 'invalid'])
def test_reject_non_anon_credentials(key):
    with pytest.raises(ValueError):
        audit.probe('https://app.test', key)


def test_publishable_key_has_no_bearer(monkeypatch):
    calls = mock_http(monkeypatch, [Response(status=403)])
    audit.probe('https://app.test', 'sb_publishable_test')
    assert calls[0][2]['headers'] == {'apikey': 'sb_publishable_test'}


def test_redirect_not_followed(monkeypatch):
    calls = mock_http(monkeypatch, [Response(status=302)])
    result = audit.probe('https://app.test', token('anon'))
    assert len(calls) == 1
    assert result['notes'] == ['discovery_failed']


def test_size_limit(monkeypatch):
    mock_http(monkeypatch, [Response(raw=b'x' * 5_000_001)])
    result = audit.probe('https://app.test', token('anon'))
    assert result['notes'] == ['discovery_failed']


@pytest.mark.parametrize(
    'url',
    ['http://app.test', 'https://user:pass@app.test', 'https://app.test/path', 'https://app.test?key=secret'],
)
def test_reject_bad_project_urls(url):
    with pytest.raises(ValueError):
        audit.probe(url, token('anon'))


@pytest.mark.parametrize('lang,label', [('en', 'High'), ('vi', 'Cao')])
def test_report_merge_escape_and_fix(tmp_path, lang, label):
    result = audit.load_result(FIXTURE)
    result['findings'].append(audit.finding('rls_disabled', 'public', 'a"; DROP TABLE x;--<script>'))
    audit.report([result, result], tmp_path, lang, '<script>alert(1)</script>')
    markup = (tmp_path / 'report.html').read_text(encoding='utf-8')
    markdown = (tmp_path / 'report.md').read_text(encoding='utf-8')
    sql = (tmp_path / 'fix.sql').read_text(encoding='utf-8')
    assert '<script>' not in markup
    assert '&lt;script&gt;' in markup
    assert '&lt;script&gt;' in markdown
    assert label in markup
    assert markup.count('<tr>') == len(result['findings']) + 1  # header + deduplicated findings
    assert '"a""; DROP TABLE x;--<script>" ENABLE' in sql
    assert 'ROLLBACK;' in sql
    assert 'CHANGE user_id to the actual ownership column' in sql
    if lang == 'vi':
        assert 'SỬA cột user_id cho đúng' in sql
    assert '-- CREATE POLICY' in sql and '(SELECT auth.uid()) = user_id' in sql
    assert '@media print' in markup and '<html lang="' + lang in markup


def test_import_drops_raw_data(tmp_path):
    result = {
        'findings': [
            dict(
                rule='anon_readable',
                schema_name='public',
                object_name='todos',
                columns=['id'],
                row_count=2,
                rows=[{'id': 'SECRET'}],
                key='SECRET',
            )
        ],
        'notes': ['SECRET'],
    }
    path = tmp_path / 'probe.json'
    path.write_text(json.dumps(result), encoding='utf-8')
    assert 'SECRET' not in json.dumps(audit.load_result(path))


def test_cli_pipeline_and_errors(tmp_path, capsys):
    output = tmp_path / 'result.json'
    assert audit.main(['sql', '--from', str(FIXTURE), '--out', str(output), '--have-written-consent']) == 0
    assert audit.main(['report', '--from', str(output), '--out-dir', str(tmp_path), '--i-own-this-project']) == 0
    assert (tmp_path / 'report.html').exists()
    assert (tmp_path / 'report.md').exists()
    assert (tmp_path / 'fix.sql').exists()
    output.write_text('{"secret": "PRIVATE"}', encoding='utf-8')
    assert audit.main(['sql', '--from', str(output), '--i-own-this-project']) == 1
    assert 'PRIVATE' not in capsys.readouterr().err


def test_empty_export_report(tmp_path):
    path = tmp_path / 'empty.csv'
    path.write_text('rule,schema_name,object_name,policy_name\n', encoding='utf-8')
    audit.report([audit.load_result(path)], tmp_path)
    assert 'not proof of safety' in (tmp_path / 'report.html').read_text(encoding='utf-8')


def test_demo_has_exactly_three_findings():
    result = audit.load_result(Path(__file__).parents[1] / 'demo' / 'todo_ai.csv')
    assert len(result['findings']) == 3


@pytest.mark.parametrize('content', ['', 'wrong,columns\n', 'rule,schema_name,object_name\nunknown,public,todos\n'])
def test_invalid_csv_rejected(tmp_path, content):
    path = tmp_path / 'bad.csv'
    path.write_text(content, encoding='utf-8')
    with pytest.raises(ValueError):
        audit.load_result(path)


def test_head_can_prove_visible_rows_after_empty_get(monkeypatch):
    mock_http(
        monkeypatch,
        [Response({'paths': {'/todos': {'get': {}}}}), Response([]), Response(headers={'content-range': '*/2'})],
    )
    result = audit.probe('https://app.test', token('anon'))
    assert result['observations'][0]['status'] == 'readable'
    assert result['findings'][0]['row_count'] == 2


def test_site_inline_token_and_malformed_token(monkeypatch):
    secret = token('service_role')
    mock_http(monkeypatch, [Response(raw=('<script>' + secret + '</script>').encode())])
    with requests.Session() as session:
        findings, notes = audit.scan_site(session, 'https://site.test')
    assert len(findings) == 1 and not notes
    assert audit.jwt_role('a.bad.c') is None


@pytest.mark.parametrize('data', [{'findings': [], 'observations': ['bad']}, {'findings': [], 'notes': None}])
def test_malformed_envelope_cli_error(tmp_path, data):
    path = tmp_path / 'bad.json'
    path.write_text(json.dumps(data), encoding='utf-8')
    assert audit.main(['sql', '--from', str(path), '--i-own-this-project']) == 1


@pytest.mark.parametrize('rule', list(audit.RULES))
def test_explain_cli_for_every_rule(rule, capsys):
    assert audit.main(['explain', rule]) == 0
    out = capsys.readouterr().out
    severity, title, remedy, _, _ = audit.RULES[rule]
    assert f'Rule: {rule}' in out
    assert f'Severity: {severity}' in out
    assert title in out
    assert remedy in out


def test_explain_case_insensitive_vietnamese_and_unknown_rule(capsys):
    assert audit.main(['explain', '  RLS_DISABLED  ', '--lang', 'vi']) == 0
    vi_out = capsys.readouterr().out
    assert 'Chưa bật bảo mật cấp dòng' in vi_out

    leaked_jwt = token('service_role')
    assert audit.main(['explain', leaked_jwt]) == 1
    err = capsys.readouterr().err
    assert 'Available rules:' in err
    assert leaked_jwt not in err


def test_sql_print_bundled_check_query(capsys):
    assert audit.main(['sql', '--print-sql']) == 0
    sql_text = capsys.readouterr().out
    assert sql_text == audit.get_check_sql_path().read_text(encoding='utf-8')
    for rule_name in audit.SQL_RULES:
        assert rule_name in sql_text


def test_mcp_core_analyze_and_explain_without_sdk(tmp_path):
    summary = mcp_server.analyze_sql_export(str(FIXTURE))
    assert summary['total_findings'] == 31
    assert summary['counts'] == {'Critical': 3, 'High': 15, 'Medium': 7, 'Low': 6}
    assert {item['rule'] for item in summary['findings']} == set(audit.SQL_RULES)
    assert all('basis' in item for item in summary['findings'])
    bases = {(item['rule'], item['object_name']): item['basis'] for item in summary['findings']}
    assert bases[('sensitive_anon_policy', 'payments')] == "table name matches pattern 'payment'"
    assert bases[('sensitive_anon_policy', 'journal_entries')] == "table comment tag 'pii'"
    assert bases[('secret_column_exposed', 'user_api_keys')] == 'openai_api_key'
    assert bases[('definer_trusts_id_arg', 'get_user_orders(p_user_id uuid)')] == 'p_user_id'
    assert 'ROLLBACK;' in summary['fix_sql']

    explanation = mcp_server.explain_rule('definer_anon_exec')
    assert 'REVOKE EXECUTE' in explanation

    env_file = tmp_path / '.env'
    env_file.write_text('SUPABASE_SERVICE_ROLE_KEY=TOP_SECRET_VALUE\n', encoding='utf-8')
    with pytest.raises(ValueError) as exc:
        mcp_server.analyze_sql_export(str(env_file))
    assert 'TOP_SECRET_VALUE' not in str(exc.value)

    bad_json = tmp_path / 'corrupt.json'
    bad_json.write_text('not-json: TOP_SECRET_VALUE', encoding='utf-8')
    with pytest.raises(ValueError) as exc2:
        mcp_server.analyze_sql_export(str(bad_json))
    assert 'TOP_SECRET_VALUE' not in str(exc2.value)


def test_mcp_server_registers_only_read_only_local_tools_never_probe():
    registered = []

    class DummyFastMCP:
        def __init__(self, name):
            self.name = name

        def tool(self):
            def decorator(fn):
                registered.append(fn.__name__)
                return fn

            return decorator

    server = mcp_server.create_mcp_server(DummyFastMCP)
    assert server.name == 'supabase-rls-check'
    assert tuple(registered) == ('analyze_sql_export', 'explain_rule', 'scan_public_env', 'diff_results')
    assert 'probe' not in registered
    assert not hasattr(mcp_server, 'probe')


def test_mcp_cli_reports_install_hint_when_mcp_missing(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, 'mcp', None)
    monkeypatch.setitem(sys.modules, 'mcp.server', None)
    monkeypatch.setitem(sys.modules, 'mcp.server.fastmcp', None)
    assert audit.main(['mcp']) == 1
    err = capsys.readouterr().err
    assert 'pip install "supabase-rls-check[mcp]"' in err


def test_backward_compatible_audit_supabase_wrapper():
    import audit_supabase

    assert audit_supabase.main is audit.main
    assert audit_supabase.RULES is audit.RULES


def test_probe_anon_key_from_env(monkeypatch, tmp_path):
    from supabase_rls_check import cli
    seen = {}

    def fake_probe(url, key, tables, site):
        seen['key'] = key
        return {'findings': [], 'notes': [], 'observations': []}

    monkeypatch.setattr(cli, 'probe', fake_probe)
    monkeypatch.setenv('SUPABASE_ANON_KEY', 'sb_publishable_test')
    out = tmp_path / 'p.json'
    cli.main(['probe', '--url', 'https://abc.supabase.co', '--tables', 'notes', '--out', str(out), '--i-own-this-project'])
    assert seen['key'] == 'sb_publishable_test'


def test_probe_without_any_key_fails(monkeypatch):
    import pytest
    from supabase_rls_check import cli
    monkeypatch.delenv('SUPABASE_ANON_KEY', raising=False)
    with pytest.raises(SystemExit):
        cli.main(['probe', '--url', 'https://abc.supabase.co', '--i-own-this-project'])


@pytest.mark.parametrize('lang', ['en', 'vi'])
@pytest.mark.parametrize('rule,severity', [
    ('policy_true_writable', 'Critical'),
    ('policy_user_metadata', 'High'),
    ('policy_auth_per_row', 'Low'),
    ('auth_users_exposed', 'Critical'),
    ('matview_api_exposed', 'High'),
    ('public_bucket_listable', 'Medium'),
    ('policy_any_authenticated', 'Medium'),
    ('secret_column_exposed', 'Medium'),
    ('definer_trusts_id_arg', 'Medium'),
])
def test_new_catalog_rule_reports_and_manual_fixes(tmp_path, lang, rule, severity):
    schema = 'storage' if rule == 'public_bucket_listable' else 'public'
    policy = '' if rule in ('auth_users_exposed', 'matview_api_exposed', 'secret_column_exposed', 'definer_trusts_id_arg') else 'review_policy'
    basis = 'openai_api_key' if rule == 'secret_column_exposed' else ('p_user_id' if rule == 'definer_trusts_id_arg' else '')
    item = audit.finding(rule, schema, 'review_target', policy, basis)
    result = {'findings': [item], 'notes': [], 'observations': []}
    audit.report([result], tmp_path, lang=lang)
    title, remedy = audit.RULES[rule][3:5] if lang == 'vi' else audit.RULES[rule][1:3]
    severity_label = audit.VI_SEVERITIES[audit.SEVERITIES.index(severity)] if lang == 'vi' else severity
    for filename in ('report.md', 'report.html'):
        content = (tmp_path / filename).read_text(encoding='utf-8')
        assert rule in content
        assert title in content
        assert remedy in content
        assert severity_label in content
        assert f'{schema}.review_target' in content
        if item['policy_name']:
            assert item['policy_name'] in content
        if item['basis']:
            assert item['basis'] in content
    sql = (tmp_path / 'fix.sql').read_text(encoding='utf-8')
    assert f'-- {rule}: {schema}.review_target' in sql
    if item['basis']:
        assert item['basis'] in sql
    assert f'-- {remedy}' in sql
    # These rules must never introduce executable fixes, even inside the rollback template.
    statements = [line for line in sql.splitlines() if line and not line.startswith('--')]
    assert statements == [
        'BEGIN;',
        'ROLLBACK; -- Deliberate dry run. Change to COMMIT only after review and staging tests.',
    ]


@pytest.mark.parametrize('rule,severity,explanation,remedy', [
    ('policy_true_writable', 'Critical', 'UPDATE or DELETE', '(select auth.uid()) = user_id'),
    ('policy_user_metadata', 'High', 'End users can edit', 'app_metadata'),
    ('policy_auth_per_row', 'Low', 'not a vulnerability', '(select auth.uid())'),
    ('auth_users_exposed', 'Critical', 'materialized view', 'revoke SELECT'),
    ('matview_api_exposed', 'High', 'Row Level Security does not apply', 'security_invoker = true'),
    ('public_bucket_listable', 'Medium', 'Public buckets serve files by URL', 'storage.objects'),
    ('policy_any_authenticated', 'Medium', 'signed in', '(select auth.uid()) = user_id'),
    ('secret_column_exposed', 'Medium', 'plaintext secret', 'REVOKE SELECT (col) ON public.t FROM anon, authenticated'),
    ('definer_trusts_id_arg', 'Medium', 'Review needed', 'auth.uid()'),
    ('agent_config_secret', 'Critical', '.claude/settings.json', 'Rotate'),
])
def test_new_catalog_rule_explanations_and_mcp(rule, severity, explanation, remedy):
    text = audit.explain_rule(rule)
    assert f'Severity: {severity}' in text
    assert explanation in text
    assert remedy in text
    assert mcp_server.explain_rule(rule) == text
    vi_text = audit.explain_rule(rule, lang='vi')
    assert audit.RULES[rule][3] in vi_text
    assert audit.RULES[rule][4] in vi_text
