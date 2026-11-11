import base64
import json
from pathlib import Path

import pytest

import supabase_rls_check as audit
from supabase_rls_check import envscan, mcp_server

FIXTURE = Path(__file__).parent / 'fixtures' / 'all_findings.csv'


def build_jwt(role: str) -> str:
    header = base64.urlsafe_b64encode(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode()).decode().rstrip('=')
    payload = base64.urlsafe_b64encode(json.dumps({'role': role}).encode()).decode().rstrip('=')
    return f'{header}.{payload}.test_sig_9876'


def test_expo_env_service_role_jwt_is_critical(tmp_path):
    sr_jwt = build_jwt('service_role')
    (tmp_path / '.env').write_text(
        f'EXPO_PUBLIC_SUPABASE_SERVICE_ROLE_KEY={sr_jwt}\n',
        encoding='utf-8',
    )
    result = envscan.scan_env(tmp_path)
    assert len(result['findings']) == 1
    item = result['findings'][0]
    assert item['rule'] == 'public_env_service_role'
    assert item['severity'] == 'Critical'
    assert audit.RULES[item['rule']][0] == 'Critical'
    assert item['file'] == '.env'
    assert item['line'] == 1
    assert item['variable'] == 'EXPO_PUBLIC_SUPABASE_SERVICE_ROLE_KEY'
    assert item['masked_value'] == f'{sr_jwt[:6]}…{sr_jwt[-4:]}'
    assert sr_jwt not in item['masked_value']
    assert sr_jwt not in json.dumps(result)


def test_next_public_anon_key_produces_no_finding(tmp_path):
    anon_jwt = build_jwt('anon')
    (tmp_path / '.env').write_text(
        f'NEXT_PUBLIC_SUPABASE_ANON_KEY={anon_jwt}\n'
        'EXPO_PUBLIC_SUPABASE_KEY=sb_publishable_demo123456\n',
        encoding='utf-8',
    )
    result = envscan.scan_env(tmp_path)
    assert result['findings'] == []


def test_vite_stripe_live_key_is_high(tmp_path):
    secret = 'sk_live_xxx'
    (tmp_path / '.env.production').write_text(
        f'VITE_STRIPE_KEY={secret}\n',
        encoding='utf-8',
    )
    result = envscan.scan_env(tmp_path)
    assert len(result['findings']) == 1
    item = result['findings'][0]
    assert item['rule'] == 'public_env_secret_key'
    assert item['severity'] == 'High'
    assert item['file'] == '.env.production'
    assert item['line'] == 1
    assert item['variable'] == 'VITE_STRIPE_KEY'
    assert item['masked_value'] == f'{secret[:2]}…{secret[-2:]}'
    assert secret not in item['masked_value']
    assert secret not in item['masked_value']
    assert secret not in json.dumps(result)


def test_next_public_secret_name_only_is_high_and_notes_name(tmp_path):
    secret = 'abc'
    (tmp_path / '.env').write_text(
        f'NEXT_PUBLIC_API_SECRET={secret}\n',
        encoding='utf-8',
    )
    result = envscan.scan_env(tmp_path)
    assert len(result['findings']) == 1
    item = result['findings'][0]
    assert item['rule'] == 'public_env_secret_key'
    assert item['severity'] == 'High'
    assert item['file'] == '.env'
    assert item['line'] == 1
    assert item['variable'] == 'NEXT_PUBLIC_API_SECRET'
    assert item['reason'] == 'name suggests a secret'
    assert 'name suggests a secret' in item['policy_name']
    assert secret not in item['masked_value']
    assert f'={secret}' not in json.dumps(result)


def test_service_role_in_client_code_vs_server_paths(tmp_path):
    sr_jwt = build_jwt('service_role')
    client_file = tmp_path / 'src' / 'lib' / 'supabase.ts'
    client_file.parent.mkdir(parents=True)
    client_file.write_text(
        f'import {{ createClient }} from "@supabase/supabase-js";\n'
        f'export const admin = createClient("https://example.supabase.co", "{sr_jwt}");\n',
        encoding='utf-8',
    )

    edge_file = tmp_path / 'supabase' / 'functions' / 'admin' / 'index.ts'
    edge_file.parent.mkdir(parents=True)
    edge_file.write_text(
        f'const key = "{sr_jwt}";\n',
        encoding='utf-8',
    )

    for server_dir in ('server', 'api', 'scripts', 'backend'):
        srv = tmp_path / server_dir / 'worker.ts'
        srv.parent.mkdir(parents=True)
        srv.write_text(f'const key = "{sr_jwt}";\n', encoding='utf-8')

    result = envscan.scan_env(tmp_path)
    assert len(result['findings']) == 1
    item = result['findings'][0]
    assert item['rule'] == 'service_role_in_client_code'
    assert item['severity'] == 'Critical'
    assert item['file'] == 'src/lib/supabase.ts'
    assert item['line'] == 2
    assert item['masked_value'] == f'{sr_jwt[:6]}…{sr_jwt[-4:]}'
    assert sr_jwt not in item['masked_value']
    assert sr_jwt not in json.dumps(result)


def test_skipped_directories_binary_and_oversized_files_produce_no_findings(tmp_path):
    sr_jwt = build_jwt('service_role')
    for skipped in (
        'node_modules/pkg/index.js',
        '.git/hooks/pre-commit.js',
        '.venv/lib/site.js',
        'venv/lib/site.js',
        'dist/bundle.js',
        'build/app.js',
        '.next/static/chunk.js',
        '.expo/types.ts',
        'ios/Pods/ Pod.js',
        'android/build/generated.js',
    ):
        target = tmp_path / skipped
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f'const leaked = "{sr_jwt}";\n', encoding='utf-8')

    binary_file = tmp_path / 'src' / 'binary.js'
    binary_file.parent.mkdir(parents=True, exist_ok=True)
    binary_file.write_bytes(b'\x00\x01const k = "' + sr_jwt.encode() + b'";')

    huge_file = tmp_path / 'src' / 'huge.js'
    huge_file.write_text(('// ' + ('x' * 1024) + '\n') * 2100 + f'const k = "{sr_jwt}";\n', encoding='utf-8')

    result = envscan.scan_env(tmp_path)
    assert result['findings'] == []


def test_cli_scan_env_and_report_integration(tmp_path, capsys):
    sr_jwt = build_jwt('service_role')
    sb_secret = 'sb_secret_live_super_secret_9999'
    (tmp_path / '.env').write_text(
        f'EXPO_PUBLIC_SUPABASE_SERVICE_ROLE_KEY={sr_jwt}\n'
        'NEXT_PUBLIC_API_SECRET=abc\n'
        f'PUBLIC_SB_KEY={sb_secret}\n',
        encoding='utf-8',
    )
    env_json = tmp_path / 'envscan.json'
    sql_json = tmp_path / 'sql_results.json'
    report_dir = tmp_path / 'report_out'

    # scan-env requires no consent flag
    assert audit.main(['scan-env', str(tmp_path), '--out', str(env_json)]) == 0
    table_out = capsys.readouterr().out
    assert 'public_env_service_role' in table_out
    assert 'public_env_secret_key' in table_out
    assert 'name suggests a secret' in table_out
    assert sr_jwt not in table_out
    assert sb_secret not in table_out

    raw_json = env_json.read_text(encoding='utf-8')
    assert sr_jwt not in raw_json
    assert sb_secret not in raw_json

    assert audit.main(['sql', '--from', str(FIXTURE), '--out', str(sql_json), '--i-own-this-project']) == 0
    assert (
        audit.main(
            [
                'report',
                '--from',
                str(sql_json),
                str(env_json),
                '--out-dir',
                str(report_dir),
                '--i-own-this-project',
            ]
        )
        == 0
    )

    report_md = (report_dir / 'report.md').read_text(encoding='utf-8')
    report_html = (report_dir / 'report.html').read_text(encoding='utf-8')
    for doc in (report_md, report_html):
        assert 'public_env_service_role' in doc
        assert 'public_env_secret_key' in doc
        assert 'EXPO_PUBLIC_SUPABASE_SERVICE_ROLE_KEY' in doc
        assert 'name suggests a secret' in doc
        assert sr_jwt not in doc
        assert sb_secret not in doc


def test_mcp_scan_public_env_tool(tmp_path):
    sr_jwt = build_jwt('service_role')
    (tmp_path / 'eas.json').write_text(
        json.dumps({'build': {'production': {'env': {'EXPO_PUBLIC_SERVICE_KEY': sr_jwt}}}}),
        encoding='utf-8',
    )
    summary = mcp_server.scan_public_env(str(tmp_path))
    assert summary['total_findings'] == 1
    assert summary['counts']['Critical'] == 1
    finding_item = summary['findings'][0]
    assert finding_item['rule'] == 'public_env_service_role'
    assert finding_item['file'] == 'eas.json'
    assert finding_item['variable'] == 'EXPO_PUBLIC_SERVICE_KEY'
    assert finding_item['masked_value'] == f'{sr_jwt[:6]}…{sr_jwt[-4:]}'
    assert sr_jwt not in json.dumps(summary)

    with pytest.raises(ValueError):
        mcp_server.scan_public_env(str(tmp_path / 'nonexistent'))


def test_agent_config_files_json_key_paths_and_masking(tmp_path, capsys):
    sr_jwt = build_jwt('service_role')
    sb_secret = 'sb_secret_fake_agent_key_1234567890'
    pg_url = 'postgresql://postgres:fake_inline_pw_999@db.example.supabase.co:5432/postgres'

    claude_settings = tmp_path / '.claude' / 'settings.json'
    claude_settings.parent.mkdir(parents=True)
    claude_settings.write_text(
        json.dumps({'env': {'SUPABASE_SECRET_KEY': sb_secret}}, indent=2),
        encoding='utf-8',
    )

    cursor_mcp = tmp_path / '.cursor' / 'mcp.json'
    cursor_mcp.parent.mkdir(parents=True)
    cursor_mcp.write_text(
        json.dumps(
            {
                'mcpServers': {
                    'supabase': {
                        'env': {
                            'SUPABASE_SERVICE_ROLE_KEY': sr_jwt,
                            'DATABASE_URL': pg_url,
                        }
                    }
                }
            },
            indent=2,
        ),
        encoding='utf-8',
    )

    vscode_mcp = tmp_path / 'packages' / 'web' / '.vscode' / 'mcp.json'
    vscode_mcp.parent.mkdir(parents=True)
    vscode_mcp.write_text(
        json.dumps({'servers': {'db': {'args': ['--db-url', 'postgres://admin:fake_pw_2@localhost:5432/app']}}}),
        encoding='utf-8',
    )

    # Safe .mcp.json (anon JWT, publishable key, passwordless Postgres URL) -> no finding
    root_mcp = tmp_path / '.mcp.json'
    root_mcp.write_text(
        json.dumps(
            {
                'env': {
                    'ANON': build_jwt('anon'),
                    'PUB': 'sb_publishable_fake_12345',
                    'LOCAL_DB': 'postgresql://postgres@127.0.0.1:5432/postgres',
                }
            }
        ),
        encoding='utf-8',
    )

    result = envscan.scan_env(tmp_path)
    assert len(result['findings']) == 4
    by_file_var = {(f['file'], f['variable']): f for f in result['findings']}
    assert ('.claude/settings.json', 'env.SUPABASE_SECRET_KEY') in by_file_var
    assert ('.cursor/mcp.json', 'mcpServers.supabase.env.SUPABASE_SERVICE_ROLE_KEY') in by_file_var
    assert ('.cursor/mcp.json', 'mcpServers.supabase.env.DATABASE_URL') in by_file_var
    assert ('packages/web/.vscode/mcp.json', 'servers.db.args[1]') in by_file_var

    for item in result['findings']:
        assert item['rule'] == 'agent_config_secret'
        assert item['severity'] == 'Critical'

    serialized = json.dumps(result)
    assert sr_jwt not in serialized
    assert sb_secret not in serialized
    assert 'fake_inline_pw_999' not in serialized
    assert 'fake_pw_2' not in serialized

    assert audit.main(['scan-env', str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert 'agent_config_secret' in out
    assert 'mcpServers.supabase.env.DATABASE_URL' in out
    assert 'fake_inline_pw_999' not in out


def test_agent_config_invalid_json_falls_back_to_text_search(tmp_path):
    sb_secret = 'sb_secret_fake_local_broken_987654'
    claude_local = tmp_path / '.claude' / 'settings.local.json'
    claude_local.parent.mkdir(parents=True)
    claude_local.write_text(
        '{\n  "env": {\n    "KEY": "' + sb_secret + '",\n  // invalid json comment\n',
        encoding='utf-8',
    )

    result = envscan.scan_env(tmp_path)
    assert len(result['findings']) == 1
    item = result['findings'][0]
    assert item['rule'] == 'agent_config_secret'
    assert item['severity'] == 'Critical'
    assert item['file'] == '.claude/settings.local.json'
    assert item['line'] == 3
    assert item['masked_value'] == f'{sb_secret[:6]}…{sb_secret[-4:]}'
    assert sb_secret not in json.dumps(result)


def _write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    return path


def test_react_native_app_json_and_app_config_files(tmp_path):
    sr_jwt = build_jwt('service_role')
    anon_jwt = build_jwt('anon')
    sb_secret = 'sb_secret_rn_live_secret_4242'
    _write(
        tmp_path,
        'app.json',
        json.dumps(
            {
                'expo': {
                    'extra': {
                        'supabaseUrl': 'https://example.supabase.co',
                        'supabaseAnonKey': anon_jwt,
                        'supabasePublishable': 'sb_publishable_demo123456',
                        'supabaseServiceKey': sr_jwt,
                    }
                }
            },
            indent=2,
        ),
    )
    _write(tmp_path, 'app.config.js', f'export default {{ extra: {{ adminKey: "{sb_secret}" }} }};\n')
    # The anon key is expected in a client app and must not be reported.
    _write(tmp_path, 'app.config.ts', f'export default {{ extra: {{ anonKey: "{anon_jwt}" }} }};\n')
    result = envscan.scan_env(tmp_path)
    by_file = {(f['file'], f['rule']): f for f in result['findings']}
    assert set(by_file) == {
        ('app.json', 'service_role_in_client_code'),
        ('app.config.js', 'service_role_in_client_code'),
    }
    app_json = by_file[('app.json', 'service_role_in_client_code')]
    assert app_json['variable'] == 'supabaseServiceKey'
    assert app_json['severity'] == 'Critical'
    assert app_json['masked_value'] == f'{sr_jwt[:6]}…{sr_jwt[-4:]}'
    dumped = json.dumps(result)
    for secret in (sr_jwt, sb_secret, anon_jwt):
        assert secret not in dumped


def test_react_native_src_layouts_and_postgres_urls(tmp_path):
    password = 'hunter2Hunter2'
    url = f'postgresql://postgres:{password}@db.example.supabase.co:5432/postgres'
    sr_jwt = build_jwt('service_role')
    _write(tmp_path, 'src/lib/db.ts', f'export const DB = "{url}";\n')
    _write(tmp_path, 'app/(tabs)/index.tsx', f'const key = "{sr_jwt}";\n')
    _write(tmp_path, 'screens/Home.jsx', 'const dbUrl = "postgres://user:${DB_PASSWORD}@localhost/db";\n')
    _write(tmp_path, 'components/Safe.js', 'const u = "postgres://readonly@localhost/db";\n')
    result = envscan.scan_env(tmp_path)
    items = {(f['file'], f['rule']): f for f in result['findings']}
    assert set(items) == {
        ('src/lib/db.ts', 'db_url_in_client_code'),
        ('app/(tabs)/index.tsx', 'service_role_in_client_code'),
    }
    db_item = items[('src/lib/db.ts', 'db_url_in_client_code')]
    assert db_item['severity'] == 'Critical'
    assert db_item['variable'] == 'DB'
    assert db_item['reason'] == 'Postgres connection string'
    assert db_item['line'] == 1
    dumped = json.dumps(result)
    assert password not in dumped
    assert url not in dumped
    assert sr_jwt not in dumped


def test_react_native_scan_skips_build_output_and_server_paths(tmp_path):
    sr_jwt = build_jwt('service_role')
    url = 'postgresql://postgres:hunter2Hunter2@db.example.com/postgres'
    for rel in (
        'node_modules/pkg/index.js',
        'android/app/build/generated/Config.js',
        'ios/build/Config.js',
        'ios/Pods/Pod/Config.js',
        'web-build/static/main.js',
        '.git/hooks/note.js',
        'backend/db.ts',
        'supabase/functions/x/index.ts',
    ):
        _write(tmp_path, rel, f'const a = "{sr_jwt}"; const b = "{url}";\n')
    (tmp_path / 'src').mkdir()
    (tmp_path / 'src' / 'blob.js').write_bytes(b'\x00' + sr_jwt.encode())
    assert envscan.scan_env(tmp_path)['findings'] == []


def test_react_native_scan_cli_output_masks_values_and_ignores_publishable_keys(tmp_path, capsys):
    password = 'hunter2Hunter2'
    url = f'postgresql://postgres:{password}@db.example.supabase.co:5432/postgres'
    _write(
        tmp_path,
        'src/config.ts',
        f'export const anon = "{build_jwt("anon")}";\n'
        'export const pub = "sb_publishable_abc123def456";\n'
        f'export const dsn = "{url}";\n',
    )
    out_json = tmp_path / 'envscan.json'
    assert audit.main(['scan-env', str(tmp_path), '--out', str(out_json)]) == 0
    table = capsys.readouterr().out
    assert 'db_url_in_client_code' in table
    assert 'service_role_in_client_code' not in table
    assert password not in table
    assert url not in table
    assert password not in out_json.read_text(encoding='utf-8')
    assert audit.load_result(out_json)['findings'][0]['rule'] == 'db_url_in_client_code'


def test_agent_config_placeholder_passwords_are_not_flagged(tmp_path):
    _write(
        tmp_path,
        '.mcp.json',
        json.dumps({'mcpServers': {'db': {'args': ['postgresql://user:${DB_PASSWORD}@host/db']}}}),
    )
    assert envscan.scan_env(tmp_path)['findings'] == []
