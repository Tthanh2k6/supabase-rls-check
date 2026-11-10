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
