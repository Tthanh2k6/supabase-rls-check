"""0.7.0 CLI, report and MCP coverage; live catalog cases run separately in CI."""
import html
import json
from pathlib import Path
import tomllib

import pytest

import supabase_rls_check as audit
from supabase_rls_check import mcp_server


FIXTURES = Path(__file__).parent / 'fixtures'
NEW_RULES = {
    'realtime_messages_no_policy': 'Medium',
    'realtime_messages_policy_true': 'High',
    'mfa_table_without_aal2': 'Medium',
}


@pytest.mark.parametrize('lang', ['en', 'vi'])
@pytest.mark.parametrize('rule,severity', NEW_RULES.items())
def test_new_rules_explain_report_and_comment_only_fixes(tmp_path, capsys, lang, rule, severity):
    assert audit.main(['explain', rule, '--lang', lang]) == 0
    explanation = capsys.readouterr().out
    title, remedy = audit.RULES[rule][3:5] if lang == 'vi' else audit.RULES[rule][1:3]
    assert title in explanation and remedy in explanation
    guide = audit.RULE_GUIDES[rule]
    assert guide['why_vi' if lang == 'vi' else 'why'] in explanation
    assert guide['caveat_vi' if lang == 'vi' else 'caveat'] in explanation

    schema = 'public' if rule == 'mfa_table_without_aal2' else 'realtime'
    basis = "table comment tag 'mfa'" if schema == 'public' else 'review <topic>'
    item = audit.finding(rule, schema, 'review_target', 'review_policy', basis)
    envelope = {'findings': [item], 'notes': [], 'observations': []}
    audit.report([envelope], tmp_path, lang=lang)
    for filename in ('report.md', 'report.html'):
        output = (tmp_path / filename).read_text(encoding='utf-8')
        assert rule in output
        assert html.escape(title) in output
        assert html.escape(remedy) in output
        assert html.escape(basis) in output
        label = audit.VI_SEVERITIES[audit.SEVERITIES.index(severity)] if lang == 'vi' else severity
        assert label in output
    sql = (tmp_path / 'fix.sql').read_text(encoding='utf-8')
    assert f'-- {rule}: {schema}.review_target: review_policy ({basis})' in sql
    assert f'-- {remedy}' in sql
    assert [line for line in sql.splitlines() if line and not line.startswith('--')] == [
        'BEGIN;',
        'ROLLBACK; -- Deliberate dry run. Change to COMMIT only after review and staging tests.',
    ]


def test_mcp_lists_and_analyzes_all_new_rules_without_network(tmp_path):
    listed = mcp_server.list_rules()
    assert len(listed) == len(audit.RULES)
    assert {entry['rule'] for entry in listed} == set(audit.RULES)
    listed_by_rule = {entry['rule']: entry for entry in listed}
    findings = []
    for filename in ('all_findings.csv', 'realtime_no_policy.csv'):
        findings.extend(audit.load_result(FIXTURES / filename)['findings'])
    export = tmp_path / 'combined.json'
    export.write_text(json.dumps(findings), encoding='utf-8')
    analyzed = mcp_server.analyze_sql_export(str(export))
    for rule, severity in NEW_RULES.items():
        matching = [f for f in analyzed['findings'] if f['rule'] == rule]
        assert matching
        for item in matching:
            assert item['severity'] == severity
            assert item['title'] == listed_by_rule[rule]['title']
            assert item['remediation'] == listed_by_rule[rule]['remediation']
            assert item['basis']
        assert mcp_server.explain_rule(rule) == audit.explain_rule(rule)


def test_new_rule_guides_state_heuristic_limits():
    mfa = audit.explain_rule('mfa_table_without_aal2')
    assert 'PERMISSIVE policy checking aal2 does not enforce MFA' in mfa
    assert 'RESTRICTIVE' in mfa and 'unmarked tables' in mfa
    assert 'WITH CHECK' in mfa and 'FOR ALL TO authenticated' in mfa
    assert 'https://supabase.com/docs/guides/auth/auth-mfa' in mfa


def test_release_versions_match():
    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / 'pyproject.toml').read_text(encoding='utf-8'))
    server = json.loads((root / 'server.json').read_text(encoding='utf-8'))
    assert project['project']['version'] == audit.__version__ == server['version'] == '0.7.0'
    assert all(package['version'] == audit.__version__ for package in server['packages'])
