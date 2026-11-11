import json
from pathlib import Path

import pytest

import supabase_rls_check as audit
from supabase_rls_check import diff as diff_mod, mcp_server

FIXTURE = Path(__file__).parent / 'fixtures' / 'all_findings.csv'


def _write_json(path: Path, findings: list[dict]) -> Path:
    path.write_text(
        json.dumps({'findings': findings, 'notes': [], 'observations': []}, indent=2),
        encoding='utf-8',
    )
    return path


def test_diff_identical_inputs(tmp_path, capsys):
    base = [
        audit.finding('rls_disabled', 'public', 'todos'),
        audit.finding('policy_true', 'public', 'profiles', 'allow_everyone'),
    ]
    old_path = _write_json(tmp_path / 'old.json', base)
    new_path = _write_json(tmp_path / 'new.json', base)

    result = diff_mod.diff_findings(old_path, new_path)
    assert result == {'new': [], 'resolved': [], 'unchanged_count': 2}

    assert audit.main(['diff', '--old', str(old_path), '--new', str(new_path)]) == 0
    out = capsys.readouterr().out
    assert 'No new or resolved findings' in out
    assert 'unchanged: 2' in out


def test_diff_one_added_finding(tmp_path):
    old_findings = [
        audit.finding('rls_disabled', 'public', 'todos'),
    ]
    added = audit.finding('policy_true_writable', 'public', 'shared_notes', 'anyone_edits_notes')
    new_findings = [old_findings[0], added]

    old_path = _write_json(tmp_path / 'old.json', old_findings)
    new_path = _write_json(tmp_path / 'new.json', new_findings)

    result = diff_mod.diff_findings([old_path], [new_path])
    assert result['new'] == [added]
    assert result['resolved'] == []
    assert result['unchanged_count'] == 1


def test_diff_one_removed_finding(tmp_path):
    removed = audit.finding('policy_true_writable', 'public', 'shared_notes', 'anyone_edits_notes')
    kept = audit.finding('rls_disabled', 'public', 'todos')

    old_path = _write_json(tmp_path / 'old.json', [removed, kept])
    new_path = _write_json(tmp_path / 'new.json', [kept])

    result = diff_mod.diff_findings(old_path, new_path)
    assert result['new'] == []
    assert result['resolved'] == [removed]
    assert result['unchanged_count'] == 1


def test_diff_csv_old_vs_json_new_and_sorting(tmp_path):
    loaded = audit.load_result(FIXTURE)
    extra_b = audit.finding('rls_disabled', 'public', 'z_table')
    extra_a = audit.finding('auth_users_exposed', 'public', 'a_view')
    json_new = _write_json(
        tmp_path / 'new_results.json',
        [*loaded['findings'], extra_b, extra_a],
    )

    result = diff_mod.diff_findings(FIXTURE, json_new)
    assert result['new'] == [extra_a, extra_b]
    assert result['resolved'] == []
    assert result['unchanged_count'] == len(loaded['findings'])


def test_diff_cli_fail_on_new_severity_and_out(tmp_path, capsys):
    base = [audit.finding('rls_disabled', 'public', 'todos')]
    crit_new = [
        *base,
        audit.finding('policy_true_writable', 'public', 'shared_notes', 'anyone_edits_notes'),
    ]
    low_new = [
        *base,
        audit.finding('public_extension', 'public', 'pg_trgm'),
    ]

    old_path = _write_json(tmp_path / 'old.json', base)
    crit_path = _write_json(tmp_path / 'crit.json', crit_new)
    low_path = _write_json(tmp_path / 'low.json', low_new)
    out_json = tmp_path / 'diff.json'

    # --fail-on-new high exits 1 for a new Critical finding
    rc_crit = audit.main(
        [
            'diff',
            '--old',
            str(old_path),
            '--new',
            str(crit_path),
            '--out',
            str(out_json),
            '--fail-on-new',
            'high',
        ]
    )
    assert rc_crit == 1
    table_out = capsys.readouterr().out
    assert 'policy_true_writable' in table_out
    assert 'Critical' in table_out
    saved = json.loads(out_json.read_text(encoding='utf-8'))
    assert len(saved['new']) == 1
    assert saved['new'][0]['rule'] == 'policy_true_writable'

    # --fail-on-new high exits 0 for a new Low finding
    rc_low = audit.main(
        [
            'diff',
            '--old',
            str(old_path),
            '--new',
            str(low_path),
            '--fail-on-new',
            'high',
        ]
    )
    assert rc_low == 0
    low_out = capsys.readouterr().out
    assert 'public_extension' in low_out
    assert 'Low' in low_out

    # Default (no --fail-on-new) never fails even with a new Critical finding
    assert audit.main(['diff', '--old', str(old_path), '--new', str(crit_path)]) == 0
    capsys.readouterr()


def test_diff_resolved_only_never_fails(tmp_path, capsys):
    old_findings = [
        audit.finding('policy_true_writable', 'public', 'shared_notes', 'anyone_edits_notes'),
        audit.finding('rls_disabled', 'public', 'todos'),
    ]
    new_findings = [
        audit.finding('rls_disabled', 'public', 'todos'),
    ]
    old_path = _write_json(tmp_path / 'old.json', old_findings)
    new_path = _write_json(tmp_path / 'new.json', new_findings)

    for sev in ('critical', 'high', 'medium', 'low'):
        rc = audit.main(
            [
                'diff',
                '--old',
                str(old_path),
                '--new',
                str(new_path),
                '--fail-on-new',
                sev,
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert 'resolved' in out
        assert 'policy_true_writable' in out


def test_mcp_diff_results_tool(tmp_path):
    old_path = _write_json(
        tmp_path / 'old.json',
        [audit.finding('rls_disabled', 'public', 'todos')],
    )
    new_path = _write_json(
        tmp_path / 'new.json',
        [
            audit.finding('policy_true_writable', 'public', 'shared_notes', 'anyone_edits_notes'),
        ],
    )

    summary = mcp_server.diff_results(str(old_path), str(new_path))
    assert summary['new_count'] == 1
    assert summary['resolved_count'] == 1
    assert summary['unchanged_count'] == 0
    assert summary['counts_new']['Critical'] == 1
    assert summary['new'][0]['rule'] == 'policy_true_writable'
    assert summary['new'][0]['severity'] == 'Critical'
    assert summary['resolved'][0]['rule'] == 'rls_disabled'

    bad_file = tmp_path / 'bad.json'
    bad_file.write_text('not-json: SECRET_TOKEN_123', encoding='utf-8')
    with pytest.raises(ValueError) as exc:
        mcp_server.diff_results(str(old_path), str(bad_file))
    assert 'SECRET_TOKEN_123' not in str(exc.value)


def test_diff_failure_injection_pii_comment_and_identical_csv(tmp_path, capsys):
    csv_one = tmp_path / 'run1.csv'
    csv_two = tmp_path / 'run2.csv'
    csv_one.write_text(
        'rule,schema_name,object_name,policy_name,basis\n'
        'rls_disabled,public,todos,,\n'
        "sensitive_anon_policy,public,payments,anon_payments,table name matches pattern 'payment'\n",
        encoding='utf-8',
    )
    csv_two.write_text(
        'rule,schema_name,object_name,policy_name,basis\n'
        'rls_disabled,public,todos,,\n'
        "sensitive_anon_policy,public,payments,anon_payments,table comment tag 'pii'\n"
        "sensitive_anon_policy,public,journal_entries,anon_journal,table comment tag 'pii'\n",
        encoding='utf-8',
    )

    # Identical CSV runs produce empty new/resolved and exit 0
    same = diff_mod.diff_findings(csv_one, csv_one)
    assert same == {'new': [], 'resolved': [], 'unchanged_count': 2}
    assert audit.main(['diff', '--old', str(csv_one), '--new', str(csv_one), '--fail-on-new', 'high']) == 0
    capsys.readouterr()

    # Adding a pii comment tag between runs shows up as NEW (and old basis as resolved) and exits 1 on --fail-on-new high
    diff_res = diff_mod.diff_findings(csv_one, csv_two)
    assert set(diff_res.keys()) == {'new', 'resolved', 'unchanged_count'}
    assert diff_res['unchanged_count'] == 1
    assert [f['basis'] for f in diff_res['new']] == ["table comment tag 'pii'", "table comment tag 'pii'"]
    assert [f['basis'] for f in diff_res['resolved']] == ["table name matches pattern 'payment'"]

    rc = audit.main(['diff', '--old', str(csv_one), '--new', str(csv_two), '--fail-on-new', 'high'])
    assert rc == 1
    out = capsys.readouterr().out
    assert "table comment tag 'pii'" in out
    assert "table name matches pattern 'payment'" in out


def test_diff_backward_compatibility_without_basis(tmp_path):
    legacy_old = tmp_path / 'legacy_old.json'
    legacy_old.write_text(
        json.dumps(
            {
                'findings': [
                    {'rule': 'rls_disabled', 'schema_name': 'public', 'object_name': 'todos', 'policy_name': ''}
                ],
                'notes': [],
                'observations': [],
            }
        ),
        encoding='utf-8',
    )
    current_new = _write_json(tmp_path / 'current_new.json', [audit.finding('rls_disabled', 'public', 'todos')])
    res = diff_mod.diff_findings(legacy_old, current_new)
    assert res == {'new': [], 'resolved': [], 'unchanged_count': 1}
