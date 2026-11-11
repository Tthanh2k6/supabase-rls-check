"""Unit tests for scripts/e2e_diff.py. The PostgreSQL half runs in CI; these cover the database-free half."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('e2e_diff', ROOT / 'scripts' / 'e2e_diff.py')
e2e = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(e2e)

HEADER = 'rule,schema_name,object_name,policy_name,basis\n'
BEFORE = HEADER + 'rls_disabled,public,todos,,\n'
AFTER = BEFORE + "sensitive_anon_policy,public,journal_entries,anon_journal,table comment tag 'pii'\n"


def _csv(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding='utf-8')
    return path


def test_check_diff_behaviour_passes_on_expected_exports(tmp_path):
    e2e.check_diff_behaviour(
        tmp_path,
        _csv(tmp_path, 'before.csv', BEFORE),
        _csv(tmp_path, 'unchanged.csv', BEFORE),
        _csv(tmp_path, 'after.csv', AFTER),
    )


def test_check_diff_behaviour_fails_when_pii_comment_is_not_detected(tmp_path):
    with pytest.raises(e2e.E2EFailure, match='must exit non-zero'):
        e2e.check_diff_behaviour(
            tmp_path,
            _csv(tmp_path, 'before.csv', BEFORE),
            _csv(tmp_path, 'unchanged.csv', BEFORE),
            _csv(tmp_path, 'after.csv', BEFORE),
        )


def test_check_diff_behaviour_fails_when_unchanged_rerun_differs(tmp_path):
    with pytest.raises(e2e.E2EFailure, match='unchanged rerun'):
        e2e.check_diff_behaviour(
            tmp_path,
            _csv(tmp_path, 'before.csv', BEFORE),
            _csv(tmp_path, 'unchanged.csv', AFTER),
            _csv(tmp_path, 'after.csv', AFTER),
        )


def test_script_guards_without_touching_a_database(monkeypatch, capsys):
    assert e2e.main(['--psql', '', '--dbname', 'rls_check_e2e']) == 2
    assert 'psql not found' in capsys.readouterr().err
    assert e2e.main(['--psql', 'psql', '--dbname', 'production']) == 2
    assert 'Refusing to drop' in capsys.readouterr().err


def test_fixture_schema_has_the_tables_the_script_expects():
    sql = e2e.SCHEMA_SQL.read_text(encoding='utf-8')
    for fragment in ('public.todos', 'public.journal_entries', 'anon_journal', 'storage.buckets'):
        assert fragment in sql
    assert not any(line.startswith('COMMENT ON') for line in sql.splitlines())  # the script adds it between runs
