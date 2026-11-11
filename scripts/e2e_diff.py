"""End-to-end check of `supabase-rls-check diff` against a real PostgreSQL.

Flow (everything runs in a throwaway database, default `rls_check_e2e`, which is dropped and recreated):

1. Apply tests/fixtures/e2e_diff_schema.sql, run the read-only check.sql, build a JSON report.
2. Run again with nothing changed: `diff --fail-on-new high` must exit 0 with no new findings.
3. `COMMENT ON TABLE public.journal_entries IS 'pii'`, run again.
4. `diff --fail-on-new high` must exit non-zero with the escalated sensitive_anon_policy finding
   (basis "table comment tag 'pii'"); `--fail-on-new critical` must still exit 0 (the finding is High).

Connection settings come from the standard libpq variables (PGHOST, PGPORT, PGUSER, PGPASSWORD).
The user needs permission to create databases and roles.

Usage (CI or local):
    PGHOST=127.0.0.1 PGUSER=postgres python scripts/e2e_diff.py
Exit codes: 0 pass, 1 assertion failed, 2 environment problem (for example psql not found).
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CHECK_SQL = ROOT / 'src' / 'supabase_rls_check' / 'sql' / 'check.sql'
SCHEMA_SQL = ROOT / 'tests' / 'fixtures' / 'e2e_diff_schema.sql'
PII_FINDING = ('sensitive_anon_policy', 'public', 'journal_entries', 'anon_journal', "table comment tag 'pii'")


class E2EFailure(AssertionError):
    """Raised when the diff behaviour does not match what the release promises."""


def tool(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the CLI exactly as a user would: `python -m supabase_rls_check ...`."""
    env = {**os.environ, 'PYTHONPATH': os.pathsep.join(filter(None, [str(ROOT / 'src'), os.environ.get('PYTHONPATH')]))}
    return subprocess.run(
        [sys.executable, '-m', 'supabase_rls_check', *args],
        capture_output=True,
        text=True,
        encoding='utf-8',
        env=env,
    )


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise E2EFailure(message)


def keys(findings: list[dict]) -> set[tuple[str, str, str, str, str]]:
    return {
        (f['rule'], f['schema_name'], f['object_name'], f['policy_name'], f.get('basis', ''))
        for f in findings
    }


def check_diff_behaviour(workdir: Path, before_csv: Path, unchanged_csv: Path, after_csv: Path) -> None:
    """Build JSON reports from three catalog exports and assert the diff exit codes and findings.

    This part needs no database, so unit tests can exercise it with hand-written CSV exports.
    """
    reports = {}
    for name, csv_path in (('before', before_csv), ('unchanged', unchanged_csv), ('after', after_csv)):
        out = workdir / f'{name}.json'
        done = tool('sql', '--from', str(csv_path), '--out', str(out), '--i-own-this-project')
        expect(done.returncode == 0, f'sql step failed for {name}: {done.stderr}')
        reports[name] = out

    before = json.loads(reports['before'].read_text(encoding='utf-8'))['findings']
    expect(
        ('rls_disabled', 'public', 'todos', '', '') in keys(before),
        'baseline report should contain rls_disabled on public.todos',
    )
    expect(
        not any(f['rule'] == 'sensitive_anon_policy' for f in before),
        'baseline report must not contain sensitive_anon_policy before the pii comment',
    )

    same_out = workdir / 'diff_unchanged.json'
    same = tool(
        'diff', '--old', str(reports['before']), '--new', str(reports['unchanged']),
        '--fail-on-new', 'high', '--out', str(same_out),
    )
    expect(same.returncode == 0, f'unchanged rerun must exit 0, got {same.returncode}: {same.stdout}{same.stderr}')
    same_data = json.loads(same_out.read_text(encoding='utf-8'))
    expect(same_data['new'] == [] and same_data['resolved'] == [], f'unchanged rerun reported changes: {same_data}')
    expect(same_data['unchanged_count'] == len(before), 'unchanged_count should equal the baseline finding count')

    gate_out = workdir / 'diff_escalated.json'
    gate = tool(
        'diff', '--old', str(reports['before']), '--new', str(reports['after']),
        '--fail-on-new', 'high', '--out', str(gate_out),
    )
    expect(gate.returncode != 0, f'diff --fail-on-new high must exit non-zero after the pii comment: {gate.stdout}')
    gate_data = json.loads(gate_out.read_text(encoding='utf-8'))
    expect(keys(gate_data['new']) == {PII_FINDING}, f'unexpected new findings: {keys(gate_data["new"])}')
    expect(gate_data['resolved'] == [], f'unexpected resolved findings: {gate_data["resolved"]}')
    expect("table comment tag 'pii'" in gate.stdout, 'diff table should print the pii basis')

    critical = tool(
        'diff', '--old', str(reports['before']), '--new', str(reports['after']), '--fail-on-new', 'critical',
    )
    expect(critical.returncode == 0, 'a new High finding must not trip --fail-on-new critical')


def psql(psql_path: str, dbname: str, *args: str, stdout=None) -> None:
    command = [psql_path, '-X', '-v', 'ON_ERROR_STOP=1', '-d', dbname, *args]
    done = subprocess.run(command, text=True, encoding='utf-8', stdout=stdout, stderr=subprocess.PIPE)
    if done.returncode != 0:
        raise RuntimeError(f'psql failed ({" ".join(args)[:80]}): {done.stderr.strip()}')


def export_check_sql(psql_path: str, dbname: str, target: Path) -> None:
    """Run the bundled check.sql in a read-only session and save the CSV export."""
    previous = os.environ.get('PGOPTIONS')
    os.environ['PGOPTIONS'] = '-c default_transaction_read_only=on'
    try:
        with target.open('w', encoding='utf-8', newline='') as stream:
            psql(psql_path, dbname, '--csv', '-f', str(CHECK_SQL), stdout=stream)
    finally:
        if previous is None:
            os.environ.pop('PGOPTIONS', None)
        else:
            os.environ['PGOPTIONS'] = previous


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='End-to-end test of the diff command on a real PostgreSQL.')
    parser.add_argument('--dbname', default='rls_check_e2e', help='Throwaway database to drop and recreate')
    parser.add_argument('--psql', default=shutil.which('psql'), help='Path to the psql client')
    args = parser.parse_args(argv)

    if not args.psql:
        print('psql not found. Install the PostgreSQL client or pass --psql PATH.', file=sys.stderr)
        return 2
    if not args.dbname.startswith('rls_check_e2e'):
        print('Refusing to drop a database whose name does not start with rls_check_e2e.', file=sys.stderr)
        return 2

    try:
        psql(args.psql, 'postgres', '-c', f'DROP DATABASE IF EXISTS {args.dbname}')
        psql(args.psql, 'postgres', '-c', f'CREATE DATABASE {args.dbname}')
        psql(args.psql, args.dbname, '-f', str(SCHEMA_SQL))
        with tempfile.TemporaryDirectory(prefix='rls-e2e-') as tmp:
            work = Path(tmp)
            before, unchanged, after = (work / f'{n}.csv' for n in ('before', 'unchanged', 'after'))
            export_check_sql(args.psql, args.dbname, before)
            export_check_sql(args.psql, args.dbname, unchanged)
            psql(args.psql, args.dbname, '-c', "COMMENT ON TABLE public.journal_entries IS 'pii'")
            export_check_sql(args.psql, args.dbname, after)
            check_diff_behaviour(work, before, unchanged, after)
    except RuntimeError as exc:
        print(f'Environment problem: {exc}', file=sys.stderr)
        return 2
    except E2EFailure as exc:
        print(f'FAILED: {exc}', file=sys.stderr)
        return 1
    finally:
        try:
            psql(args.psql, 'postgres', '-c', f'DROP DATABASE IF EXISTS {args.dbname}')
        except RuntimeError:
            pass

    print('diff e2e passed: unchanged rerun exits 0; pii comment is a new High finding and exits non-zero.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
