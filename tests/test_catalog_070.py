"""Run the real SQL against PostgreSQL 15 in CI, using synthetic pg_policies text.

Set RLS_CHECK_TEST_DATABASE to the database seeded with seed_pg.sql, plus normal
libpq PGHOST/PGUSER settings. Tests only SELECT in read-only sessions; no driver
dependency is needed. Offline runs skip this module.
"""
import csv
import io
import os
import shutil
import subprocess

import pytest

from supabase_rls_check import read_check_sql


pytestmark = pytest.mark.skipif(
    not os.environ.get('RLS_CHECK_TEST_DATABASE'),
    reason='Live PostgreSQL catalog tests run in CI (RLS_CHECK_TEST_DATABASE required)',
)


def sql_literal(value):
    return 'NULL::text' if value is None else "'" + value.replace("'", "''") + "'::text"


def run_policy(qual=None, with_check=None, *, schema='realtime', table='messages',
               role='authenticated', permissive='PERMISSIVE', cmd='SELECT'):
    """Replace policy metadata only, so the production SQL/regex itself is exercised."""
    psql = shutil.which('psql')
    assert psql, 'psql is required when RLS_CHECK_TEST_DATABASE is set'
    policy = (
        f'(SELECT {sql_literal(schema)}::name AS schemaname, '
        f'{sql_literal(table)}::name AS tablename, '
        f"'test_policy'::name AS policyname, {sql_literal(permissive)} AS permissive, "
        f'ARRAY[{sql_literal(role)}]::name[] AS roles, {sql_literal(cmd)} AS cmd, '
        f'{sql_literal(qual)} AS qual, {sql_literal(with_check)} AS with_check)'
    )
    query = read_check_sql().replace('pg_catalog.pg_policies', 'test_policies')
    query = query.replace('WITH policy_expressions AS (', f'WITH test_policies AS {policy}, policy_expressions AS (', 1)
    result = subprocess.run(
        [psql, '-X', '-q', '-v', 'ON_ERROR_STOP=1', '--csv', '-d', os.environ['RLS_CHECK_TEST_DATABASE']],
        input=query, capture_output=True, text=True, encoding='utf-8', check=True,
        env={**os.environ, 'PGOPTIONS': '-c default_transaction_read_only=on'},
    )
    return list(csv.DictReader(io.StringIO(result.stdout)))


@pytest.mark.parametrize('role', ['anon', 'authenticated', 'public', 'postgres'])
@pytest.mark.parametrize('cmd,qual,with_check', [
    ('SELECT', '(( true ))', None),
    ('INSERT', None, '(true)'),
])
def test_realtime_true_roles_and_commands(role, cmd, qual, with_check):
    rows = run_policy(qual, with_check, role=role, cmd=cmd)
    matches = [r for r in rows if r['rule'] == 'realtime_messages_policy_true']
    assert [r['basis'] for r in matches] == ([] if role == 'postgres' else [f'test_policy ({cmd})'])
    missing = [r for r in rows if r['rule'] == 'realtime_messages_no_policy']
    assert bool(missing) == (role in ('anon', 'postgres'))


@pytest.mark.parametrize('qual,with_check,permissive,flagged', [
    ("(SELECT auth.jwt()->>'aal') = 'aal2'", None, 'PERMISSIVE', True),
    ("(SELECT auth.jwt()->>'aal') = 'aal2'", None, 'RESTRICTIVE', False),
    (None, "(SELECT AUTH . JWT ( )->>'aal') = 'AAL2'", 'RESTRICTIVE', False),
    ("auth.jwt()->>'aal' = 'aal1'", None, 'RESTRICTIVE', True),
    ("user_id::text = 'aal2'", None, 'RESTRICTIVE', True),
    (None, None, 'RESTRICTIVE', True),
    ("auth.jwt()->>'aal' = 'notaal2'", None, 'RESTRICTIVE', True),
])
def test_mfa_requires_restrictive_jwt_and_aal2(qual, with_check, permissive, flagged):
    rows = run_policy(qual, with_check, schema='public', table='billing_settings', permissive=permissive)
    matches = [r for r in rows if r['rule'] == 'mfa_table_without_aal2' and r['object_name'] == 'billing_settings']
    assert [r['basis'] for r in matches] == (["table comment tag 'mfa'"] if flagged else [])
