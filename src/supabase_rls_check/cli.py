"""Command-line interface for supabase-rls-check."""
from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
import os
from pathlib import Path
import sys

import requests

from . import __version__
from .envscan import format_envscan_table, scan_env
from .mcp_server import run_mcp_server
from .probe import probe
from .report import report
from .rules import explain_rule, load_result, read_check_sql


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog='supabase-rls-check',
        description='Consent-gated, read-only RLS, policy, and anonymous exposure checks for Supabase.',
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')

    consent = argparse.ArgumentParser(add_help=False)
    consent.add_argument(
        '--i-own-this-project',
        '--have-written-consent',
        dest='consent',
        action='store_true',
        help='Confirm project ownership or explicit written authorization for all targets',
    )

    sub = parser.add_subparsers(dest='mode', required=True)

    sql_parser = sub.add_parser(
        'sql',
        parents=[consent],
        help='Validate and normalize a CSV/JSON export from check.sql (or print check.sql)',
    )
    sql_group = sql_parser.add_mutually_exclusive_group(required=True)
    sql_group.add_argument(
        '--from',
        dest='source',
        help='Path to CSV or JSON catalog metadata exported from check.sql',
    )
    sql_group.add_argument(
        '--print-sql',
        action='store_true',
        help='Print the bundled read-only check.sql query to stdout and exit',
    )
    sql_parser.add_argument(
        '--out',
        default='sql_results.json',
        help='Output JSON path (default: sql_results.json)',
    )

    probe_parser = sub.add_parser(
        'probe',
        parents=[consent],
        help='Run read-only GET/HEAD checks with an anon/publishable key',
    )
    probe_parser.add_argument('--url', required=True, help='Project HTTPS origin (e.g. https://project.supabase.co)')
    probe_parser.add_argument('--anon-key', help='Public anon JWT or sb_publishable_ key (or set SUPABASE_ANON_KEY to keep it out of shell history)')
    probe_parser.add_argument('--tables', nargs='*', default=[], help='Known table/view names when OpenAPI is disabled')
    probe_parser.add_argument('--site', help='Authorized frontend HTTPS URL to check for exposed service_role JWTs')
    probe_parser.add_argument('--out', default='probe_results.json', help='Output JSON path (default: probe_results.json)')

    report_parser = sub.add_parser(
        'report',
        parents=[consent],
        help='Generate standalone report.md, report.html, and rollback-first fix.sql',
    )
    report_parser.add_argument('--from', dest='sources', nargs='+', required=True, help='Result JSON/CSV file(s)')
    report_parser.add_argument('--out-dir', default='.', help='Directory for report.md, report.html, and fix.sql')
    report_parser.add_argument('--lang', choices=('en', 'vi'), default='en', help='Report language (default: en)')
    report_parser.add_argument('--project', default='Supabase app', help='Project title shown in the report')

    explain_parser = sub.add_parser(
        'explain',
        parents=[consent],
        help='Explain a rule and show how to remediate it',
    )
    explain_parser.add_argument('rule', help='Rule identifier (e.g. rls_disabled, policy_true, definer_anon_exec)')
    explain_parser.add_argument('--lang', choices=('en', 'vi'), default='en', help='Output language (default: en)')

    scan_env_parser = sub.add_parser(
        'scan-env',
        parents=[consent],
        help='Scan local project files only (read-only, no network) for secrets in public env variables and client code',
    )
    scan_env_parser.add_argument(
        'path',
        help='Project directory to scan (reads local files only and masks secret values)',
    )
    scan_env_parser.add_argument(
        '--out',
        help='Optional output JSON path compatible with report --from (e.g. envscan.json)',
    )

    sub.add_parser(
        'mcp',
        parents=[consent],
        help='Run the optional stdio MCP server (analyze_sql_export, explain_rule, and scan_public_env; local files only)',
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point returning POSIX exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.mode == 'explain':
        try:
            print(explain_rule(args.rule, lang=args.lang))
            return 0
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    if args.mode == 'scan-env':
        try:
            result = scan_env(args.path)
            print(format_envscan_table(result))
            if args.out:
                Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            return 0
        except (OSError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 1

    if args.mode == 'mcp':
        try:
            run_mcp_server()
            return 0
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    if args.mode == 'sql' and args.print_sql:
        print(read_check_sql(), end='')
        return 0

    if not args.consent:
        parser.error('Written authorization required: --i-own-this-project or --have-written-consent')

    try:
        if args.mode == 'report':
            report([load_result(p) for p in args.sources], args.out_dir, args.lang, args.project)
        elif args.mode == 'sql':
            result = load_result(args.source)
            Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        else:
            anon_key = args.anon_key or os.environ.get('SUPABASE_ANON_KEY')
            if not anon_key:
                parser.error('Provide --anon-key or set SUPABASE_ANON_KEY')
            result = probe(args.url, anon_key, args.tables, args.site)
            Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    except (OSError, ValueError, KeyError, TypeError, requests.RequestException):
        print(
            'Check failed: verify input format, file permissions and HTTPS targets. Sensitive error details suppressed.',
            file=sys.stderr,
        )
        return 1

    print('Done. Review output and coverage limitations before acting on findings.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
