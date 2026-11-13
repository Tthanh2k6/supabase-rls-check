"""Consent-gated, read-only Supabase RLS, policy, and anonymous exposure checks."""
from __future__ import annotations

__version__ = '0.6.2'

from .cli import build_parser, main
from .diff import diff_findings, format_diff_table, should_fail_on_new
from .envscan import PUBLIC_PREFIXES, format_envscan_table, mask_secret, scan_env
from .probe import Scripts, fetch, jwt_role, probe, scan_site, validate_url
from .report import deduplicate_and_sort_findings, fix_sql, quote_identifier, report
from .rules import (
    ENV_RULES,
    EXTENSION_REMEDY,
    JWT,
    NOTES,
    RULE_GUIDES,
    RULES,
    SEVERITIES,
    SQL_RULES,
    VI_SEVERITIES,
    clean,
    explain_rule,
    extension_owner,
    finding,
    get_check_sql_path,
    load_result,
    read_check_sql,
)

__all__ = [
    'ENV_RULES',
    'EXTENSION_REMEDY',
    'JWT',
    'NOTES',
    'PUBLIC_PREFIXES',
    'RULES',
    'RULE_GUIDES',
    'SEVERITIES',
    'SQL_RULES',
    'Scripts',
    'VI_SEVERITIES',
    '__version__',
    'build_parser',
    'clean',
    'deduplicate_and_sort_findings',
    'diff_findings',
    'explain_rule',
    'extension_owner',
    'fetch',
    'finding',
    'fix_sql',
    'format_diff_table',
    'format_envscan_table',
    'get_check_sql_path',
    'jwt_role',
    'load_result',
    'main',
    'mask_secret',
    'probe',
    'quote_identifier',
    'read_check_sql',
    'report',
    'scan_env',
    'scan_site',
    'should_fail_on_new',
    'validate_url',
]
