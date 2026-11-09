"""Consent-gated, read-only Supabase RLS, policy, and anonymous exposure checks."""
from __future__ import annotations

__version__ = '0.2.1'

from .cli import build_parser, main
from .probe import Scripts, fetch, jwt_role, probe, scan_site, validate_url
from .report import deduplicate_and_sort_findings, fix_sql, quote_identifier, report
from .rules import (
    JWT,
    NOTES,
    RULE_GUIDES,
    RULES,
    SEVERITIES,
    SQL_RULES,
    VI_SEVERITIES,
    clean,
    explain_rule,
    finding,
    get_check_sql_path,
    load_result,
    read_check_sql,
)

__all__ = [
    'JWT',
    'NOTES',
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
    'explain_rule',
    'fetch',
    'finding',
    'fix_sql',
    'get_check_sql_path',
    'jwt_role',
    'load_result',
    'main',
    'probe',
    'quote_identifier',
    'read_check_sql',
    'report',
    'scan_site',
    'validate_url',
]
