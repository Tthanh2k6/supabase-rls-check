"""Backward-compatible entry point re-exporting from supabase_rls_check."""
from __future__ import annotations

from pathlib import Path
import sys

_SRC = Path(__file__).resolve().parent / 'src'
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from supabase_rls_check import (  # noqa: E402
    JWT,
    NOTES,
    RULES,
    SEVERITIES,
    Scripts,
    VI_SEVERITIES,
    clean,
    explain_rule,
    fetch,
    finding,
    fix_sql,
    jwt_role,
    load_result,
    main,
    probe,
    quote_identifier,
    report,
    scan_site,
    validate_url,
)

__all__ = [
    'JWT',
    'NOTES',
    'RULES',
    'SEVERITIES',
    'Scripts',
    'VI_SEVERITIES',
    'clean',
    'explain_rule',
    'fetch',
    'finding',
    'fix_sql',
    'jwt_role',
    'load_result',
    'main',
    'probe',
    'quote_identifier',
    'report',
    'scan_site',
    'validate_url',
]

if __name__ == '__main__':
    raise SystemExit(main())
