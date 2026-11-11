"""Optional stdio MCP server exposing strictly local, read-only SQL/env analysis and rule docs.

Network probing is intentionally excluded from MCP so AI assistants never handle API keys
or initiate HTTP requests against Supabase projects through this server.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .diff import diff_findings
from .envscan import scan_env
from .report import deduplicate_and_sort_findings, fix_sql
from .rules import NOTES, RULES, SEVERITIES, explain_rule as _explain_rule, load_result

MCP_INSTALL_HINT = (
    'Optional dependency "mcp" is not installed. '
    'Install it with: pip install "supabase-rls-check[mcp]"'
)
MCP_TOOL_NAMES: tuple[str, str, str, str] = (
    'analyze_sql_export',
    'explain_rule',
    'scan_public_env',
    'diff_results',
)


def analyze_sql_export(path: str) -> dict[str, Any]:
    """Validate and summarize a local CSV or JSON metadata export from check.sql."""
    if not isinstance(path, str) or not path.strip():
        raise ValueError('Provide a path to a .csv or .json SQL metadata export.')
    target = Path(path)
    if target.suffix.lower() not in ('.csv', '.json'):
        raise ValueError('Only .csv and .json metadata export files are supported.')
    try:
        envelope = load_result(target)
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            'Invalid or unreadable SQL export; expected UTF-8 CSV or JSON metadata with '
            'rule, schema_name, object_name, and optional policy_name columns.'
        ) from exc

    findings = deduplicate_and_sort_findings([envelope])
    enriched: list[dict[str, Any]] = []
    for item in findings:
        severity, title, remedy, _, _ = RULES[item['rule']]
        entry: dict[str, Any] = {
            'rule': item['rule'],
            'severity': severity,
            'title': title,
            'schema_name': item['schema_name'],
            'object_name': item['object_name'],
            'policy_name': item['policy_name'],
            'basis': item.get('basis', ''),
            'remediation': remedy,
        }
        if item['rule'] == 'anon_readable':
            entry['columns'] = item['columns']
            entry['row_count'] = item['row_count']
        enriched.append(entry)

    counts = {sev: sum(1 for f in enriched if f['severity'] == sev) for sev in SEVERITIES}
    return {
        'total_findings': len(enriched),
        'counts': counts,
        'findings': enriched,
        'notes': [NOTES[n][0] for n in envelope['notes']],
        'fix_sql': fix_sql(findings, lang='en'),
        'limitations': (
            'Limited review of supplied catalog metadata only. Configuration flags do not prove '
            'exploitation or write access, and zero findings does not certify safety.'
        ),
    }


def explain_rule(rule: str) -> str:
    """Explain what a supabase-rls-check rule detects, caveats, and how to remediate it."""
    return _explain_rule(rule, lang='en')


def scan_public_env(path: str) -> dict[str, Any]:
    """Scan a local project directory (read-only, local files only, no network) for secrets in public env variables and client source files, returning masked values only."""
    if not isinstance(path, str) or not path.strip():
        raise ValueError('Provide a path to a local project directory.')
    try:
        envelope = scan_env(path)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError('Unable to scan local project directory; verify the directory exists and is readable.') from exc

    findings = deduplicate_and_sort_findings([envelope])
    enriched: list[dict[str, Any]] = []
    for item in findings:
        severity, title, remedy, _, _ = RULES[item['rule']]
        entry: dict[str, Any] = {
            'rule': item['rule'],
            'severity': severity,
            'title': title,
            'file': item.get('file', ''),
            'line': item.get('line'),
            'variable': item.get('variable', ''),
            'masked_value': item.get('masked_value', ''),
            'schema_name': item['schema_name'],
            'object_name': item['object_name'],
            'policy_name': item['policy_name'],
            'remediation': remedy,
        }
        if 'reason' in item:
            entry['reason'] = item['reason']
        enriched.append(entry)

    counts = {sev: sum(1 for f in enriched if f['severity'] == sev) for sev in SEVERITIES}
    return {
        'total_findings': len(enriched),
        'counts': counts,
        'findings': enriched,
        'limitations': (
            'Read-only scan of local project files only; no network requests are made and all secret '
            'values are masked. Zero findings does not certify that no secrets exist in other files.'
        ),
    }


def _enrich_finding(item: dict[str, Any]) -> dict[str, Any]:
    severity, title, remedy, _, _ = RULES[item['rule']]
    entry: dict[str, Any] = {
        'rule': item['rule'],
        'severity': severity,
        'title': title,
        'schema_name': item['schema_name'],
        'object_name': item['object_name'],
        'policy_name': item['policy_name'],
        'basis': item.get('basis', ''),
        'remediation': remedy,
    }
    if item['rule'] == 'anon_readable':
        entry['columns'] = item['columns']
        entry['row_count'] = item['row_count']
    return entry


def diff_results(old_path: str, new_path: str) -> dict[str, Any]:
    """Compare two local CSV or JSON result files (read-only, local files only, no network) and return new and resolved findings."""
    for label, raw in (('old_path', old_path), ('new_path', new_path)):
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError(f'Provide a path to a .csv or .json result file for {label}.')
        if Path(raw).suffix.lower() not in ('.csv', '.json'):
            raise ValueError('Only .csv and .json result files are supported.')
    try:
        raw_diff = diff_findings(old_path, new_path)
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            'Invalid or unreadable result file; expected UTF-8 CSV or JSON metadata with '
            'rule, schema_name, object_name, and optional policy_name columns.'
        ) from exc

    enriched_new = [_enrich_finding(item) for item in raw_diff['new']]
    enriched_resolved = [_enrich_finding(item) for item in raw_diff['resolved']]
    counts_new = {sev: sum(1 for f in enriched_new if f['severity'] == sev) for sev in SEVERITIES}
    return {
        'new': enriched_new,
        'resolved': enriched_resolved,
        'unchanged_count': raw_diff['unchanged_count'],
        'new_count': len(enriched_new),
        'resolved_count': len(enriched_resolved),
        'counts_new': counts_new,
        'limitations': (
            'Read-only comparison of local result files only; no network requests are made '
            'and zero new findings does not certify safety.'
        ),
    }


def create_mcp_server(fastmcp_cls: Any = None) -> Any:
    """Instantiate FastMCP with only local read-only tools registered."""
    if fastmcp_cls is None:
        try:  # mcp >= 2.0 renamed FastMCP to MCPServer
            from mcp.server.mcpserver import MCPServer as fastmcp_cls
        except ImportError:
            try:  # mcp 1.x
                from mcp.server.fastmcp import FastMCP as fastmcp_cls
            except ImportError as exc:
                raise RuntimeError(MCP_INSTALL_HINT) from exc
    server = fastmcp_cls('supabase-rls-check')
    server.tool()(analyze_sql_export)
    server.tool()(explain_rule)
    server.tool()(scan_public_env)
    server.tool()(diff_results)
    return server


def run_mcp_server() -> None:
    """Run the MCP server over stdio."""
    server = create_mcp_server()
    server.run(transport='stdio')
