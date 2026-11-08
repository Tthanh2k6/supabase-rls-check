"""Optional stdio MCP server exposing strictly local, read-only SQL analysis and rule docs.

Network probing is intentionally excluded from MCP so AI assistants never handle API keys
or initiate HTTP requests against Supabase projects through this server.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .report import deduplicate_and_sort_findings, fix_sql
from .rules import NOTES, RULES, SEVERITIES, explain_rule as _explain_rule, load_result

MCP_INSTALL_HINT = (
    'Optional dependency "mcp" is not installed. '
    'Install it with: pip install "supabase-rls-check[mcp]"'
)
MCP_TOOL_NAMES: tuple[str, str] = ('analyze_sql_export', 'explain_rule')


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


def create_mcp_server(fastmcp_cls: Any = None) -> Any:
    """Instantiate FastMCP with only analyze_sql_export and explain_rule registered."""
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
    return server


def run_mcp_server() -> None:
    """Run the MCP server over stdio."""
    server = create_mcp_server()
    server.run(transport='stdio')
