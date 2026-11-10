"""Compare two local check runs and report new and resolved findings."""
from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .rules import RULES, SEVERITIES, load_result


def _load_sources(
    sources: str | Path | Sequence[str | Path | dict[str, Any]],
) -> list[dict[str, Any]]:
    """Load one or more CSV/JSON result sources using rules.load_result."""
    if isinstance(sources, (str, Path)):
        items: list[str | Path | dict[str, Any]] = [sources]
    else:
        items = list(sources)
    if not items:
        raise ValueError('Provide at least one result file path.')
    loaded: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict) and isinstance(item.get('findings'), list):
            loaded.append(item)
        elif isinstance(item, (str, Path)):
            loaded.append(load_result(item))
        else:
            raise ValueError('Each source must be a CSV/JSON path or loaded result dict.')
    return loaded


def _finding_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
    """Return the canonical (rule, schema, object, policy) tuple for a finding."""
    return (
        item['rule'],
        item.get('schema_name', ''),
        item.get('object_name', ''),
        item.get('policy_name', ''),
    )


def diff_findings(
    old_sources: str | Path | Sequence[str | Path | dict[str, Any]],
    new_sources: str | Path | Sequence[str | Path | dict[str, Any]],
) -> dict[str, Any]:
    """Compare old and new finding sources keyed and sorted by (rule, schema, object, policy)."""
    old_envelopes = _load_sources(old_sources)
    new_envelopes = _load_sources(new_sources)

    old_by_key = {_finding_key(f): f for env in old_envelopes for f in env['findings']}
    new_by_key = {_finding_key(f): f for env in new_envelopes for f in env['findings']}

    old_keys = set(old_by_key)
    new_keys = set(new_by_key)

    added_keys = sorted(new_keys - old_keys)
    removed_keys = sorted(old_keys - new_keys)
    unchanged_count = len(old_keys & new_keys)

    return {
        'new': [new_by_key[k] for k in added_keys],
        'resolved': [old_by_key[k] for k in removed_keys],
        'unchanged_count': unchanged_count,
    }


def should_fail_on_new(diff_result: dict[str, Any], fail_on_new: str | None) -> bool:
    """Return True if any NEW finding is at or above fail_on_new severity."""
    if fail_on_new is None:
        return False
    cleaned = fail_on_new.strip()
    if not cleaned or cleaned.lower() == 'none':
        return False
    normalized = cleaned.capitalize()
    if normalized not in SEVERITIES:
        raise ValueError(f"Invalid severity '{fail_on_new}'. Expected one of: critical, high, medium, low")
    threshold = SEVERITIES.index(normalized)
    return any(
        SEVERITIES.index(RULES[f['rule']][0]) <= threshold
        for f in diff_result.get('new', [])
    )


def format_diff_table(result: dict[str, Any]) -> str:
    """Format new and resolved findings as a concise plain-text table with severity."""
    new_items = result.get('new', [])
    resolved_items = result.get('resolved', [])
    unchanged = result.get('unchanged_count', 0)

    if not new_items and not resolved_items:
        return (
            'Status  Severity  Rule  Object  Policy\n'
            '------  --------  ----  ------  ------\n'
            f'No new or resolved findings (unchanged: {unchanged}; local files only).'
        )

    rows: list[tuple[str, str, str, str, str]] = []
    for status, items in (('new', new_items), ('resolved', resolved_items)):
        for item in items:
            rule_id = item['rule']
            severity = item.get('severity') or RULES[rule_id][0]
            target = '.'.join(x for x in (item.get('schema_name', ''), item.get('object_name', '')) if x) or '-'
            policy = item.get('policy_name') or '-'
            rows.append((status, severity, rule_id, target, policy))

    headers = ('Status', 'Severity', 'Rule', 'Object', 'Policy')
    widths = [
        max(len(headers[i]), *(len(r[i]) for r in rows))
        for i in range(len(headers))
    ]
    header_line = '  '.join(headers[i].ljust(widths[i]) for i in range(len(headers))).rstrip()
    sep_line = '  '.join('-' * widths[i] for i in range(len(headers))).rstrip()
    body_lines = [
        '  '.join(r[i].ljust(widths[i]) for i in range(len(headers))).rstrip()
        for r in rows
    ]
    summary_line = f'New: {len(new_items)}, resolved: {len(resolved_items)}, unchanged: {unchanged}'
    return '\n'.join([header_line, sep_line, *body_lines, summary_line])
