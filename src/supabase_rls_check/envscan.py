"""Local, read-only scanner for secrets in public environment variables and client source code."""
from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

from .probe import jwt_role
from .rules import JWT, RULES, finding

MAX_FILE_BYTES = 2 * 1024 * 1024

SKIP_DIRS: frozenset[str] = frozenset(
    {
        'node_modules',
        '.git',
        '.venv',
        'venv',
        'dist',
        'build',
        '.next',
        '.expo',
    }
)
SKIP_REL_DIRS: tuple[str, ...] = ('ios/Pods', 'android/build')

SOURCE_EXTENSIONS: frozenset[str] = frozenset(
    {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte'}
)

PUBLIC_PREFIXES: tuple[str, ...] = (
    'EXPO_PUBLIC_',
    'NEXT_PUBLIC_',
    'VITE_',
    'REACT_APP_',
    'PUBLIC_',
    'NUXT_PUBLIC_',
)

SECRET_VALUE_PREFIXES: tuple[str, ...] = (
    'sk_live_',
    'rk_live_',
    'sk-proj-',
    'sk-ant-',
)

SECRET_NAME_TOKENS: tuple[str, ...] = (
    'SERVICE_ROLE',
    'SECRET',
    'PRIVATE_KEY',
)

SERVER_PATH_PREFIXES: tuple[str, ...] = (
    'supabase/functions/',
    'server/',
    'api/',
    'scripts/',
    'backend/',
)

ENV_LINE_RE = re.compile(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$')
PUBLIC_VAR_IN_CODE_RE = re.compile(
    r'''["']?\b((?:EXPO_PUBLIC_|NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_)[A-Za-z0-9_]*)\b["']?\s*[:=]\s*["'`]([^"'`\r\n]+)["'`]'''
)
SB_SECRET_RE = re.compile(r'\bsb_secret_[A-Za-z0-9_-]+')
CLIENT_VAR_ASSIGN_RE = re.compile(r'\b([A-Za-z_$][A-Za-z0-9_$]*)\s*[:=]\s*["\'`]')


def mask_secret(value: str) -> str:
    """Mask a secret value as first 6 chars + … + last 4, never returning the full value."""
    raw = value.strip()
    if len(raw) >= 20 and '…' not in raw:
        return f'{raw[:6]}…{raw[-4:]}'
    if len(raw) >= 7 and '…' not in raw:
        # Short values: 6 + 4 visible characters could reveal most or all of the value.
        return f'{raw[:2]}…{raw[-2:]}'
    if len(raw) > 2 and '…' not in raw:
        return f'{raw[:1]}…{raw[-1:]}'
    return '…'


def _is_env_file(name: str) -> bool:
    return name == '.env' or name.startswith('.env.')


def _is_config_file(name: str) -> bool:
    return name in ('app.json', 'eas.json') or name.startswith('app.config.')


def _is_source_file(name: str) -> bool:
    return Path(name).suffix.lower() in SOURCE_EXTENSIONS


def _is_client_path(rel_posix_path: str) -> bool:
    norm = rel_posix_path.lstrip('./')
    return not norm.startswith(SERVER_PATH_PREFIXES)


def _parse_env_rhs(rhs: str) -> str:
    rhs = rhs.strip()
    if not rhs:
        return ''
    if len(rhs) >= 2 and rhs[0] == rhs[-1] and rhs[0] in ('"', "'", '`'):
        return rhs[1:-1]
    if rhs[0] in ('"', "'", '`'):
        quote_char = rhs[0]
        end = rhs.find(quote_char, 1)
        if end != -1:
            return rhs[1:end]
        return rhs[1:].strip()
    return re.sub(r'\s+#.*$', '', rhs).strip()


def _is_service_role_value(value: str) -> bool:
    if value.startswith('sb_secret_'):
        return True
    if jwt_role(value) == 'service_role':
        return True
    return any(jwt_role(m.group()) == 'service_role' for m in JWT.finditer(value))


def _classify_public_var(var_name: str, value: str) -> tuple[str, str] | None:
    """Return (rule_id, reason) if a public-prefixed variable exposes a secret."""
    if not var_name.startswith(PUBLIC_PREFIXES) or not value:
        return None
    if _is_service_role_value(value):
        reason = 'sb_secret_ key' if value.startswith('sb_secret_') else 'service_role JWT'
        return ('public_env_service_role', reason)
    if value.startswith(SECRET_VALUE_PREFIXES):
        return ('public_env_secret_key', 'secret key prefix')
    upper_name = var_name.upper()
    if any(token in upper_name for token in SECRET_NAME_TOKENS):
        return ('public_env_secret_key', 'name suggests a secret')
    return None


def _build_env_finding(
    rule: str,
    rel_path: str,
    line_no: int,
    variable: str,
    raw_value: str,
    reason: str = '',
) -> dict[str, Any]:
    masked = mask_secret(raw_value)
    if variable and reason == 'name suggests a secret':
        detail = f'{variable} = {masked} (name suggests a secret)'
    elif variable:
        detail = f'{variable} = {masked}'
    else:
        detail = masked
    return finding(
        rule,
        schema_name='',
        object_name=f'{rel_path}:{line_no}',
        policy_name=detail,
        file=rel_path,
        line=line_no,
        variable=variable,
        masked_value=masked,
        reason=reason or None,
    )


def scan_env(path: str | Path) -> dict[str, Any]:
    """Walk a local project directory and scan public env variables and client files for secrets."""
    root = Path(path)
    if not root.exists() or not root.is_dir():
        raise ValueError('Provide an existing local project directory path.')

    findings: list[dict[str, Any]] = []
    for dirpath, dirs, files in os.walk(root, topdown=True, followlinks=False):
        kept_dirs: list[str] = []
        for d in sorted(dirs):
            if d in SKIP_DIRS:
                continue
            rel_dir = (Path(dirpath) / d).relative_to(root).as_posix()
            if rel_dir in SKIP_REL_DIRS or rel_dir.endswith(('/ios/Pods', '/android/build')):
                continue
            kept_dirs.append(d)
        dirs[:] = kept_dirs

        for filename in sorted(files):
            is_env = _is_env_file(filename)
            is_cfg = _is_config_file(filename)
            is_src = _is_source_file(filename)
            if not (is_env or is_cfg or is_src):
                continue

            file_path = Path(dirpath) / filename
            try:
                if file_path.is_symlink() or file_path.stat().st_size > MAX_FILE_BYTES:
                    continue
                raw = file_path.read_bytes()
            except OSError:
                continue

            if len(raw) > MAX_FILE_BYTES or b'\x00' in raw:
                continue

            text = raw.decode('utf-8', errors='replace')
            del raw
            rel_path = file_path.relative_to(root).as_posix()

            for line_no, line in enumerate(text.splitlines(), start=1):
                matched_tokens_on_line: set[str] = set()

                if is_env:
                    stripped = line.strip()
                    if not stripped or stripped.startswith('#'):
                        continue
                    env_match = ENV_LINE_RE.match(line)
                    if env_match:
                        var_name, rhs = env_match.group(1), env_match.group(2)
                        val = _parse_env_rhs(rhs)
                        classified = _classify_public_var(var_name, val)
                        if classified is not None:
                            rule_id, reason = classified
                            findings.append(
                                _build_env_finding(rule_id, rel_path, line_no, var_name, val, reason)
                            )
                            matched_tokens_on_line.add(val)
                else:
                    for var_match in PUBLIC_VAR_IN_CODE_RE.finditer(line):
                        var_name, val = var_match.group(1), var_match.group(2).strip()
                        classified = _classify_public_var(var_name, val)
                        if classified is not None:
                            rule_id, reason = classified
                            findings.append(
                                _build_env_finding(rule_id, rel_path, line_no, var_name, val, reason)
                            )
                            matched_tokens_on_line.add(val)

                if is_src and _is_client_path(rel_path):
                    var_match = CLIENT_VAR_ASSIGN_RE.search(line)
                    inferred_var = var_match.group(1) if var_match else ''
                    if inferred_var.startswith(PUBLIC_PREFIXES):
                        inferred_var = ''

                    for jwt_match in JWT.finditer(line):
                        tok = jwt_match.group()
                        if tok in matched_tokens_on_line:
                            continue
                        if jwt_role(tok) == 'service_role':
                            matched_tokens_on_line.add(tok)
                            findings.append(
                                _build_env_finding(
                                    'service_role_in_client_code',
                                    rel_path,
                                    line_no,
                                    inferred_var,
                                    tok,
                                    'service_role JWT',
                                )
                            )

                    for sb_match in SB_SECRET_RE.finditer(line):
                        tok = sb_match.group()
                        if tok in matched_tokens_on_line:
                            continue
                        matched_tokens_on_line.add(tok)
                        findings.append(
                            _build_env_finding(
                                'service_role_in_client_code',
                                rel_path,
                                line_no,
                                inferred_var,
                                tok,
                                'sb_secret_ key',
                            )
                        )

    return {'findings': findings, 'notes': [], 'observations': []}


def format_envscan_table(result: dict[str, Any]) -> str:
    """Format scan-env findings as a concise plain-text table with masked values only."""
    findings = result.get('findings', [])
    if not findings:
        return (
            'Severity  Rule                         Location  Variable  Masked\n'
            '--------  ---------------------------  --------  --------  ------\n'
            'No public-env or client-code secret findings (local files only).'
        )

    rows: list[tuple[str, str, str, str, str]] = []
    for item in findings:
        rule_id = item['rule']
        severity = item.get('severity') or RULES[rule_id][0]
        location = f"{item.get('file', '')}:{item.get('line', '')}".strip(':') or item.get('object_name', '')
        variable = item.get('variable') or '-'
        masked = item.get('masked_value', '')
        if item.get('reason') == 'name suggests a secret':
            masked = f'{masked} (name suggests a secret)'
        rows.append((severity, rule_id, location, variable, masked))

    headers = ('Severity', 'Rule', 'Location', 'Variable', 'Masked')
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
    return '\n'.join([header_line, sep_line, *body_lines])
