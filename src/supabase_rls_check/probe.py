"""Read-only GET/HEAD PostgREST anonymous probe and same-origin frontend bundle check."""
from __future__ import annotations

import base64
from collections.abc import Iterable
from html.parser import HTMLParser
import json
import re
from typing import Any
from urllib.parse import quote, unquote, urljoin, urlsplit

import requests

from .rules import JWT, clean, finding


def jwt_role(token: str) -> str | None:
    """Extract the unverified JWT role claim without retaining the token."""
    try:
        part = token.split('.')[1]
        payload = json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
        return payload.get('role') if isinstance(payload, dict) else None
    except (ValueError, IndexError, UnicodeError):
        return None


def validate_url(url: str) -> str:
    """Require an HTTPS URL without embedded credentials or URL fragments."""
    parts = urlsplit(url)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError('Use an HTTPS URL without credentials or fragment')
    return url


def fetch(
    session: requests.Session,
    method: str,
    url: str,
    **kwargs: Any,
) -> tuple[int, dict[str, str], bytes]:
    """No redirects (including credential forwarding); bounded, ephemeral body."""
    if method not in ('GET', 'HEAD'):
        raise ValueError('Only GET and HEAD methods are permitted')
    with session.request(method, url, timeout=20, allow_redirects=False, stream=True, **kwargs) as response:
        status, headers = response.status_code, dict(response.headers)
        # Do not retain HTTP error bodies, which can contain sensitive data.
        if status not in (200, 206) or method == 'HEAD':
            return status, headers, b''
        body = bytearray()
        for chunk in response.iter_content(65536):
            body.extend(chunk)
            if len(body) > 5_000_000:
                raise ValueError('Response exceeds scan limit')
        return status, headers, bytes(body)


class Scripts(HTMLParser):
    """Collect script src attributes from an HTML document."""

    def __init__(self) -> None:
        super().__init__()
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == 'script':
            src = dict(attrs).get('src')
            if src:
                self.sources.append(src)


def scan_site(session: requests.Session, site: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Inspect HTML and up to 20 same-origin scripts for exposed service_role JWTs."""
    validate_url(site)
    result: list[dict[str, Any]] = []
    notes: list[str] = []
    try:
        status, _, body = fetch(session, 'GET', site)
        if status != 200:
            return [], ['site_incomplete']
        text = body.decode('utf-8', errors='replace')
        parser = Scripts()
        parser.feed(text)
        resources = [(site, text)]
        urls = list(dict.fromkeys(urljoin(site, src) for src in parser.sources))
        if len(urls) > 20:
            notes.append('site_incomplete')
        for url in urls[:20]:
            if urlsplit(url).netloc != urlsplit(site).netloc or urlsplit(url).scheme != 'https':
                notes.append('site_incomplete')
                continue
            try:
                validate_url(url)
                status, _, body = fetch(session, 'GET', url)
                if status == 200:
                    resources.append((url, body.decode('utf-8', errors='replace')))
                else:
                    notes.append('site_incomplete')
            except (requests.RequestException, ValueError):
                notes.append('site_incomplete')
        for index, (_, content) in enumerate(resources):
            if any(jwt_role(m.group()) == 'service_role' for m in JWT.finditer(content)):
                # Numbered resource avoids saving URLs containing query/path secrets.
                result.append(finding('service_role_exposed', object_name=f'frontend resource {index + 1}'))
    except (requests.RequestException, ValueError):
        notes.append('site_incomplete')
    return result, sorted(set(notes))


def probe(
    url: str,
    key: str,
    tables: Iterable[str] = (),
    site: str | None = None,
) -> dict[str, Any]:
    """Run read-only GET/HEAD checks using only an anon JWT or publishable key."""
    validate_url(url)
    if urlsplit(url).query or urlsplit(url).path not in ('', '/'):
        raise ValueError('--url must be the project HTTPS origin')
    if not key.startswith('sb_publishable_') and jwt_role(key) != 'anon':
        raise ValueError('Only an anon JWT or publishable key is accepted')
    headers = {'apikey': key}
    if not key.startswith('sb_publishable_'):
        headers['Authorization'] = 'Bearer ' + key
    result: dict[str, Any] = {'findings': [], 'notes': [], 'observations': []}
    base = url.rstrip('/') + '/rest/v1/'
    names = set(tables)
    with requests.Session() as session:
        session.trust_env = False
        try:
            status, _, body = fetch(session, 'GET', base, headers=headers)
            spec = json.loads(body) if status == 200 else {}
            paths = spec.get('paths', {})
            if status != 200 or not isinstance(paths, dict) or not paths:
                result['notes'].append('discovery_failed')
            else:
                for path, operations in paths.items():
                    if re.fullmatch(r'/[^/{}]+', path) and path != '/' and isinstance(operations, dict) and 'get' in operations:
                        names.add(unquote(path[1:]))
        except (requests.RequestException, ValueError, AttributeError):
            result['notes'].append('discovery_failed')
        for name in sorted(names):
            if not name or '/' in name or name in ('.', '..'):
                raise ValueError('Invalid table name')
            endpoint = base + quote(name, safe='')
            observation = {'table': clean(name), 'status': 'error'}
            try:
                status, _, body = fetch(
                    session,
                    'GET',
                    endpoint,
                    headers=headers,
                    params={'select': '*', 'limit': 1},
                )
                if status in (401, 403):
                    observation['status'] = 'denied'
                elif status in (200, 206):
                    rows = json.loads(body)
                    if not isinstance(rows, list) or len(rows) > 1 or any(not isinstance(r, dict) for r in rows):
                        raise ValueError('Invalid row response')
                    columns = list(rows[0]) if rows else []
                    has_rows = bool(rows)
                    del rows, body
                    observation['status'] = 'readable' if has_rows else 'empty'
                    count = None
                    try:
                        head_status, head_headers, _ = fetch(
                            session,
                            'HEAD',
                            endpoint,
                            headers={**headers, 'Prefer': 'count=exact'},
                            params={'select': '*', 'limit': 1},
                        )
                        range_value = next((v for k, v in head_headers.items() if k.lower() == 'content-range'), '')
                        match = re.fullmatch(r'(?:\d+-\d+|\*)/(\d+)', range_value)
                        if head_status in (200, 206) and match:
                            count = int(match[1])
                        else:
                            result['notes'].append('probe_incomplete')
                    except (requests.RequestException, ValueError):
                        result['notes'].append('probe_incomplete')
                    if has_rows or (count is not None and count > 0):
                        observation['status'] = 'readable'
                        result['findings'].append(
                            finding('anon_readable', 'public', name, columns=columns, row_count=count)
                        )
                if observation['status'] == 'error':
                    result['notes'].append('probe_incomplete')
            except (requests.RequestException, ValueError):
                result['notes'].append('probe_incomplete')
            result['observations'].append(observation)
        if site:
            findings, notes = scan_site(session, site)
            result['findings'].extend(findings)
            result['notes'].extend(notes)
    result['notes'] = sorted(set(result['notes']))
    return result
