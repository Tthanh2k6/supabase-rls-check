"""The CLI must write UTF-8 even when stdout is redirected with a non-UTF-8 encoding (Windows cp1252)."""
from __future__ import annotations

import os
import subprocess
import sys


def test_explain_vi_survives_cp1252_redirect():
    env = dict(os.environ, PYTHONIOENCODING='cp1252')
    proc = subprocess.run(
        [sys.executable, '-m', 'supabase_rls_check', 'explain', 'rls_disabled', '--lang', 'vi'],
        capture_output=True,
        env=env,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr.decode('utf-8', 'replace')
    text = proc.stdout.decode('utf-8')
    assert any(ch in text for ch in 'ạảấầậắặẹệịọộợụựỳ')
