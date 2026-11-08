"""Allow running `python -m supabase_rls_check`."""
from __future__ import annotations

from .cli import main

if __name__ == '__main__':
    raise SystemExit(main())
