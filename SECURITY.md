# Security policy

## Supported versions

The latest release on PyPI gets fixes. Older releases do not.

## Reporting a vulnerability

Report it privately through GitHub: https://github.com/Tthanh2k6/supabase-rls-check/security/advisories/new

Do not open a public issue for a security problem. Do not put a real API key, JWT, database URL or table data in a report. Replace them with `[REDACTED]`.

Include the version (`supabase-rls-check --version`), the command, your OS and Python version, and steps or a small CSV or JSON file that reproduces it.

This is a one-person project. Reports are handled on a best-effort basis, with no promised response time.

## In scope

- `probe` sending a request with a key other than an `anon` JWT or an `sb_publishable_` key, such as a `service_role` or `authenticated` token.
- `probe` or any other command sending anything but `GET` and `HEAD`, or following a redirect.
- The tool reading table row values, or writing them, an HTTP error body or a raw JWT to a result file, report or error output.
- A key leaking into a report, a log or terminal output, including a `scan-env` result that is not masked.
- Writing a file outside the directory given by `--out` or `--out-dir`.
- A target-facing command running without `--i-own-this-project` or `--have-written-consent`.
- `probe` becoming reachable through the MCP server.
- Report HTML or `fix.sql` that does not escape or quote names taken from the input.

## Out of scope

- Findings the tool misses or flags wrongly. Open a normal bug report for those.
- Anything listed under "Limitations" in the README.
- Weaknesses in a Supabase project that the tool reports. Those belong to the project owner.
