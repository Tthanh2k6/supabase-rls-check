# Contributing

Contributions that improve rule accuracy, documentation clarity, or report usability are welcome.

## Safety and scope boundaries

Pull requests **must** preserve the project's safety invariants:

1. **Read-only behavior only** — Never add `INSERT`, `UPDATE`, `DELETE`, DDL execution, or RPC (`POST`) calls against target projects. `probe` may use `GET` and `HEAD` only.
2. **Explicit authorization** — Target-facing CLI commands (`sql --from`, `probe`, `report`) must continue to require `--i-own-this-project` or `--have-written-consent`.
3. **Zero secret or row retention** — Never persist customer row values, HTTP error bodies, or raw JWT strings in result files, reports, or error output.
4. **No probing in MCP** — Keep `probe` out of `mcp_server.py`; MCP tools operate strictly on local SQL metadata exports and static rule documentation.

## Development setup

```bash
python -m venv .venv
# Activate the virtual environment, then:
python -m pip install -e ".[dev]"
python -m pytest -q
```

All unit tests run offline and forbid real network requests via an `autouse` fixture. If you modify `src/supabase_rls_check/sql/check.sql`, update `tests/fixtures/seed_pg.sql` and `tests/fixtures/all_findings.csv` so PostgreSQL 15 CI stays in sync. `scripts/e2e_diff.py` runs the `diff` end-to-end check against a local PostgreSQL (`PGHOST`/`PGUSER` set, `psql` on the PATH); it creates and drops a throwaway `rls_check_e2e` database.
