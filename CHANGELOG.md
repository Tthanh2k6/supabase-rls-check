# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.2] - 2026-11-13

### Changed
- All four MCP tools now declare `readOnlyHint=true`, `destructiveHint=false`, `idempotentHint=true`, and `openWorldHint=false` (plus a human `title`), as required by MCP directories that reject tools missing a hint; the optional `mcp` extra now requires `mcp>=1.10`. A test asserts the four boolean hints on every tool.

## [0.6.1] - 2026-11-12

### Added
- `check.sql` detects tables in `public` that belong to an extension through `pg_depend` (`deptype = 'e'`). `rls_disabled` still reports them, with `basis` set to `owned by extension <name>`; `fix.sql` and the reports recommend moving the extension out of `public` into an `extensions` schema (Supabase discussion #52767) instead of suggesting `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`, which fails on Supabase with "must be owner". Detection covers direct extension members only, and some extensions cannot be relocated.
- `scan-env` now scans React Native / Expo projects more completely: `app.json`, `app.config.*`, and `eas.json` are checked for hardcoded `service_role` JWTs and `sb_secret_` keys (`service_role_in_client_code`), and client sources plus config are checked for Postgres connection strings with a password through the new `db_url_in_client_code` rule (Critical). The anon and publishable keys are never reported. Build output folders such as `web-build`, `android/app/build`, and `ios/build` are skipped. The scan is pattern-based and can miss obfuscated or split keys. Values stay masked.
- `scripts/e2e_diff.py` and a `diff-e2e` CI job: against a real PostgreSQL 15 it applies a fixture schema, builds a report, reruns unchanged (`diff --fail-on-new high` exits 0), adds a `pii` table comment, reruns, and asserts that the same command exits non-zero with the escalated `sensitive_anon_policy` finding.
- PostgreSQL 15 fixture for an extension-owned table (32 expected catalog findings) and unit tests for all three changes.

### Changed
- Because `basis` is part of the `diff` key, a baseline exported before 0.6.1 lists an extension-owned table with an empty `basis`; the first diff against it reports that table as new (with the extension basis) and the old entry as resolved. Re-export the baseline once to clear it.
- Connection strings whose password is a placeholder such as `${DB_PASSWORD}` are no longer flagged in agent config files or client code.

## [0.6.0] - 2026-11-11

### Added
- Optional `basis` field on SQL catalog findings explaining why a rule/severity applied (for example `table name matches pattern 'payment'` or `table comment tag 'pii'` on `sensitive_anon_policy`, the column name on `secret_column_exposed`, and the argument name(s) on `definer_trusts_id_arg`), shown across text/Markdown/HTML reports, JSON output, MCP `analyze_sql_export`, and `diff` identity keys `(rule, schema_name, object_name, policy_name, basis)` while keeping backward compatibility with older JSON files (idea from a dev.to reader comment).
- Two read-only catalog rules: `secret_column_exposed` (Medium) for tables in `public` with a secret-like column name (`api_key`, `apikey`, `secret`, `client_secret`, `access_token`, `refresh_token`, `private_key`, `password` exact or suffix) selectable by `anon` or `authenticated`, and `definer_trusts_id_arg` (Medium, review needed) for `SECURITY DEFINER` functions in `public` executable by `anon` or `authenticated` that take an `_id` or `uid`/`user`/`org`/`tenant` argument without referencing `auth.uid()` or `auth.jwt()` in `prosrc`, bringing the catalog total to 17 checks (ideas from dev.to articles and reader comments).
- `agent_config_secret` (Critical) in `scan-env` and `scan_public_env(path)` to scan `.claude/settings.json`, `.claude/settings.local.json`, `.cursor/mcp.json`, `.mcp.json`, and `.vscode/mcp.json` (with JSON key paths when valid JSON and text fallback when invalid) for `sb_secret_` keys, `service_role` JWTs, and PostgreSQL connection strings with inline passwords, masking all secret values.
- English and Vietnamese titles/remediation, `explain` guides, comment-only `fix.sql` guidance, PostgreSQL 15 fixtures (31 expected catalog findings), and unit tests for `basis` failure-injection diffs, `secret_column_exposed`, `definer_trusts_id_arg`, and `agent_config_secret`.

### Fixed
- The JWT pattern used to redact tokens from finding metadata now matches only real JWTs (`eyJ...` header). The old pattern also matched any `a.b.c` text, which redacted file paths such as `.claude/settings.local.json` and dotted JSON key paths.

## [0.5.0] - 2026-11-10

### Added
- Read-only catalog rule `policy_true_writable` (Critical) for permissive `UPDATE`, `DELETE`, or `ALL` policies in `public` whose `USING` expression is unconditionally `true` on a table where `anon` or `authenticated` holds `UPDATE` or `DELETE` privileges, bringing the catalog total to 15 checks (ideas from LinkedIn and dev.to readers).
- `diff` command (`supabase-rls-check diff --old OLD --new NEW [--out diff.json] [--fail-on-new SEVERITY]`) and `diff_results(old_path, new_path)` MCP tool to compare two local CSV/JSON runs, report new and resolved findings with severity, and optionally fail CI only on new findings at or above a chosen severity (ideas from LinkedIn and dev.to readers).
- English and Vietnamese titles/remediation, `explain` guide, comment-only `fix.sql` guidance, PostgreSQL 15 fixtures (29 expected catalog findings), and unit tests for `policy_true_writable` and `diff`.

## [0.4.0] - 2026-11-10

### Added
- Read-only catalog rule `policy_any_authenticated` (Medium) for policies in `public` whose `USING` or `WITH CHECK` expression only checks that the caller is signed in (`auth.role() = 'authenticated'` or `auth.uid() IS NOT NULL`, with or without a `(SELECT ...)` wrapper), bringing the catalog total to 14 checks (ideas from dev.to and LinkedIn readers).
- Local public-env and client-code secret scanner (`supabase-rls-check scan-env PATH [--out envscan.json]` and `scan_public_env(path)` MCP tool) detecting `public_env_service_role` (Critical), `public_env_secret_key` (High), and `service_role_in_client_code` (Critical) across `.env*`, Expo/EAS config files, and client source files while masking secret values (ideas from dev.to and LinkedIn readers).
- English and Vietnamese titles/remediation, `explain` guides, HTML/Markdown report integration, comment-only `fix.sql` guidance, PostgreSQL 15 fixtures (26 expected catalog findings), and unit tests for `policy_any_authenticated` and `scan-env`.

## [0.3.0] - 2026-11-10

### Added
- Two read-only catalog rules: `matview_api_exposed` (High) for materialized views or foreign tables in `public` selectable by `anon`/`authenticated`, and `public_bucket_listable` (Medium) for public Storage buckets paired with a broad `anon`/`public` `SELECT` policy on `storage.objects`, bringing the catalog total to 13 checks.
- `pii` table-comment tag support (`COMMENT ON TABLE public.x IS 'pii'`) in `sensitive_anon_policy` alongside the existing table-name regex (idea from a reader comment on the dev.to article).
- English and Vietnamese titles/remediation, CLI and MCP explanations, HTML/Markdown report rendering, comment-only `fix.sql` guidance, and PostgreSQL 15 fixtures/tests for the new rules and `pii` table tag (24 expected catalog findings, 74 unit tests).

## [0.2.2] - 2026-11-10

### Changed
- PyPI page now links to the source, changelog, Agensi skill and Glama listing.

## [0.2.1] - 2026-11-10

### Added
- Composite GitHub Action (`action.yml`): runs the read-only `check.sql` with `psql`, writes the report, adds a job summary, and fails on findings at or above `fail-on`. Refuses to run unless `i-own-this-project: "true"`.
- `server.json` and the `mcp-name` marker for the Official MCP Registry.

## [0.2.0] - 2026-11-09

### Added
- Three read-only catalog rules: `policy_user_metadata` (High), `policy_auth_per_row` (Low, performance), and `auth_users_exposed` (Critical), bringing the catalog total to 11 checks.
- English and Vietnamese titles/remediation, CLI and MCP explanations, HTML/Markdown report support, and comment-only `fix.sql` guidance for all three new rules.
- PostgreSQL 15 fixtures covering both JWT sources, wrapped/unwrapped authentication helpers, mixed calls, Auth views/materialized views, grants, and negative controls. CI compares 19 expected findings and checks missing Auth objects in read-only transactions.
- Report, manual-fix, and explanation coverage; the unit suite now contains 66 tests.

## [0.1.1] - 2026-11-09

### Changed
- `probe` reads the anon key from `SUPABASE_ANON_KEY` when `--anon-key` is omitted.

## [0.1.0] - 2026-11-08

### Added
- Packaged `supabase-rls-check` (`src/supabase_rls_check/`) with console entry point `supabase-rls-check`.
- Bundled PostgreSQL 15+ read-only catalog query (`sql/check.sql` and `supabase-rls-check sql --print-sql`) covering 8 rules: `rls_disabled`, `policy_true`, `sensitive_anon_policy`, `definer_anon_exec`, `definer_search_path`, `view_not_invoker`, `public_bucket`, and `public_extension`.
- Consent-gated, read-only `probe` command (`GET`/`HEAD` only, `anon`/`sb_publishable_` keys only, ephemeral `limit=1` row inspection without saving row values) plus optional same-origin frontend bundle check for `service_role_exposed`.
- Standalone HTML (`report.html`), Markdown (`report.md`), and `ROLLBACK`-safe SQL review template (`fix.sql`) generation with English default and `--lang vi` support.
- `explain <rule>` command with severity, context, caveats, and remediation examples for every rule.
- Optional stdio MCP server (`supabase-rls-check mcp` via `supabase-rls-check[mcp]`) exposing `analyze_sql_export` and `explain_rule` while excluding network probing.
- Offline unit test suite and GitHub Actions CI across Python 3.11, Python 3.12, and live `postgres:15` catalog verification.
