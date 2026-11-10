# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
