# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
