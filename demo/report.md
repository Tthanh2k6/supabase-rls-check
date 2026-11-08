# Supabase security review

todo-ai (fictional demo)

3 findings need review. Address critical and high risks first. Configuration flags do not by themselves prove data exposure or write access.

Critical: 0 / High: 2 / Medium: 1 / Low: 0

Limited review of supplied metadata and/or anonymous read probes. No security certification. An empty result is not proof of safety. Public data may be intentional. Row values and keys are not saved.

## Findings

| Severity | Finding / object | Evidence | Remediation |
| --- | --- | --- | --- |
| High | Unconditional policy expression — public.profiles | policy_true: read_every_profile | Review command, roles and permissive/restrictive policy combinations; replace overly broad policies. |
| High | Row security is disabled — public.todos | rls_disabled | Enable RLS and review grants and ownership policies before release. |
| Medium | Storage bucket is public — storage.todo-attachments | public_bucket | Confirm public delivery is intentional; make private if sensitive and review storage.objects policies. |

## Coverage and limitations

- Only the supplied inputs are covered; untested areas remain unknown.

## Next steps

Review fix.sql on staging; export current policies/grants for rollback. The owner should self-check write access using SQL and test isolation between two users. Re-run checks after changes. No write tests were performed.
