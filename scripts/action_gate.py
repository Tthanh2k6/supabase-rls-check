"""Severity gate for the GitHub Action: counts findings, writes the job summary, sets the exit code."""
import json
import os
import sys
from pathlib import Path

from supabase_rls_check.rules import RULES, SEVERITIES


def main() -> int:
    report_dir = Path(os.environ.get("REPORT_DIR", "rls-report"))
    fail_on = os.environ.get("FAIL_ON", "High").strip().capitalize()
    if fail_on != "None" and fail_on not in SEVERITIES:
        print(f"::error::fail-on must be one of {', '.join(SEVERITIES)} or none, got {fail_on!r}")
        return 2

    findings = json.loads((report_dir / "results.json").read_text(encoding="utf-8")).get("findings", [])
    severity = lambda f: RULES.get(f.get("rule", ""), ("Low",))[0]
    limit = len(SEVERITIES) if fail_on == "None" else SEVERITIES.index(fail_on) + 1
    failing = [f for f in findings if severity(f) in SEVERITIES[:limit]] if fail_on != "None" else []

    counts = {s: sum(severity(f) == s for f in findings) for s in SEVERITIES}
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        lines = ["## Supabase RLS Check", "", "| Severity | Findings |", "| :--- | ---: |"]
        lines += [f"| {s} | {n} |" for s, n in counts.items()]
        report_md = report_dir / "report.md"
        if report_md.exists():
            lines += ["", report_md.read_text(encoding="utf-8")]
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as fh:
            fh.write(f"findings={len(findings)}\nfailing={len(failing)}\n")

    for f in failing:
        where = ".".join(p for p in (f.get("schema_name"), f.get("object_name")) if p)
        print(f"::error title={severity(f)}: {f.get('rule')}::{where} {f.get('policy_name') or ''}".rstrip())
    print(f"{len(findings)} finding(s); {len(failing)} at or above {fail_on}.")
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
