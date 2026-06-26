---
name: add-check
description: How to add a cloud-misconfiguration check to a ramwingu scanner. Use when adding, writing, or modifying a security check in ramwingu/scanners/ (aws.py, azure.py, future gcp.py), wiring a check into scan(), writing its unit tests, or building an approved daily-agent issue.
---

# Add a Check

How to add a misconfiguration check to a ramwingu scanner the way the project
expects. This file is a table of contents — load a reference below only when the
task matches it. Most check work needs only this page plus `references/check-recipe.md`.

## The shape of a check (memorize this)

A check is a **pure function** that takes already-fetched cloud resources and
returns a `list[str]` of human-readable findings:

```python
def check_<thing>(resources, ...):
    issues = []
    for r in resources:
        if <insecure>:
            issues.append("[HIGH] <what is wrong, which resource, how to fix>.")
    if not issues:
        issues.append("No <thing> issues found.")   # exact clean-status string
    return issues
```

Taking fetched resources (not a live client, where avoidable) is what makes it
unit-testable with a fake. The real cloud calls live in `scan()` /
`run_scan_with_*`; the check only reasons over their output.

## When to load what

- **Writing the check + wiring it into `scan()`** → read `references/check-recipe.md`.
- **Writing the unit tests** (fake-client pattern, exact clean strings) → read `references/testing.md`.
- **Design rules / "is this allowed?"** (standalone scanners, severity, never
  weaken a check, no new deps, credential safety) → read `references/design-rules.md`.

Do not load a reference unless the request matches it.

## Assets — copy, don't regenerate

- `assets/check-template.py` — a check function + clean-status string to copy.
- `assets/test-template.py` — a unittest class with a fake client to copy.

## Scripts — run, don't read

Run scripts; only their output costs tokens. Don't open them into context.

- After writing or changing a check, run the scanner tests:
  `./.claude/skills/add-check/scripts/run-check-tests.sh`

## Before you open a PR

- Run the scanner tests (above) — they must pass.
- **Never** run `git commit`; the owner (Allan Wasonga) does all committing.
- Keep the change minimal and single-purpose (< ~150 lines).
- PR description: **one sentence**. Use "Part of #N", or "Closes #N" only if it's
  the whole issue. Never merge, force-push, or touch `main`.
