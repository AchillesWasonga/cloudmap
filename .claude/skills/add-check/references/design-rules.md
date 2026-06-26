# Design Rules

> Loaded for "is this allowed?" questions and before any structural change.

These are the project's hard rules. The validator
(`.claude/scripts/validate-checks.sh`) and the `check-reviewer` agent enforce the
mechanical ones; the rest are judgment calls. Do not violate them without
discussion with the owner.

## Standalone scanners (the big one)

Each platform's checks live **entirely in its own scanner**. `aws.py` and
`azure.py` are deliberately separate; GCP will be its own `gcp.py`.

- **No shared cross-platform check-logic module.** Do not add
  `scanners/shared.py`, `scanners/common.py`, `scanners/base.py`, etc., and do
  not `import` one scanner from another.
- Helpers may be shared **within** a scanner only (`_underscore` functions).
- When two scanners need the same idea (e.g. the port-risk severity model), it is
  **intentionally duplicated** in each file and kept in sync by hand. See the
  `_HIGH_RISK_PORTS` / `_LOW_RISK_PORTS` tables that appear in both `aws.py` and
  `azure.py` with a comment saying exactly this.

## Never weaken or delete an existing check

Add checks; don't remove or loosen them. If you change a finding's wording,
update its test in the same change. Tightening false positives is fine; silently
dropping a detection is not.

## Severity convention

Findings carry severity as an **inline string prefix**, not a structured field:
`[HIGH]`, `[MEDIUM]`, or `[LOW]` at the very start of the message. Rough guide
used across the scanners:

- **HIGH** — world-reachable sensitive service (SSH/RDP/DB ports), live public
  data exposure, credential-theft vectors (IMDSv1), all-ports/all-protocols rules.
- **MEDIUM** — latent exposure (a guardrail off but nothing public *yet*),
  non-web service open to the world.
- **LOW** — expected-public web ports (80/443) open to the world.

Not every check needs severity, but security findings should carry one.

## Clean-status string, never an empty list

A check that finds nothing returns `["No <thing> ... found."]`. Tests assert the
exact text. (Findings then flow up as `findings[category] = [...]` and through
the formatters.)

## No new dependencies or outbound calls

Only the existing cloud SDKs (boto3, the azure-mgmt-* packages) and the `az` CLI.
Do not add packages to `requirements.txt` or make network calls beyond the SDKs.

## Never touch credential handling

Credentials are prompted at runtime and held in memory only. Never store, log, or
transmit them — no writing creds to a file, no `requests`/`urllib`/`socket`
exfil, no logging the secret. The validator guards `credentials.py` against
obvious persistence/exfil patterns.
