# Ramwingu Design Document

## Overview

Ramwingu is a modular CLI tool that scans AWS and Azure environments for
misconfigurations that can lead to security breaches. It is a lightweight,
developer-friendly alternative to ScoutSuite / Prowler / AzSecPack, and is free
and open source. A GCP scanner is planned.

## Architecture

- **CLI (`ramwingu/cli.py`):** Click entry point. Loads `config/config.yaml`,
  obtains credentials, dispatches to the selected platform's scanner, and prints
  the findings as a `rich` table (default) or JSON (`--verbose`).
- **Credentials (`ramwingu/credentials.py`):** Prompts for credentials at runtime
  (with environment-variable fallback) and holds them in memory only — they are
  never stored, logged, or transmitted.
- **Logger (`ramwingu/logger.py`):** Shared logger (`logging.getLogger("ramwingu")`).
- **Scanners (`ramwingu/scanners/`):**
  - `aws.py` — AWS checks via boto3: open security-group rules, public S3 access
    (ACL + account/bucket Block Public Access), overly permissive IAM, EC2 IMDSv2
    enforcement, and cross-service confused-deputy bucket policies.
  - `azure.py` — Azure checks via the Azure SDK (with `az` CLI login): overly
    permissive NSG rules and insecure Storage account exposure.
  - A future `gcp.py` will be added the same way.
- **Output formatting (`ramwingu/utils/output_formatter.py`):** `format_output`
  (pretty JSON) and `format_table` (rich table). Re-exported from
  `ramwingu/utils/__init__.py`.
- **Tests (`tests/`):** `unittest` with hand-rolled fake clients — no live cloud
  calls.

## Design rules

- **Standalone scanners.** Each platform's checks live entirely in its own scanner
  module. Scanners do **not** import one another, and there is **no shared
  cross-platform check-logic module**. Helpers may be shared only *within* a
  scanner. Any logic common across clouds (e.g. the port-risk severity model) is
  deliberately duplicated and kept in sync by hand.
- **Pure, testable checks.** Each `check_*` function takes already-fetched cloud
  resources (or an injectable client) and returns a `list[str]` of human-readable
  findings, so it is unit-testable with a fake. The real cloud calls live in
  `scan()` / `run_scan_with_*`.
- **Clean-status string.** When a check finds nothing it returns a single
  `"No ... found."` string, never an empty list. Tests assert on these exact
  strings.
- **Inline severity.** Security findings are prefixed with `[HIGH]` / `[MEDIUM]` /
  `[LOW]`, justified by the risk; severity is a string prefix, not a structured
  field.
- **Never weaken or delete an existing check.**
- **No new dependencies or outbound network calls** beyond the existing cloud SDKs,
  and credential handling is never changed to store, log, or transmit secrets.

## Future enhancements

- Add a GCP scanner as `ramwingu/scanners/gcp.py`.
- Expand the AWS and Azure check coverage.
- Improve API error handling and pagination across scanners.
