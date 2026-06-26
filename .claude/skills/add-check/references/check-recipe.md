# Check Recipe

> Loaded when writing a new check and wiring it into a scanner's `scan()`.

A misconfiguration check is added in two places: the **check function** (pure,
testable) and the **call site** inside `scan()` (fetches resources, stores
findings). Follow these steps.

## 1. Write the check function

Add it to the scanner for its platform — `ramwingu/scanners/aws.py` or
`ramwingu/scanners/azure.py` (a GCP scanner will be `gcp.py`). Copy
`assets/check-template.py` as a starting point.

- Name it `check_<thing>` (e.g. `check_security_groups`,
  `check_storage_accounts`). The `check_` prefix is what the validator and tests
  look for.
- Take **already-fetched resources** as the argument (a list of dicts for AWS, a
  list of SDK objects for Azure), not a live client — that is what lets a test
  pass in a fake. Where the check genuinely needs to call the API per-resource
  (e.g. `get_bucket_policy` per bucket), accept the client as a parameter so the
  test can pass a fake client (see `check_bucket_policy_confused_deputy`).
- Return a `list[str]`. Each finding is one human-readable sentence: **what is
  wrong, which resource, and how to fix it**. Prefix it with a severity —
  `[HIGH]`, `[MEDIUM]`, or `[LOW]` (see `references/design-rules.md`).
- When nothing is found, return a single **clean-status string**, not `[]`
  (e.g. `"No insecure storage account configurations found."`). Tests assert on
  this exact text, so pick it deliberately and keep it stable.

Factor shared sub-logic into `_underscore`-prefixed helpers **within the same
scanner** (e.g. `_severity_for_permission`, `_missing_bpa_flags`). Do not create
a cross-scanner shared module — see the standalone rule in design-rules.

## 2. Wire it into `scan()`

In the same scanner, find `scan()` (AWS) or `run_scan_with_az_login()` (Azure).
Add a numbered block that fetches the resources and stores the result under a
new `findings` key:

```python
# ------------------------------
# N. Check <thing>
# ------------------------------
response = some_client.describe_things()
things = response.get("Things", [])
findings["<thing>"] = check_<thing>(things)
```

- Reuse already-fetched resources when you can (e.g. the AWS scanner fetches
  `buckets` once and feeds several S3 checks) instead of calling the API again.
- Wrap per-resource API calls that may fail in `try/except ClientError` and turn
  unexpected errors into findings rather than letting them abort the scan; the
  whole `scan()` body is already inside a `try/except` that records `error`.

## 3. Add tests

Every new check needs unit tests using the fake-client pattern — this is
enforced by the validator. See `references/testing.md` and
`assets/test-template.py`.

## 4. Run the tests

`./.claude/skills/add-check/scripts/run-check-tests.sh` — all scanner tests must
pass before you open a PR.
