# Testing a Check

> Loaded when writing the unit tests for a new check.

Tests live in `tests/tests_aws.py` and `tests/tests_azure.py` (a GCP scanner gets
`tests/tests_gcp.py`). They use `unittest` with **hand-rolled fake clients** — no
live cloud calls, no mocking library. Copy `assets/test-template.py` to start.

## The pattern

1. **Import the check** at the top of the matching test module so the validator
   can see it is covered:

   ```python
   from ramwingu.scanners.aws import check_<thing>
   ```

2. **Define the clean string once** as a constant and assert against it:

   ```python
   CLEAN_THING = "No <thing> issues found."   # must match the scanner exactly
   ```

3. **Build a fake client** only if the check calls the API per-resource. The fake
   implements just the methods the check uses, keyed by resource name, and raises
   the same `ClientError` codes the real API would (e.g. `NoSuchBucketPolicy`).
   See `_FakeS3Client` / `_FakePublicS3Client` in `tests/tests_aws.py` and
   `_FakeStorageClient` / `_FakeRule` / `_FakeNSG` in `tests/tests_azure.py`.

4. **Cover, at minimum:**
   - the insecure case is flagged (assert the resource id and key phrase appear),
   - the secure/hardened case returns exactly `[CLEAN_THING]`,
   - the empty input returns exactly `[CLEAN_THING]`,
   - each severity branch, if the check assigns severity (assert
     `i.startswith("[HIGH]")` etc.),
   - any "mitigated" path that should *not* be flagged (e.g. a scoped CIDR, a
     source condition, BPA fully enabled).

## Conventions that tests rely on

- The clean string is asserted **verbatim** — if you change the wording in the
  scanner, update the test constant in the same change.
- Assert on **substrings** of findings (`"sg-0v4" in i`, `"Shared Key" in i`),
  not the whole sentence, so wording can evolve without churn.
- Group a check's tests in their own `unittest.TestCase` subclass named
  `Test<Thing>Check`.

## Run them

`./.claude/skills/add-check/scripts/run-check-tests.sh` runs every
`tests/tests_*.py`. (The full `unittest discover` also pulls in `test_utils.py`,
which is a known pre-existing failure unrelated to scanners — the runner script
and the pre-commit hook deliberately scope to the scanner tests.)
