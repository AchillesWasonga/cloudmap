# Template: tests for a check. Copy the relevant parts into the matching test
# module (tests/tests_aws.py or tests/tests_azure.py) and adapt. Delete this header.

import unittest

from ramwingu.scanners.aws import check_<thing>  # import so coverage is visible

CLEAN_THING = "No <thing> issues found."  # must match the scanner string exactly


class _FakeClient:
    """Minimal stand-in for the boto3/Azure client — only the methods the check
    uses, keyed by resource name. Raise the same errors the real API would."""

    def __init__(self, data=None):
        self._data = data or {}

    def describe_things(self):
        return {"Things": list(self._data.values())}


class TestThingCheck(unittest.TestCase):
    def test_flags_insecure(self):
        resources = [{"Id": "r-bad", "<insecure-field>": True}]
        issues = check_<thing>(resources)
        self.assertTrue(any("r-bad" in i for i in issues))

    def test_high_severity(self):
        resources = [{"Id": "r-bad", "<insecure-field>": True}]
        issues = check_<thing>(resources)
        self.assertTrue(any(i.startswith("[HIGH]") for i in issues))

    def test_secure_is_clean(self):
        resources = [{"Id": "r-ok", "<insecure-field>": False}]
        self.assertEqual(check_<thing>(resources), [CLEAN_THING])

    def test_empty_is_clean(self):
        self.assertEqual(check_<thing>([]), [CLEAN_THING])


if __name__ == "__main__":
    unittest.main()
