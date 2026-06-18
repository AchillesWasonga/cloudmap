import unittest

from ramwingu.utils.misconfiguration_checks import check_instance_metadata

CLEAN = "No insecure EC2 instance metadata configurations found."


class TestInstanceMetadataCheck(unittest.TestCase):
    def test_flags_imdsv1_allowed(self):
        instances = [
            {
                "InstanceId": "i-0abc",
                "MetadataOptions": {
                    "HttpTokens": "optional",
                    "HttpEndpoint": "enabled",
                    "HttpPutResponseHopLimit": 1,
                },
            }
        ]
        issues = check_instance_metadata(instances)
        self.assertTrue(any("i-0abc" in i and "IMDSv1" in i for i in issues))

    def test_imdsv2_enforced_is_clean(self):
        instances = [
            {
                "InstanceId": "i-0def",
                "MetadataOptions": {
                    "HttpTokens": "required",
                    "HttpEndpoint": "enabled",
                    "HttpPutResponseHopLimit": 1,
                },
            }
        ]
        self.assertEqual(check_instance_metadata(instances), [CLEAN])

    def test_flags_high_hop_limit(self):
        instances = [
            {
                "InstanceId": "i-0hop",
                "MetadataOptions": {
                    "HttpTokens": "required",
                    "HttpEndpoint": "enabled",
                    "HttpPutResponseHopLimit": 3,
                },
            }
        ]
        issues = check_instance_metadata(instances)
        self.assertTrue(any("hop limit" in i and "i-0hop" in i for i in issues))

    def test_disabled_endpoint_skips_hop_limit(self):
        instances = [
            {
                "InstanceId": "i-0off",
                "MetadataOptions": {
                    "HttpTokens": "required",
                    "HttpEndpoint": "disabled",
                    "HttpPutResponseHopLimit": 5,
                },
            }
        ]
        self.assertEqual(check_instance_metadata(instances), [CLEAN])

    def test_missing_metadata_options_flags_imdsv1(self):
        # No MetadataOptions at all -> defaults to IMDSv1-allowed semantics.
        issues = check_instance_metadata([{"InstanceId": "i-0bare"}])
        self.assertTrue(any("i-0bare" in i and "IMDSv1" in i for i in issues))

    def test_no_instances_is_clean(self):
        self.assertEqual(check_instance_metadata([]), [CLEAN])


if __name__ == "__main__":
    unittest.main()
