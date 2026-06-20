import json
import unittest

from botocore.exceptions import ClientError

from ramwingu.scanners import aws
from ramwingu.scanners.aws import (
    check_bucket_policy_confused_deputy,
    check_instance_metadata,
    check_security_groups,
)

CLEAN_METADATA = "No insecure EC2 instance metadata configurations found."
CLEAN_POLICY = "No confused-deputy S3 bucket policies found."
CLEAN_SG = "No overly permissive security group rules found."


class _FakeS3Client:
    """Minimal stand-in for a boto3 S3 client over get_bucket_policy.

    ``policies`` maps a bucket name to a policy dict; map to ``None`` to simulate a
    bucket with no attached policy (boto3 raises ``NoSuchBucketPolicy``).
    """

    def __init__(self, policies):
        self._policies = policies

    def get_bucket_policy(self, Bucket):
        policy = self._policies.get(Bucket)
        if policy is None:
            raise ClientError(
                {"Error": {"Code": "NoSuchBucketPolicy", "Message": "no policy"}},
                "GetBucketPolicy",
            )
        return {"Policy": json.dumps(policy)}


def _bucket_policy(condition=None, effect="Allow", principal=None):
    statement = {
        "Effect": effect,
        "Principal": principal if principal is not None else {"Service": "cloudtrail.amazonaws.com"},
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::my-bucket/*",
    }
    if condition is not None:
        statement["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [statement]}


class TestAWSScanner(unittest.TestCase):
    def test_scan_returns_findings(self):
        config = {"region": "us-east-1"}
        creds = {"aws_access_key_id": "dummy", "aws_secret_access_key": "dummy"}
        findings = aws.scan(config, creds)
        self.assertIsInstance(findings, dict)


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
        self.assertEqual(check_instance_metadata(instances), [CLEAN_METADATA])

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
        self.assertEqual(check_instance_metadata(instances), [CLEAN_METADATA])

    def test_missing_metadata_options_flags_imdsv1(self):
        # No MetadataOptions at all -> defaults to IMDSv1-allowed semantics.
        issues = check_instance_metadata([{"InstanceId": "i-0bare"}])
        self.assertTrue(any("i-0bare" in i and "IMDSv1" in i for i in issues))

    def test_no_instances_is_clean(self):
        self.assertEqual(check_instance_metadata([]), [CLEAN_METADATA])


class TestSecurityGroupsCheck(unittest.TestCase):
    def test_flags_ipv4_world_open(self):
        sgs = [
            {
                "GroupId": "sg-0v4",
                "IpPermissions": [
                    {"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ],
            }
        ]
        issues = check_security_groups(sgs)
        self.assertTrue(any("sg-0v4" in i and "open rule" in i for i in issues))

    def test_flags_ipv6_world_open(self):
        # ::/0 lives in Ipv6Ranges -- previously missed entirely.
        sgs = [
            {
                "GroupId": "sg-0v6",
                "IpPermissions": [
                    {"IpProtocol": "tcp", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
                ],
            }
        ]
        issues = check_security_groups(sgs)
        self.assertTrue(any("sg-0v6" in i and "open IPv6 rule" in i for i in issues))

    def test_flags_both_families_in_one_permission(self):
        sgs = [
            {
                "GroupId": "sg-0both",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                    }
                ],
            }
        ]
        issues = check_security_groups(sgs)
        self.assertEqual(len(issues), 2)
        self.assertTrue(any("open IPv6 rule" in i for i in issues))
        self.assertTrue(any("has open rule on" in i and "IPv6" not in i for i in issues))

    def test_high_risk_port_is_high_severity(self):
        sgs = [
            {
                "GroupId": "sg-ssh",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            }
        ]
        issues = check_security_groups(sgs)
        self.assertTrue(any(i.startswith("[HIGH]") and "port 22" in i for i in issues))

    def test_web_port_is_low_severity(self):
        sgs = [
            {
                "GroupId": "sg-web",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            }
        ]
        issues = check_security_groups(sgs)
        self.assertTrue(any(i.startswith("[LOW]") for i in issues))

    def test_other_port_is_medium_severity(self):
        sgs = [
            {
                "GroupId": "sg-other",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 8080,
                        "ToPort": 8080,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            }
        ]
        issues = check_security_groups(sgs)
        self.assertTrue(any(i.startswith("[MEDIUM]") for i in issues))

    def test_all_protocols_rule_is_high_severity(self):
        # IpProtocol "-1" exposes every port -> includes the high-risk set.
        sgs = [
            {
                "GroupId": "sg-all",
                "IpPermissions": [
                    {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ],
            }
        ]
        issues = check_security_groups(sgs)
        self.assertTrue(any(i.startswith("[HIGH]") and "all ports" in i for i in issues))

    def test_high_risk_within_range_is_high_severity(self):
        # A wide range that straddles a high-risk port (3389/RDP) is HIGH.
        sgs = [
            {
                "GroupId": "sg-range",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 3380,
                        "ToPort": 3400,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            }
        ]
        issues = check_security_groups(sgs)
        self.assertTrue(any(i.startswith("[HIGH]") for i in issues))

    def test_scoped_ranges_are_clean(self):
        sgs = [
            {
                "GroupId": "sg-0safe",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                        "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/32"}],
                    }
                ],
            }
        ]
        self.assertEqual(check_security_groups(sgs), [CLEAN_SG])

    def test_no_security_groups_is_clean(self):
        self.assertEqual(check_security_groups([]), [CLEAN_SG])


class TestBucketPolicyConfusedDeputy(unittest.TestCase):
    def test_flags_service_principal_without_source_condition(self):
        s3 = _FakeS3Client({"my-bucket": _bucket_policy()})
        issues = check_bucket_policy_confused_deputy([{"Name": "my-bucket"}], s3)
        self.assertTrue(
            any("my-bucket" in i and "cloudtrail.amazonaws.com" in i for i in issues)
        )

    def test_source_account_condition_is_clean(self):
        policy = _bucket_policy(
            condition={"StringEquals": {"aws:SourceAccount": "111122223333"}}
        )
        s3 = _FakeS3Client({"my-bucket": policy})
        self.assertEqual(
            check_bucket_policy_confused_deputy([{"Name": "my-bucket"}], s3),
            [CLEAN_POLICY],
        )

    def test_source_arn_condition_is_clean(self):
        policy = _bucket_policy(
            condition={
                "ArnLike": {"aws:SourceArn": "arn:aws:cloudtrail:*:111122223333:trail/*"}
            }
        )
        s3 = _FakeS3Client({"my-bucket": policy})
        self.assertEqual(
            check_bucket_policy_confused_deputy([{"Name": "my-bucket"}], s3),
            [CLEAN_POLICY],
        )

    def test_bucket_without_policy_is_skipped(self):
        s3 = _FakeS3Client({"my-bucket": None})
        self.assertEqual(
            check_bucket_policy_confused_deputy([{"Name": "my-bucket"}], s3),
            [CLEAN_POLICY],
        )

    def test_non_service_principal_is_ignored(self):
        policy = _bucket_policy(principal={"AWS": "arn:aws:iam::111122223333:root"})
        s3 = _FakeS3Client({"my-bucket": policy})
        self.assertEqual(
            check_bucket_policy_confused_deputy([{"Name": "my-bucket"}], s3),
            [CLEAN_POLICY],
        )

    def test_deny_statement_is_ignored(self):
        policy = _bucket_policy(effect="Deny")
        s3 = _FakeS3Client({"my-bucket": policy})
        self.assertEqual(
            check_bucket_policy_confused_deputy([{"Name": "my-bucket"}], s3),
            [CLEAN_POLICY],
        )

    def test_no_buckets_is_clean(self):
        self.assertEqual(
            check_bucket_policy_confused_deputy([], _FakeS3Client({})), [CLEAN_POLICY]
        )


if __name__ == "__main__":
    unittest.main()
