import json
import unittest

from botocore.exceptions import ClientError

from ramwingu.scanners import aws
from ramwingu.scanners.aws import (
    check_bucket_policy_confused_deputy,
    check_instance_metadata,
)

CLEAN_METADATA = "No insecure EC2 instance metadata configurations found."
CLEAN_POLICY = "No confused-deputy S3 bucket policies found."


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
