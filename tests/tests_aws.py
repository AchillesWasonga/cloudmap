import json
import unittest

from botocore.exceptions import ClientError

from ramwingu.scanners import aws
from ramwingu.scanners.aws import (
    check_bucket_policy_confused_deputy,
    check_cloudtrail,
    check_instance_metadata,
    check_lambda_function_urls,
    check_role_privileges,
    check_s3_public_access,
    check_security_groups,
)

CLEAN_METADATA = "No insecure EC2 instance metadata configurations found."
CLEAN_POLICY = "No confused-deputy S3 bucket policies found."
CLEAN_SG = "No overly permissive security group rules found."
CLEAN_PUBLIC = "No public S3 access exposure found."
CLEAN_LAMBDA = "No publicly invokable Lambda Function URLs found."
CLEAN_CLOUDTRAIL = "No CloudTrail logging gaps found."
CLEAN_ROLES = "No over-privileged EC2 instance-profile roles found."

_ALL_USERS_GRANT = {
    "Grantee": {
        "Type": "Group",
        "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
    },
    "Permission": "READ",
}
_BPA_FULL = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def _public_policy(condition=None):
    statement = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::my-bucket/*",
    }
    if condition is not None:
        statement["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [statement]}


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

    def test_imdsv1_finding_is_high_severity(self):
        issues = check_instance_metadata([{"InstanceId": "i-0sev"}])
        self.assertTrue(any(i.startswith("[HIGH]") and "i-0sev" in i for i in issues))

    def test_imdsv1_admin_profile_is_critical_blast_radius(self):
        arn = "arn:aws:iam::111122223333:instance-profile/admin-profile"
        instances = [
            {
                "InstanceId": "i-0adm",
                "MetadataOptions": {"HttpTokens": "optional"},
                "IamInstanceProfile": {"Arn": arn},
            }
        ]
        issues = check_instance_metadata(instances, {arn})
        self.assertTrue(
            any(
                "i-0adm" in i and "AdministratorAccess" in i and arn in i
                for i in issues
            )
        )

    def test_imdsv1_nonadmin_profile_is_annotated(self):
        arn = "arn:aws:iam::111122223333:instance-profile/app-profile"
        instances = [
            {
                "InstanceId": "i-0app",
                "MetadataOptions": {"HttpTokens": "optional"},
                "IamInstanceProfile": {"Arn": arn},
            }
        ]
        issues = check_instance_metadata(instances, frozenset())
        self.assertTrue(
            any(
                "i-0app" in i and arn in i and "AdministratorAccess" not in i
                for i in issues
            )
        )

    def test_imdsv1_without_profile_notes_no_role(self):
        issues = check_instance_metadata([{"InstanceId": "i-0nor"}])
        self.assertTrue(
            any("i-0nor" in i and "No instance profile" in i for i in issues)
        )

    def test_hop_limit_finding_is_medium_severity(self):
        instances = [
            {
                "InstanceId": "i-0hopsev",
                "MetadataOptions": {
                    "HttpTokens": "required",
                    "HttpEndpoint": "enabled",
                    "HttpPutResponseHopLimit": 3,
                },
            }
        ]
        issues = check_instance_metadata(instances)
        self.assertTrue(any(i.startswith("[MEDIUM]") for i in issues))


class _FakePublicS3Client:
    """Stand-in for a boto3 S3 client over the public-access surface.

    Each mapping is keyed by bucket name. ``blocks`` maps to a
    PublicAccessBlockConfiguration dict (or ``None`` to raise
    ``NoSuchPublicAccessBlockConfiguration``); ``acls`` to a get_bucket_acl
    response; ``policies`` to a policy dict (or ``None`` for no policy).
    """

    def __init__(self, blocks=None, acls=None, policies=None):
        self._blocks = blocks or {}
        self._acls = acls or {}
        self._policies = policies or {}

    def get_public_access_block(self, Bucket):
        block = self._blocks.get(Bucket)
        if block is None:
            raise ClientError(
                {
                    "Error": {
                        "Code": "NoSuchPublicAccessBlockConfiguration",
                        "Message": "none",
                    }
                },
                "GetPublicAccessBlock",
            )
        return {"PublicAccessBlockConfiguration": block}

    def get_bucket_acl(self, Bucket):
        return self._acls.get(Bucket, {"Grants": []})

    def get_bucket_policy(self, Bucket):
        policy = self._policies.get(Bucket)
        if policy is None:
            raise ClientError(
                {"Error": {"Code": "NoSuchBucketPolicy", "Message": "no policy"}},
                "GetBucketPolicy",
            )
        return {"Policy": json.dumps(policy)}


class TestS3PublicAccessCheck(unittest.TestCase):
    def test_account_bpa_off_is_medium(self):
        issues = check_s3_public_access([], _FakePublicS3Client(), account_block=None)
        self.assertTrue(
            any(i.startswith("[MEDIUM]") and "Account-level" in i for i in issues)
        )

    def test_account_bpa_full_and_no_buckets_is_clean(self):
        issues = check_s3_public_access(
            [], _FakePublicS3Client(), account_block=_BPA_FULL
        )
        self.assertEqual(issues, [CLEAN_PUBLIC])

    def test_account_unchecked_is_skipped(self):
        # account_block omitted -> no account-level finding emitted.
        issues = check_s3_public_access([], _FakePublicS3Client())
        self.assertEqual(issues, [CLEAN_PUBLIC])

    def test_bucket_bpa_off_with_public_acl_is_high(self):
        s3 = _FakePublicS3Client(
            blocks={"b": None},
            acls={"b": {"Grants": [_ALL_USERS_GRANT]}},
        )
        issues = check_s3_public_access([{"Name": "b"}], s3)
        self.assertTrue(
            any(i.startswith("[HIGH]") and "ACL" in i and "b" in i for i in issues)
        )

    def test_bucket_bpa_off_with_public_policy_is_high(self):
        s3 = _FakePublicS3Client(
            blocks={"b": None}, policies={"b": _public_policy()}
        )
        issues = check_s3_public_access([{"Name": "b"}], s3)
        self.assertTrue(
            any(i.startswith("[HIGH]") and "bucket policy" in i for i in issues)
        )

    def test_bucket_bpa_off_nothing_public_is_medium_latent(self):
        s3 = _FakePublicS3Client(blocks={"b": None})
        issues = check_s3_public_access([{"Name": "b"}], s3)
        self.assertTrue(
            any(i.startswith("[MEDIUM]") and "latent" in i for i in issues)
        )

    def test_bucket_bpa_fully_enabled_is_skipped(self):
        # BPA fully on neutralises a public ACL -> no per-bucket finding.
        s3 = _FakePublicS3Client(
            blocks={"b": _BPA_FULL},
            acls={"b": {"Grants": [_ALL_USERS_GRANT]}},
        )
        issues = check_s3_public_access([{"Name": "b"}], s3)
        self.assertEqual(issues, [CLEAN_PUBLIC])

    def test_public_policy_with_condition_is_not_high(self):
        s3 = _FakePublicS3Client(
            blocks={"b": None},
            policies={
                "b": _public_policy(
                    condition={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}
                )
            },
        )
        issues = check_s3_public_access([{"Name": "b"}], s3)
        # A restricting condition scopes the grant -> latent (MEDIUM), not HIGH.
        self.assertTrue(any(i.startswith("[MEDIUM]") for i in issues))
        self.assertFalse(any(i.startswith("[HIGH]") for i in issues))

    def test_partial_bpa_counts_as_not_fully_enabled(self):
        partial = dict(_BPA_FULL, RestrictPublicBuckets=False)
        s3 = _FakePublicS3Client(blocks={"b": partial})
        issues = check_s3_public_access([{"Name": "b"}], s3)
        self.assertTrue(
            any("RestrictPublicBuckets" in i and "latent" in i for i in issues)
        )

    def test_no_buckets_and_account_full_is_clean(self):
        self.assertEqual(
            check_s3_public_access([], _FakePublicS3Client(), account_block=_BPA_FULL),
            [CLEAN_PUBLIC],
        )


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


class _FakeLambdaClient:
    """Stand-in for a boto3 Lambda client over get_function_url_config.

    ``url_configs`` maps a function name to a Function-URL-config dict; map to
    ``None`` to simulate a function with no URL (boto3 raises
    ``ResourceNotFoundException``).
    """

    def __init__(self, url_configs):
        self._url_configs = url_configs

    def get_function_url_config(self, FunctionName):
        config = self._url_configs.get(FunctionName)
        if config is None:
            raise ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "no url"}},
                "GetFunctionUrlConfig",
            )
        return config


class TestLambdaFunctionUrls(unittest.TestCase):
    def test_flags_authtype_none_as_high(self):
        client = _FakeLambdaClient(
            {"fn": {"AuthType": "NONE", "FunctionUrl": "https://x.lambda-url.on.aws/"}}
        )
        issues = check_lambda_function_urls([{"FunctionName": "fn"}], client)
        self.assertTrue(
            any(i.startswith("[HIGH]") and "fn" in i and "AuthType NONE" in i for i in issues)
        )

    def test_authtype_iam_is_clean(self):
        client = _FakeLambdaClient({"fn": {"AuthType": "AWS_IAM"}})
        self.assertEqual(
            check_lambda_function_urls([{"FunctionName": "fn"}], client), [CLEAN_LAMBDA]
        )

    def test_function_without_url_is_clean(self):
        client = _FakeLambdaClient({"fn": None})
        self.assertEqual(
            check_lambda_function_urls([{"FunctionName": "fn"}], client), [CLEAN_LAMBDA]
        )

    def test_no_functions_is_clean(self):
        self.assertEqual(
            check_lambda_function_urls([], _FakeLambdaClient({})), [CLEAN_LAMBDA]
        )


class _FakeCloudTrailClient:
    """Stand-in for a boto3 CloudTrail client over get_trail_status.

    ``statuses`` maps a trail name/ARN to a get_trail_status response.
    """

    def __init__(self, statuses=None):
        self._statuses = statuses or {}

    def get_trail_status(self, Name):
        return self._statuses.get(Name, {"IsLogging": False})


def _trail(name="t1", multiregion=True, validation=True):
    arn = f"arn:aws:cloudtrail:us-east-1:111122223333:trail/{name}"
    return {
        "Name": name,
        "TrailARN": arn,
        "IsMultiRegionTrail": multiregion,
        "LogFileValidationEnabled": validation,
    }


class TestCloudTrail(unittest.TestCase):
    def test_no_trails_is_high(self):
        issues = check_cloudtrail([], _FakeCloudTrailClient())
        self.assertTrue(any(i.startswith("[HIGH]") and "No CloudTrail" in i for i in issues))

    def test_multiregion_logging_trail_is_clean(self):
        trail = _trail()
        client = _FakeCloudTrailClient({trail["TrailARN"]: {"IsLogging": True}})
        self.assertEqual(check_cloudtrail([trail], client), [CLEAN_CLOUDTRAIL])

    def test_single_region_trail_is_high(self):
        trail = _trail(multiregion=False)
        client = _FakeCloudTrailClient({trail["TrailARN"]: {"IsLogging": True}})
        issues = check_cloudtrail([trail], client)
        self.assertTrue(
            any(i.startswith("[HIGH]") and "multi-region" in i for i in issues)
        )

    def test_not_logging_trail_is_high(self):
        trail = _trail()
        client = _FakeCloudTrailClient({trail["TrailARN"]: {"IsLogging": False}})
        issues = check_cloudtrail([trail], client)
        self.assertTrue(any(i.startswith("[HIGH]") for i in issues))

    def test_no_log_file_validation_is_medium(self):
        trail = _trail(validation=False)
        client = _FakeCloudTrailClient({trail["TrailARN"]: {"IsLogging": True}})
        issues = check_cloudtrail([trail], client)
        self.assertTrue(
            any(i.startswith("[MEDIUM]") and "validation" in i for i in issues)
        )


def _role_doc(action, resource, effect="Allow"):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": effect, "Action": action, "Resource": resource}],
    }


class TestRolePrivileges(unittest.TestCase):
    def test_full_wildcard_is_high(self):
        roles = [{"RoleName": "r", "PolicyDocuments": [_role_doc("*", "*")]}]
        issues = check_role_privileges(roles)
        self.assertTrue(
            any(i.startswith("[HIGH]") and "full wildcard" in i and "r" in i for i in issues)
        )

    def test_iam_wildcard_is_high(self):
        roles = [{"RoleName": "r", "PolicyDocuments": [_role_doc("iam:*", "*")]}]
        issues = check_role_privileges(roles)
        self.assertTrue(any(i.startswith("[HIGH]") and "iam:*" in i for i in issues))

    def test_broad_assume_role_is_medium(self):
        roles = [{"RoleName": "r", "PolicyDocuments": [_role_doc("sts:AssumeRole", "*")]}]
        issues = check_role_privileges(roles)
        self.assertTrue(
            any(i.startswith("[MEDIUM]") and "assume any role" in i for i in issues)
        )

    def test_full_admin_suppresses_assume_medium(self):
        # A statement that is full admin should not also emit the MEDIUM assume note.
        roles = [
            {
                "RoleName": "r",
                "PolicyDocuments": [_role_doc(["*", "sts:AssumeRole"], "*")],
            }
        ]
        issues = check_role_privileges(roles)
        self.assertTrue(any(i.startswith("[HIGH]") for i in issues))
        self.assertFalse(any(i.startswith("[MEDIUM]") for i in issues))

    def test_scoped_policy_is_clean(self):
        roles = [
            {
                "RoleName": "r",
                "PolicyDocuments": [
                    _role_doc("s3:GetObject", "arn:aws:s3:::bucket/*")
                ],
            }
        ]
        self.assertEqual(check_role_privileges(roles), [CLEAN_ROLES])

    def test_no_roles_is_clean(self):
        self.assertEqual(check_role_privileges([]), [CLEAN_ROLES])


if __name__ == "__main__":
    unittest.main()
