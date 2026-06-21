"""
AWS Scanner Module

This module uses boto3 to connect to AWS and scan for common misconfigurations such as:
  - Overly permissive security group rules
  - Public access S3 bucket misconfigurations
  - Overly permissive IAM policies
  - Weak EC2 instance metadata (IMDSv2) settings
  - Cross-service confused-deputy bucket policies
"""

import json
import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("ramwingu.aws")


def check_instance_metadata(instances, admin_profile_arns=frozenset()):
    """
    Checks EC2 instances for weak Instance Metadata Service (IMDS) settings.

    The metadata service exposes the instance's IAM role credentials at
    169.254.169.254. While IMDSv1 is still allowed, a server-side request forgery
    (SSRF) in any app on the instance can reach that endpoint and steal those
    credentials. Enforcing IMDSv2 (``HttpTokens=required``) and a low hop limit is
    the durable defense.

    Enforcement alone is necessary but not sufficient: CVE-2026-40175 (axios
    header-injection chain, CVSS 9.9) showed an SSRF can be smuggled past IMDSv2's
    token PUT, and the blast radius of any such theft equals the privileges of the
    instance's IAM role. Each IMDSv1 finding is therefore annotated with the
    attached instance-profile ARN, and escalated when that profile's role is broad.

    :param instances: List of EC2 instance dicts (from ``describe_instances``).
    :param admin_profile_arns: Set of instance-profile ARNs whose attached role
        grants broad/admin access (resolved in ``scan`` via the step-3 IAM logic);
        an IMDSv1 instance using one of these has critical blast radius.
    :return: List of detected issues.
    """
    issues = []
    for instance in instances:
        instance_id = instance.get("InstanceId", "Unknown")
        options = instance.get("MetadataOptions", {})
        profile_arn = instance.get("IamInstanceProfile", {}).get("Arn")

        # IMDSv1 still usable -> an SSRF can mint credential tokens (high risk).
        if options.get("HttpTokens") != "required":
            message = (
                f"[HIGH] EC2 instance {instance_id} allows IMDSv1 "
                f"(MetadataOptions.HttpTokens is "
                f"'{options.get('HttpTokens', 'optional')}', not 'required'); "
                f"enforce IMDSv2 to prevent SSRF credential theft (CVE-2026-40175)."
            )
            if profile_arn and profile_arn in admin_profile_arns:
                message += (
                    f" Blast radius is critical: attached instance profile "
                    f"{profile_arn} grants AdministratorAccess."
                )
            elif profile_arn:
                message += f" Attached instance profile: {profile_arn}."
            else:
                message += " No instance profile is attached (no role credentials to steal)."
            issues.append(message)

        # Permissive hop limit while the endpoint is reachable (lower-signal note).
        if options.get("HttpEndpoint", "enabled") != "disabled":
            hop_limit = options.get("HttpPutResponseHopLimit")
            if isinstance(hop_limit, int) and hop_limit > 1:
                issues.append(
                    f"[MEDIUM] EC2 instance {instance_id} has a metadata hop limit of "
                    f"{hop_limit} (greater than 1); lower it to 1 unless containers "
                    f"on the host require more."
                )

    if not issues:
        issues.append("No insecure EC2 instance metadata configurations found.")
    return issues


# Condition keys that scope a service principal to a specific source account, ARN,
# or organization -- their presence mitigates the confused-deputy risk.
_SOURCE_CONDITION_KEYS = frozenset(
    {"aws:sourceaccount", "aws:sourcearn", "aws:sourceorgid"}
)


def _service_principals_without_source_condition(policy_document):
    """
    Finds ``Allow`` statements that trust an AWS service principal but carry no
    source condition (``aws:SourceAccount`` / ``aws:SourceArn`` /
    ``aws:SourceOrgID``) -- the cross-service "confused deputy" smell.

    Resource-type agnostic: it works on any parsed AWS resource policy (S3 bucket
    policy, KMS key policy, SNS/SQS, ...), so other scanners can reuse it.

    :param policy_document: A parsed resource-policy dict.
    :return: List of service-principal strings from the offending statements.
    """
    offenders = []
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):  # a lone statement may be a bare object
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal")
        if not isinstance(principal, dict):
            continue  # "*" or a bare string principal is not a service principal
        services = principal.get("Service")
        if not services:
            continue
        if isinstance(services, str):
            services = [services]

        # Collect every condition key used anywhere in the Condition block.
        present_keys = set()
        for comparison in statement.get("Condition", {}).values():
            if isinstance(comparison, dict):
                present_keys.update(key.lower() for key in comparison)

        # A source condition is present -> treat as mitigated and skip (high-signal).
        if present_keys & _SOURCE_CONDITION_KEYS:
            continue

        offenders.extend(services)

    return offenders


def check_bucket_policy_confused_deputy(buckets, s3_client):
    """
    Flags S3 bucket policies that trust an AWS service principal without a source
    condition, leaving the bucket open to cross-service confused-deputy abuse:
    another account can coerce the trusted service into acting on your bucket.

    :param buckets: List of bucket dicts (from ``list_buckets``).
    :param s3_client: An initialized boto3 S3 client.
    :return: List of detected issues.
    """
    issues = []
    for bucket in buckets:
        bucket_name = bucket.get("Name")
        try:
            policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_document = json.loads(policy_response.get("Policy", "{}"))
        except ClientError as e:
            # A bucket with no policy is the common case, not a finding.
            if e.response.get("Error", {}).get("Code") == "NoSuchBucketPolicy":
                continue
            issues.append(f"Error checking bucket policy for {bucket_name}: {str(e)}")
            continue

        for service in _service_principals_without_source_condition(policy_document):
            issues.append(
                f"S3 bucket {bucket_name} policy trusts service principal "
                f"'{service}' without an aws:SourceAccount/aws:SourceArn/"
                f"aws:SourceOrgID condition (cross-service confused-deputy risk)."
            )

    if not issues:
        issues.append("No confused-deputy S3 bucket policies found.")
    return issues


# The four S3 Block Public Access (BPA) flags. All must be True for BPA to be
# fully enabled -- AWS's single most important S3 guardrail. While it is fully on,
# no public ACL or bucket policy can take effect, so a gap here is what lets the
# other public-exposure vectors matter at all.
_BPA_FLAGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)

# Sentinel: account-level BPA was not checked (e.g. permissions) and should not be
# reported, distinct from ``None`` which means "no account BPA configured" (a gap).
_ACCOUNT_BPA_UNCHECKED = object()


def _missing_bpa_flags(block_config):
    """
    Returns the BPA flags that are not explicitly ``True`` in a
    PublicAccessBlockConfiguration. A missing/empty config means BPA is unset, so
    every flag is reported as missing.

    :param block_config: A PublicAccessBlockConfiguration dict, or a falsy value.
    :return: List of missing flag names ([] means BPA is fully enabled).
    """
    if not block_config:
        return list(_BPA_FLAGS)
    return [flag for flag in _BPA_FLAGS if block_config.get(flag) is not True]


def _acl_grants_public(acl):
    """True if a bucket ACL grants access to the public ``AllUsers`` group."""
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        if grantee.get("Type") == "Group" and "AllUsers" in grantee.get("URI", ""):
            return True
    return False


def _policy_grants_public(policy_document):
    """
    True if a bucket policy has an ``Allow`` statement open to everyone
    (``Principal: "*"`` or ``AWS: "*"``) with no restricting ``Condition``.

    A condition (e.g. a source-VPC or IP bound) scopes the access, so such
    statements are not treated as world-public here.
    """
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):  # a lone statement may be a bare object
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition"):
            continue  # a restricting condition scopes the grant

        principal = statement.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws_principal = principal.get("AWS")
            if aws_principal == "*" or (
                isinstance(aws_principal, list) and "*" in aws_principal
            ):
                return True
    return False


def _live_public_vectors(bucket_name, s3_client, issues):
    """
    Returns the live public-exposure vectors for a bucket -- any of ``"ACL"`` and
    ``"bucket policy"`` that currently grant world access. Unexpected API errors
    are appended to ``issues`` so they surface as findings rather than vanish.
    """
    vectors = []
    try:
        if _acl_grants_public(s3_client.get_bucket_acl(Bucket=bucket_name)):
            vectors.append("ACL")
    except ClientError as e:
        issues.append(f"Error checking ACL for {bucket_name}: {str(e)}")

    try:
        policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_document = json.loads(policy_response.get("Policy", "{}"))
        if _policy_grants_public(policy_document):
            vectors.append("bucket policy")
    except ClientError as e:
        # A bucket with no policy is the common case, not a finding.
        if e.response.get("Error", {}).get("Code") != "NoSuchBucketPolicy":
            issues.append(f"Error checking bucket policy for {bucket_name}: {str(e)}")
    return vectors


def check_s3_public_access(buckets, s3_client, account_block=_ACCOUNT_BPA_UNCHECKED):
    """
    Flags S3 public-exposure gaps that the ACL-only check misses, centred on Block
    Public Access (BPA) -- the guardrail AWS itself flags first.

    Reports, with inline severity:

    - Account-level BPA not fully enabled -> ``[MEDIUM]`` (public ACLs/policies are
      able to take effect across the account).
    - A bucket whose BPA is not fully enabled *and* that is already public via an
      ``AllUsers`` ACL or a ``Principal: "*"`` policy -> ``[HIGH]``.
    - A bucket whose BPA is not fully enabled with nothing public yet ->
      ``[MEDIUM]`` (latent exposure).

    A bucket with BPA fully enabled is skipped: BPA neutralises any public ACL or
    policy, so there is no live exposure to report.

    :param buckets: List of bucket dicts (from ``list_buckets``).
    :param s3_client: An initialized boto3 S3 client.
    :param account_block: The account-level PublicAccessBlockConfiguration dict,
        ``None`` if none is configured, or left unset to skip the account check.
    :return: List of detected issues.
    """
    issues = []

    if account_block is not _ACCOUNT_BPA_UNCHECKED:
        account_missing = _missing_bpa_flags(account_block)
        if account_missing:
            issues.append(
                f"[MEDIUM] Account-level S3 Block Public Access is not fully enabled "
                f"(missing: {', '.join(account_missing)}); public ACLs or bucket "
                f"policies are able to take effect on buckets in this account."
            )

    for bucket in buckets:
        bucket_name = bucket.get("Name")
        try:
            response = s3_client.get_public_access_block(Bucket=bucket_name)
            bucket_block = response.get("PublicAccessBlockConfiguration", {})
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code != "NoSuchPublicAccessBlockConfiguration":
                issues.append(
                    f"Error checking Block Public Access for {bucket_name}: {str(e)}"
                )
                continue
            bucket_block = {}  # no BPA configured -> every flag missing

        bucket_missing = _missing_bpa_flags(bucket_block)
        if not bucket_missing:
            continue  # BPA fully enabled neutralises any public ACL/policy

        vectors = _live_public_vectors(bucket_name, s3_client, issues)
        if vectors:
            issues.append(
                f"[HIGH] S3 bucket {bucket_name} is publicly exposed via "
                f"{' and '.join(vectors)} and Block Public Access is not fully "
                f"enabled (missing: {', '.join(bucket_missing)})."
            )
        else:
            issues.append(
                f"[MEDIUM] S3 bucket {bucket_name} has Block Public Access not fully "
                f"enabled (missing: {', '.join(bucket_missing)}); latent "
                f"public-exposure risk."
            )

    if not issues:
        issues.append("No public S3 access exposure found.")
    return issues


# World-open inbound exposure to these ports is treated as HIGH severity: they
# front remote-admin, database, and similar sensitive services that get probed and
# popped quickly once reachable from the internet. (Per the standalone-scanner
# design rule this port-risk model is intentionally duplicated in azure.py rather
# than shared -- keep the two in sync by hand, do not extract a shared module.)
_HIGH_RISK_PORTS = frozenset(
    {
        22,     # SSH
        23,     # Telnet
        445,    # SMB
        1433,   # MSSQL
        1521,   # Oracle DB
        3306,   # MySQL / MariaDB
        3389,   # RDP
        5432,   # PostgreSQL
        5601,   # Kibana
        5984,   # CouchDB
        6379,   # Redis
        6789,   # privileged unauth service cited in the source intel
        9200,   # Elasticsearch HTTP
        9300,   # Elasticsearch transport
        11211,  # Memcached
        27017,  # MongoDB
    }
)

# World-open exposure here is commonly an intentional public-web decision, so it is
# still reported but at LOW severity to keep the high-risk signal from drowning.
_LOW_RISK_PORTS = frozenset({80, 443})


def _severity_for_permission(permission):
    """
    Classifies a world-open inbound permission into HIGH / MEDIUM / LOW by the
    ports it exposes.

    HIGH if the rule reaches any high-risk port (or exposes all ports, e.g. an
    all-protocols ``-1`` rule); LOW if it only reaches expected public-web ports
    (80/443); MEDIUM otherwise.

    :param permission: An IpPermission dict (from ``describe_security_groups``).
    :return: Severity string.
    """
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    # "-1" (all protocols) or an unscoped range exposes every port -> high-risk set.
    if permission.get("IpProtocol") == "-1" or from_port is None or to_port is None:
        return "HIGH"
    if any(from_port <= port <= to_port for port in _HIGH_RISK_PORTS):
        return "HIGH"
    if all(port in _LOW_RISK_PORTS for port in range(from_port, to_port + 1)):
        return "LOW"
    return "MEDIUM"


def _describe_ports(permission):
    """Renders a permission's port range for a finding message."""
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if permission.get("IpProtocol") == "-1" or from_port is None or to_port is None:
        return "all ports"
    if from_port == to_port:
        return f"port {from_port}"
    return f"ports {from_port}-{to_port}"


def check_security_groups(security_groups):
    """
    Flags security group inbound rules open to the entire internet, tagged with a
    port-aware severity.

    Inspects both address families: IPv4 (``IpRanges`` with
    ``CidrIp == "0.0.0.0/0"``) and IPv6 (``Ipv6Ranges`` with
    ``CidrIpv6 == "::/0"``). A rule open to ``::/0`` is the exact IPv6 equivalent
    of ``0.0.0.0/0`` and carries identical exposure, but was previously missed
    because only IPv4 ranges were inspected. Each finding is prefixed with a
    ``[HIGH]`` / ``[MEDIUM]`` / ``[LOW]`` severity derived from the exposed ports.

    :param security_groups: List of SG dicts (from ``describe_security_groups``).
    :return: List of detected issues.
    """
    issues = []
    for sg in security_groups:
        group_id = sg.get("GroupId", "Unknown")
        for permission in sg.get("IpPermissions", []):
            ipv4_open = any(
                r.get("CidrIp") == "0.0.0.0/0" for r in permission.get("IpRanges", [])
            )
            ipv6_open = any(
                r.get("CidrIpv6") == "::/0" for r in permission.get("Ipv6Ranges", [])
            )
            if not (ipv4_open or ipv6_open):
                continue

            severity = _severity_for_permission(permission)
            ports = _describe_ports(permission)
            if ipv4_open:
                issues.append(
                    f"[{severity}] Security Group {group_id} has open rule on "
                    f"{ports}: {permission}"
                )
            if ipv6_open:
                issues.append(
                    f"[{severity}] Security Group {group_id} has open IPv6 rule on "
                    f"{ports}: {permission}"
                )

    if not issues:
        issues.append("No overly permissive security group rules found.")
    return issues


def scan(config, creds):
    """
    Performs an AWS scan for common misconfigurations.
    
    :param config: AWS configuration dictionary (e.g., region).
    :param creds: AWS credentials dictionary (e.g., aws_access_key_id, aws_secret_access_key).
    :return: A dictionary with findings.
    """
    findings = {}
    region = config.get("region", "us-east-1")
    logger.info("Starting AWS scan in region: %s", region)
    
    try:
        # Initialize AWS clients
        ec2_client = boto3.client(
            "ec2",
            region_name=region,
            aws_access_key_id=creds.get("aws_access_key_id"),
            aws_secret_access_key=creds.get("aws_secret_access_key")
        )
        s3_client = boto3.client(
            "s3",
            aws_access_key_id=creds.get("aws_access_key_id"),
            aws_secret_access_key=creds.get("aws_secret_access_key")
        )
        iam_client = boto3.client(
            "iam",
            aws_access_key_id=creds.get("aws_access_key_id"),
            aws_secret_access_key=creds.get("aws_secret_access_key")
        )
        s3control_client = boto3.client(
            "s3control",
            region_name=region,
            aws_access_key_id=creds.get("aws_access_key_id"),
            aws_secret_access_key=creds.get("aws_secret_access_key")
        )
        sts_client = boto3.client(
            "sts",
            aws_access_key_id=creds.get("aws_access_key_id"),
            aws_secret_access_key=creds.get("aws_secret_access_key")
        )

        # ------------------------------
        # 1. Check Security Groups
        # ------------------------------
        sg_response = ec2_client.describe_security_groups()
        security_groups = sg_response.get("SecurityGroups", [])
        findings["security_groups"] = check_security_groups(security_groups)

        # ------------------------------
        # 2. Check S3 Buckets
        # ------------------------------
        s3_response = s3_client.list_buckets()
        buckets = s3_response.get("Buckets", [])
        s3_findings = []
        for bucket in buckets:
            bucket_name = bucket.get("Name")
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("Type") == "Group" and "AllUsers" in grantee.get("URI", ""):
                        s3_findings.append(f"S3 bucket {bucket_name} has public access via ACL.")
            except ClientError as e:
                s3_findings.append(f"Error checking bucket {bucket_name}: {str(e)}")
        if not s3_findings:
            s3_findings.append("No public S3 buckets found.")
        findings["s3_buckets"] = s3_findings

        # ------------------------------
        # 2b. Check S3 public access (Block Public Access + public policy/ACL)
        # ------------------------------
        # Account-level BPA is the highest guardrail; resolve it once. A missing
        # configuration (NoSuchPublicAccessBlockConfiguration) means BPA is off and
        # is reported, whereas a permissions failure leaves it unchecked.
        account_block = _ACCOUNT_BPA_UNCHECKED
        try:
            account_id = sts_client.get_caller_identity().get("Account")
            if account_id:
                try:
                    account_block = s3control_client.get_public_access_block(
                        AccountId=account_id
                    ).get("PublicAccessBlockConfiguration", {})
                except ClientError as e:
                    if e.response.get("Error", {}).get("Code") == (
                        "NoSuchPublicAccessBlockConfiguration"
                    ):
                        account_block = None
                    else:
                        logger.warning("Could not fetch account-level S3 BPA: %s", e)
        except ClientError as e:
            logger.warning("Could not resolve account id for S3 BPA: %s", e)
        findings["s3_public_access"] = check_s3_public_access(
            buckets, s3_client, account_block
        )

        # ------------------------------
        # 3. Check IAM Policies
        # ------------------------------
        iam_response = iam_client.list_users()
        users = iam_response.get("Users", [])
        iam_findings = []
        for user in users:
            user_name = user.get("UserName")
            try:
                policy_response = iam_client.list_attached_user_policies(UserName=user_name)
                for policy in policy_response.get("AttachedPolicies", []):
                    policy_name = policy.get("PolicyName", "")
                    if "AdministratorAccess" in policy_name:
                        iam_findings.append(f"IAM user {user_name} has overly permissive policy: {policy_name}.")
            except ClientError as e:
                iam_findings.append(f"Error checking policies for user {user_name}: {str(e)}")
        if not iam_findings:
            iam_findings.append("No overly permissive IAM policies found.")
        findings["iam_policies"] = iam_findings

        # ------------------------------
        # 4. Check EC2 Instance Metadata (IMDSv2 enforcement)
        # ------------------------------
        instances = []
        instances_response = ec2_client.describe_instances()
        for reservation in instances_response.get("Reservations", []):
            instances.extend(reservation.get("Instances", []))

        # Blast-radius context (CVE-2026-40175): resolve which attached instance
        # profiles grant broad access so an IMDSv1 finding can be escalated. Reuses
        # the step-3 "AdministratorAccess" heuristic, once per distinct profile.
        admin_profile_arns = set()
        profile_arns = {
            inst["IamInstanceProfile"]["Arn"]
            for inst in instances
            if inst.get("IamInstanceProfile", {}).get("Arn")
        }
        for profile_arn in profile_arns:
            profile_name = profile_arn.split("/")[-1]
            try:
                profile = iam_client.get_instance_profile(
                    InstanceProfileName=profile_name
                ).get("InstanceProfile", {})
                for role in profile.get("Roles", []):
                    attached = iam_client.list_attached_role_policies(
                        RoleName=role.get("RoleName")
                    ).get("AttachedPolicies", [])
                    if any(
                        "AdministratorAccess" in p.get("PolicyName", "")
                        for p in attached
                    ):
                        admin_profile_arns.add(profile_arn)
                        break
            except ClientError as e:
                logger.warning(
                    "Could not resolve instance profile %s: %s", profile_name, e
                )

        findings["instance_metadata"] = check_instance_metadata(
            instances, admin_profile_arns
        )

        # ------------------------------
        # 5. Check S3 Bucket Policies (cross-service confused deputy)
        # ------------------------------
        findings["s3_bucket_policies"] = check_bucket_policy_confused_deputy(
            buckets, s3_client
        )

    except Exception as e:
        logger.error("Error during AWS scan: %s", e)
        findings["error"] = str(e)
    
    return findings

def run_scan_with_aws_credentials(config, creds):
    """
    Wrapper function that ensures AWS credentials are available and then runs the scan.
    
    :param config: AWS configuration (e.g., region).
    :param creds: AWS credentials (e.g., aws_access_key_id, aws_secret_access_key).
    :return: Findings from the scan.
    """
    # Here you could add additional logic to check/ensure credentials.
    # For now, we assume creds are already provided.
    return scan(config, creds)
