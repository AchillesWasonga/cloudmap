"""
AWS Scanner Module

This module uses boto3 to connect to AWS services and scan for vulnerabilities:
  - Overly permissive security group rules (e.g., open to 0.0.0.0/0)
  - Publicly accessible S3 buckets
  - IAM users with overly permissive policies (e.g., AdministratorAccess)
"""

import boto3
import logging
from cloudmap.utils.misconfiguration_checks import (
    check_security_groups,
    check_s3_buckets,
    check_iam_policies,
)

logger = logging.getLogger("cloudmap.aws")


def scan(config, creds):
    """
    Scans AWS for misconfigurations.
    
    :param config: A dict containing AWS configuration (e.g., region).
    :param creds: A dict with AWS credentials (aws_access_key_id, aws_secret_access_key).
    :return: A dict with findings from the scan.
    """
    findings = {}
    region = config.get("region", "us-east-1")
    logger.info("Starting AWS scan in region: %s", region)

    try:
        # Initialize AWS clients for EC2, S3, and IAM
        ec2_client = boto3.client(
            "ec2",
            region_name=region,
            aws_access_key_id=creds.get("aws_access_key_id"),
            aws_secret_access_key=creds.get("aws_secret_access_key"),
        )
        s3_client = boto3.client(
            "s3",
            aws_access_key_id=creds.get("aws_access_key_id"),
            aws_secret_access_key=creds.get("aws_secret_access_key"),
        )
        iam_client = boto3.client(
            "iam",
            aws_access_key_id=creds.get("aws_access_key_id"),
            aws_secret_access_key=creds.get("aws_secret_access_key"),
        )

        # Retrieve resources
        sec_groups = ec2_client.describe_security_groups().get("SecurityGroups", [])
        buckets = s3_client.list_buckets().get("Buckets", [])
        iam_users = iam_client.list_users().get("Users", [])

        # Run vulnerability checks using our shared utility functions
        findings["security_groups"] = check_security_groups(sec_groups)
        findings["s3_buckets"] = check_s3_buckets(buckets, s3_client)
        findings["iam_policies"] = check_iam_policies(iam_users, iam_client)

    except Exception as e:
        logger.error("Error during AWS scan: %s", e)
        findings["error"] = str(e)

    return findings
