"""
AWS Scanner Module

This module uses boto3 to connect to AWS and scan for common misconfigurations such as:
  - Overly permissive security group rules
  - Public access S3 bucket misconfigurations
  - Overly permissive IAM policies
"""

import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("cloudmap.aws")

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
        
        # ------------------------------
        # 1. Check Security Groups
        # ------------------------------
        sg_response = ec2_client.describe_security_groups()
        security_groups = sg_response.get("SecurityGroups", [])
        sg_findings = []
        for sg in security_groups:
            group_id = sg.get("GroupId", "Unknown")
            for permission in sg.get("IpPermissions", []):
                for ip_range in permission.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr == "0.0.0.0/0":
                        sg_findings.append(f"Security Group {group_id} has open rule: {permission}")
        if not sg_findings:
            sg_findings.append("No overly permissive security group rules found.")
        findings["security_groups"] = sg_findings

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
