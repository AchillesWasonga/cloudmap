"""
Misconfiguration Checks

This module provides utility functions to analyze cloud resource data and detect common misconfigurations.
"""

def check_security_groups(security_groups):
    """
    Checks each security group for inbound rules that are overly permissive.
    
    :param security_groups: List of security group dicts.
    :return: List of detected issues.
    """
    issues = []
    for sg in security_groups:
        group_id = sg.get("GroupId", "Unknown")
        for permission in sg.get("IpPermissions", []):
            for ip_range in permission.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    issues.append(
                        f"Security Group {group_id} has an open rule: {permission}"
                    )
    if not issues:
        issues.append("No overly permissive security group rules found.")
    return issues


def check_s3_buckets(buckets, s3_client):
    """
    Checks each S3 bucket for public access configurations.
    
    :param buckets: List of bucket dicts.
    :param s3_client: An initialized boto3 S3 client.
    :return: List of detected issues.
    """
    issues = []
    for bucket in buckets:
        bucket_name = bucket.get("Name")
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("Type") == "Group" and "AllUsers" in grantee.get("URI", ""):
                    issues.append(f"S3 bucket {bucket_name} has public access via ACL.")
        except Exception as e:
            issues.append(f"Error checking bucket {bucket_name}: {str(e)}")
    if not issues:
        issues.append("No public S3 buckets found.")
    return issues


def check_iam_policies(users, iam_client):
    """
    Checks each IAM user for overly permissive policies.
    
    :param users: List of IAM user dicts.
    :param iam_client: An initialized boto3 IAM client.
    :return: List of detected issues.
    """
    issues = []
    for user in users:
        user_name = user.get("UserName")
        try:
            response = iam_client.list_attached_user_policies(UserName=user_name)
            for policy in response.get("AttachedPolicies", []):
                policy_name = policy.get("PolicyName", "")
                if "AdministratorAccess" in policy_name:
                    issues.append(
                        f"IAM user {user_name} has overly permissive policy: {policy_name}."
                    )
        except Exception as e:
            issues.append(f"Error checking policies for user {user_name}: {str(e)}")
    if not issues:
        issues.append("No overly permissive IAM policies found.")
    return issues


def check_nsg_rules(nsgs):
    """
    Checks Azure NSG rules for overly permissive inbound traffic.
    
    :param nsgs: List of NSG objects (from Azure SDK).
    :return: List of detected issues.
    """
    issues = []
    for nsg in nsgs:
        # Each NSG object should have a property "security_rules" (this may vary with the SDK version)
        for rule in getattr(nsg, "security_rules", []):
            # We assume rule.direction is a string and rule.source_address_prefix is available
            if rule.direction.lower() == "inbound":
                if rule.source_address_prefix in ["0.0.0.0/0", "*"]:
                    issues.append(
                        f"NSG {nsg.name} has open inbound rule '{rule.name}' allowing {rule.protocol} on port {rule.destination_port_range}."
                    )
    if not issues:
        issues.append("No overly permissive NSG rules found.")
    return issues


def check_storage_accounts(credential, subscription_id):
    """
    Placeholder function to check Azure Storage Account configurations.
    Extend this function as needed.
    
    :param credential: Azure credential object.
    :param subscription_id: Azure subscription ID.
    :return: List of detected issues.
    """
    # For now, simply return a placeholder message.
    return ["Storage account checks not implemented yet."]
