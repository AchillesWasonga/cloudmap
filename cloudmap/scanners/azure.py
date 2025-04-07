"""
Azure Scanner Module

This module uses the Azure SDK to authenticate and scan for common misconfigurations:
  - Overly permissive NSG rules (inbound rules open to 0.0.0.0/0 or "*")
  - Public access configurations on Storage Accounts
"""

import logging
import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient

logger = logging.getLogger("cloudmap.azure")

def scan(config, creds):
    """
    Scans Azure for misconfigurations.

    :param config: A dict containing Azure configuration (can include subscription_id).
    :param creds: A dict for compatibility (not used when using DefaultAzureCredential).
    :return: A dict with findings from the scan.
    """
    # Try to get subscription_id from config or environment variable.
    subscription_id = config.get("subscription_id") or os.getenv("AZURE_SUBSCRIPTION_ID")
    if not subscription_id:
        subscription_id = input("Enter your Azure Subscription ID (you can find it via 'az account show'): ").strip()
    
    logger.info("Starting Azure scan with subscription: %s", subscription_id)

    findings = {}

    try:
        # Use DefaultAzureCredential to simplify authentication
        credential = DefaultAzureCredential()

        # Initialize clients for resource, network, and storage management
        resource_client = ResourceManagementClient(credential, subscription_id)
        network_client = NetworkManagementClient(credential, subscription_id)
        storage_client = StorageManagementClient(credential, subscription_id)

        # ------------------------------
        # 1. Check NSG Rules
        # ------------------------------
        all_nsgs = []
        for rg in resource_client.resource_groups.list():
            nsg_list = list(network_client.network_security_groups.list(rg.name))
            all_nsgs.extend(nsg_list)

        nsg_issues = check_nsg_rules(all_nsgs)
        findings["nsg_rules"] = nsg_issues

        # ------------------------------
        # 2. Check Storage Accounts for Public Access
        # ------------------------------
        storage_issues = []
        storage_accounts = list(storage_client.storage_accounts.list())
        for sa in storage_accounts:
            sa_name = sa.name
            rg_name = sa.id.split("/")[4]  # Extract resource group from resource ID
            sa_properties = storage_client.storage_accounts.get_properties(rg_name, sa_name)
            
            # Check if the network rule set default action is Allow (which might be too permissive)
            network_rules = getattr(sa_properties, "network_rule_set", None)
            if network_rules and network_rules.default_action.lower() == "allow":
                storage_issues.append(f"Storage account {sa_name} in resource group {rg_name} allows public access by default.")
        
        if not storage_issues:
            storage_issues.append("No publicly accessible storage accounts found.")
        findings["storage_accounts"] = storage_issues

    except Exception as e:
        logger.error("Error during Azure scan: %s", e)
        findings["error"] = str(e)

    return findings

def check_nsg_rules(nsgs):
    """
    Checks Azure NSG rules for overly permissive inbound traffic.

    :param nsgs: List of NSG objects from the Azure SDK.
    :return: List of detected issues.
    """
    issues = []
    for nsg in nsgs:
        for rule in getattr(nsg, "security_rules", []):
            if rule.direction.lower() == "inbound":
                if rule.source_address_prefix in ["0.0.0.0/0", "*"]:
                    issues.append(
                        f"NSG '{nsg.name}' in resource group '{nsg.id.split('/')[4]}' has open inbound rule '{rule.name}' "
                        f"allowing {rule.protocol} on port(s) {rule.destination_port_range}."
                    )
    if not issues:
        issues.append("No overly permissive NSG rules found.")
    return issues
