"""
Azure Scanner Module

This module uses the Azure SDK to authenticate and scan for common misconfigurations:
  - Overly permissive NSG rules (inbound rules open to 0.0.0.0/0 or "*")
  - Public access configurations on Storage Accounts

It includes functions to prompt for Azure CLI login, set the subscription, and logout afterward.
"""

import logging
import os
import subprocess
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient

logger = logging.getLogger("cloudmap.azure")

def ensure_az_login():
    """
    Checks if the user is already logged in via Azure CLI.
    If not, it runs 'az login' to prompt for login.
    """
    try:
        subprocess.run(["az", "account", "show"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception:
        print("You are not logged in to Azure. Launching 'az login'...")
        subprocess.run(["az", "login"], check=True)

def logout_az():
    """
    Logs out the current Azure CLI session.
    """
    subprocess.run(["az", "logout"], check=True)

def run_scan_with_az_login(config, creds):
    """
    Wrapper function that:
      - Ensures the user is logged in via Azure CLI.
      - Prompts for and sets the Azure Subscription ID if not provided or if it is still a placeholder.
      - Runs the scan.
      - Logs out afterward.
    
    :param config: A dict containing Azure configuration (e.g., subscription_id).
    :param creds: A dict for Azure credentials (not used when using DefaultAzureCredential).
    :return: A dict with findings from the scan.
    """
    ensure_az_login()

    # Attempt to get the subscription ID from the config or environment.
    subscription_id = config.get("subscription_id") or os.getenv("AZURE_SUBSCRIPTION_ID")
    
    # Check if subscription_id is missing or is still the placeholder value.
    if not subscription_id or subscription_id.lower() == "subscription_id":
        subscription_id = input("Enter your Azure Subscription ID (you won't need to enter it again during this session): ").strip()
        os.environ["AZURE_SUBSCRIPTION_ID"] = subscription_id
        subprocess.run(["az", "account", "set", "--subscription", subscription_id], check=True)
    
    logger.info("Starting Azure scan with subscription: %s", subscription_id)
    findings = {}

    try:
        # Use DefaultAzureCredential for authentication.
        credential = DefaultAzureCredential()
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
        findings["nsg_rules"] = check_nsg_rules(all_nsgs)

        # ------------------------------
        # 2. Check Storage Accounts for Public Access
        # ------------------------------
        storage_issues = []
        storage_accounts = list(storage_client.storage_accounts.list())
        for sa in storage_accounts:
            sa_name = sa.name
            rg_name = sa.id.split("/")[4]  # Extract resource group from the resource ID.
            sa_properties = storage_client.storage_accounts.get_properties(rg_name, sa_name)
            network_rules = getattr(sa_properties, "network_rule_set", None)
            if network_rules and network_rules.default_action.lower() == "allow":
                storage_issues.append(f"Storage account {sa_name} in resource group {rg_name} allows public access by default.")
        if not storage_issues:
            storage_issues.append("No publicly accessible storage accounts found.")
        findings["storage_accounts"] = storage_issues

    except Exception as e:
        logger.error("Error during Azure scan: %s", e)
        findings["error"] = str(e)

    logout_az()
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
