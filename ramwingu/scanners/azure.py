"""
Azure Scanner Module

This module uses the Azure SDK to authenticate and scan for common misconfigurations:
  - Overly permissive NSG rules (inbound rules open to 0.0.0.0/0 or "*")
  - Storage account exposure (Shared Key auth, public blob access, open public network)

It includes functions to prompt for Azure CLI login, set the subscription, and logout afterward.
"""

import logging
import os
import subprocess
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient

logger = logging.getLogger("ramwingu.azure")

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
        # 2. Check Storage Accounts (Shared Key auth + public blob/network)
        # ------------------------------
        findings["storage_accounts"] = check_storage_accounts(storage_client)

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


def check_storage_accounts(storage_client):
    """
    Checks Azure Storage accounts for insecure data-plane exposure.

    Three high-signal misconfigurations are flagged:

      * **Shared Key authorization allowed** -- account access keys grant full,
        un-scoped, un-audited access to all data in the account. The
        ``allowSharedKeyAccess`` property is unset (null) by default and a null
        value is treated as *permitted*, so the insecure posture is the default.
        Microsoft's guidance is to disable it and use Entra ID (RBAC).
      * **Anonymous public blob access** -- ``allowBlobPublicAccess`` true lets
        containers/blobs be read with no credentials.
      * **Open public network access** -- the account is reachable from any network
        (``publicNetworkAccess`` enabled) with a default-allow network rule set.

    :param storage_client: An initialized ``StorageManagementClient``.
    :return: List of detected issues.
    """
    issues = []
    for sa in storage_client.storage_accounts.list():
        sa_name = sa.name
        rg_name = sa.id.split("/")[4]  # Resource group sits at index 4 of the ID.
        props = storage_client.storage_accounts.get_properties(rg_name, sa_name)

        # 1. Shared Key authorization -- null (default) or True both permit it.
        if getattr(props, "allow_shared_key_access", None) in (None, True):
            issues.append(
                f"Storage account {sa_name} (resource group {rg_name}) permits Shared "
                f"Key authorization (allow_shared_key_access is not disabled); disable "
                f"it and use Entra ID (RBAC)."
            )

        # 2. Anonymous public blob access.
        if getattr(props, "allow_blob_public_access", None) is True:
            issues.append(
                f"Storage account {sa_name} (resource group {rg_name}) allows anonymous "
                f"public blob access (allow_blob_public_access is True); disable public "
                f"blob access."
            )

        # 3. Reachable from any network with no default-deny network rule.
        public_network = getattr(props, "public_network_access", None)
        network_rules = getattr(props, "network_rule_set", None)
        default_action = getattr(network_rules, "default_action", None)
        reachable = public_network is None or str(public_network).lower() == "enabled"
        no_network_restriction = network_rules is None or (
            default_action is not None and str(default_action).lower() == "allow"
        )
        if reachable and no_network_restriction:
            shown = public_network if public_network is not None else "Enabled (default)"
            issues.append(
                f"Storage account {sa_name} (resource group {rg_name}) is reachable from "
                f"any network (public_network_access is '{shown}' with a default-allow "
                f"network rule set); restrict with network rules or disable public "
                f"network access."
            )

    if not issues:
        issues.append("No insecure storage account configurations found.")
    return issues
