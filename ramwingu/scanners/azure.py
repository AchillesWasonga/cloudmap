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

# Source prefixes that expose an inbound rule to the entire internet. "*" (Any)
# and the "Internet" service tag cover both address families; "0.0.0.0/0" is
# IPv4-any and "::/0" is its IPv6 equivalent (the IPv6 form was previously
# missed). Compared case-insensitively so the "Internet" tag matches any casing.
_WORLD_OPEN_SOURCE_PREFIXES = frozenset({"0.0.0.0/0", "*", "::/0", "internet"})


def _rule_source_prefixes(rule):
    """
    Collects every source prefix declared on an NSG rule.

    Azure rules carry a source either as a single ``source_address_prefix`` or as
    a list in ``source_address_prefixes`` (plural). The original check only read
    the singular field, so a world-open rule expressed via the plural list slipped
    through entirely; this gathers both.

    :param rule: An NSG security-rule object from the Azure SDK.
    :return: List of source-prefix strings.
    """
    prefixes = []
    single = getattr(rule, "source_address_prefix", None)
    if single:
        prefixes.append(single)
    prefixes.extend(getattr(rule, "source_address_prefixes", None) or [])
    return prefixes


# World-open inbound exposure to these ports is treated as HIGH severity: they
# front remote-admin, database, and similar sensitive services that get probed and
# popped quickly once reachable from the internet. (Per the standalone-scanner
# design rule this port-risk model is intentionally duplicated from aws.py rather
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


def _rule_dest_port_specs(rule):
    """
    Collects every destination-port spec on an NSG rule, from both the singular
    ``destination_port_range`` and the plural ``destination_port_ranges`` list.

    :param rule: An NSG security-rule object from the Azure SDK.
    :return: List of port-spec strings (e.g. ``"22"``, ``"8000-8100"``, ``"*"``).
    """
    specs = []
    single = getattr(rule, "destination_port_range", None)
    if single:
        specs.append(str(single))
    specs.extend(str(s) for s in (getattr(rule, "destination_port_ranges", None) or []))
    return specs


def _port_bounds(spec):
    """Parses an Azure port spec into an inclusive ``(lo, hi)`` range; ``"*"`` is
    all ports."""
    spec = spec.strip()
    if spec == "*":
        return (0, 65535)
    if "-" in spec:
        low, high = spec.split("-", 1)
        return (int(low), int(high))
    return (int(spec), int(spec))


def _severity_for_rule(rule):
    """
    Classifies a world-open inbound NSG rule into HIGH / MEDIUM / LOW by the ports
    it exposes (same model as the AWS scanner).

    HIGH if any spec reaches a high-risk port (or exposes all ports); LOW if every
    exposed port is an expected public-web port (80/443); MEDIUM otherwise. An
    unparseable or unspecified port set defaults to HIGH (assume broad exposure).

    :param rule: An NSG security-rule object from the Azure SDK.
    :return: Severity string.
    """
    specs = _rule_dest_port_specs(rule)
    if not specs:
        return "HIGH"
    try:
        bounds = [_port_bounds(spec) for spec in specs]
    except (ValueError, TypeError):
        return "HIGH"
    if any(low <= port <= high for (low, high) in bounds for port in _HIGH_RISK_PORTS):
        return "HIGH"
    if all(
        port in _LOW_RISK_PORTS
        for (low, high) in bounds
        for port in range(low, high + 1)
    ):
        return "LOW"
    return "MEDIUM"


def check_nsg_rules(nsgs):
    """
    Checks Azure NSG rules for overly permissive inbound traffic, tagged with a
    port-aware severity.

    Flags any inbound rule whose source is open to the entire internet across
    both address families and both the singular ``source_address_prefix`` and the
    plural ``source_address_prefixes`` list (see ``_WORLD_OPEN_SOURCE_PREFIXES``).
    Each finding is prefixed with a ``[HIGH]`` / ``[MEDIUM]`` / ``[LOW]`` severity
    derived from the exposed ports.

    :param nsgs: List of NSG objects from the Azure SDK.
    :return: List of detected issues.
    """
    issues = []
    for nsg in nsgs:
        for rule in getattr(nsg, "security_rules", []):
            if rule.direction.lower() != "inbound":
                continue
            prefixes = _rule_source_prefixes(rule)
            if not any(p.lower() in _WORLD_OPEN_SOURCE_PREFIXES for p in prefixes):
                continue
            severity = _severity_for_rule(rule)
            ports = ", ".join(_rule_dest_port_specs(rule)) or "*"
            issues.append(
                f"[{severity}] NSG '{nsg.name}' in resource group '{nsg.id.split('/')[4]}' "
                f"has open inbound rule '{rule.name}' allowing {rule.protocol} on port(s) {ports}."
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

        # 4. At-rest encryption hardening (defense-in-depth). Data is always
        # encrypted, so these are LOW: a second encryption layer and key control.
        encryption = getattr(props, "encryption", None)
        if getattr(encryption, "require_infrastructure_encryption", None) is not True:
            issues.append(
                f"[LOW] Storage account {sa_name} (resource group {rg_name}) does not "
                f"have infrastructure (double) encryption enabled; enable it for a "
                f"second at-rest encryption layer."
            )
        key_source = getattr(encryption, "key_source", None)
        if key_source is None or str(key_source).lower() == "microsoft.storage":
            issues.append(
                f"[LOW] Storage account {sa_name} (resource group {rg_name}) uses "
                f"Microsoft-managed encryption keys (no customer-managed key); consider "
                f"a customer-managed key (CMK) for key control and rotation."
            )

    if not issues:
        issues.append("No insecure storage account configurations found.")
    return issues
