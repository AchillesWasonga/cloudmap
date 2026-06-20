import unittest
from ramwingu.scanners import azure
from ramwingu.scanners.azure import check_nsg_rules, check_storage_accounts

CLEAN_STORAGE = "No insecure storage account configurations found."
CLEAN_NSG = "No overly permissive NSG rules found."


class _FakeProps:
    """Stand-in for a StorageManagementClient account-properties object."""

    def __init__(
        self,
        allow_shared_key_access=None,
        allow_blob_public_access=None,
        public_network_access=None,
        network_default_action=None,
    ):
        self.allow_shared_key_access = allow_shared_key_access
        self.allow_blob_public_access = allow_blob_public_access
        self.public_network_access = public_network_access
        if network_default_action is None:
            self.network_rule_set = None
        else:
            self.network_rule_set = type(
                "NRS", (), {"default_action": network_default_action}
            )()


class _FakeAccount:
    def __init__(self, name, rg):
        self.name = name
        self.id = (
            f"/subscriptions/sub/resourceGroups/{rg}"
            f"/providers/Microsoft.Storage/storageAccounts/{name}"
        )


class _FakeStorageClient:
    """Minimal storage_client exposing storage_accounts.list()/get_properties()."""

    def __init__(self, accounts, props_by_name):
        self._accounts = accounts
        self._props = props_by_name
        self.storage_accounts = self

    def list(self):
        return list(self._accounts)

    def get_properties(self, rg_name, sa_name):
        return self._props[sa_name]


def _client_with(props):
    """Build a storage client holding a single account 'acct1' with given props."""
    return _FakeStorageClient([_FakeAccount("acct1", "rg1")], {"acct1": props})


# A fully hardened baseline: Shared Key disabled, no public blob, network locked down.
def _hardened(**overrides):
    base = dict(
        allow_shared_key_access=False,
        allow_blob_public_access=False,
        public_network_access="Disabled",
    )
    base.update(overrides)
    return _FakeProps(**base)


class _FakeRule:
    """Stand-in for an Azure NSG security-rule object."""

    def __init__(
        self,
        name="rule1",
        direction="Inbound",
        protocol="Tcp",
        destination_port_range="22",
        source_address_prefix=None,
        source_address_prefixes=None,
    ):
        self.name = name
        self.direction = direction
        self.protocol = protocol
        self.destination_port_range = destination_port_range
        self.source_address_prefix = source_address_prefix
        self.source_address_prefixes = source_address_prefixes


class _FakeNSG:
    def __init__(self, rules, name="nsg1", rg="rg1"):
        self.name = name
        self.id = (
            f"/subscriptions/sub/resourceGroups/{rg}"
            f"/providers/Microsoft.Network/networkSecurityGroups/{name}"
        )
        self.security_rules = rules


class TestNSGRulesCheck(unittest.TestCase):
    def test_flags_ipv4_world_open(self):
        nsgs = [_FakeNSG([_FakeRule(source_address_prefix="0.0.0.0/0")])]
        issues = check_nsg_rules(nsgs)
        self.assertTrue(any("nsg1" in i and "open inbound rule" in i for i in issues))

    def test_flags_any_star(self):
        nsgs = [_FakeNSG([_FakeRule(source_address_prefix="*")])]
        self.assertTrue(any("open inbound rule" in i for i in check_nsg_rules(nsgs)))

    def test_flags_ipv6_world_open(self):
        # ::/0 was previously missed -- the singular field only matched IPv4-any.
        nsgs = [_FakeNSG([_FakeRule(source_address_prefix="::/0")])]
        self.assertTrue(any("open inbound rule" in i for i in check_nsg_rules(nsgs)))

    def test_flags_internet_service_tag(self):
        nsgs = [_FakeNSG([_FakeRule(source_address_prefix="Internet")])]
        self.assertTrue(any("open inbound rule" in i for i in check_nsg_rules(nsgs)))

    def test_flags_world_open_in_plural_prefixes(self):
        # World-open expressed via the plural list -- previously unread entirely.
        nsgs = [
            _FakeNSG(
                [_FakeRule(source_address_prefix=None, source_address_prefixes=["10.0.0.0/8", "::/0"])]
            )
        ]
        self.assertTrue(any("open inbound rule" in i for i in check_nsg_rules(nsgs)))

    def test_outbound_rule_is_ignored(self):
        nsgs = [_FakeNSG([_FakeRule(direction="Outbound", source_address_prefix="*")])]
        self.assertEqual(check_nsg_rules(nsgs), [CLEAN_NSG])

    def test_scoped_source_is_clean(self):
        nsgs = [
            _FakeNSG(
                [_FakeRule(source_address_prefix="10.0.0.0/8", source_address_prefixes=["192.168.0.0/16"])]
            )
        ]
        self.assertEqual(check_nsg_rules(nsgs), [CLEAN_NSG])

    def test_no_nsgs_is_clean(self):
        self.assertEqual(check_nsg_rules([]), [CLEAN_NSG])

    def test_high_risk_port_is_high_severity(self):
        nsgs = [_FakeNSG([_FakeRule(source_address_prefix="*", destination_port_range="3389")])]
        issues = check_nsg_rules(nsgs)
        self.assertTrue(any(i.startswith("[HIGH]") and "3389" in i for i in issues))

    def test_web_port_is_low_severity(self):
        nsgs = [_FakeNSG([_FakeRule(source_address_prefix="*", destination_port_range="443")])]
        self.assertTrue(any(i.startswith("[LOW]") for i in check_nsg_rules(nsgs)))

    def test_other_port_is_medium_severity(self):
        nsgs = [_FakeNSG([_FakeRule(source_address_prefix="*", destination_port_range="8080")])]
        self.assertTrue(any(i.startswith("[MEDIUM]") for i in check_nsg_rules(nsgs)))

    def test_star_port_is_high_severity(self):
        nsgs = [_FakeNSG([_FakeRule(source_address_prefix="*", destination_port_range="*")])]
        self.assertTrue(any(i.startswith("[HIGH]") for i in check_nsg_rules(nsgs)))

    def test_plural_dest_ports_picks_high_severity(self):
        nsgs = [
            _FakeNSG(
                [
                    _FakeRule(
                        source_address_prefix="*",
                        destination_port_range=None,
                        # 443 alone would be LOW, but 22 in the list makes it HIGH.
                    )
                ]
            )
        ]
        nsgs[0].security_rules[0].destination_port_ranges = ["443", "22"]
        issues = check_nsg_rules(nsgs)
        self.assertTrue(any(i.startswith("[HIGH]") and "443, 22" in i for i in issues))


class TestStorageAccountsCheck(unittest.TestCase):
    def test_flags_shared_key_null_default(self):
        client = _client_with(_hardened(allow_shared_key_access=None))
        issues = check_storage_accounts(client)
        self.assertTrue(any("acct1" in i and "Shared Key" in i for i in issues))

    def test_flags_shared_key_explicit_true(self):
        client = _client_with(_hardened(allow_shared_key_access=True))
        issues = check_storage_accounts(client)
        self.assertTrue(any("Shared Key" in i for i in issues))

    def test_flags_public_blob_access(self):
        client = _client_with(_hardened(allow_blob_public_access=True))
        issues = check_storage_accounts(client)
        self.assertTrue(any("public blob access" in i for i in issues))

    def test_flags_open_public_network(self):
        client = _client_with(
            _hardened(public_network_access="Enabled", network_default_action="Allow")
        )
        issues = check_storage_accounts(client)
        self.assertTrue(any("reachable from" in i for i in issues))

    def test_network_deny_is_not_flagged(self):
        client = _client_with(
            _hardened(public_network_access="Enabled", network_default_action="Deny")
        )
        self.assertEqual(check_storage_accounts(client), [CLEAN_STORAGE])

    def test_fully_hardened_account_is_clean(self):
        self.assertEqual(check_storage_accounts(_client_with(_hardened())), [CLEAN_STORAGE])

    def test_multiple_issues_reported_together(self):
        client = _client_with(
            _FakeProps(
                allow_shared_key_access=None,
                allow_blob_public_access=True,
                public_network_access="Enabled",
                network_default_action="Allow",
            )
        )
        issues = check_storage_accounts(client)
        self.assertEqual(len(issues), 3)

    def test_no_accounts_is_clean(self):
        client = _FakeStorageClient([], {})
        self.assertEqual(check_storage_accounts(client), [CLEAN_STORAGE])


if __name__ == "__main__":
    unittest.main()
