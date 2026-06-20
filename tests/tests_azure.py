import unittest
from ramwingu.scanners import azure
from ramwingu.scanners.azure import check_storage_accounts

CLEAN_STORAGE = "No insecure storage account configurations found."


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
