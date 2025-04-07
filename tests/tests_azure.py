import unittest
from cloudmap.scanners import azure

class TestAzureScanner(unittest.TestCase):
    def test_scan_returns_findings(self):
        config = {"subscription_id": "dummy"}
        creds = {"tenant_id": "dummy", "client_id": "dummy", "client_secret": "dummy"}
        findings = azure.scan(config, creds)
        self.assertIsInstance(findings, dict)

if __name__ == '__main__':
    unittest.main()
