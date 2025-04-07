import unittest
from cloudmap.scanners import aws

class TestAWSScanner(unittest.TestCase):
    def test_scan_returns_findings(self):
        config = {"region": "us-east-1"}
        creds = {"aws_access_key_id": "dummy", "aws_secret_access_key": "dummy"}
        findings = aws.scan(config, creds)
        self.assertIsInstance(findings, dict)

if __name__ == '__main__':
    unittest.main()
