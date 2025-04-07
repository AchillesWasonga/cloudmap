import unittest
from cloudmap import utils

class TestUtils(unittest.TestCase):
    def test_format_output(self):
        findings = {"issues": ["test"]}
        output = utils.format_output(findings)
        self.assertIn("test", output)

if __name__ == '__main__':
    unittest.main()
