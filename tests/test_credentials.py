import unittest
from cloudmap import credentials

class TestCredentials(unittest.TestCase):
    def test_get_credentials_invalid_platform(self):
        with self.assertRaises(ValueError):
            credentials.get_credentials("invalid_platform")

if __name__ == '__main__':
    unittest.main()
