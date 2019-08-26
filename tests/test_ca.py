from certautomator.user import CA
import unittest
import os
import sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


class Test_TestCA(unittest.TestCase):
    def test_valid_ca(self):
        ca = CA(
            "user1",
            4096,
            True,
            'sha512',
            90,
            'US',
            'State',
            'City',
            'Some Company',
            'Some unit in company',
            'user one',
            'user_one@_unknown_.com',
            'conf_dir',
            'ca_dir',
            'ca_1.key',
            'request_ca.csr',
            'cert_ca.crt',
            None,
            None
        )
        self.assertTrue(ca.is_valid())

    def test_invalid_conf_file(self):
        ca = CA(
            "user2",
            4096,
            True,
            'sha512',
            90,
            'US',
            'State',
            'Some City',
            'Some Company',
            'Some Department',
            'USER2',
            'user2@_unknown_.com',
            '   ',
            'ca_dir',
            'ca_user2.key',
            'request_ca_user2.csr',
            'cert_ca_user2.crt',
            None,
            None
        )
        self.assertIsNone(ca.config_file)
        ca = CA(
            "user3",
            4096,
            True,
            'sha512',
            90,
            'US',
            'Some State',
            'Some City',
            'Some Organization',
            'Some Organization Unit',
            'USER3',
            'user_3@_unknown_.com',
            True,
            'ca_dir',
            'ca_3.key',
            'request_ca_3.csr',
            'cert_ca_3.crt',
            None,
            None
        )
        self.assertIsNone(ca.config_file)
        ca = CA(
            "user4",
            4096,
            True,
            'sha512',
            90,
            'US',
            'Some Different state',
            'Some different city',
            'Some different company',
            'Some different department',
            'USER4',
            'user@_unknown_.com',
            1,
            'ca_dir',
            'ca_4.key',
            'request_ca_4.csr',
            'cert_ca_4.crt',
            None,
            None
        )
        self.assertIsNone(ca.config_file)
