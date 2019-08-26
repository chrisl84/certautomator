from certautomator.user import User
import unittest
import os
import sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


class Test_TestUser(unittest.TestCase):
    def test_valid_user(self):
        user = User(
            "user1",
            4096,
            True,
            'sha512',
            90,
            'US',
            'State',
            'City',
            'Company',
            'Dept',
            'USER1',
            'user@_unknown_.com',
            './',
            'a.key',
            'r.csr',
            'c.crt'
        )
        self.assertTrue(user.is_valid())

    def test_wrong_types(self):
        user = User(
            "user1",
            "4096",
            True,
            'sha512',
            90,
            'US',
            'State',
            'City',
            'Company',
            'Dept',
            'USER1',
            'user@_unknown_.com',
            './',
            'a.key',
            'r.csr',
            'c.crt'
        )
        self.assertFalse(user.is_valid())
        user = User(
            "user1",
            4096,
            "True",
            'sha512',
            90,
            'US',
            'State',
            'City',
            'Company',
            'Dept',
            'USER1',
            'user@_unknown_.com',
            './',
            'a.key',
            'r.csr',
            'c.crt'
        )
        self.assertFalse(user.is_valid())
        user = User(
            "user1",
            4096,
            True,
            512,
            90,
            'US',
            'State',
            'City',
            'Company',
            'Dept',
            'USER1',
            'user@_unknown_.com',
            './',
            'a.key',
            'r.csr',
            'c.crt'
        )
        self.assertFalse(user.is_valid())
        user = User(
            "user1",
            4096,
            True,
            '512',
            True,
            'US',
            'State',
            'City',
            'Company',
            'Dept',
            'USER1',
            'user@_unknown_.com',
            './',
            'a.key',
            'r.csr',
            'c.crt'
        )
        self.assertFalse(user.is_valid())
