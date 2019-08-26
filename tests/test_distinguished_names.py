from certautomator.distinguished_names import DistinguishedNames
import unittest
import os
import sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


class Test_TestDistinguishedNames(unittest.TestCase):
    def test_set_properties(self):
        names = DistinguishedNames(
            country="US",
            state="Some State",
            locality="Some City",
            organization_name="Some Company",
            organizational_unit_name="Company Department",
            common_name="Some_Common_Name",
            email="user@email.com"
        )
        self.assertEqual(names.country, "US")
        self.assertEqual(names.state, "Some State")
        self.assertEqual(names.locality, "Some City")
        self.assertEqual(names.organization_name, "Some Company")
        self.assertEqual(names.organizational_unit_name, "Company Department")
        self.assertEqual(names.common_name, "Some_Common_Name")
        self.assertEqual(names.email, "user@email.com")

    def test_formatting(self):
        names = DistinguishedNames(
            country="US",
            state="STATE",
            locality="CITY",
            organization_name="ORG",
            organizational_unit_name="DEPT_NAME",
            common_name="NAME",
            email="EMAIL"
        )
        expected = "/C=US/ST=STATE/L=CITY/O=ORG/OU=DEPT_NAME/CN=NAME/emailAddress=EMAIL/"
        self.assertEqual(names.format_distinguished_names(), expected)
        
    def test_empty_formatting(self):
        names = DistinguishedNames()
        expected = "//"
        self.assertEqual(names.format_distinguished_names(), expected)
