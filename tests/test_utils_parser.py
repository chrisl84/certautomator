from certautomator.crypto_cmds import CryptoCommands
from certautomator.user import CA, User
from certautomator.utils import FileHandler
from certautomator.utils_parser import Utils_Parser, CAParser, UserParser
import unittest
from unittest.mock import MagicMock
import os
import sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


# class Test_CAParser(unittest.TestCase):
#    pass

class Test_UserParser(unittest.TestCase):
    def test_parse_data(self):
        data = {
            "common_name": 'test',
            "key_name": 'test_key.key',
            "cert_name": 'certificate_test.crt',
            "cert_request_name": 'test_cert_request_name.csr',
            "country": 'some country',
            "locality": "some city",
            "state": 'some state',
            "organization_name": 'company name',
            "organizational_unit_name": 'department name',
            "email": 'test@email.com',
            "password": 'password',
        }
        parser = UserParser()
        parsed = parser.parse(data)
        data['password_file'] = None
        self.assertEqual(data, parsed)

    def test_parse_extra_data(self):
        data = {
            "common_name": 'test',
            "key_name": 'test_key.key',
            "cert_name": 'certificate_test.crt',
            "cert_request_name": 'test_cert_request_name.csr',
            "country": 'some country',
            "locality": "some city",
            "state": 'some state',
            "organization_name": 'company name',
            "organizational_unit_name": 'department name',
            "email": 'test@email.com',
            "sample_data": "data",
            "Unknown_option": "some unknown option",
            "password_file": './password.txt',
        }
        expected = {
            "common_name": 'test',
            "key_name": 'test_key.key',
            "cert_name": 'certificate_test.crt',
            "cert_request_name": 'test_cert_request_name.csr',
            "country": 'some country',
            "locality": "some city",
            "state": 'some state',
            "organization_name": 'company name',
            "organizational_unit_name": 'department name',
            "email": 'test@email.com',
            "password": None,
            "password_file": "./password.txt"
        }
        parser = UserParser()
        parsed = parser.parse(data)
        self.assertEqual(expected, parsed)

    def test_parse_no_data(self):
        data = {}
        utilsParser = Utils_Parser()
        result = utilsParser.parse(data)
        self.assertEqual({}, result)
        data = []
        result = utilsParser.parse(data)
        self.assertEqual({}, result)
        data = None
        result = utilsParser.parse(data)
        self.assertEqual({}, result)
        data = "[]"
        result = utilsParser.parse(data)
        self.assertEqual({}, result)
        data = True
        result = utilsParser.parse(data)
        self.assertEqual({}, result)

    def test_parse_custom_ssldefaults(self):
        file_handler = FileHandler()
        file_handler.create_directory = MagicMock(return_value=True)
        data = {
            "mygroup": {
                "ssl_defaults": {
                    "bits": 2048,
                    "days": 3650,
                    "protected": False,
                    "message_digest": "sha512",
                    "user_dir": "/some/random/directory/test_dir",
                    "ca_dir": "/some/random/directory/test_dir/ca"
                },
                "name_defaults": {
                    "country": "US",
                    "state": "State",
                    "locality": "City",
                    "organization_name": "Company",
                    "organizational_unit_name": "IT Dept",
                    "email": "test@test.com"
                },
                "ca": {
                    "test_ca": {
                        "common_name": "test_ca",
                        "key_name": "test_ca.key",
                        "cert_name": "test_ca.crt",
                        "message_digest": "sha256",
                        "cert_request_name": "test_ca.csr",
                        "ca_dir": "/some/random/directory/custom/ca",
                    }
                },
                "users": {
                    "user1": {
                        "common_name": "test_server2",
                        "bits": 1,
                        "protected": True,
                        "user_dir": "/some/random/directory/another/directory/test_dir",
                        "key_name": "test_server2.key",
                        "cert_name": "test_server2.crt",
                        "cert_request_name": "test_server2.csr"
                    },
                    "user": {
                        "common_name": "test_server",
                        "days": 250,
                        "key_name": "test_server.key",
                        "cert_name": "test_server.crt",
                        "cert_request_name": "test_server.csr"
                    }
                }
            },
            "second_group": {
                "ssl_defaults": {
                    "bits": 8192,
                    "days": 12,
                    "protected": False,
                    "message_digest": "sha512",
                    "user_dir": "/some/random/directory/test_dir",
                    "ca_dir": "/some/random/directory/test_dir/ca2"
                },
                "name_defaults": {
                    "country": "US",
                    "state": "State",
                    "locality": "City",
                    "organization_name": "Company",
                    "organizational_unit_name": "IT Dept",
                    "email": "test@test.com"
                },
                "ca": {
                    "test_ca": {
                        "common_name": "test_ca_2",
                        "key_name": "test_ca_2.key",
                        "cert_name": "test_ca_2.crt",
                        "cert_request_name": "test_ca_2.csr"
                    }
                }
            }
        }
        expected = {
            "mygroup": {
                "ca": {
                    "test_ca": CA(name="test_ca",
                                  bits=2048,
                                  protected=False,
                                  message_digest="sha256",
                                  certificate_expiration=3650,
                                  country="US",
                                  state="State",
                                  locality="City",
                                  organization_name="Company",
                                  organizational_unit_name="IT Dept",
                                  common_name="test_ca",
                                  email="test@test.com",
                                  ca_dir="/some/random/directory/custom/ca",
                                  key_name="test_ca_2.key",
                                  cert_name="test_ca_2.crt",
                                  request_name="test_ca_2.csr"),
                },
                "users": {
                    "user1": User(name="user1",
                                  bits=1,
                                  protected=True,
                                  message_digest="sha512",
                                  certificate_expiration=3650,
                                  country="US",
                                  state="State",
                                  locality="City",
                                  organization_name="Company",
                                  organizational_unit_name="IT Dept",
                                  common_name="test_server2",
                                  email="test@test.com",
                                  dir="/some/random/directory/another/directory/test_dir",
                                  key_name="test_server2.key",
                                  cert_name="test_server2.crt",
                                  request_name="test_server2.csr"),
                    "user": User(name="user",
                                 bits=2048,
                                 protected=False,
                                 message_digest="sha512",
                                 certificate_expiration=250,
                                 country="US",
                                 state="State",
                                 locality="City",
                                 organization_name="Company",
                                 organizational_unit_name="IT Dept",
                                 common_name="test_server",
                                 email="test@test.com",
                                 dir="/some/random/directory/test_dir",
                                 key_name="test_server.key",
                                 cert_name="test_server.crt",
                                 request_name="test_server.csr"),
                }
            },
            "second_group": {
                "ca": {
                    "test_ca": CA(name="test_ca",
                                  bits=8192,
                                  protected=False,
                                  message_digest="sha512",
                                  certificate_expiration=12,
                                  country="US",
                                  state="State",
                                  locality="City",
                                  organization_name="Company",
                                  organizational_unit_name="IT Dept",
                                  common_name="test_ca_2",
                                  email="test@test.com",
                                  ca_dir="/some/random/directory/test_dir/ca2",
                                  key_name="test_ca_2.key",
                                  cert_name="test_ca_2.crt",
                                  request_name="test_ca_2.csr"),
                },
                "users": {

                }
            }
        }
        utilsParser = Utils_Parser(filehandler=file_handler)
        result = utilsParser.parse(data)
        first_group = result.get("mygroup")
        self.assertIsNotNone(first_group)
        result_cas = first_group.get('ca')
        self.assertIsNotNone(result_cas)
        expected_ca = expected["mygroup"]["ca"]['test_ca']
        result_ca = result_cas.get('test_ca')
        self.assertIsNotNone(result_ca)
        self.assertEqual(expected_ca.name, result_ca.name)
        self.assertEqual(expected_ca.bits, result_ca.bits)
        self.assertEqual(expected_ca.message_digest, result_ca.message_digest)
        self.assertEqual(expected_ca.certificate_expiration,
                         result_ca.certificate_expiration)
        self.assertEqual(expected_ca.country, result_ca.country)
        self.assertEqual(expected_ca.state, result_ca.state)
        self.assertEqual(expected_ca.locality, result_ca.locality)
        self.assertEqual(expected_ca.organization_name,
                         result_ca.organization_name)
        self.assertEqual(expected_ca.organizational_unit_name,
                         result_ca.organizational_unit_name)
        self.assertEqual(expected_ca.common_name, result_ca.common_name)
        self.assertEqual(expected_ca.email, result_ca.email)
        self.assertEqual(expected_ca.ca_dir, result_ca.ca_dir)
        self.assertEqual(expected_ca.format_distinguished_names(),
                         result_ca.format_distinguished_names())
        second_group = result.get("second_group")
        self.assertIsNotNone(second_group)
        result_cas = second_group.get('ca')
        self.assertIsNotNone(result_cas)
        expected_ca = expected["second_group"]["ca"]['test_ca']
        result_ca = result_cas.get('test_ca')
        self.assertIsNotNone(result_ca)
        self.assertEqual(expected_ca.name, result_ca.name)
        self.assertEqual(expected_ca.bits, result_ca.bits)
        self.assertEqual(expected_ca.message_digest, result_ca.message_digest)
        self.assertEqual(expected_ca.certificate_expiration,
                         result_ca.certificate_expiration)
        self.assertEqual(expected_ca.country, result_ca.country)
        self.assertEqual(expected_ca.state, result_ca.state)
        self.assertEqual(expected_ca.locality, result_ca.locality)
        self.assertEqual(expected_ca.organization_name,
                         result_ca.organization_name)
        self.assertEqual(expected_ca.organizational_unit_name,
                         result_ca.organizational_unit_name)
        self.assertEqual(expected_ca.common_name, result_ca.common_name)
        self.assertEqual(expected_ca.email, result_ca.email)
        self.assertEqual(expected_ca.ca_dir, result_ca.ca_dir)
        self.assertEqual(expected_ca.format_distinguished_names(),
                         result_ca.format_distinguished_names())
        result_users = first_group.get('users')
        self.assertIsNotNone(result_users)
        user = result_users.get('user1')
        self.assertIsNotNone(user)
        expected_user = expected["mygroup"]["users"]['user1']

        self.assertEqual(expected_user.name, user.name)
        self.assertEqual(expected_user.bits, user.bits)
        self.assertEqual(expected_user.message_digest, user.message_digest)
        self.assertEqual(expected_user.certificate_expiration,
                         user.certificate_expiration)
        self.assertEqual(expected_user.country, user.country)
        self.assertEqual(expected_user.state, user.state)
        self.assertEqual(expected_user.locality, user.locality)
        self.assertEqual(expected_user.organization_name,
                         user.organization_name)
        self.assertEqual(expected_user.organizational_unit_name,
                         user.organizational_unit_name)
        self.assertEqual(expected_user.common_name, user.common_name)
        self.assertEqual(expected_user.email, user.email)
        self.assertEqual(expected_user.dir, user.dir)
        self.assertEqual(expected_user.format_distinguished_names(),
                         user.format_distinguished_names())
        user = result_users.get('user')
        self.assertIsNotNone(user)
        expected_user = expected["mygroup"]["users"]['user']

        self.assertEqual(expected_user.name, user.name)
        self.assertEqual(expected_user.bits, user.bits)
        self.assertEqual(expected_user.message_digest, user.message_digest)
        self.assertEqual(expected_user.certificate_expiration,
                         user.certificate_expiration)
        self.assertEqual(expected_user.country, user.country)
        self.assertEqual(expected_user.state, user.state)
        self.assertEqual(expected_user.locality, user.locality)
        self.assertEqual(expected_user.organization_name,
                         user.organization_name)
        self.assertEqual(expected_user.organizational_unit_name,
                         user.organizational_unit_name)
        self.assertEqual(expected_user.common_name, user.common_name)
        self.assertEqual(expected_user.email, user.email)
        self.assertEqual(expected_user.dir, user.dir)
        self.assertEqual(expected_user.format_distinguished_names(),
                         user.format_distinguished_names())

    def test_parse_custom_state(self):
        file_handler = FileHandler()
        file_handler.create_directory = MagicMock(return_value=True)
        data = {
            "mygroup": {
                "ssl_defaults": {
                    "bits": 2048,
                    "days": 3650,
                    "protected": False,
                    "message_digest": "sha512",
                    "user_dir": "/some/random/directory/test_dir",
                    "ca_dir": "/some/random/directory/test_dir/ca"
                },
                "name_defaults": {
                    "country": "US",
                    "state": "State",
                    "locality": "City",
                    "organization_name": "Company",
                    "organizational_unit_name": "IT Dept",
                    "email": "test@test.com"
                },
                "ca": {
                    "test_ca": {
                        "common_name": "test_ca",
                        "key_name": "test_ca.key",
                        "cert_name": "test_ca.crt",
                        "organization_name": "My Company",
                        "cert_request_name": "test_ca.csr"
                    }
                },
                "users": {
                    "user1": {
                        "common_name": "test_server2",
                        "key_name": "test_server2.key",
                        "cert_name": "test_server2.crt",
                        "locality": "user1City",
                        "cert_request_name": "test_server2.csr"
                    },
                    "user": {
                        "common_name": "test_server",
                        "key_name": "test_server.key",
                        "cert_name": "test_server.crt",
                        "email": "user@test.com",
                        "cert_request_name": "test_server.csr"
                    }
                }
            },
            "second_group": {
                "ssl_defaults": {
                    "bits": 8192,
                    "days": 12,
                    "protected": False,
                    "message_digest": "sha512",
                    "user_dir": "/some/random/directory/test_dir",
                    "ca_dir": "/some/random/directory/test_dir/ca2"
                },
                "name_defaults": {
                    "country": "US",
                    "state": "State",
                    "locality": "City",
                    "organization_name": "Company",
                    "organizational_unit_name": "IT Dept",
                    "email": "test@test.com"
                },
                "ca": {
                    "test_ca": {
                        "common_name": "test_ca_2",
                        "key_name": "test_ca_2.key",
                        "country": "UK",
                        "cert_name": "test_ca_2.crt",
                        "cert_request_name": "test_ca_2.csr"
                    }
                }
            }
        }
        expected = {
            "mygroup": {
                "ca": {
                    "test_ca": CA(name="test_ca",
                                  bits=2048,
                                  protected=False,
                                  message_digest="sha512",
                                  certificate_expiration=3650,
                                  country="US",
                                  state="State",
                                  locality="City",
                                  organization_name="My Company",
                                  organizational_unit_name="IT Dept",
                                  common_name="test_ca",
                                  email="test@test.com",
                                  ca_dir="/some/random/directory/test_dir/ca",
                                  key_name="test_ca.key",
                                  cert_name="test_ca.crt",
                                  request_name="test_ca.csr"),
                },
                "users": {
                    "user1": User(name="user1",
                                  bits=2048,
                                  protected=False,
                                  message_digest="sha512",
                                  certificate_expiration=3650,
                                  country="US",
                                  state="State",
                                  locality="user1City",
                                  organization_name="Company",
                                  organizational_unit_name="IT Dept",
                                  common_name="test_server2",
                                  email="test@test.com",
                                  dir="/some/random/directory/test_dir",
                                  key_name="test_server2.key",
                                  cert_name="test_server2.crt",
                                  request_name="test_server2.csr"),
                    "user": User(name="user",
                                 bits=2048,
                                 protected=False,
                                 message_digest="sha512",
                                 certificate_expiration=3650,
                                 country="US",
                                 state="State",
                                 locality="City",
                                 organization_name="Company",
                                 organizational_unit_name="IT Dept",
                                 common_name="test_server",
                                 email="user@test.com",
                                 dir="/some/random/directory/test_dir",
                                 key_name="test_server.key",
                                 cert_name="test_server.crt",
                                 request_name="test_server.csr"),
                }
            },
            "second_group": {
                "ca": {
                    "test_ca": CA(name="test_ca",
                                  bits=8192,
                                  protected=False,
                                  message_digest="sha512",
                                  certificate_expiration=12,
                                  country="UK",
                                  state="State",
                                  locality="City",
                                  organization_name="Company",
                                  organizational_unit_name="IT Dept",
                                  common_name="test_ca_2",
                                  email="test@test.com",
                                  ca_dir="/some/random/directory/test_dir/ca2",
                                  key_name="test_ca_2.key",
                                  cert_name="test_ca_2.crt",
                                  request_name="test_ca_2.csr"),
                },
                "users": {

                }
            }
        }
        utilsParser = Utils_Parser(filehandler=file_handler)
        result = utilsParser.parse(data)
        first_group = result.get("mygroup")
        self.assertIsNotNone(first_group)
        result_cas = first_group.get('ca')
        self.assertIsNotNone(result_cas)
        expected_ca = expected["mygroup"]["ca"]['test_ca']
        result_ca = result_cas.get('test_ca')
        self.assertIsNotNone(result_ca)
        self.assertEqual(expected_ca.name, result_ca.name)
        self.assertEqual(expected_ca.bits, result_ca.bits)
        self.assertEqual(expected_ca.message_digest, result_ca.message_digest)
        self.assertEqual(expected_ca.certificate_expiration,
                         result_ca.certificate_expiration)
        self.assertEqual(expected_ca.country, result_ca.country)
        self.assertEqual(expected_ca.state, result_ca.state)
        self.assertEqual(expected_ca.locality, result_ca.locality)
        self.assertEqual(expected_ca.organization_name,
                         result_ca.organization_name)
        self.assertEqual(expected_ca.organizational_unit_name,
                         result_ca.organizational_unit_name)
        self.assertEqual(expected_ca.common_name, result_ca.common_name)
        self.assertEqual(expected_ca.email, result_ca.email)
        self.assertEqual(expected_ca.ca_dir, result_ca.ca_dir)
        self.assertEqual(expected_ca.format_distinguished_names(),
                         result_ca.format_distinguished_names())
        second_group = result.get("second_group")
        self.assertIsNotNone(second_group)
        result_cas = second_group.get('ca')
        self.assertIsNotNone(result_cas)
        expected_ca = expected["second_group"]["ca"]['test_ca']
        result_ca = result_cas.get('test_ca')
        self.assertIsNotNone(result_ca)
        self.assertEqual(expected_ca.name, result_ca.name)
        self.assertEqual(expected_ca.bits, result_ca.bits)
        self.assertEqual(expected_ca.message_digest, result_ca.message_digest)
        self.assertEqual(expected_ca.certificate_expiration,
                         result_ca.certificate_expiration)
        self.assertEqual(expected_ca.country, result_ca.country)
        self.assertEqual(expected_ca.state, result_ca.state)
        self.assertEqual(expected_ca.locality, result_ca.locality)
        self.assertEqual(expected_ca.organization_name,
                         result_ca.organization_name)
        self.assertEqual(expected_ca.organizational_unit_name,
                         result_ca.organizational_unit_name)
        self.assertEqual(expected_ca.common_name, result_ca.common_name)
        self.assertEqual(expected_ca.email, result_ca.email)
        self.assertEqual(expected_ca.ca_dir, result_ca.ca_dir)
        self.assertEqual(expected_ca.format_distinguished_names(),
                         result_ca.format_distinguished_names())
        result_users = first_group.get('users')
        self.assertIsNotNone(result_users)
        user = result_users.get('user1')
        self.assertIsNotNone(user)
        expected_user = expected["mygroup"]["users"]['user1']

        self.assertEqual(expected_user.name, user.name)
        self.assertEqual(expected_user.bits, user.bits)
        self.assertEqual(expected_user.message_digest, user.message_digest)
        self.assertEqual(expected_user.certificate_expiration,
                         user.certificate_expiration)
        self.assertEqual(expected_user.country, user.country)
        self.assertEqual(expected_user.state, user.state)
        self.assertEqual(expected_user.locality, user.locality)
        self.assertEqual(expected_user.organization_name,
                         user.organization_name)
        self.assertEqual(expected_user.organizational_unit_name,
                         user.organizational_unit_name)
        self.assertEqual(expected_user.common_name, user.common_name)
        self.assertEqual(expected_user.email, user.email)
        self.assertEqual(expected_user.dir, user.dir)
        self.assertEqual(expected_user.format_distinguished_names(),
                         user.format_distinguished_names())
        user = result_users.get('user')
        self.assertIsNotNone(user)
        expected_user = expected["mygroup"]["users"]['user']

        self.assertEqual(expected_user.name, user.name)
        self.assertEqual(expected_user.bits, user.bits)
        self.assertEqual(expected_user.message_digest, user.message_digest)
        self.assertEqual(expected_user.certificate_expiration,
                         user.certificate_expiration)
        self.assertEqual(expected_user.country, user.country)
        self.assertEqual(expected_user.state, user.state)
        self.assertEqual(expected_user.locality, user.locality)
        self.assertEqual(expected_user.organization_name,
                         user.organization_name)
        self.assertEqual(expected_user.organizational_unit_name,
                         user.organizational_unit_name)
        self.assertEqual(expected_user.common_name, user.common_name)
        self.assertEqual(expected_user.email, user.email)
        self.assertEqual(expected_user.dir, user.dir)
        self.assertEqual(expected_user.format_distinguished_names(),
                         user.format_distinguished_names())
        data = {
            "mygroup": {
                "ssl_defaults": {
                    "bits": 2048,
                    "days": 3650,
                    "protected": False,
                    "message_digest": "sha512",
                    "user_dir": "/some/random/directory/test_dir",
                    "ca_dir": "/some/random/directory/test_dir/ca"
                },
                "name_defaults": {
                    "country": "US",
                    "state": "State",
                    "locality": "City",
                    "organization_name": "Company",
                    "organizational_unit_name": "IT Dept",
                    "email": "test@test.com"
                },
                "ca": {
                    "test_ca": {
                        "common_name": "test_ca",
                        "key_name": "test_ca.key",
                        "cert_name": "test_ca.crt",
                        "state": "New State",
                        "cert_request_name": "test_ca.csr"
                    }
                },
                "users": {
                    "user1": {
                        "common_name": "test_server2",
                        "key_name": "test_server2.key",
                        "cert_name": "test_server2.crt",
                        "organizational_unit_name": "HR Dept",
                        "cert_request_name": "test_server2.csr"
                    },
                    "user": {
                        "common_name": "test_server",
                        "key_name": "test_server.key",
                        "cert_name": "test_server.crt",
                        "cert_request_name": "test_server.csr"
                    }
                }
            },
            "second_group": {
                "ssl_defaults": {
                    "bits": 8192,
                    "days": 12,
                    "protected": False,
                    "message_digest": "sha512",
                    "user_dir": "/some/random/directory/test_dir",
                    "ca_dir": "/some/random/directory/test_dir/ca2"
                },
                "name_defaults": {
                    "country": "US",
                    "state": "State",
                    "locality": "City",
                    "organization_name": "Company",
                    "organizational_unit_name": "IT Dept",
                    "email": "test@test.com"
                },
                "ca": {
                    "test_ca": {
                        "common_name": "test_ca_2",
                        "key_name": "test_ca_2.key",
                        "cert_name": "test_ca_2.crt",
                        "cert_request_name": "test_ca_2.csr"
                    }
                }
            }
        }
        expected = {
            "mygroup": {
                "ca": {
                    "test_ca": CA(name="test_ca",
                                  bits=2048,
                                  protected=False,
                                  message_digest="sha512",
                                  certificate_expiration=3650,
                                  country="US",
                                  state="New State",
                                  locality="City",
                                  organization_name="Company",
                                  organizational_unit_name="IT Dept",
                                  common_name="test_ca",
                                  email="test@test.com",
                                  ca_dir="/some/random/directory/test_dir/ca",
                                  key_name="test_ca.key",
                                  cert_name="test_ca.crt",
                                  request_name="test_ca.csr"),
                },
                "users": {
                    "user1": User(name="user1",
                                  bits=2048,
                                  protected=False,
                                  message_digest="sha512",
                                  certificate_expiration=3650,
                                  country="US",
                                  state="State",
                                  locality="City",
                                  organization_name="Company",
                                  organizational_unit_name="HR Dept",
                                  common_name="test_server2",
                                  email="test@test.com",
                                  dir="/some/random/directory/test_dir",
                                  key_name="test_server2.key",
                                  cert_name="test_server2.crt",
                                  request_name="test_server2.csr"),
                    "user": User(name="user",
                                 bits=2048,
                                 protected=False,
                                 message_digest="sha512",
                                 certificate_expiration=3650,
                                 country="US",
                                 state="State",
                                 locality="City",
                                 organization_name="Company",
                                 organizational_unit_name="IT Dept",
                                 common_name="test_server",
                                 email="test@test.com",
                                 dir="/some/random/directory/test_dir",
                                  key_name="test_server.key",
                                  cert_name="test_server.crt",
                                  request_name="test_server.csr"),
                }
            },
            "second_group": {
                "ca": {
                    "test_ca": CA(name="test_ca",
                                  bits=8192,
                                  protected=False,
                                  message_digest="sha512",
                                  certificate_expiration=12,
                                  country="US",
                                  state="State",
                                  locality="City",
                                  organization_name="Company",
                                  organizational_unit_name="IT Dept",
                                  common_name="test_ca_2",
                                  email="test@test.com",
                                  ca_dir="/some/random/directory/test_dir/ca2",
                                  key_name="test_ca_2.key",
                                  cert_name="test_ca_2.crt",
                                  request_name="test_ca_2.csr"),
                },
                "users": {

                }
            }
        }
        utilsParser = Utils_Parser(filehandler=file_handler)
        result = utilsParser.parse(data)
        first_group = result.get("mygroup")
        self.assertIsNotNone(first_group)
        result_cas = first_group.get('ca')
        self.assertIsNotNone(result_cas)
        expected_ca = expected["mygroup"]["ca"]['test_ca']
        result_ca = result_cas.get('test_ca')
        self.assertIsNotNone(result_ca)
        self.assertEqual(expected_ca.name, result_ca.name)
        self.assertEqual(expected_ca.bits, result_ca.bits)
        self.assertEqual(expected_ca.message_digest, result_ca.message_digest)
        self.assertEqual(expected_ca.certificate_expiration,
                         result_ca.certificate_expiration)
        self.assertEqual(expected_ca.country, result_ca.country)
        self.assertEqual(expected_ca.state, result_ca.state)
        self.assertEqual(expected_ca.locality, result_ca.locality)
        self.assertEqual(expected_ca.organization_name,
                         result_ca.organization_name)
        self.assertEqual(expected_ca.organizational_unit_name,
                         result_ca.organizational_unit_name)
        self.assertEqual(expected_ca.common_name, result_ca.common_name)
        self.assertEqual(expected_ca.email, result_ca.email)
        self.assertEqual(expected_ca.ca_dir, result_ca.ca_dir)
        self.assertEqual(expected_ca.format_distinguished_names(),
                         result_ca.format_distinguished_names())
        second_group = result.get("second_group")
        self.assertIsNotNone(second_group)
        result_cas = second_group.get('ca')
        self.assertIsNotNone(result_cas)
        expected_ca = expected["second_group"]["ca"]['test_ca']
        result_ca = result_cas.get('test_ca')
        self.assertIsNotNone(result_ca)
        self.assertEqual(expected_ca.name, result_ca.name)
        self.assertEqual(expected_ca.bits, result_ca.bits)
        self.assertEqual(expected_ca.message_digest, result_ca.message_digest)
        self.assertEqual(expected_ca.certificate_expiration,
                         result_ca.certificate_expiration)
        self.assertEqual(expected_ca.country, result_ca.country)
        self.assertEqual(expected_ca.state, result_ca.state)
        self.assertEqual(expected_ca.locality, result_ca.locality)
        self.assertEqual(expected_ca.organization_name,
                         result_ca.organization_name)
        self.assertEqual(expected_ca.organizational_unit_name,
                         result_ca.organizational_unit_name)
        self.assertEqual(expected_ca.common_name, result_ca.common_name)
        self.assertEqual(expected_ca.email, result_ca.email)
        self.assertEqual(expected_ca.ca_dir, result_ca.ca_dir)
        self.assertEqual(expected_ca.format_distinguished_names(),
                         result_ca.format_distinguished_names())
        result_users = first_group.get('users')
        self.assertIsNotNone(result_users)
        user = result_users.get('user1')
        self.assertIsNotNone(user)
        expected_user = expected["mygroup"]["users"]['user1']

        self.assertEqual(expected_user.name, user.name)
        self.assertEqual(expected_user.bits, user.bits)
        self.assertEqual(expected_user.message_digest, user.message_digest)
        self.assertEqual(expected_user.certificate_expiration,
                         user.certificate_expiration)
        self.assertEqual(expected_user.country, user.country)
        self.assertEqual(expected_user.state, user.state)
        self.assertEqual(expected_user.locality, user.locality)
        self.assertEqual(expected_user.organization_name,
                         user.organization_name)
        self.assertEqual(expected_user.organizational_unit_name,
                         user.organizational_unit_name)
        self.assertEqual(expected_user.common_name, user.common_name)
        self.assertEqual(expected_user.email, user.email)
        self.assertEqual(expected_user.dir, user.dir)
        self.assertEqual(expected_user.format_distinguished_names(),
                         user.format_distinguished_names())
        user = result_users.get('user')
        self.assertIsNotNone(user)
        expected_user = expected["mygroup"]["users"]['user']

        self.assertEqual(expected_user.name, user.name)
        self.assertEqual(expected_user.bits, user.bits)
        self.assertEqual(expected_user.message_digest, user.message_digest)
        self.assertEqual(expected_user.certificate_expiration,
                         user.certificate_expiration)
        self.assertEqual(expected_user.country, user.country)
        self.assertEqual(expected_user.state, user.state)
        self.assertEqual(expected_user.locality, user.locality)
        self.assertEqual(expected_user.organization_name,
                         user.organization_name)
        self.assertEqual(expected_user.organizational_unit_name,
                         user.organizational_unit_name)
        self.assertEqual(expected_user.common_name, user.common_name)
        self.assertEqual(expected_user.email, user.email)
        self.assertEqual(expected_user.dir, user.dir)
        self.assertEqual(expected_user.format_distinguished_names(),
                         user.format_distinguished_names())

    def test_parse(self):
        file_handler = FileHandler()
        file_handler.create_directory = MagicMock(return_value=True)
        data = {
            "mygroup": {
                "ssl_defaults": {
                    "bits": 2048,
                    "days": 3650,
                    "protected": False,
                    "message_digest": "sha512",
                    "user_dir": "/some/random/directory/test_dir",
                    "ca_dir": "/some/random/directory/test_dir/ca"
                },
                "name_defaults": {
                    "country": "US",
                    "state": "State",
                    "locality": "City",
                    "organization_name": "Company",
                    "organizational_unit_name": "IT Dept",
                    "email": "test@test.com"
                },
                "ca": {
                    "test_ca": {
                        "common_name": "test_ca",
                        "key_name": "test_ca.key",
                        "cert_name": "test_ca.crt",
                        "cert_request_name": "test_ca.csr"
                    }
                },
                "users": {
                    "user1": {
                        "common_name": "test_server2",
                        "key_name": "test_server2.key",
                        "cert_name": "test_server2.crt",
                        "cert_request_name": "test_server2.csr"
                    },
                    "user": {
                        "common_name": "test_server",
                        "key_name": "test_server.key",
                        "cert_name": "test_server.crt",
                        "cert_request_name": "test_server.csr"
                    }
                }
            },
            "second_group": {
                "ssl_defaults": {
                    "bits": 8192,
                    "days": 12,
                    "protected": False,
                    "message_digest": "sha512",
                    "user_dir": "/some/random/directory/test_dir",
                    "ca_dir": "/some/random/directory/test_dir/ca2"
                },
                "name_defaults": {
                    "country": "US",
                    "state": "State",
                    "locality": "City",
                    "organization_name": "Company",
                    "organizational_unit_name": "IT Dept",
                    "email": "test@test.com"
                },
                "ca": {
                    "test_ca": {
                        "common_name": "test_ca_2",
                        "key_name": "test_ca_2.key",
                        "cert_name": "test_ca_2.crt",
                        "cert_request_name": "test_ca_2.csr"
                    }
                }
            }
        }
        expected = {
            "mygroup": {
                "ca": {
                    "test_ca": CA(name="test_ca",
                                  bits=2048,
                                  protected=False,
                                  message_digest="sha512",
                                  certificate_expiration=3650,
                                  country="US",
                                  state="State",
                                  locality="City",
                                  organization_name="Company",
                                  organizational_unit_name="IT Dept",
                                  common_name="test_ca",
                                  email="test@test.com",
                                  ca_dir="/some/random/directory/test_dir/ca",
                                  key_name="test_ca.key",
                                  cert_name="test_ca.crt",
                                  request_name="test_ca.csr"),
                },
                "users": {
                    "user1": User(name="user1",
                                  bits=2048,
                                  protected=False,
                                  message_digest="sha512",
                                  certificate_expiration=3650,
                                  country="US",
                                  state="State",
                                  locality="City",
                                  organization_name="Company",
                                  organizational_unit_name="IT Dept",
                                  common_name="test_server2",
                                  email="test@test.com",
                                  dir="/some/random/directory/test_dir",
                                  key_name="test_server2.key",
                                  cert_name="test_server2.crt",
                                  request_name="test_server2.csr"),
                    "user": User(name="user",
                                 bits=2048,
                                 protected=False,
                                 message_digest="sha512",
                                 certificate_expiration=3650,
                                 country="US",
                                 state="State",
                                 locality="City",
                                 organization_name="Company",
                                 organizational_unit_name="IT Dept",
                                 common_name="test_server",
                                 email="test@test.com",
                                 dir="/some/random/directory/test_dir",
                                  key_name="test_server.key",
                                  cert_name="test_server.crt",
                                  request_name="test_server.csr"),
                }
            },
            "second_group": {
                "ca": {
                    "test_ca": CA(name="test_ca",
                                  bits=8192,
                                  protected=False,
                                  message_digest="sha512",
                                  certificate_expiration=12,
                                  country="US",
                                  state="State",
                                  locality="City",
                                  organization_name="Company",
                                  organizational_unit_name="IT Dept",
                                  common_name="test_ca_2",
                                  email="test@test.com",
                                  ca_dir="/some/random/directory/test_dir/ca2",
                                  key_name="test_ca_2.key",
                                  cert_name="test_ca_2.crt",
                                  request_name="test_ca_2.csr"),
                },
                "users": {

                }
            }
        }
        utilsParser = Utils_Parser(filehandler=file_handler)
        result = utilsParser.parse(data)
        first_group = result.get("mygroup")
        self.assertIsNotNone(first_group)
        result_cas = first_group.get('ca')
        self.assertIsNotNone(result_cas)
        expected_ca = expected["mygroup"]["ca"]['test_ca']
        result_ca = result_cas.get('test_ca')
        self.assertIsNotNone(result_ca)
        self.assertEqual(expected_ca.name, result_ca.name)
        self.assertEqual(expected_ca.bits, result_ca.bits)
        self.assertEqual(expected_ca.message_digest, result_ca.message_digest)
        self.assertEqual(expected_ca.certificate_expiration,
                         result_ca.certificate_expiration)
        self.assertEqual(expected_ca.country, result_ca.country)
        self.assertEqual(expected_ca.state, result_ca.state)
        self.assertEqual(expected_ca.locality, result_ca.locality)
        self.assertEqual(expected_ca.organization_name,
                         result_ca.organization_name)
        self.assertEqual(expected_ca.organizational_unit_name,
                         result_ca.organizational_unit_name)
        self.assertEqual(expected_ca.common_name, result_ca.common_name)
        self.assertEqual(expected_ca.email, result_ca.email)
        self.assertEqual(expected_ca.ca_dir, result_ca.ca_dir)
        self.assertEqual(expected_ca.format_distinguished_names(),
                         result_ca.format_distinguished_names())
        second_group = result.get("second_group")
        self.assertIsNotNone(second_group)
        result_cas = second_group.get('ca')
        self.assertIsNotNone(result_cas)
        expected_ca = expected["second_group"]["ca"]['test_ca']
        result_ca = result_cas.get('test_ca')
        self.assertIsNotNone(result_ca)
        self.assertEqual(expected_ca.name, result_ca.name)
        self.assertEqual(expected_ca.bits, result_ca.bits)
        self.assertEqual(expected_ca.message_digest, result_ca.message_digest)
        self.assertEqual(expected_ca.certificate_expiration,
                         result_ca.certificate_expiration)
        self.assertEqual(expected_ca.country, result_ca.country)
        self.assertEqual(expected_ca.state, result_ca.state)
        self.assertEqual(expected_ca.locality, result_ca.locality)
        self.assertEqual(expected_ca.organization_name,
                         result_ca.organization_name)
        self.assertEqual(expected_ca.organizational_unit_name,
                         result_ca.organizational_unit_name)
        self.assertEqual(expected_ca.common_name, result_ca.common_name)
        self.assertEqual(expected_ca.email, result_ca.email)
        self.assertEqual(expected_ca.ca_dir, result_ca.ca_dir)
        self.assertEqual(expected_ca.format_distinguished_names(),
                         result_ca.format_distinguished_names())
        result_users = first_group.get('users')
        self.assertIsNotNone(result_users)
        user = result_users.get('user1')
        self.assertIsNotNone(user)
        expected_user = expected["mygroup"]["users"]['user1']

        self.assertEqual(expected_user.name, user.name)
        self.assertEqual(expected_user.bits, user.bits)
        self.assertEqual(expected_user.message_digest, user.message_digest)
        self.assertEqual(expected_user.certificate_expiration,
                         user.certificate_expiration)
        self.assertEqual(expected_user.country, user.country)
        self.assertEqual(expected_user.state, user.state)
        self.assertEqual(expected_user.locality, user.locality)
        self.assertEqual(expected_user.organization_name,
                         user.organization_name)
        self.assertEqual(expected_user.organizational_unit_name,
                         user.organizational_unit_name)
        self.assertEqual(expected_user.common_name, user.common_name)
        self.assertEqual(expected_user.email, user.email)
        self.assertEqual(expected_user.dir, user.dir)
        self.assertEqual(expected_user.format_distinguished_names(),
                         user.format_distinguished_names())
        user = result_users.get('user')
        self.assertIsNotNone(user)
        expected_user = expected["mygroup"]["users"]['user']

        self.assertEqual(expected_user.name, user.name)
        self.assertEqual(expected_user.bits, user.bits)
        self.assertEqual(expected_user.message_digest, user.message_digest)
        self.assertEqual(expected_user.certificate_expiration,
                         user.certificate_expiration)
        self.assertEqual(expected_user.country, user.country)
        self.assertEqual(expected_user.state, user.state)
        self.assertEqual(expected_user.locality, user.locality)
        self.assertEqual(expected_user.organization_name,
                         user.organization_name)
        self.assertEqual(expected_user.organizational_unit_name,
                         user.organizational_unit_name)
        self.assertEqual(expected_user.common_name, user.common_name)
        self.assertEqual(expected_user.email, user.email)
        self.assertEqual(expected_user.dir, user.dir)
        self.assertEqual(expected_user.format_distinguished_names(),
                         user.format_distinguished_names())
