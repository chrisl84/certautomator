from certautomator.crypto_cmds import CryptoCommands
from certautomator.user import CA, User
from certautomator.utils import FileHandler
import unittest
from unittest.mock import MagicMock
import os
import sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


class Test_CryptoCommands(unittest.TestCase):

    def test_empty_user(self):
        cryptoCmds = CryptoCommands()
        self.assertFalse(cryptoCmds.generate_key(None))
        cryptoCmds = CryptoCommands()
        self.assertFalse(cryptoCmds.generate_csr(None))
        cryptoCmds = CryptoCommands()
        self.assertFalse(cryptoCmds.generate_ca_certificate(None))
        cryptoCmds = CryptoCommands()
        self.assertFalse(cryptoCmds.sign_certificate(None, True, CA(
            key_name='a.key',
            request_name='r.csr',
            cert_name='c.crt')))

    def test_empty_ca_when_signing(self):
        user = User(name='test', key_name='a.key',
                    request_name='r.csr',
                    cert_name='c.crt')
        cryptoCmds = CryptoCommands()
        self.assertFalse(cryptoCmds.sign_certificate(user, True, None))

    def test_do_not_overwrite(self):
        user = User(name='test',
                    key_name='a.key',
                    request_name='r.csr',
                    cert_name='c.crt')
        filehandler = FileHandler(logger=None)
        filehandler.file_exists = MagicMock(return_value=True)
        cryptoCmds = CryptoCommands(filehandler=filehandler)
        self.assertTrue(cryptoCmds.generate_key(user))
        cryptoCmds = CryptoCommands(filehandler=filehandler)
        self.assertTrue(cryptoCmds.generate_csr(user))
        cryptoCmds = CryptoCommands(filehandler=filehandler)
        self.assertTrue(cryptoCmds.generate_ca_certificate(user))
        cryptoCmds = CryptoCommands(filehandler=filehandler)
        self.assertTrue(cryptoCmds.sign_certificate(
            user, False, CA(name='test_ca',
                            key_name='a.key',
                            request_name='r.csr',
                            cert_name='c.crt')))

    def test_valid_generate_key(self):
        user = User(name='test', bits=1, dir='/test/dir', key_name='a.key',
                    request_name='r.csr',
                    cert_name='c.crt')
        filehandler = FileHandler(logger=None)
        filehandler.file_exists = MagicMock(return_value=False)
        cryptoCommands = CryptoCommands(logger=None,
                                        filehandler=filehandler)
        cryptoCommands._execute_command = MagicMock(return_value=True)
        self.assertTrue(cryptoCommands.generate_key(user))
        commands = cryptoCommands._execute_command.call_args
        self.assertEqual(commands[0][0][0], '/usr/bin/openssl')
        self.assertEqual(commands[0][0][1], 'genrsa')
        self.assertEqual(commands[0][0][2], '-out')
        self.assertEqual(commands[0][0][3], '/test/dir/keys/a.key')
        self.assertEqual(commands[0][0][4], '1')

    def test_valid_generate_csr(self):
        filehandler = FileHandler()

        def test_file_exists(*args, **kwargs):
            if args[0] == '/test/dir/keys/a.key':
                return True
            if args[0] == '/test/dir/ca/keys/a.key':
                return True
            return False
        filehandler.file_exists = MagicMock(side_effect=test_file_exists)
        cryptoCommands = CryptoCommands(filehandler=filehandler)
        cryptoCommands._execute_command = MagicMock(return_value=True)
        user = User(name='test',
                    bits=1,
                    dir='/test/dir',
                    country='US',
                    state='State',
                    locality='City',
                    organization_name='Company',
                    organizational_unit_name='Dept',
                    common_name='USER1',
                    email='user@_unknown_.com',
                    key_name='a.key',
                    request_name='r.csr',
                    cert_name='c.crt')
        self.assertTrue(cryptoCommands.generate_csr(user))
        commands = cryptoCommands._execute_command.call_args
        test = cryptoCommands._execute_command.call_args_list
        self.assertEqual(commands[0][0][0], '/usr/bin/openssl')
        self.assertEqual(commands[0][0][1], 'req')
        self.assertEqual(commands[0][0][2], '-new')
        self.assertEqual(commands[0][0][3], '-out')
        self.assertEqual(commands[0][0][4], '/test/dir/csrs/r.csr')
        self.assertEqual(commands[0][0][5], '-subj')
        self.assertEqual(commands[0][0][6],
                         '/C=US/ST=State/L=City/O=Company/OU=Dept/CN=USER1/emailAddress=user@_unknown_.com/')
        self.assertEqual(commands[0][0][7], '-key')
        self.assertEqual(commands[0][0][8], '/test/dir/keys/a.key')

    def test_valid_generate_ca_certificate(self):
        filehandler = FileHandler()

        def test_file_exists(*args, **kwargs):
            if args[0] == '/test/dir/ca/keys/a.key':
                return True
            return False
        filehandler.file_exists = MagicMock(side_effect=test_file_exists)
        cryptoCommands = CryptoCommands(filehandler=filehandler)
        cryptoCommands._execute_command = MagicMock(return_value=True)
        ca = CA(name='test_ca_generate',
                bits=5,
                ca_dir='/test/dir/ca',
                country='US',
                certificate_expiration=10000,
                state='State',
                locality='City',
                organization_name='Company',
                organizational_unit_name='Dept',
                common_name='CA1',
                email='ca@_unknown_.com',
                key_name='a.key',
                request_name='r.csr',
                cert_name='c.crt')
        self.assertTrue(cryptoCommands.generate_ca_certificate(ca))
        commands = cryptoCommands._execute_command.call_args
        test = cryptoCommands._execute_command.call_args_list
        self.assertEqual(commands[0][0][0], '/usr/bin/openssl')
        self.assertEqual(commands[0][0][1], 'req')
        self.assertEqual(commands[0][0][2], '-new')
        self.assertEqual(commands[0][0][3], '-x509')
        self.assertEqual(commands[0][0][4], '-key')
        self.assertEqual(commands[0][0][5],
                         '/test/dir/ca/keys/a.key')
        self.assertEqual(commands[0][0][6], '-subj')
        self.assertEqual(commands[0][0][7],
                         '/C=US/ST=State/L=City/O=Company/OU=Dept/CN=CA1/emailAddress=ca@_unknown_.com/')
        self.assertEqual(commands[0][0][8], '-days')
        self.assertEqual(commands[0][0][9], '10000')
        self.assertEqual(commands[0][0][10], '-out')
        self.assertEqual(commands[0][0][11],
                         '/test/dir/ca/crts/c.crt')

    def test_valid_sign_certificate(self):
        filehandler = FileHandler()

        def test_file_exists(*args, **kwargs):
            if (args[0] == '/test/dir/ca/keys/ca.key' or
                    args[0] == '/test/dir/keys/a.key' or
                    args[0] == '/test/dir/csrs/r.csr' or
                    args[0] == '/test/dir/ca/crts/ca.crt'):
                return True
            return False
        filehandler.file_exists = MagicMock(side_effect=test_file_exists)
        cryptoCommands = CryptoCommands(filehandler=filehandler)
        cryptoCommands._execute_command = MagicMock(return_value=True)
        user = User(name='test',
                    bits=1,
                    dir='/test/dir',
                    country='US',
                    state='State',
                    locality='City',
                    organization_name='Company',
                    organizational_unit_name='Dept',
                    certificate_expiration=1200,
                    common_name='USER1',
                    email='user@_unknown_.com',
                    key_name='a.key',
                    request_name='r.csr',
                    cert_name='c.crt')
        ca = CA(name='test_ca_generate',
                bits=5,
                ca_dir='/test/dir/ca',
                country='US',
                certificate_expiration=10000,
                state='State',
                locality='City',
                organization_name='Company',
                organizational_unit_name='Dept',
                common_name='CA1',
                email='ca@_unknown_.com',
                key_name='ca.key',
                request_name='r.csr',
                cert_name='ca.crt')
        self.assertTrue(cryptoCommands.sign_certificate(user, False, ca))
        commands = cryptoCommands._execute_command.call_args
        test = cryptoCommands._execute_command.call_args_list
        self.assertEqual(commands[0][0][0], '/usr/bin/openssl')
        self.assertEqual(commands[0][0][1], 'x509')
        self.assertEqual(commands[0][0][2], '-req')
        self.assertEqual(commands[0][0][3], '-CAcreateserial')
        self.assertEqual(commands[0][0][4], '-in')
        self.assertEqual(commands[0][0][5],
                         '/test/dir/csrs/r.csr')
        self.assertEqual(commands[0][0][6], '-CA')
        self.assertEqual(commands[0][0][7],
                         '/test/dir/ca/crts/ca.crt')
        self.assertEqual(commands[0][0][8], '-CAkey')
        self.assertEqual(commands[0][0][9],
                         '/test/dir/ca/keys/ca.key')
        self.assertEqual(commands[0][0][10], '-out')
        self.assertEqual(commands[0][0][11],
                         '/test/dir/crts/c.crt')
        self.assertEqual(commands[0][0][12], '-days')
        self.assertEqual(commands[0][0][13], '1200')


if __name__ == '__main__':
    unittest.main()
