from certautomator.user import User
from certautomator.utils import FileHandler
import logging
import subprocess


class CryptoCommands:

    def __init__(self,
                 logger=logging.getLogger('certautomator.cryptocommands'),
                 openssl_location='/usr/bin/openssl',
                 filehandler=FileHandler()):
        """
        Args:
            logger (logging.Logger) : Handles logging features.
            openssl_location (str) : Location of the openssl binaries
            filehandler (certautomator.FileHandler) : object responsible for file operations,
                           file exists, etc.
        """

        self._logger = logger
        self._openssl_location = openssl_location
        self._fh = filehandler

    def generate(self, parameters, data):
        """
        Generates keys, requests and signed certificates based
        on the values in the parameters dictionary.

        Args:
            parameters (dictionary) : The parsed command line arguments
            data (dictionary) : Containing the groups of cas and users

        """
        ca = data.get('ca')
        users = data.get('users')
        selected_ca = None
        overwrite = parameters.get('overwrite')
        if ca is not None:
            for ca_key, ca_val in ca.items():
                selected_ca = ca_val
                if parameters.get('key') or parameters.get('all'):
                    self._logger.info(
                        "Generating key for Certificate Authority: %s.", ca_key)
                    self.generate_key(ca_val, overwrite)
                if parameters.get('req') or parameters.get('all'):
                    self._logger.info(
                        "Generating certificate request for Certificate Authority: %s.", ca_key)
                    self.generate_csr(ca_val, overwrite)
                if parameters.get('sign') or parameters.get('all'):
                    self._logger.info(
                        "Generating certificate for Certificate Authority: %s.", ca_key)
                    self.generate_ca_certificate(ca_val, overwrite)
        if users is not None:
            for user_key, user_val in users.items():
                if parameters.get('key') or parameters.get('all'):
                    self._logger.info("Generating key for user: %s.", user_key)
                    self.generate_key(user_val, overwrite)
                if parameters.get('req') or parameters.get('all'):
                    self._logger.info(
                        "Generating certificate request for user: %s.", user_key)
                    self.generate_csr(user_val, overwrite)
                if parameters.get('sign') or parameters.get('all'):
                    self._logger.info(
                        "Generating certificate user: %s.", user_key)
                    self.sign_certificate(
                        user_val, overwrite, selected_ca)

    def generate_key(self, user, overwrite=False):
        """
        Generates a key for the user. Returns True if the key
        was generated or if the overwrite parameter is set to False
        and a key already exists.

        Args:
            user (certautomator.User) : object containing the parameters
                    necessary for openssl to generate the key
            overwrite (bool) : True if any existing key should be overwritten,
                         False if it should not be overwritten.

        Returns:
            False if the user is None or
            there was an error generating the key.

        """
        if user is None:
            self._logger.warning("User is empty.")
            return False
        if self._fh.file_exists(user.key_file) and overwrite is False:
            self._logger.warning(
                "Key already exists for %s at location %s, will not overwrite.",
                user.name,
                user.key_file)
            return True
        command = [self._openssl_location, "genrsa"]
        command.append('-out')
        command.append(user.key_file)
        if user.protected:
            password = self._access_password(user)
            if password is not False:
                command.append('-des3')
                command.append('-passout')
                command.append(password)
            else:
                return False
        # -- Bits must be the last parameter in the command --
        command.append(str(user.bits))
        return self._execute_command(command)

    def generate_csr(self, user, overwrite=False):
        """
        Generates a certificate request for the user. Returns True if the request
        was generated or if the overwrite parameter is set to False
        and a request file already exists.
        Assumes that the user's key has already been generated.

        Args:
            user (certautomator.User) : object containing the parameters
                                          necessary for openssl to generate the request
            overwrite (bool) : True if any existing request should be overwritten,
                               False if it should not be overwritten.

        Returns:
            False if the user is None or there was an error generating the request.

        """

        if user is None:
            self._logger.warning("User is empty.")
            return False
        if self._fh.file_exists(user.key_file) is False:
            self._logger.warning("Key for %s does not exist at %s, aborting.",
                                 user.name,
                                 user.key_file)
            return False
        if self._fh.file_exists(user.certificate_signing_request_file) and overwrite is False:
            self._logger.warning(
                "Certificate Signing Request for %s already exists at %s, will not overwrite.",
                user.name,
                user.certificate_signing_request_file)
            return True
        command = [self._openssl_location, "req", "-new"]
        command.append('-out')
        command.append(user.certificate_signing_request_file)
        command.append('-subj')
        command.append(user.format_distinguished_names())
        command.append('-key')
        command.append(user.key_file)
        if user.protected:
            password = self._access_password(user)
            if password is not False:
                command.append('-passin')
                command.append(password)
            else:
                return False
        return self._execute_command(command)

    def generate_ca_certificate(self, user, overwrite=False):
        """
        Generates a certificate for the Certificate Authority.
        Assumes that the ca's key has been generated.

        Args:
            user (certautomator.User) : containing the parameters
                    necessary for openssl to generate the certificate
            overwrite (bool) : True if any existing certificate should be overwritten,
                         False if it should not be overwritten.

        Returns:
            True if the certificate was generated or if the overwrite parameter
            is set to False and a certificate already exists.
            False if the user is None or there was an error generating the certificate.

        """

        if user is None:
            self._logger.warning("CA is None.")
            return False
        if self._fh.file_exists(user.key_file) is False:
            self._logger.warning(
                "CA Key for %s does not exist at %s, aborting.",
                user.name,
                user.key_file)
            return False
        if self._fh.file_exists(user.certificate_file) and overwrite is False:
            self._logger.warning(
                "CA's Certificate for %s already exists at %s, will not overwrite.",
                user.name,
                user.certificate_file)
            return True
        command = [self._openssl_location,
                   "req",
                   "-new",
                   "-x509"]
        command.append("-key")
        command.append(user.key_file)
        command.append("-subj")
        command.append(user.format_distinguished_names())
        command.append("-days")
        command.append(str(user.certificate_expiration))
        command.append("-out")
        command.append(user.certificate_file)
        if user.protected:
            password = self._access_password(user)
            if password is not False:
                command.append('-passin')
                command.append(password)
            else:
                return False
        return self._execute_command(command)

    def sign_certificate(self, user, overwrite=False, ca=None):
        """
        Generates a certificate for the user.
        Assumes that the user's certificate request file already exists, as
        well as the key and certificate for the certificate authority responsible for
        signing the new certificate.

        Args:
            user (certautomator.User) : containing the parameters
                    necessary for openssl to generate the certificate.
            overwrite (bool) : True if any existing certificate should be overwritten,
                         False if it should not be overwritten.
            ca (certautomator.CA) : containing the necessary parameters to sign the
                  user's certificate request.

        Returns:
            True if the certificate was generated or if the  overwrite parameter
            is set to False and a certificate already exists.
            False if the user is None, the CA is none or there was an
            error generating the certificate.

        """

        if user is None:
            self._logger.warning(
                "No user specified."
            )
            return False
        if ca is None:
            self._logger.warning(
                "No CA supplied when attempting to sign certificate for %s.", user.name)
            return False
        if self._fh.file_exists(user.certificate_file) and overwrite is False:
            self._logger.warning(
                "Certificate already exists for %s at location %s, will not overwrite.",
                user.name,
                user.certificate_file)
            return True
        if self._fh.file_exists(user.certificate_signing_request_file) is False:
            self._logger.warning(
                "Certificate signing request file for %s does not exist at %s, aborting.",
                user.name,
                user.certificate_signing_request_file)
            return False
        if self._fh.file_exists(ca.certificate_file) is False:
            self._logger.warning(
                "Certificate Authority's Certificate for %s at location %s does not exist, aborting.",
                ca.name,
                ca.certificate_file)
            return False
        if self._fh.file_exists(ca.key_file) is False:
            self._logger.warning(
                "Certificate Authority's Key for %s at location %s does not exist, aborting.",
                ca.name,
                ca.key_file)
            return False
        command = [self._openssl_location, "x509", "-req", "-CAcreateserial"]
        command.append("-in")
        command.append(user.certificate_signing_request_file)
        command.append("-CA")
        command.append(ca.certificate_file)
        command.append("-CAkey")
        command.append(ca.key_file)
        if ca.protected:
            password = self._access_password(ca)
            if password is not False:
                command.append('-passin')
                command.append(password)
            else:
                return False
        command.append("-out")
        command.append(user.certificate_file)
        command.append('-days')
        command.append(str(user.certificate_expiration))
        return self._execute_command(command)

    def _access_password(self, user):
        """
        Formats the password, either passphrase or file as specified in the
        configuration file, and returns it.
        Returns False if there is an issue with the passphrase or file not being
        set or if the file doesn't exist.

        Args:
            user (user.User) : User object containing either the passphrase or password file.

        Returns:
            str : Containing the passphrase or file to use, False if an error occurred.
        """

        self._logger.info(
            "Enabling password protected key for user %s.", user.name)
        if user.password:
            self._logger.debug("Using password phrase for user %s.", user.name)
            return 'pass:{0}'.format(user.password)
        elif user.password_file:
            if self._fh.file_exists(user.password_file):
                self._logger.debug(
                    "Using password file for user %s.", user.name)
                return 'file:{0}'.format(user.password_file)
            else:
                self._logger.warning(
                    "%s specified password protected key using password " +
                    "file at location %s but no such file exists.",
                    user.name,
                    user.password_file)
                return False
        else:
            self._logger.warning(
                "%s specified password protected key, but no password or " +
                "password file was specified in configuration file.", user.name)
            return False

    def _execute_command(self, command):
        """
        Passes the parameters in command to the a process that
        executes the command.

        Args:
            command (list) : all commands to be executed.

        Returns:
            True if the return code is 0,
            False otherwise.

        """

        self._logger.debug("Executing command : [%s]", ','.join(
            list(map(lambda x: x if "pass:" not in x else "pass:*********", command)))
        )
        process = subprocess.Popen(command,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        stdout, stderr = process.communicate()
        return_code = process.returncode
        self._logger.debug(stdout)
        if return_code != 0:
            self._logger.warning(stdout)
        return return_code == 0
