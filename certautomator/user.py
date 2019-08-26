from certautomator.distinguished_names import DistinguishedNames
from certautomator.file_properties import FileProperties

import logging


class User(DistinguishedNames, FileProperties):

    def __init__(self,
                 name,
                 bits=2048,
                 protected=False,
                 message_digest='sha256',
                 certificate_expiration=365,
                 country=None,
                 state=None,
                 locality=None,
                 organization_name=None,
                 organizational_unit_name=None,
                 common_name=None,
                 email=None,
                 dir=None,
                 key_name=None,
                 request_name=None,
                 cert_name=None,
                 password=None,
                 password_file=None,
                 logger=logging.getLogger('certautomator.user')):
        self._logger = logger
        self._name = name
        if key_name is None:
            raise Exception("Key file for {0} is None.".format(name))
        if request_name is None:
            raise Exception(
                "Certificate Signing Request file for {0} is None.".format(name))
        if cert_name is None:
            raise Exception("Certificate file for {0} is None.".format(name))
        DistinguishedNames.__init__(self,
                                    country,
                                    state,
                                    locality,
                                    organization_name,
                                    organizational_unit_name,
                                    common_name,
                                    email)
        FileProperties.__init__(self,
                                "{0}/keys/{1}".format(
                                    dir,
                                    key_name if key_name is not None else "{0}.key".format(name)),
                                "{0}/crts/{1}".format(
                                    dir,
                                    cert_name if cert_name is not None else "{0}.crt".format(name)),
                                "{0}/csrs/{1}".format(
                                    dir,
                                    request_name if request_name is not None else "{0}.csr".format(name)))
        self._dir = dir
        self.bits = bits
        self.protected = protected
        self.message_digest = message_digest
        self.certificate_expiration = certificate_expiration
        self.password = password
        self.password_file = password_file

    @property
    def bits(self):
        return self._bits

    @bits.setter
    def bits(self, b):
        self._logger.debug('Setting bits %s for %s.', str(b), self.name)
        if isinstance(b, int):
            self._bits = b
        else:
            self._bits = None

    @property
    def protected(self):
        return self._protected

    @protected.setter
    def protected(self, p):
        self._logger.debug('Setting protected %s for %s.', str(p), self.name)
        if isinstance(p, bool):
            self._protected = p
        else:
            self._protected = None

    @property
    def message_digest(self):
        return self._message_digest

    @message_digest.setter
    def message_digest(self, md):
        self._logger.debug(
            'Setting message_digest %s for %s.', str(md), self.name)
        if isinstance(md, str):
            self._message_digest = md
        else:
            self._message_digest = None

    @property
    def certificate_expiration(self):
        return self._certificate_expiration

    @certificate_expiration.setter
    def certificate_expiration(self, ce):
        self._logger.debug(
            'Setting certificate expiration %s for %s.', str(ce), self.name)
        if isinstance(ce, bool):
            self._certificate_expiration = None
        elif isinstance(ce, int):
            self._certificate_expiration = ce
        else:
            self._certificate_expiration = None

    @property
    def name(self):
        return self._name

    @property
    def dir(self):
        return self._dir

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, pwd):
        self._password = pwd

    @property
    def password_file(self):
        return self._password_file

    @password_file.setter
    def password_file(self, pwd_file):
        self._password_file = pwd_file

    def is_valid(self):
        valid = (FileProperties.is_valid(self) and
                 self.bits is not None and
                 self.protected is not None and
                 self.message_digest is not None and
                 self.certificate_expiration is not None)
        return valid


class CA(User):
    def __init__(self,
                 name=None,
                 bits=2048,
                 protected=False,
                 message_digest='sha256',
                 certificate_expiration=365,
                 country=None,
                 state=None,
                 locality=None,
                 organization_name=None,
                 organizational_unit_name=None,
                 common_name=None,
                 email=None,
                 ca_conf=None,
                 ca_dir=None,
                 key_name=None,
                 request_name=None,
                 cert_name=None,
                 password=None,
                 password_file=None,
                 logger=logging.getLogger('certautomator.ca')):
        self._logger = logger
        User.__init__(self,
                      name,
                      bits,
                      protected,
                      message_digest,
                      certificate_expiration,
                      country,
                      state,
                      locality,
                      organization_name,
                      organizational_unit_name,
                      common_name,
                      email,
                      ca_dir,
                      key_name,
                      request_name,
                      cert_name,
                      password,
                      password_file)
        # unused. This is for creating conf file to setup a complete
        # CA with certificate revocation lists etc.
        # May be implemented on a later date.
        self.config_file = ca_conf
        self._ca_dir = ca_dir

    @property
    def ca_dir(self):
        return self._ca_dir

    @property
    def config_file(self):
        return self._config_file

    @config_file.setter
    def config_file(self, cf):
        self._logger.debug(
            'Setting configuration file %s for CA %s.', str(cf), super().name)
        if isinstance(cf, str) and cf.strip() is not '':
            self._config_file = cf
        else:
            self._config_file = None
