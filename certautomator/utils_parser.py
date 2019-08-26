
from certautomator.distinguished_names import DistinguishedNames
from certautomator.file_properties import FileProperties
from certautomator.user import User
from certautomator.utils import FileHandler
from certautomator.user import CA

import re
import logging


class UserParser:

    def __init__(self,
                 filehandler=FileHandler()):
        self._fh = filehandler

    def parse(self, data):
        """
        Moves the data from the data dictionary to another.
        Meant to allow to change any parameters or add any if required.

        Args:
            data (dictionary) : values retrieved from the user's config file.

        Returns:
            parsed (dictionary) : all values copied.
        """

        parsed = {}
        parsed['common_name'] = data.get("common_name")
        parsed['key_name'] = data.get('key_name')
        parsed['cert_name'] = data.get('cert_name')
        parsed['cert_request_name'] = data.get('cert_request_name')
        parsed['country'] = data.get('country')
        parsed['state'] = data.get('state')
        parsed['locality'] = data.get('locality')
        parsed['organization_name'] = data.get('organization_name')
        parsed['organizational_unit_name'] = data.get(
            'organizational_unit_name')
        parsed['email'] = data.get('email')
        parsed['password'] = data.get('password')
        parsed['password_file'] = data.get('password_file')
        return parsed


class CAParser(UserParser):

    def __init__(self,
                 logger=logging.getLogger('certautomator.CAParser')):
        UserParser.__init__(self)
        self._logger = logger


class Utils_Parser:

    def __init__(self,
                 ssl_defaults="ssl_defaults",
                 name_defaults="name_defaults",
                 ca_key='ca',
                 user_key='users',
                 ca_default_conf_line="#CA_DIRECTORY_LOCATION",
                 filehandler=FileHandler(),
                 logger=logging.getLogger('certautomator.utils_parser'),
                 ca_parser=CAParser(),
                 user_parser=UserParser()):
        self._ssl_defaults = ssl_defaults
        self._name_defaults = name_defaults
        self._ca_key = ca_key
        self._user_key = user_key
        self._CA_DEFAULT_CONF_LINE = ca_default_conf_line
        self._fh = filehandler
        self._logger = logger
        self._ca_parser = ca_parser
        self._user_parser = user_parser

    def parse(self, data, specified_groups=None, specified_users=None):
        """
            Parses the JSON data and returns a dictionary of all the groups and
            users, cas in those groups. Can use specified_groups and specified_users
            to only create elements specified in the two lists.
            Defaults to none for both which will generate all groups and users.

            Args:
                data (dictionary) : parsed from the config file
                specified_groups (list) : groups to be generated.
                specified_users (list) : users to be generated

            Returns:
                all_groups : contains all the groups and users
        """

        all_groups = {}
        try:
            self._logger.debug("Parsing data :")
            self._logger.debug(data)
            for group_key, group_value in data.items() if data is not None else []:
                if specified_groups is None or group_key in specified_groups:
                    self._logger.debug("Parsing data for group %s.", group_key)
                    group_users = {}
                    ssl_defaults_value = group_value.get(self._ssl_defaults)
                    if ssl_defaults_value is None:
                        self._logger.warning(
                            "ssl_defaults entry for group %s was not found, aborting.", group_key)
                        break
                    user_dir = ssl_defaults_value.get('user_dir')
                    if self.setup_directories(user_dir) is False:
                        self._logger.warning(
                            "Unable to create directory for group %s at %s.", group_key, user_dir)
                    name_defaults_value = group_value.get(self._name_defaults)
                    if name_defaults_value is None:
                        self._logger.warning(
                            "Name_defaults entry for group %s was not found, aborting.", group_key)
                        break
                    cas = group_value.get(self._ca_key)
                    if cas is not None:
                        self._logger.debug(
                            "Generating CAs for group %s.", group_key)
                        group_users['ca'] = self._add_users(
                            cas.items(),
                            specified_users,
                            self._create_CA,
                            ssl_defaults_value,
                            name_defaults_value)
                    users = group_value.get(self._user_key)
                    if users is not None:
                        self._logger.debug(
                            "Generating users for group %s.", group_key)
                        group_users['users'] = self._add_users(
                            users.items(),
                            specified_users,
                            self._create_user,
                            ssl_defaults_value,
                            name_defaults_value)
                    all_groups[group_key] = group_users
                else:
                    self._logger.debug(
                        "Group key %s is not in the list of specified groups.", group_key)
        except AttributeError as ae:
            self._logger.warning(ae)
        return all_groups

    def _add_users(self, all_users, specified_users, factory, ssl_defaults_value, name_defaults_value):
        """
        Loops through the lists of users from the all_users parameter and creates user and cas.

        Args:
            all_users (list) : all the users and ca
            specified_users (list) : users to include, skip any that are not in the list.
            factory (method) : method to create the user
            ssl_defaults_value (dictionary) : default ssl related values.
            name_defaults_value (dictionary) : distinguished name default values.
        Returns:
            dictionary of all the users and cas.

        """

        users = {}
        for user_key, user_value in all_users:
            if specified_users is None or user_key in specified_users:
                self._logger.debug("Generating new user %s.", user_key)
                new_user_values = self._user_parser.parse(
                    user_value)
                new_user = factory(
                    ssl_defaults_value, name_defaults_value, user_key, user_value)
                users[user_key] = new_user
            else:
                self._logger.debug(
                    "User %s is not in the list of users to generate.", user_key)
        return users

    def _create_user(self, ssl_defaults_value, name_defaults_value, user_key, user_value):
        """
        Creates a new user object based on the parsed values and returns it. All values
        in the config file that is specified at the user or ca level will take precedent over the
        default values. If none exists on the user level, defaults will be used.

        Args:
            ssl_defaults_value (dictionary) : default ssl related values.
            name_defaults_value (dictionary) : distinguished name default values.
            user_key (str) : name of the user as specified in the config file.
            user_value (str) : values from the user_key in the config file.

        Returns:
            user : User object or None if the User was not created, or
                   creating the directory structure failed.
        """
        try:
            user = User(name=user_key,
                        bits=user_value.get('bits') if user_value.get(
                            'bits') is not None else ssl_defaults_value.get('bits'),
                        protected=user_value.get('protected') if user_value.get(
                            'protected') is not None else ssl_defaults_value.get('protected'),
                        message_digest=user_value.get('message_digest') if user_value.get(
                            'message_digest') is not None else ssl_defaults_value.get('message_digest'),
                        certificate_expiration=user_value.get('days') if user_value.get(
                            'days') is not None else ssl_defaults_value.get('days'),
                        country=user_value.get('country') if user_value.get(
                            'country') is not None else name_defaults_value.get('country'),
                        state=user_value.get('state') if user_value.get(
                            'state') is not None else name_defaults_value.get('state'),
                        locality=user_value.get('locality') if user_value.get(
                            'locality') is not None else name_defaults_value.get('locality'),
                        organization_name=user_value.get('organization_name') if user_value.get(
                            'organization_name') is not None else name_defaults_value.get('organization_name'),
                        organizational_unit_name=user_value.get('organizational_unit_name') if user_value.get(
                            'organizational_unit_name') is not None else name_defaults_value.get('organizational_unit_name'),
                        common_name=user_value.get('common_name'),
                        email=user_value.get('email') if user_value.get(
                            'email') is not None else name_defaults_value.get('email'),
                        dir=user_value.get("user_dir") if user_value.get(
                            'user_dir') is not None else ssl_defaults_value.get("user_dir"),
                        key_name=user_value.get("key_name"),
                        request_name=user_value.get("cert_request_name"),
                        cert_name=user_value.get("cert_name"),
                        password=user_value.get('password'),
                        password_file=user_value.get('password_file')
                        )
            if self.setup_directories(user.dir):
                self._logger.debug(
                    "Successfully generated new user %s.", user.name)
                return user
            else:
                self._logger.warning(
                    "Unable to create directory at %s.", user.dir)
                return None
        except Exception as e:
            self._logger.warning(e)
        return None

    def _create_CA(self, ssl_defaults_value, name_defaults_value, ca_key, ca_value):
        """
        Creates a new CA object based on the parsed values and returns it. All values
        in the config file that is specified on the user or ca will take precedent over the
        default values. If none exists on the user level, defaults will be used.

        Args:
            ssl_defaults_value (dictionary) : all the default ssl related values.
            name_defaults_value (dictionary) : all distinguished name default values.
            ca_key (str) : name of the ca as specified in the config file.
            ca_value (str) : values from the ca_key in the config file.

        Returns:
            CA : CA object or None if the CA was not created, or
                 creating the directory structure failed.
        """
        try:
            ca = CA(name=ca_key,
                    bits=ca_value.get('bits') if ca_value.get(
                        'bits') is not None else ssl_defaults_value.get('bits'),
                    protected=ca_value.get('protected') if ca_value.get(
                        'protected') is not None else ssl_defaults_value.get('protected'),
                    message_digest=ca_value.get('message_digest') if ca_value.get(
                        'message_digest') is not None else ssl_defaults_value.get('message_digest'),
                    certificate_expiration=ca_value.get('days') if ca_value.get(
                        'days') is not None else ssl_defaults_value.get('days'),
                    country=ca_value.get('country') if ca_value.get(
                        'country') is not None else name_defaults_value.get('country'),
                    state=ca_value.get('state') if ca_value.get(
                        'state') is not None else name_defaults_value.get('state'),
                    locality=ca_value.get('locality') if ca_value.get(
                        'locality') is not None else name_defaults_value.get('locality'),
                    organization_name=ca_value.get('organization_name') if ca_value.get(
                        'organization_name') is not None else name_defaults_value.get('organization_name'),
                    organizational_unit_name=ca_value.get('organizational_unit_name') if ca_value.get(
                        'organizational_unit_name') is not None else name_defaults_value.get('organizational_unit_name'),
                    common_name=ca_value.get('common_name'),
                    email=ca_value.get('email') if ca_value.get(
                        'email') is not None else name_defaults_value.get('email'),
                    # ca_conf=ca_value.get('ca_conf'),
                    ca_dir=ca_value.get('ca_dir') if ca_value.get(
                        'ca_dir') is not None else ssl_defaults_value.get('ca_dir'),
                    key_name=ca_value.get("key_name"),
                    request_name=ca_value.get("cert_request_name"),
                    cert_name=ca_value.get("cert_name"),
                    password=ca_value.get('password'),
                    password_file=ca_value.get('password_file')
                    )
            if self.setup_directories(ca.ca_dir):
                self._logger.debug(
                    "Successfully generated new CA %s.", ca.name)
                return ca
            else:
                self._logger.warning(
                    "Unable to generate ca file directory structure.")
                return None
        except Exception as e:
            self._logger.warning(e)
        return None

    def setup_directories(self, path):
        """
        Recursively creates the necessary directories to hold
        the keys, requests and certificates.

        Args:
            path (str) : location of the folder to create the
                         new folders. Will create path if path
                         does not already exist.

        Returns:
            bool: True if all directories were created, False otherwise.

        """

        self._logger.debug("Generating directory structure at %s.", path)
        all_paths = ["{0}/keys".format(path),
                     "{0}/csrs".format(path),
                     "{0}/crts".format(path)]
        result = True
        for p in all_paths:
            result &= self._fh.create_directory(p)
        return result
