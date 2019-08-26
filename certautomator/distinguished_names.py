
class DistinguishedNames:

    def __init__(self,
                 country=None,
                 state=None,
                 locality=None,
                 organization_name=None,
                 organizational_unit_name=None,
                 common_name=None,
                 email=None):
        self.country = country
        self.state = state
        self.locality = locality
        self.organization_name = organization_name
        self.organizational_unit_name = organizational_unit_name
        self.common_name = common_name
        self.email = email

    @property
    def country(self):
        return self._country

    @country.setter
    def country(self, country):
        if isinstance(country, str):
            self._country = country
        else:
            self._country = None

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, state):
        if isinstance(state, str):
            self._state = state
        else:
            self._state = None

    @property
    def locality(self):
        return self._locality

    @locality.setter
    def locality(self, locality):
        if isinstance(locality, str):
            self._locality = locality
        else:
            self._locality = None

    @property
    def organization_name(self):
        return self._organization_name

    @organization_name.setter
    def organization_name(self, organization_name):
        if isinstance(organization_name, str):
            self._organization_name = organization_name
        else:
            self._organization_name = None

    @property
    def organizational_unit_name(self):
        return self._organizational_unit_name

    @organizational_unit_name.setter
    def organizational_unit_name(self, organizational_unit_name):
        if isinstance(organizational_unit_name, str):
            self._organizational_unit_name = organizational_unit_name
        else:
            self._organizational_unit_name = None

    @property
    def common_name(self):
        return self._common_name

    @common_name.setter
    def common_name(self, common_name):
        if isinstance(common_name, str):
            self._common_name = common_name
        else:
            self._common_name = None

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, email):
        if isinstance(email, str):
            self._email = email
        else:
            self._email = None

    def format_distinguished_names(self):
        """ 
        Returns the parsed distinguished names in way
        that OpenSSL can interpret. Does not include
        properties that are not set, i.e. None.

        Returns:
            The distinguished names starting with / and ending with /,
            separated by / for each variable.

        """

        values = {}
        if self._country is not None:
            values['C'] = self.country
        if self._state is not None:
            values['ST'] = self.state
        if self._locality is not None:
            values['L'] = self.locality
        if self._organization_name is not None:
            values['O'] = self.organization_name
        if self._organizational_unit_name is not None:
            values['OU'] = self.organizational_unit_name
        if self._common_name is not None:
            values['CN'] = self.common_name
        if self._email is not None:
            values['emailAddress'] = self.email
        names = '/'+ ''.join("{0}={1}/".format(k, v) for (k, v) in values.items()) if len(values.items()) > 0 else '//'
        return names
