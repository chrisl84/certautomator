
class FileProperties:

    def __init__(self,
                 key_file=None,
                 certificate_file=None,
                 certificate_signing_request_file=None):
        self._key_file = key_file
        self._certificate_file = certificate_file
        self._certificate_signing_request_file = certificate_signing_request_file

    @property
    def key_file(self):
        return self._key_file

    @property
    def certificate_file(self):
        return self._certificate_file

    @property
    def certificate_signing_request_file(self):
        return self._certificate_signing_request_file

    def is_valid(self):
        return (isinstance(self._key_file, str) and self._key_file.strip() is not "" and
                isinstance(self._certificate_file, str) and self._certificate_file.strip() is not "" and
                isinstance(self.certificate_signing_request_file, str) and self.certificate_signing_request_file.strip() is not "")
