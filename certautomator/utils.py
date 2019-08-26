
# Read the config file
# Get the CA
# Get any users
from json.decoder import JSONDecodeError
import json
import logging
import os
import stat


class FileHandler:
    def __init__(self,
                 logger=logging.getLogger('opensstoolslib.filehandler'),
                 default_mode=stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR):
        self._default_mode = default_mode
        self._logger = logger

    def write(self, filename, data, format=''):
        """
        Writes the data to filename in the format provided.

        Args:
            filename (str) : path and filename to write content to
            data (str) : data to write to the file.
            format (str) : allows for writing of binary if necessary

        Returns:
            (bool) : True if data was written to, False otherwise.
        """

        try:
            self._logger.debug(
                "Attempting to write data %s to file %s.", data, filename)
            if format != '':
                self._logger.debug(
                    "Using custom format when writing to file %s.", format)
            with open(filename, 'w'+format) as f:
                f.write(data)
                f.close()
                self._logger.debug(
                    "Successfully wrote data to file %s.", filename)
                return True
        except PermissionError as pe:
            self._logger.exception(pe)
        except OSError as oe:
            self._logger.exception(oe)
        except:
            self._logger.exception('Unknown Exception, aborting.')
        return False

    def directory_exists(self, location):
        """
        Checks to see if the path exists and that it is a directory.

        Args:
            location (str) : location to check

        Returns:
            (bool) : True if this is a directory, False otherwise.
        """

        self._logger.debug("Check if directory at %s exists.", location)
        return os.path.exists(location) and os.path.isdir(location)

    def file_exists(self, location):
        """
        Checks to see if the path exists and that it is a file.

        Args:
            location (str) : location to check

        Returns:
            (bool) : True if this is a file, False otherwise.
        """

        self._logger.debug("Check if file at %s exists.", location)
        return os.path.exists(location) and os.path.isfile(location)

    def create_directory(self, full_path, permissions=None):
        """
        Creates the directory if it doesn't already exist. 
        If permissions are not specified, defaults to Read Write and Execute
        for user running the script.

        Args:
            full_path (str) : path of directory
            permissions (stat) : Read/Write/Execute permissions.

        Returns:
            (bool) : True if the directory was created or already exists.
                     False if there was an error creating the directory.

        """

        if full_path is None or full_path.strip() == "":
            self._logger.warning("%s is not a valid path.", full_path)
            return False
        if permissions is None:
            self._logger.debug(
                "No custom permissions specified, using default %s", str(self._default_mode))
            permissions = self._default_mode
        else:
            self._logger.debug(
                "Custom permissions specified, using %s.", str(permissions))
        try:
            if not os.path.exists(full_path):
                os.makedirs(
                    full_path,
                    exist_ok=True,
                    mode=permissions)
                self._logger.debug("Created directory at %s", full_path)
            else:
                self._logger.info("%s already exists.", full_path)
        except OSError as ose:
            self._logger.exception(ose)
            return False
        except:
            self._logger.exception(
                "Encountered exception when creating directory, aborting.")
            return False
        return True

    def read(self, filename):
        """
        Reads the data from filename.

        Args:
            filename (str) : path and filename to read content from

        Returns:
            data (str) : content of the file.
        """

        data = None
        try:
            self._logger.debug(
                "Attempting to read data from file %s.", filename)
            with open(filename, 'r') as f:
                data = f.read()
        except FileNotFoundError as fnfe:
            self._logger.exception(fnfe)
        except PermissionError as pe:
            self._logger.exception(pe)
        except OSError as oe:
            self._logger.exception(oe)
        except IOError as ioe:
            self._logger.exception(ioe)
        except:
            self._logger.exception(
                "Unknown error for file %s, aborting read.", filename)
        return data

    def replace_content(self, data, old_line, new_line):
        replaced_data = data.replace(old_line, new_line)
        return replaced_data


class Config:

    def __init__(self,
                 filehandler=FileHandler(),
                 logger=logging.getLogger('opensstoolslib.config')):
        self._filehandler = filehandler
        self._logger = logger

    def read_config(self, filename):
        """
        Reads the content from filename and then parses it to JSON.

        Args:
            filename (str) : path and filename of the config file.

        Returns:
            json_data (dictionary) : Dictionary of all the config file content,
                                     If an error occurred, None.
        """
        try:
            self._logger.debug(
                "Attempting to read configuration data from file %s.", filename)
            raw_data = self._filehandler.read(filename)
            json_data = json.loads(raw_data)
            return json_data
        except TypeError as te:
            self._logger.warning(te)
        except JSONDecodeError as jde:
            self._logger.warning(jde)
        return None
