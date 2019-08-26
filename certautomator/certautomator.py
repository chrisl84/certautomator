from argparse import ArgumentParser
from certautomator.utils import Config
from certautomator.utils import FileHandler
from certautomator.utils_parser import Utils_Parser
from certautomator.crypto_cmds import CryptoCommands
import logging
import operator


class Main():

    def __init__(self, cryptoCommands=CryptoCommands(), filehandler=FileHandler()):
        self._crypto_commands = cryptoCommands
        self._filehandler = filehandler

    def _setupLogging(self, logfile='./certautomator.log', loglevel=logging.INFO):
        self._logger = logging.getLogger('certautomator')
        self._logger.setLevel(logging.DEBUG)
        self._fh = logging.FileHandler(logfile, mode='w')
        self._fh.setLevel(loglevel)
        self._formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self._fh.setFormatter(self._formatter)
        self._logger.addHandler(self._fh)

    def main(self):
        try:
            parser = ArgumentParser()
            loggingGroup = parser.add_mutually_exclusive_group()
            loggingGroup.add_argument(
                '--verbose',
                '-v',
                help="Verbose logging enabled.",
                action='store_true'
            )
            loggingGroup.add_argument(
                '--quiet',
                '-q',
                help="Log only warning messages.",
                action='store_true'
            )
            parser.add_argument(
                '--config',
                type=str,
                help='Location of config file, defaults to ./config.json.',
                default='./config.json',
                required=False
            )
            parser.add_argument(
                '--log',
                type=str,
                help='Location of log file, defaults to ./certautomator.log.',
                default='./certautomator.log',
                required=False
            )
            parser.add_argument(
                '--openssl',
                type=str,
                help="Location of the OpenSSL binaries, defaults to /usr/bin/openssl",
                default='/usr/bin/openssl',
                required=False
            )
            parser.add_argument(
                '--overwrite',
                help="Overwrite existing files.",
                action='store_true',
                default=False,
                required=False
            )
            parser.add_argument('--all',
                                '-a',
                                dest='all',
                                action='store_true',
                                default=False,
                                help="Perform generate key, certificate request and signature actions on users.")
            parser.add_argument('--key',
                                '-k',
                                dest='key',
                                action='store_true',
                                default=False,
                                help="Generate keys for users.")
            parser.add_argument('--req',
                                '-r',
                                dest='req',
                                action='store_true',
                                default=False,
                                help="Generate certificate request for users.")
            parser.add_argument('--sign',
                                '-s',
                                dest='sign',
                                action='store_true',
                                default=False,
                                help="Sign certificate requests and generate certificates.")
            parser.add_argument('--group',
                                dest='group',
                                type=str,
                                action='store',
                                default=False,
                                help="Enter the name of the group, separated by ','.")
            parser.add_argument('--users',
                                dest='users',
                                type=str,
                                action='store',
                                default=False,
                                help="Enter the name of the users, separated by ','.")
            cmds = vars(parser.parse_args())
            logfile = cmds.get('log')
            self._setupLogging(logfile=logfile)
            if cmds.get('verbose'):
                self._fh.setLevel(logging.DEBUG)
            if cmds.get('quiet'):
                self._fh.setLevel(logging.WARN)
            if cmds.get('config'):
                config = cmds.get('config')
            openssl = cmds.get('openssl')
            config = cmds.get('config')
            if self._filehandler.file_exists(openssl) is False:
                raise Exception(
                    'Cannot find the openssl binaries at {0}.'.format(openssl))
            if self._filehandler.file_exists(config) is False:
                raise Exception(
                    '{0} configuration file does not exist.'.format(config))
            if(cmds.get('all') is False and
               (cmds.get('key') is False and
                cmds.get('req') is False and
                    cmds.get('sign') is False)):
                print('--all or one of --key, --req and/or --sign is required.')
                parser.print_help()
            else:
                reader = Config()
                data_parser = Utils_Parser()
                file_content = reader.read_config(config)
                data = data_parser.parse(
                    data=file_content,
                    specified_groups=cmds.get('group').split(',') if cmds.get(
                        'group') is not False else None,
                    specified_users=cmds.get('users').split(',') if cmds.get(
                        'users') is not False else None)
                if data is not None:
                    for group_key, group_value in data.items():
                        self._logger.info(
                            "Generating files for group: %s.", group_key)
                        self._crypto_commands.generate(cmds, group_value)
                else:
                    print('No data found in configuration file.')
        except IOError as ioe:
            print(ioe)
        except Exception as e:
            print(str(e))


if __name__ == "__main__":
    main = Main()
    main.main()
