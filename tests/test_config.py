from certautomator.utils import Config
from certautomator.utils import FileHandler
import unittest
from unittest.mock import MagicMock
import os
import sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


class Test_TestConfig(unittest.TestCase):
    def test_valid_config_data(self):
        filehandler = FileHandler()
        filehandler.read = MagicMock(return_value='{"test":"value"}')
        config = Config(filehandler=filehandler)
        result = config.read_config('ignore_file.json')
        self.assertEqual(result,{
            "test":"value"
        })
    
    def test_content_isnt_json(self):
        filehandler = FileHandler()
        filehandler.read = MagicMock(return_value='{"test":"value"')
        config = Config(filehandler=filehandler)
        result = config.read_config('ignore_file.json')
        self.assertEqual(result,None)
    
    def test_content_is_none(self):
        filehandler = FileHandler()
        filehandler.read = MagicMock(return_value=None)
        config = Config(filehandler=filehandler)
        result = config.read_config('ignore_file.json')
        self.assertEqual(result,None)
