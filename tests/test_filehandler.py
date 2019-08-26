
from certautomator.utils import FileHandler
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch
from unittest.mock import mock_open
import os
import sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


class Test_TestFileHandler(unittest.TestCase):

    @patch("builtins.open", new_callable=mock_open, read_data="data")
    def test_read_ok(self,mock_read):
        fileHandler = FileHandler()
        result = fileHandler.read('sample_file')
        assert open('sample_file','r').read() == 'data'
        mock_read.assert_called_with('sample_file', 'r')
        self.assertEqual('data',result)

    @patch("builtins.open", new_callable=mock_open, read_data="data")
    def test_read_file_not_found(self,mock_read):
        mock_read.side_effect = FileNotFoundError()
        fileHandler = FileHandler()
        result = fileHandler.read('sample_file')
        self.assertIsNone(result)

    @patch("builtins.open", new_callable=mock_open, read_data="data")
    def test_read_file_io_error(self,mock_read):
        mock_read.side_effect = IOError()
        fileHandler = FileHandler()
        result = fileHandler.read('sample_file')
        self.assertIsNone(result)

    @patch("builtins.open", new_callable=mock_open, read_data="data")
    def test_read_file_os_error(self,mock_read):
        mock_read.side_effect = OSError()
        fileHandler = FileHandler()
        result = fileHandler.read('sample_file')
        self.assertIsNone(result)

    @patch("builtins.open", new_callable=mock_open, read_data="data")
    def test_read_file_permission_error(self,mock_read):
        mock_read.side_effect = PermissionError()
        fileHandler = FileHandler()
        result = fileHandler.read('sample_file')
        self.assertIsNone(result)

    @patch("builtins.open", new_callable=mock_open, read_data="data")
    def test_read_file_random_exception(self,mock_read):
        mock_read.side_effect = Exception()
        fileHandler = FileHandler()
        result = fileHandler.read('sample_file')
        self.assertIsNone(result)

    def test_create_directory_with_empty_path(self):
        fileHandler = FileHandler()
        self.assertFalse(fileHandler.create_directory(''))

    @patch('os.path.exists')
    def test_create_directory_return_true_if_it_already_exists(self,ospath):
        ospath.return_value = True
        fileHandler = FileHandler()
        result = fileHandler.create_directory('sample_path')
        self.assertTrue(result)

    @patch('os.path.exists')
    @patch('os.mkdir')
    def test_create_directory_success(self,ospath,mkdir):
        ospath.return_value = False
        fileHandler = FileHandler()
        result = fileHandler.create_directory('sample_path')
        self.assertTrue(result)

    @patch("builtins.open", new_callable=mock_open, create=True)
    def test_write_success(self,mock_open):
        fileHandler = FileHandler()
        result = fileHandler.write('sample_path','random_data')
        self.assertTrue(result)

    @patch("builtins.open", new_callable=mock_open, create=True)
    def test_write_failed(self, mock_open):
        mock_open.side_effect = PermissionError()
        fileHandler = FileHandler()
        result = fileHandler.write('sample_path','random_data')
        self.assertFalse(result)
        mock_open.side_effect = OSError()
        fileHandler = FileHandler()
        result = fileHandler.write('sample_path','random_data')
        self.assertFalse(result)
        mock_open.side_effect = Exception()
        fileHandler = FileHandler()
        result = fileHandler.write('sample_path','random_data')
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
