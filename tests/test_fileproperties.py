from certautomator.file_properties import FileProperties
import unittest
import os
import sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


class Test_TestFileProperties(unittest.TestCase):

    def test_valid_properties(self):
        fileproperties = FileProperties("item1", "item2", "item3")
        self.assertTrue(fileproperties.is_valid())

    def test_all_elements_are_none(self):
        fileproperties = FileProperties()
        self.assertFalse(fileproperties.is_valid())

    def test_one_item_is_none(self):
        fileproperties = FileProperties(None, "item", "item2")
        self.assertFalse(fileproperties.is_valid())
        fileproperties = FileProperties("item2", None, "item2")
        self.assertFalse(fileproperties.is_valid())
        fileproperties = FileProperties("item2", "item1", None)
        self.assertFalse(fileproperties.is_valid())

    def test_item_is_not_a_str(self):
        fileproperties = FileProperties(True, "item1", "a")
        self.assertFalse(fileproperties.is_valid())
        fileproperties = FileProperties("item", 1, "w")
        self.assertFalse(fileproperties.is_valid())
        fileproperties = FileProperties("item", "something", {})
        self.assertFalse(fileproperties.is_valid())
    
    def test_empty_string(self):
        fileproperties = FileProperties("", "item", "item2")
        self.assertFalse(fileproperties.is_valid())
        fileproperties = FileProperties("item2", "    ", "item2")
        self.assertFalse(fileproperties.is_valid())
        fileproperties = FileProperties("item2", "item1", " ")
        self.assertFalse(fileproperties.is_valid())
