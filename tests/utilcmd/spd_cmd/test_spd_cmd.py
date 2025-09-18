import unittest
from unittest.mock import Mock
from chipsec.utilcmd.spd_cmd import SPDCommand
from tests.test_utils import MockFactory

class TestSPDCommand(unittest.TestCase):
    def setUp(self):
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.spd_command = SPDCommand(['detect'], cs=self.mock_cs)

    def test_initialization(self):
        self.assertIsNotNone(self.spd_command)

if __name__ == '__main__':
    unittest.main()
