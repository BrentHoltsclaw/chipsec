import unittest
from unittest.mock import Mock
from chipsec.utilcmd.spidesc_cmd import SPIDescCommand
from tests.test_utils import MockFactory

class TestSPIDescCommand(unittest.TestCase):
    def setUp(self):
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.spidesc_command = SPIDescCommand(['spidesc'], cs=self.mock_cs)

    def test_initialization(self):
        self.assertIsNotNone(self.spidesc_command)

if __name__ == '__main__':
    unittest.main()
