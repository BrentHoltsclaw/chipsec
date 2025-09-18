import unittest
from unittest.mock import patch, Mock
from tests.test_utils import MockFactory


class TestECCommand(unittest.TestCase):
    """Test EC command functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        with patch('chipsec.chipset.cs', self.mock_cs):
            from chipsec.utilcmd.ec_cmd import ECCommand
            self._ec = ECCommand(['ec'])
    
    def test_ec_command_initialization(self):
        """Test EC command initializes correctly."""
        self.assertIsNotNone(self._ec)
        # Test that the command is properly registered
        from chipsec.utilcmd.ec_cmd import commands
        self.assertIn('ec', commands)
        self.assertEqual(commands['ec'], type(self._ec))


if __name__ == '__main__':
    unittest.main()
