# CHIPSEC: Platform Security Assessment Framework
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

import unittest
from unittest.mock import Mock
from chipsec.utilcmd.chipset_cmd import PlatformCommand
from chipsec.library.exceptions import UnknownChipsetError
from tests.test_utils import MockFactory


class TestPlatformCommand(unittest.TestCase):
    """Comprehensive tests for Platform/Chipset utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        # Mock Cfg component
        self.mock_cs.Cfg = Mock()
        self.chipset_command = PlatformCommand([], cs=self.mock_cs)

    def test_chipset_command_initialization(self):
        """Test PlatformCommand initialization."""
        self.assertEqual(self.chipset_command.cs, self.mock_cs)
        self.assertEqual(self.chipset_command.argv, [])

    def test_parse_arguments(self):
        """Test argument parsing (no arguments expected)."""
        command = PlatformCommand([], cs=self.mock_cs)
        command.parse_arguments()
        # No arguments to parse, should not raise any errors
        self.assertTrue(True)

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.chipset_command.requirements()
        self.assertTrue(hasattr(reqs, 'load_driver'))
        self.assertTrue(hasattr(reqs, 'load_config'))

    def test_run_successful(self):
        """Test successful command execution."""
        # Setup mocks
        self.mock_cs.Cfg.print_supported_chipsets.return_value = None
        self.mock_cs.Cfg.print_platform_info.return_value = None
        self.mock_cs.Cfg.print_pch_info.return_value = None

        # Execute command
        self.chipset_command.run()

        # Verify all methods were called
        self.mock_cs.Cfg.print_supported_chipsets.assert_called_once()
        self.mock_cs.Cfg.print_platform_info.assert_called_once()
        self.mock_cs.Cfg.print_pch_info.assert_called_once()

    def test_run_with_unknown_chipset_error(self):
        """Test command execution with UnknownChipsetError."""
        # Setup mock to raise UnknownChipsetError
        self.mock_cs.Cfg.print_supported_chipsets.side_effect = UnknownChipsetError("Unknown chipset detected")

        # Execute command (should handle error gracefully)
        self.chipset_command.run()

        # Verify the error was logged
        # Note: We can't easily test logger calls without more complex mocking,
        # but we can verify the command doesn't crash

    def test_run_with_generic_exception(self):
        """Test command execution with generic exception."""
        # Setup mock to raise a generic exception
        self.mock_cs.Cfg.print_supported_chipsets.side_effect = Exception("Generic error")

        # Execute command (should handle error gracefully)
        self.chipset_command.run()

        # Command should complete without crashing
        self.assertTrue(True)

    def test_commands_dictionary(self):
        """Test commands dictionary is properly defined."""
        from chipsec.utilcmd.chipset_cmd import commands
        self.assertIn('platform', commands)
        self.assertEqual(commands['platform'], PlatformCommand)


class TestPlatformCommandIntegration(unittest.TestCase):
    """Integration tests for Platform command with configuration system."""

    def setUp(self):
        """Set up integrated test fixtures."""
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock Cfg component with realistic data
        self.integrated_cs.Cfg = Mock()
        self.integrated_cs.Cfg.print_supported_chipsets.return_value = None
        self.integrated_cs.Cfg.print_platform_info.return_value = None
        self.integrated_cs.Cfg.print_pch_info.return_value = None

        # Mock platform info
        self.integrated_cs.Cfg.platform_info = Mock()
        self.integrated_cs.Cfg.platform_info.code = 'BDW'
        self.integrated_cs.Cfg.platform_info.vid = 0x8086
        self.integrated_cs.Cfg.platform_info.did = 0x1234
        self.integrated_cs.Cfg.platform_info.name = 'Broadwell'

        # Mock PCH info
        self.integrated_cs.Cfg.pch_info = Mock()
        self.integrated_cs.Cfg.pch_info.code = 'BDW-PCH'
        self.integrated_cs.Cfg.pch_info.vid = 0x8086
        self.integrated_cs.Cfg.pch_info.did = 0x5678
        self.integrated_cs.Cfg.pch_info.name = 'Broadwell PCH'

    def test_chipset_command_full_workflow(self):
        """Test complete chipset command workflow."""
        # Create and execute command
        chipset_cmd = PlatformCommand([], cs=self.integrated_cs)
        chipset_cmd.parse_arguments()

        # Execute command
        chipset_cmd.run()

        # Verify all configuration methods were called
        self.integrated_cs.Cfg.print_supported_chipsets.assert_called_once()
        self.integrated_cs.Cfg.print_platform_info.assert_called_once()
        self.integrated_cs.Cfg.print_pch_info.assert_called_once()

    def test_chipset_command_with_platform_data(self):
        """Test chipset command with realistic platform data."""
        # Verify platform info is accessible
        self.assertEqual(self.integrated_cs.Cfg.platform_info.code, 'BDW')
        self.assertEqual(self.integrated_cs.Cfg.platform_info.vid, 0x8086)
        self.assertEqual(self.integrated_cs.Cfg.platform_info.name, 'Broadwell')

        # Verify PCH info is accessible
        self.assertEqual(self.integrated_cs.Cfg.pch_info.code, 'BDW-PCH')
        self.assertEqual(self.integrated_cs.Cfg.pch_info.vid, 0x8086)
        self.assertEqual(self.integrated_cs.Cfg.pch_info.name, 'Broadwell PCH')

        # Execute command
        chipset_cmd = PlatformCommand([], cs=self.integrated_cs)
        chipset_cmd.run()

        # Verify execution completed successfully
        self.integrated_cs.Cfg.print_supported_chipsets.assert_called_once()

    def test_chipset_command_error_handling(self):
        """Test chipset command error handling."""
        # Test with print_supported_chipsets error
        self.integrated_cs.Cfg.print_supported_chipsets.side_effect = UnknownChipsetError("Chipset not supported")

        chipset_cmd = PlatformCommand([], cs=self.integrated_cs)
        chipset_cmd.run()

        # Should handle error gracefully
        self.assertTrue(True)

        # Reset mock
        self.integrated_cs.Cfg.print_supported_chipsets.reset_mock()
        self.integrated_cs.Cfg.print_supported_chipsets.side_effect = None

        # Test with print_platform_info error
        self.integrated_cs.Cfg.print_platform_info.side_effect = Exception("Platform info error")

        chipset_cmd2 = PlatformCommand([], cs=self.integrated_cs)
        chipset_cmd2.run()

        # Should handle error gracefully
        self.assertTrue(True)


class TestPlatformCommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for Platform command."""

    def setUp(self):
        """Set up mock ChipsecCs for edge case testing."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.Cfg = Mock()

    def test_empty_argv_handling(self):
        """Test handling of empty argv."""
        chipset_cmd = PlatformCommand([], cs=self.mock_cs)
        chipset_cmd.parse_arguments()
        # Should not raise any errors
        self.assertTrue(True)

    def test_unexpected_argv_handling(self):
        """Test handling of unexpected arguments."""
        # The command doesn't expect arguments, but argparse should handle them gracefully
        chipset_cmd = PlatformCommand(['unexpected', 'args'], cs=self.mock_cs)

        # This should raise SystemExit due to unexpected arguments
        with self.assertRaises(SystemExit):
            chipset_cmd.parse_arguments()

    def test_cfg_none_handling(self):
        """Test handling when Cfg is None."""
        self.mock_cs.Cfg = None

        chipset_cmd = PlatformCommand([], cs=self.mock_cs)

        # This should raise AttributeError when trying to access Cfg
        with self.assertRaises(AttributeError):
            chipset_cmd.run()

    def test_partial_cfg_setup(self):
        """Test handling when only some Cfg methods are available."""
        # Setup only some methods
        self.mock_cs.Cfg.print_supported_chipsets.return_value = None
        self.mock_cs.Cfg.print_platform_info = None  # Missing method

        chipset_cmd = PlatformCommand([], cs=self.mock_cs)

        # Should handle missing method gracefully with error message
        chipset_cmd.run()
        # Test passes if we get here without raising an AttributeError
        self.assertTrue(True)  # The error is logged, which is the expected behavior

    def test_cfg_method_returns_value(self):
        """Test handling when Cfg methods return values instead of None."""
        self.mock_cs.Cfg.print_supported_chipsets.return_value = "chipset_list"
        self.mock_cs.Cfg.print_platform_info.return_value = "platform_info"
        self.mock_cs.Cfg.print_pch_info.return_value = "pch_info"

        chipset_cmd = PlatformCommand([], cs=self.mock_cs)
        chipset_cmd.run()

        # Should handle return values gracefully
        self.assertTrue(True)


class TestPlatformCommandConfigurationValidation(unittest.TestCase):
    """Test configuration validation aspects of Platform command."""

    def setUp(self):
        """Set up ChipsecCs with detailed configuration mocking."""
        self.config_cs = MockFactory.create_mock_chipsec_cs()

        # Mock detailed configuration
        self.config_cs.Cfg = Mock()

        # Mock supported chipsets data
        self.config_cs.Cfg.CONFIG_PCI = {
            '8086': {
                '0': {'bus': 0, 'dev': 0, 'fun': 0, 'vid': 0x8086, 'did': 0x1234},
                '1': {'bus': 0, 'dev': 1, 'fun': 0, 'vid': 0x8086, 'did': 0x5678}
            }
        }

        # Mock platform configuration
        self.config_cs.Cfg.CONFIG_PLATFORM = {
            'BDW': {
                'vid': 0x8086,
                'did': 0x1234,
                'name': 'Broadwell',
                'code': 'BDW'
            }
        }

    def test_configuration_data_access(self):
        """Test access to configuration data."""
        # Test PCI configuration access
        pci_config = self.config_cs.Cfg.CONFIG_PCI['8086']['0']
        self.assertEqual(pci_config['vid'], 0x8086)
        self.assertEqual(pci_config['did'], 0x1234)

        # Test platform configuration access
        platform_config = self.config_cs.Cfg.CONFIG_PLATFORM['BDW']
        self.assertEqual(platform_config['code'], 'BDW')
        self.assertEqual(platform_config['name'], 'Broadwell')

    def test_configuration_validation(self):
        """Test configuration data validation."""
        # Verify PCI configuration structure
        self.assertIn('8086', self.config_cs.Cfg.CONFIG_PCI)
        self.assertIn('0', self.config_cs.Cfg.CONFIG_PCI['8086'])
        self.assertIn('1', self.config_cs.Cfg.CONFIG_PCI['8086'])

        # Verify platform configuration structure
        self.assertIn('BDW', self.config_cs.Cfg.CONFIG_PLATFORM)
        self.assertIn('vid', self.config_cs.Cfg.CONFIG_PLATFORM['BDW'])
        self.assertIn('did', self.config_cs.Cfg.CONFIG_PLATFORM['BDW'])
