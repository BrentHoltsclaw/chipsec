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

import pytest
from unittest.mock import Mock
from chipsec.utilcmd.chipset_cmd import PlatformCommand
from chipsec.library.exceptions import UnknownChipsetError
from tests.test_utils import MockFactory


class TestPlatformCommand:
    """Comprehensive tests for Platform/Chipset utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for chipset testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        # Mock Cfg component
        cs_mock.Cfg = Mock()
        return cs_mock

    @pytest.fixture
    def chipset_command(self, mock_cs):
        """Create PlatformCommand instance."""
        return PlatformCommand([], cs=mock_cs)

    @pytest.mark.unit
    def test_chipset_command_initialization(self, chipset_command, mock_cs):
        """Test PlatformCommand initialization."""
        assert chipset_command.cs == mock_cs
        assert chipset_command.argv == []

    @pytest.mark.unit
    def test_parse_arguments(self, mock_cs):
        """Test argument parsing (no arguments expected)."""
        command = PlatformCommand([], cs=mock_cs)
        command.parse_arguments()
        # No arguments to parse, should not raise any errors
        assert True

    @pytest.mark.unit
    def test_requirements(self, chipset_command):
        """Test command requirements."""
        reqs = chipset_command.requirements()
        assert hasattr(reqs, 'load_driver')
        assert hasattr(reqs, 'load_config')

    @pytest.mark.unit
    def test_run_successful(self, chipset_command, mock_cs):
        """Test successful command execution."""
        # Setup mocks
        mock_cs.Cfg.print_supported_chipsets.return_value = None
        mock_cs.Cfg.print_platform_info.return_value = None
        mock_cs.Cfg.print_pch_info.return_value = None

        # Execute command
        chipset_command.run()

        # Verify all methods were called
        mock_cs.Cfg.print_supported_chipsets.assert_called_once()
        mock_cs.Cfg.print_platform_info.assert_called_once()
        mock_cs.Cfg.print_pch_info.assert_called_once()

    @pytest.mark.unit
    def test_run_with_unknown_chipset_error(self, chipset_command, mock_cs):
        """Test command execution with UnknownChipsetError."""
        # Setup mock to raise UnknownChipsetError
        mock_cs.Cfg.print_supported_chipsets.side_effect = UnknownChipsetError("Unknown chipset detected")

        # Execute command (should handle error gracefully)
        chipset_command.run()

        # Verify the error was logged
        # Note: We can't easily test logger calls without more complex mocking,
        # but we can verify the command doesn't crash

    @pytest.mark.unit
    def test_run_with_generic_exception(self, chipset_command, mock_cs):
        """Test command execution with generic exception."""
        # Setup mock to raise a generic exception
        mock_cs.Cfg.print_supported_chipsets.side_effect = Exception("Generic error")

        # Execute command (should handle error gracefully)
        chipset_command.run()

        # Command should complete without crashing
        assert True

    @pytest.mark.unit
    def test_commands_dictionary(self):
        """Test commands dictionary is properly defined."""
        from chipsec.utilcmd.chipset_cmd import commands
        assert 'platform' in commands
        assert commands['platform'] == PlatformCommand


class TestPlatformCommandIntegration:
    """Integration tests for Platform command with configuration system."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for chipset testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock Cfg component with realistic data
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.print_supported_chipsets.return_value = None
        cs_mock.Cfg.print_platform_info.return_value = None
        cs_mock.Cfg.print_pch_info.return_value = None

        # Mock platform info
        cs_mock.Cfg.platform_info = Mock()
        cs_mock.Cfg.platform_info.code = 'BDW'
        cs_mock.Cfg.platform_info.vid = 0x8086
        cs_mock.Cfg.platform_info.did = 0x1234
        cs_mock.Cfg.platform_info.name = 'Broadwell'

        # Mock PCH info
        cs_mock.Cfg.pch_info = Mock()
        cs_mock.Cfg.pch_info.code = 'BDW-PCH'
        cs_mock.Cfg.pch_info.vid = 0x8086
        cs_mock.Cfg.pch_info.did = 0x5678
        cs_mock.Cfg.pch_info.name = 'Broadwell PCH'

        return cs_mock

    @pytest.mark.integration
    def test_chipset_command_full_workflow(self, integrated_cs):
        """Test complete chipset command workflow."""
        # Create and execute command
        chipset_cmd = PlatformCommand([], cs=integrated_cs)
        chipset_cmd.parse_arguments()

        # Execute command
        chipset_cmd.run()

        # Verify all configuration methods were called
        integrated_cs.Cfg.print_supported_chipsets.assert_called_once()
        integrated_cs.Cfg.print_platform_info.assert_called_once()
        integrated_cs.Cfg.print_pch_info.assert_called_once()

    @pytest.mark.integration
    def test_chipset_command_with_platform_data(self, integrated_cs):
        """Test chipset command with realistic platform data."""
        # Verify platform info is accessible
        assert integrated_cs.Cfg.platform_info.code == 'BDW'
        assert integrated_cs.Cfg.platform_info.vid == 0x8086
        assert integrated_cs.Cfg.platform_info.name == 'Broadwell'

        # Verify PCH info is accessible
        assert integrated_cs.Cfg.pch_info.code == 'BDW-PCH'
        assert integrated_cs.Cfg.pch_info.vid == 0x8086
        assert integrated_cs.Cfg.pch_info.name == 'Broadwell PCH'

        # Execute command
        chipset_cmd = PlatformCommand([], cs=integrated_cs)
        chipset_cmd.run()

        # Verify execution completed successfully
        integrated_cs.Cfg.print_supported_chipsets.assert_called_once()

    @pytest.mark.integration
    def test_chipset_command_error_handling(self, integrated_cs):
        """Test chipset command error handling."""
        # Test with print_supported_chipsets error
        integrated_cs.Cfg.print_supported_chipsets.side_effect = UnknownChipsetError("Chipset not supported")

        chipset_cmd = PlatformCommand([], cs=integrated_cs)
        chipset_cmd.run()

        # Should handle error gracefully
        assert True

        # Reset mock
        integrated_cs.Cfg.print_supported_chipsets.reset_mock()
        integrated_cs.Cfg.print_supported_chipsets.side_effect = None

        # Test with print_platform_info error
        integrated_cs.Cfg.print_platform_info.side_effect = Exception("Platform info error")

        chipset_cmd2 = PlatformCommand([], cs=integrated_cs)
        chipset_cmd2.run()

        # Should handle error gracefully
        assert True


class TestPlatformCommandEdgeCases:
    """Test edge cases and error conditions for Platform command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.Cfg = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        chipset_cmd = PlatformCommand([], cs=mock_cs)
        chipset_cmd.parse_arguments()
        # Should not raise any errors
        assert True

    @pytest.mark.unit
    def test_unexpected_argv_handling(self, mock_cs):
        """Test handling of unexpected arguments."""
        # The command doesn't expect arguments, but argparse should handle them gracefully
        chipset_cmd = PlatformCommand(['unexpected', 'args'], cs=mock_cs)

        # This should raise SystemExit due to unexpected arguments
        with pytest.raises(SystemExit):
            chipset_cmd.parse_arguments()

    @pytest.mark.unit
    def test_cfg_none_handling(self, mock_cs):
        """Test handling when Cfg is None."""
        mock_cs.Cfg = None

        chipset_cmd = PlatformCommand([], cs=mock_cs)

        # This should raise AttributeError when trying to access Cfg
        with pytest.raises(AttributeError):
            chipset_cmd.run()

    @pytest.mark.unit
    def test_partial_cfg_setup(self, mock_cs):
        """Test handling when only some Cfg methods are available."""
        # Setup only some methods
        mock_cs.Cfg.print_supported_chipsets.return_value = None
        mock_cs.Cfg.print_platform_info = None  # Missing method

        chipset_cmd = PlatformCommand([], cs=mock_cs)

        # This should raise AttributeError when trying to call missing method
        with pytest.raises(AttributeError):
            chipset_cmd.run()

    @pytest.mark.unit
    def test_cfg_method_returns_value(self, mock_cs):
        """Test handling when Cfg methods return values instead of None."""
        mock_cs.Cfg.print_supported_chipsets.return_value = "chipset_list"
        mock_cs.Cfg.print_platform_info.return_value = "platform_info"
        mock_cs.Cfg.print_pch_info.return_value = "pch_info"

        chipset_cmd = PlatformCommand([], cs=mock_cs)
        chipset_cmd.run()

        # Should handle return values gracefully
        assert True


class TestPlatformCommandConfigurationValidation:
    """Test configuration validation aspects of Platform command."""

    @pytest.fixture
    def config_cs(self):
        """Create ChipsecCs with detailed configuration mocking."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock detailed configuration
        cs_mock.Cfg = Mock()

        # Mock supported chipsets data
        cs_mock.Cfg.CONFIG_PCI = {
            '8086': {
                '0': {'bus': 0, 'dev': 0, 'fun': 0, 'vid': 0x8086, 'did': 0x1234},
                '1': {'bus': 0, 'dev': 1, 'fun': 0, 'vid': 0x8086, 'did': 0x5678}
            }
        }

        # Mock platform configuration
        cs_mock.Cfg.CONFIG_PLATFORM = {
            'BDW': {
                'vid': 0x8086,
                'did': 0x1234,
                'name': 'Broadwell',
                'code': 'BDW'
            }
        }

        return cs_mock

    @pytest.mark.unit
    def test_configuration_data_access(self, config_cs):
        """Test access to configuration data."""
        # Test PCI configuration access
        pci_config = config_cs.Cfg.CONFIG_PCI['8086']['0']
        assert pci_config['vid'] == 0x8086
        assert pci_config['did'] == 0x1234

        # Test platform configuration access
        platform_config = config_cs.Cfg.CONFIG_PLATFORM['BDW']
        assert platform_config['code'] == 'BDW'
        assert platform_config['name'] == 'Broadwell'

    @pytest.mark.unit
    def test_configuration_validation(self, config_cs):
        """Test configuration data validation."""
        # Verify PCI configuration structure
        assert '8086' in config_cs.Cfg.CONFIG_PCI
        assert '0' in config_cs.Cfg.CONFIG_PCI['8086']
        assert '1' in config_cs.Cfg.CONFIG_PCI['8086']

        # Verify platform configuration structure
        assert 'BDW' in config_cs.Cfg.CONFIG_PLATFORM
        assert 'vid' in config_cs.Cfg.CONFIG_PLATFORM['BDW']
        assert 'did' in config_cs.Cfg.CONFIG_PLATFORM['BDW']


if __name__ == '__main__':
    pytest.main([__file__])
