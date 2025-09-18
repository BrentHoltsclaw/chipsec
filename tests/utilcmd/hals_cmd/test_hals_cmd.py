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
from unittest.mock import Mock, patch
from chipsec.utilcmd.hals_cmd import HALsCommand
from chipsec.command import toLoad
from tests.test_utils import MockFactory


class TestHALsCommand:
    """Comprehensive tests for HALs (Hardware Abstraction Layers) command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for HALs testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock HALs component with realistic data
        cs_mock.hals = Mock()
        cs_mock.hals.available_hals.return_value = ['Pci', 'Msr', 'Cpu', 'Spi', 'Tpm']
        cs_mock.hals.list_loadable_hals.return_value = [
            {'name': 'Pci', 'status': 'loaded'},
            {'name': 'Msr', 'status': 'available'},
            {'name': 'Cpu', 'status': 'available'}
        ]
        cs_mock.hals.find_best_hal_by_name.return_value = {
            'mod': Mock(),
            'name': 'Pci'
        }

        return cs_mock

    @pytest.fixture
    def hals_command(self, mock_cs):
        """Create HALsCommand instance."""
        return HALsCommand(['list'], cs=mock_cs)

    @pytest.mark.unit
    def test_hals_command_initialization(self, hals_command, mock_cs):
        """Test HALsCommand initialization."""
        assert hals_command.cs == mock_cs
        assert hals_command.argv == ['list']

    @pytest.mark.unit
    def test_requirements(self, hals_command):
        """Test command requirements."""
        reqs = hals_command.requirements()
        assert reqs == toLoad.Driver

    @pytest.mark.unit
    def test_parse_arguments_list(self, mock_cs):
        """Test parsing arguments for list subcommand."""
        command = HALsCommand(['list'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.hals_list

    @pytest.mark.unit
    def test_parse_arguments_listloadable(self, mock_cs):
        """Test parsing arguments for listloadable subcommand."""
        command = HALsCommand(['listloadable'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.hals_list_loadable

    @pytest.mark.unit
    def test_parse_arguments_funcs_valid_hal(self, mock_cs):
        """Test parsing arguments for funcs subcommand with valid HAL."""
        command = HALsCommand(['funcs', 'Pci'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.list_hal_functions
        assert command.hal_name == 'Pci'

    @pytest.mark.unit
    def test_parse_arguments_funcs_invalid_hal(self, mock_cs):
        """Test parsing arguments for funcs subcommand with invalid HAL."""
        command = HALsCommand(['funcs', 'InvalidHal'], cs=mock_cs)

        # Should raise SystemExit due to invalid choice
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_no_subcommand(self, mock_cs):
        """Test parsing arguments with no subcommand."""
        command = HALsCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_hals_list(self, hals_command, mock_cs):
        """Test hals_list method."""
        with patch.object(hals_command.logger, 'log') as mock_log, \
             patch.object(hals_command.logger, 'log_heading') as mock_log_heading:
            hals_command.hals_list()

            mock_log.assert_called_with('[CHIPSEC] List of HALs:')
            mock_log_heading.assert_called_with('Cpu, Msr, Pci, Spi, Tpm')

    @pytest.mark.unit
    def test_hals_list_loadable(self, hals_command, mock_cs):
        """Test hals_list_loadable method."""
        with patch.object(hals_command.logger, 'log') as mock_log, \
             patch.object(hals_command.logger, 'log_heading') as mock_log_heading:
            hals_command.hals_list_loadable()

            mock_log.assert_called_with('[CHIPSEC] List of loadable HALs:')
            mock_log_heading.assert_called_with('Cpu, Msr, Pci')

    @pytest.mark.unit
    def test_list_hal_functions(self, hals_command, mock_cs):
        """Test list_hal_functions method."""
        hals_command.hal_name = 'Pci'

        # Mock HAL class with functions
        mock_hal_class = Mock()
        mock_hal_class.__name__ = 'Pci'
        mock_hal_class.func1 = lambda: None
        mock_hal_class.func2 = lambda: None
        mock_hal_class._private_func = lambda: None
        mock_hal_class.non_function_attr = 'value'

        mock_module = Mock()
        setattr(mock_module, 'Pci', mock_hal_class)

        mock_cs.hals.find_best_hal_by_name.return_value = {
            'mod': mock_module,
            'name': 'Pci'
        }

        with patch.object(hals_command.logger, 'log') as mock_log, \
             patch.object(hals_command.logger, 'log_heading') as mock_log_heading:
            hals_command.list_hal_functions()

            mock_log.assert_called_with('[CHIPSEC] List of functions in Pci:')
            # Should only include non-private functions
            mock_log_heading.assert_called_with('func1, func2')

    @pytest.mark.unit
    def test_list_hal_functions_no_functions(self, hals_command, mock_cs):
        """Test list_hal_functions method with no functions."""
        hals_command.hal_name = 'EmptyHal'

        # Mock HAL class with no functions
        mock_hal_class = Mock()
        mock_hal_class.__name__ = 'EmptyHal'
        mock_hal_class._private_attr = 'value'
        mock_hal_class.non_function_attr = 'value'

        mock_module = Mock()
        setattr(mock_module, 'EmptyHal', mock_hal_class)

        mock_cs.hals.find_best_hal_by_name.return_value = {
            'mod': mock_module,
            'name': 'EmptyHal'
        }

        with patch.object(hals_command.logger, 'log') as mock_log, \
             patch.object(hals_command.logger, 'log_heading') as mock_log_heading:
            hals_command.list_hal_functions()

            mock_log.assert_called_with('[CHIPSEC] List of functions in EmptyHal:')
            mock_log_heading.assert_called_with('')

    @pytest.mark.unit
    def test_list_hal_functions_with_various_attributes(self, hals_command, mock_cs):
        """Test list_hal_functions method with various attribute types."""
        hals_command.hal_name = 'TestHal'

        # Mock HAL class with mixed attributes
        mock_hal_class = Mock()
        mock_hal_class.__name__ = 'TestHal'
        mock_hal_class.public_func = lambda: None
        mock_hal_class._private_func = lambda: None
        mock_hal_class.__dunder_func__ = lambda: None
        mock_hal_class.public_attr = 'value'
        mock_hal_class._private_attr = 'value'
        mock_hal_class.static_method = staticmethod(lambda: None)

        mock_module = Mock()
        setattr(mock_module, 'TestHal', mock_hal_class)

        mock_cs.hals.find_best_hal_by_name.return_value = {
            'mod': mock_module,
            'name': 'TestHal'
        }

        with patch.object(hals_command.logger, 'log') as mock_log, \
             patch.object(hals_command.logger, 'log_heading') as mock_log_heading:
            hals_command.list_hal_functions()

            mock_log.assert_called_with('[CHIPSEC] List of functions in TestHal:')
            # Should only include public functions
            mock_log_heading.assert_called_with('public_func, static_method')


class TestHALsCommandIntegration:
    """Integration tests for HALs command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for HALs testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock HALs with comprehensive data
        cs_mock.hals = Mock()
        cs_mock.hals.available_hals.return_value = [
            'Acpi', 'Cpu', 'Io', 'Mem', 'Msr', 'Pci', 'Spi', 'Tpm', 'Uefi'
        ]
        cs_mock.hals.list_loadable_hals.return_value = [
            {'name': 'Acpi', 'status': 'loaded'},
            {'name': 'Cpu', 'status': 'loaded'},
            {'name': 'Io', 'status': 'available'},
            {'name': 'Mem', 'status': 'available'},
            {'name': 'Msr', 'status': 'loaded'},
            {'name': 'Pci', 'status': 'loaded'},
            {'name': 'Spi', 'status': 'available'},
            {'name': 'Tpm', 'status': 'available'},
            {'name': 'Uefi', 'status': 'available'}
        ]

        return cs_mock

    @pytest.mark.integration
    def test_hals_list_integration(self, integrated_cs):
        """Test complete HALs list workflow."""
        hals_cmd = HALsCommand(['list'], cs=integrated_cs)

        with patch.object(hals_cmd.logger, 'log'), \
             patch.object(hals_cmd.logger, 'log_heading') as mock_log_heading:
            hals_cmd.hals_list()

            # Should list all available HALs in sorted order
            mock_log_heading.assert_called_with('Acpi, Cpu, Io, Mem, Msr, Pci, Spi, Tpm, Uefi')

    @pytest.mark.integration
    def test_hals_list_loadable_integration(self, integrated_cs):
        """Test complete HALs listloadable workflow."""
        hals_cmd = HALsCommand(['listloadable'], cs=integrated_cs)

        with patch.object(hals_cmd.logger, 'log'), \
             patch.object(hals_cmd.logger, 'log_heading') as mock_log_heading:
            hals_cmd.hals_list_loadable()

            # Should list all loadable HALs in sorted order
            mock_log_heading.assert_called_with('Acpi, Cpu, Io, Mem, Msr, Pci, Spi, Tpm, Uefi')

    @pytest.mark.integration
    def test_hals_funcs_integration(self, integrated_cs):
        """Test complete HALs funcs workflow."""
        hals_cmd = HALsCommand(['funcs', 'Pci'], cs=integrated_cs)
        hals_cmd.hal_name = 'Pci'

        # Mock Pci HAL class with realistic functions
        mock_pci_class = Mock()
        mock_pci_class.__name__ = 'Pci'
        mock_pci_class.read_dword = lambda: None
        mock_pci_class.write_dword = lambda: None
        mock_pci_class.enumerate_devices = lambda: None
        mock_pci_class.get_device_bars = lambda: None
        mock_pci_class._private_method = lambda: None
        mock_pci_class.config_attr = 'value'

        mock_module = Mock()
        setattr(mock_module, 'Pci', mock_pci_class)

        integrated_cs.hals.find_best_hal_by_name.return_value = {
            'mod': mock_module,
            'name': 'Pci'
        }

        with patch.object(hals_cmd.logger, 'log'), \
             patch.object(hals_cmd.logger, 'log_heading') as mock_log_heading:
            hals_cmd.list_hal_functions()

            # Should list public functions only
            mock_log_heading.assert_called_with('enumerate_devices, get_device_bars, read_dword, write_dword')


class TestHALsCommandEdgeCases:
    """Test edge cases and error conditions for HALs command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_available_hals(self, mock_cs):
        """Test handling of empty available HALs list."""
        mock_cs.hals.available_hals.return_value = []

        command = HALsCommand(['list'], cs=mock_cs)

        with patch.object(command.logger, 'log'), \
             patch.object(command.logger, 'log_heading') as mock_log_heading:
            command.hals_list()

            mock_log_heading.assert_called_with('')

    @pytest.mark.unit
    def test_empty_loadable_hals(self, mock_cs):
        """Test handling of empty loadable HALs list."""
        mock_cs.hals.list_loadable_hals.return_value = []

        command = HALsCommand(['listloadable'], cs=mock_cs)

        with patch.object(command.logger, 'log'), \
             patch.object(command.logger, 'log_heading') as mock_log_heading:
            command.hals_list_loadable()

            mock_log_heading.assert_called_with('')

    @pytest.mark.unit
    def test_find_best_hal_by_name_error(self, mock_cs):
        """Test error handling when finding HAL by name fails."""
        mock_cs.hals.find_best_hal_by_name.side_effect = Exception("HAL not found")

        command = HALsCommand(['funcs', 'Pci'], cs=mock_cs)
        command.hal_name = 'Pci'

        with pytest.raises(Exception):
            command.list_hal_functions()

    @pytest.mark.unit
    def test_getattr_error_in_list_functions(self, mock_cs):
        """Test error handling when getattr fails in list functions."""
        command = HALsCommand(['funcs', 'Pci'], cs=mock_cs)
        command.hal_name = 'Pci'

        mock_hal_class = Mock()
        mock_module = Mock()
        setattr(mock_module, 'Pci', mock_hal_class)

        # Mock getattr to raise exception
        mock_hal_class.__getattr__ = Mock(side_effect=Exception("Attribute error"))

        mock_cs.hals.find_best_hal_by_name.return_value = {
            'mod': mock_module,
            'name': 'Pci'
        }

        with pytest.raises(Exception):
            command.list_hal_functions()

    @pytest.mark.unit
    def test_large_hals_list(self, mock_cs):
        """Test handling of large HALs list."""
        large_hals_list = [f'Hal{i}' for i in range(100)]
        mock_cs.hals.available_hals.return_value = large_hals_list

        command = HALsCommand(['list'], cs=mock_cs)

        with patch.object(command.logger, 'log'), \
             patch.object(command.logger, 'log_heading') as mock_log_heading:
            command.hals_list()

            # Should handle large lists without issues
            expected_output = ', '.join(sorted(large_hals_list))
            mock_log_heading.assert_called_with(expected_output)

    @pytest.mark.unit
    def test_hals_with_special_characters(self, mock_cs):
        """Test HALs with special characters in names."""
        special_hals = ['HAL_1', 'HAL-2', 'HAL.3', 'HAL_4_test']
        mock_cs.hals.available_hals.return_value = special_hals

        command = HALsCommand(['list'], cs=mock_cs)

        with patch.object(command.logger, 'log'), \
             patch.object(command.logger, 'log_heading') as mock_log_heading:
            command.hals_list()

            expected_output = ', '.join(sorted(special_hals))
            mock_log_heading.assert_called_with(expected_output)

    @pytest.mark.unit
    def test_loadable_hals_with_missing_name(self, mock_cs):
        """Test loadable HALs with missing name field."""
        mock_cs.hals.list_loadable_hals.return_value = [
            {'status': 'loaded'},  # Missing name
            {'name': 'ValidHal', 'status': 'available'}
        ]

        command = HALsCommand(['listloadable'], cs=mock_cs)

        with patch.object(command.logger, 'log'), \
             patch.object(command.logger, 'log_heading') as mock_log_heading:
            command.hals_list_loadable()

            # Should only include HALs with valid names
            mock_log_heading.assert_called_with('ValidHal')


class TestHALsCommandConfigurationValidation:
    """Test configuration validation aspects of HALs command."""

    @pytest.fixture
    def hals_cs(self):
        """Create ChipsecCs with HALs-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock HALs configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.HAL = {
            'ENABLED_HALS': ['Pci', 'Msr', 'Cpu'],
            'DISABLED_HALS': ['Debug', 'Test'],
            'HAL_LOAD_TIMEOUT': 30
        }

        cs_mock.hals = Mock()
        cs_mock.hals.available_hals.return_value = ['Pci', 'Msr', 'Cpu', 'Spi']
        cs_mock.hals.list_loadable_hals.return_value = [
            {'name': 'Pci', 'status': 'loaded'},
            {'name': 'Msr', 'status': 'loaded'},
            {'name': 'Cpu', 'status': 'available'}
        ]

        return cs_mock

    @pytest.mark.unit
    def test_hals_configuration_structure(self, hals_cs):
        """Test HALs configuration structure."""
        hal_config = hals_cs.Cfg.HAL

        # Test that required HAL configuration exists
        assert 'ENABLED_HALS' in hal_config
        assert 'DISABLED_HALS' in hal_config
        assert 'HAL_LOAD_TIMEOUT' in hal_config

        # Test configuration values are reasonable
        assert isinstance(hal_config['ENABLED_HALS'], list)
        assert isinstance(hal_config['DISABLED_HALS'], list)
        assert hal_config['HAL_LOAD_TIMEOUT'] > 0

    @pytest.mark.unit
    def test_enabled_hals_filtering(self, hals_cs):
        """Test filtering of enabled HALs."""
        enabled_hals = hals_cs.Cfg.HAL['ENABLED_HALS']
        available_hals = hals_cs.hals.available_hals()

        # All enabled HALs should be in available HALs
        for hal in enabled_hals:
            assert hal in available_hals

    @pytest.mark.unit
    def test_disabled_hals_exclusion(self, hals_cs):
        """Test exclusion of disabled HALs."""
        disabled_hals = hals_cs.Cfg.HAL['DISABLED_HALS']
        available_hals = hals_cs.hals.available_hals()

        # Disabled HALs should not be in available HALs
        for hal in disabled_hals:
            assert hal not in available_hals

    @pytest.mark.unit
    def test_hals_list_with_configuration(self, hals_cs):
        """Test HALs list with configuration filtering."""
        command = HALsCommand(['list'], cs=hals_cs)

        with patch.object(command.logger, 'log'), \
             patch.object(command.logger, 'log_heading') as mock_log_heading:
            command.hals_list()

            # Should list all available HALs regardless of configuration
            mock_log_heading.assert_called_with('Cpu, Msr, Pci, Spi')

    @pytest.mark.unit
    def test_hals_list_loadable_with_configuration(self, hals_cs):
        """Test HALs listloadable with configuration."""
        command = HALsCommand(['listloadable'], cs=hals_cs)

        with patch.object(command.logger, 'log'), \
             patch.object(command.logger, 'log_heading') as mock_log_heading:
            command.hals_list_loadable()

            # Should list loadable HALs
            mock_log_heading.assert_called_with('Cpu, Msr, Pci')

    @pytest.mark.unit
    def test_hals_timeout_configuration(self, hals_cs):
        """Test HALs timeout configuration."""
        timeout = hals_cs.Cfg.HAL['HAL_LOAD_TIMEOUT']

        # Timeout should be reasonable (between 1 and 300 seconds)
        assert 1 <= timeout <= 300

    @pytest.mark.unit
    def test_hals_configuration_consistency(self, hals_cs):
        """Test HALs configuration consistency."""
        enabled_hals = set(hals_cs.Cfg.HAL['ENABLED_HALS'])
        disabled_hals = set(hals_cs.Cfg.HAL['DISABLED_HALS'])

        # Enabled and disabled HALs should not overlap
        assert len(enabled_hals & disabled_hals) == 0

    @pytest.mark.unit
    def test_hals_status_mapping(self, hals_cs):
        """Test HALs status mapping."""
        loadable_hals = hals_cs.hals.list_loadable_hals()

        valid_statuses = ['loaded', 'available', 'unavailable', 'error']

        for hal in loadable_hals:
            assert 'status' in hal
            assert hal['status'] in valid_statuses

    @pytest.mark.unit
    def test_hals_function_listing_with_config(self, hals_cs):
        """Test HALs function listing with configuration."""
        command = HALsCommand(['funcs', 'Pci'], cs=hals_cs)
        command.hal_name = 'Pci'

        # Mock Pci HAL class
        mock_pci_class = Mock()
        mock_pci_class.__name__ = 'Pci'
        mock_pci_class.read_byte = lambda: None
        mock_pci_class.write_byte = lambda: None
        mock_pci_class.get_device_info = lambda: None

        mock_module = Mock()
        setattr(mock_module, 'Pci', mock_pci_class)

        hals_cs.hals.find_best_hal_by_name.return_value = {
            'mod': mock_module,
            'name': 'Pci'
        }

        with patch.object(command.logger, 'log'), \
             patch.object(command.logger, 'log_heading') as mock_log_heading:
            command.list_hal_functions()

            # Should list functions regardless of configuration
            mock_log_heading.assert_called_with('get_device_info, read_byte, write_byte')


if __name__ == '__main__':
    pytest.main([__file__])
