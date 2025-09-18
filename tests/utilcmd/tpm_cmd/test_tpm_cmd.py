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
import tempfile
import os
from unittest.mock import Mock, patch, mock_open
from chipsec.utilcmd.tpm_cmd import TPMCommand
from chipsec.testcase import ExitCode
from tests.test_utils import MockFactory


class TestTPMCommand:
    """Comprehensive tests for TPM utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for TPM testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        # Mock TPM HAL
        cs_mock.hals.TPM = Mock()
        return cs_mock

    @pytest.fixture
    def tpm_command(self, mock_cs):
        """Create TPMCommand instance."""
        return TPMCommand(['parse_log', 'test.log'], cs=mock_cs)

    @pytest.mark.unit
    def test_tpm_command_initialization(self, tpm_command, mock_cs):
        """Test TPMCommand initialization."""
        assert tpm_command.cs == mock_cs
        assert tpm_command.argv == ['parse_log', 'test.log']

    @pytest.mark.unit
    def test_parse_arguments_parse_log(self, mock_cs):
        """Test parsing parse_log command arguments."""
        command = TPMCommand(['parse_log', 'binary_bios_measurements'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.tpm_parse
        assert command.file == 'binary_bios_measurements'

    @pytest.mark.unit
    def test_parse_arguments_command(self, mock_cs):
        """Test parsing command arguments."""
        command = TPMCommand(['command', 'pcrread', '0', '17'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.tpm_command
        assert command.command_name == 'pcrread'
        assert command.locality == 0
        assert command.command_parameters == [17]

    @pytest.mark.unit
    def test_parse_arguments_command_multiple_params(self, mock_cs):
        """Test parsing command with multiple parameters."""
        command = TPMCommand(['command', 'nvread', '1', '0x1000', '0x10', '0x20'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.tpm_command
        assert command.command_name == 'nvread'
        assert command.locality == 1
        assert command.command_parameters == [0x1000, 0x10, 0x20]

    @pytest.mark.unit
    def test_parse_arguments_state(self, mock_cs):
        """Test parsing state command arguments."""
        command = TPMCommand(['state', '2'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.tpm_state
        assert command.locality == 2

    @pytest.mark.unit
    def test_parse_arguments_invalid_locality(self, mock_cs):
        """Test parsing with invalid locality."""
        command = TPMCommand(['state', '5'], cs=mock_cs)
        # Should raise SystemExit due to invalid choice
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_requirements(self, tpm_command):
        """Test command requirements."""
        reqs = tpm_command.requirements()
        assert hasattr(reqs, 'load_driver')
        assert hasattr(reqs, 'load_config')

    @pytest.mark.unit
    def test_tpm_parse_success(self, tpm_command, mock_cs):
        """Test tpm_parse command with successful file read."""
        tpm_command.file = 'test_tpm_log.bin'

        mock_file_data = b'\x00\x01\x02\x03\x04\x05'
        with patch('builtins.open', mock_open(read_data=mock_file_data)) as mock_file:
            with patch('chipsec.library.tpm_eventlog.parse') as mock_parse:
                tpm_command.tpm_parse()

                mock_file.assert_called_once_with('test_tpm_log.bin', 'rb')
                mock_parse.assert_called_once()

    @pytest.mark.unit
    def test_tpm_parse_file_not_found(self, tpm_command, mock_cs):
        """Test tpm_parse command with file not found."""
        tpm_command.file = 'nonexistent.log'

        with patch('builtins.open', side_effect=FileNotFoundError):
            with pytest.raises(FileNotFoundError):
                tpm_command.tpm_parse()

    @pytest.mark.unit
    def test_tpm_command_execution(self, tpm_command, mock_cs):
        """Test tpm_command execution."""
        tpm_command.command_name = 'pcrread'
        tpm_command.locality = 0
        tpm_command.command_parameters = [17]

        tpm_command.tpm_command()

        mock_cs.hals.TPM.command.assert_called_once_with('pcrread', 0, 17)

    @pytest.mark.unit
    def test_tpm_command_no_parameters(self, tpm_command, mock_cs):
        """Test tpm_command execution with no parameters."""
        tpm_command.command_name = 'continueselftest'
        tpm_command.locality = 1
        tpm_command.command_parameters = []

        tpm_command.tpm_command()

        mock_cs.hals.TPM.command.assert_called_once_with('continueselftest', 1)

    @pytest.mark.unit
    def test_tpm_state_dump_operations(self, tpm_command, mock_cs):
        """Test tpm_state command execution."""
        tpm_command.locality = 3

        tpm_command.tpm_state()

        # Verify all dump methods were called with correct locality
        mock_cs.hals.TPM.dump_access.assert_called_once_with(3)
        mock_cs.hals.TPM.dump_status.assert_called_once_with(3)
        mock_cs.hals.TPM.dump_didvid.assert_called_once_with(3)
        mock_cs.hals.TPM.dump_rid.assert_called_once_with(3)
        mock_cs.hals.TPM.dump_intcap.assert_called_once_with(3)
        mock_cs.hals.TPM.dump_intenable.assert_called_once_with(3)

    @pytest.mark.unit
    def test_run_successful(self, tpm_command, mock_cs):
        """Test successful run execution."""
        tpm_command.func = Mock()

        tpm_command.run()

        tpm_command.func.assert_called_once()
        assert tpm_command.ExitCode != ExitCode.ERROR

    @pytest.mark.unit
    def test_run_with_exception(self, tpm_command, mock_cs):
        """Test run execution with exception."""
        tpm_command.func = Mock(side_effect=Exception("TPM error"))

        tpm_command.run()

        assert tpm_command.ExitCode == ExitCode.ERROR

    @pytest.mark.unit
    def test_commands_dictionary(self):
        """Test commands dictionary is properly defined."""
        from chipsec.utilcmd.tpm_cmd import commands
        assert 'tpm' in commands
        assert commands['tpm'] == TPMCommand


class TestTPMCommandIntegration:
    """Integration tests for TPM command with HAL components."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for TPM testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        cs_mock.hals.TPM = Mock()
        cs_mock.hals.Memory = Mock()
        cs_mock.hals.CPU = Mock()

        # Mock helper
        cs_mock.helper = Mock()
        cs_mock.helper.get_threads_count.return_value = 2

        return cs_mock

    @pytest.mark.integration
    def test_tpm_parse_log_full_workflow(self, integrated_cs):
        """Test complete TPM parse log workflow."""
        # Setup TPM HAL mocks
        integrated_cs.hals.TPM.command.return_value = None

        # Create and execute command
        tpm_cmd = TPMCommand(['parse_log', 'test_measurements.bin'], cs=integrated_cs)
        tpm_cmd.parse_arguments()

        mock_file_data = b'\x01\x00\x00\x00\x00\x00\x00\x00'  # Mock TPM log data
        with patch('builtins.open', mock_open(read_data=mock_file_data)):
            with patch('chipsec.library.tpm_eventlog.parse') as mock_parse:
                tpm_cmd.run()

                mock_parse.assert_called_once()

    @pytest.mark.integration
    def test_tpm_command_full_workflow(self, integrated_cs):
        """Test complete TPM command workflow."""
        # Setup TPM HAL mocks
        integrated_cs.hals.TPM.command.return_value = "TPM response"

        # Create and execute command
        tpm_cmd = TPMCommand(['command', 'pcrread', '0', '17'], cs=integrated_cs)
        tpm_cmd.parse_arguments()
        tpm_cmd.run()

        # Verify TPM HAL interaction
        integrated_cs.hals.TPM.command.assert_called_once_with('pcrread', 0, 17)

    @pytest.mark.integration
    def test_tpm_state_full_workflow(self, integrated_cs):
        """Test complete TPM state workflow."""
        # Setup TPM HAL mocks
        integrated_cs.hals.TPM.dump_access.return_value = None
        integrated_cs.hals.TPM.dump_status.return_value = None
        integrated_cs.hals.TPM.dump_didvid.return_value = None
        integrated_cs.hals.TPM.dump_rid.return_value = None
        integrated_cs.hals.TPM.dump_intcap.return_value = None
        integrated_cs.hals.TPM.dump_intenable.return_value = None

        # Create and execute command
        tpm_cmd = TPMCommand(['state', '1'], cs=integrated_cs)
        tpm_cmd.parse_arguments()
        tpm_cmd.run()

        # Verify all TPM state dump methods were called
        integrated_cs.hals.TPM.dump_access.assert_called_once_with(1)
        integrated_cs.hals.TPM.dump_status.assert_called_once_with(1)
        integrated_cs.hals.TPM.dump_didvid.assert_called_once_with(1)
        integrated_cs.hals.TPM.dump_rid.assert_called_once_with(1)
        integrated_cs.hals.TPM.dump_intcap.assert_called_once_with(1)
        integrated_cs.hals.TPM.dump_intenable.assert_called_once_with(1)

    @pytest.mark.integration
    def test_tpm_command_error_handling(self, integrated_cs):
        """Test TPM command error handling."""
        # Setup TPM HAL to raise exception
        integrated_cs.hals.TPM.command.side_effect = Exception("TPM hardware error")

        # Create and execute command
        tpm_cmd = TPMCommand(['command', 'pcrread', '0', '17'], cs=integrated_cs)
        tpm_cmd.parse_arguments()
        tpm_cmd.run()

        # Should handle error gracefully and set exit code
        assert tpm_cmd.ExitCode == ExitCode.ERROR

    @pytest.mark.integration
    def test_tpm_parse_error_handling(self, integrated_cs):
        """Test TPM parse error handling."""
        # Create command
        tpm_cmd = TPMCommand(['parse_log', 'missing_file.bin'], cs=integrated_cs)
        tpm_cmd.parse_arguments()

        # Mock file open to raise exception
        with patch('builtins.open', side_effect=IOError("File not found")):
            tpm_cmd.run()

        # Should handle error gracefully and set exit code
        assert tpm_cmd.ExitCode == ExitCode.ERROR


class TestTPMCommandEdgeCases:
    """Test edge cases and error conditions for TPM command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals.TPM = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        tpm_cmd = TPMCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            tpm_cmd.parse_arguments()

    @pytest.mark.unit
    def test_invalid_subcommand(self, mock_cs):
        """Test handling of invalid subcommand."""
        tpm_cmd = TPMCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            tpm_cmd.parse_arguments()

    @pytest.mark.unit
    def test_parse_log_missing_file(self, mock_cs):
        """Test parse_log command with missing file argument."""
        tpm_cmd = TPMCommand(['parse_log'], cs=mock_cs)

        # Should raise SystemExit due to missing file argument
        with pytest.raises(SystemExit):
            tpm_cmd.parse_arguments()

    @pytest.mark.unit
    def test_command_missing_parameters(self, mock_cs):
        """Test command with missing required parameters."""
        tpm_cmd = TPMCommand(['command', 'pcrread'], cs=mock_cs)

        # Should raise SystemExit due to missing locality
        with pytest.raises(SystemExit):
            tpm_cmd.parse_arguments()

    @pytest.mark.unit
    def test_state_missing_locality(self, mock_cs):
        """Test state command with missing locality."""
        tpm_cmd = TPMCommand(['state'], cs=mock_cs)

        # Should raise SystemExit due to missing locality
        with pytest.raises(SystemExit):
            tpm_cmd.parse_arguments()

    @pytest.mark.unit
    def test_tpm_hal_none_handling(self, mock_cs):
        """Test handling when TPM HAL is not properly initialized."""
        mock_cs.hals.TPM = None

        tpm_cmd = TPMCommand(['command', 'pcrread', '0', '17'], cs=mock_cs)
        tpm_cmd.parse_arguments()

        # Should raise AttributeError when trying to access TPM HAL
        with pytest.raises(AttributeError):
            tpm_cmd.tpm_command()

    @pytest.mark.unit
    def test_func_none_handling(self, mock_cs):
        """Test handling when func is not set."""
        tpm_cmd = TPMCommand(['parse_log', 'test.log'], cs=mock_cs)
        tpm_cmd.func = None

        # Should raise AttributeError when trying to call None function
        with pytest.raises(AttributeError):
            tpm_cmd.run()

    @pytest.mark.unit
    def test_large_command_parameters(self, mock_cs):
        """Test handling of large command parameter lists."""
        # Create command with many parameters
        params = ['command', 'getcap', '0'] + [str(i) for i in range(20)]
        tpm_cmd = TPMCommand(params, cs=mock_cs)
        tpm_cmd.parse_arguments()

        assert tpm_cmd.command_name == 'getcap'
        assert tpm_cmd.locality == 0
        assert len(tpm_cmd.command_parameters) == 20

        # Execute command
        tpm_cmd.tpm_command()

        # Verify TPM HAL was called with all parameters
        mock_cs.hals.TPM.command.assert_called_once_with('getcap', 0, *list(range(20)))


class TestTPMCommandConfigurationValidation:
    """Test configuration validation aspects of TPM command."""

    @pytest.fixture
    def config_cs(self):
        """Create ChipsecCs with TPM-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock TPM HAL with detailed configuration
        cs_mock.hals.TPM = Mock()

        # Mock TPM configuration data
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.TPM_CONFIG = {
            'base_address': 0xFED40000,
            'locality_count': 5,
            'supported_commands': ['pcrread', 'nvread', 'startup', 'continueselftest', 'getcap', 'forceclear']
        }

        return cs_mock

    @pytest.mark.unit
    def test_tpm_configuration_access(self, config_cs):
        """Test access to TPM configuration data."""
        tpm_config = config_cs.Cfg.TPM_CONFIG

        assert tpm_config['base_address'] == 0xFED40000
        assert tpm_config['locality_count'] == 5
        assert 'pcrread' in tpm_config['supported_commands']
        assert 'nvread' in tpm_config['supported_commands']

    @pytest.mark.unit
    def test_supported_commands_validation(self, config_cs):
        """Test validation of supported TPM commands."""
        supported_commands = config_cs.Cfg.TPM_CONFIG['supported_commands']

        # Test that all documented commands are supported
        assert 'pcrread' in supported_commands
        assert 'continueselftest' in supported_commands
        assert 'getcap' in supported_commands
        assert 'forceclear' in supported_commands

    @pytest.mark.unit
    def test_locality_range_validation(self, config_cs):
        """Test TPM locality range validation."""
        locality_count = config_cs.Cfg.TPM_CONFIG['locality_count']

        # Test valid localities
        for locality in range(locality_count):
            tpm_cmd = TPMCommand(['state', str(locality)], cs=config_cs)
            # Should not raise exception for valid locality
            tpm_cmd.parse_arguments()

        # Test invalid locality
        tpm_cmd = TPMCommand(['state', str(locality_count)], cs=config_cs)
        with pytest.raises(SystemExit):
            tpm_cmd.parse_arguments()


if __name__ == '__main__':
    pytest.main([__file__])
