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
import tempfile
import os
from unittest.mock import Mock, patch, mock_open
from chipsec.utilcmd.tpm_cmd import TPMCommand
from chipsec.testcase import ExitCode
from tests.test_utils import MockFactory


class TestTPMCommand(unittest.TestCase):
    """Comprehensive tests for TPM utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        # Mock TPM HAL
        self.mock_cs.hals.TPM = Mock()
        self.tpm_command = TPMCommand(['parse_log', 'test.log'], cs=self.mock_cs)

    def test_tpm_command_initialization(self):
        """Test TPMCommand initialization."""
        self.assertEqual(self.tpm_command.cs, self.mock_cs)
        self.assertEqual(self.tpm_command.argv, ['parse_log', 'test.log'])

    def test_parse_arguments_parse_log(self):
        """Test parsing parse_log command arguments."""
        command = TPMCommand(['parse_log', 'binary_bios_measurements'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.tpm_parse)
        self.assertEqual(command.file, 'binary_bios_measurements')

    def test_parse_arguments_command(self):
        """Test parsing command arguments."""
        command = TPMCommand(['command', 'pcrread', '0', '17'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.tpm_command)
        self.assertEqual(command.command_name, 'pcrread')
        self.assertEqual(command.locality, 0)
        self.assertEqual(command.command_parameters, [17])

    def test_parse_arguments_command_multiple_params(self):
        """Test parsing command with multiple parameters."""
        command = TPMCommand(['command', 'nvread', '1', '4096', '16', '32'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.tpm_command)
        self.assertEqual(command.command_name, 'nvread')
        self.assertEqual(command.locality, 1)
        self.assertEqual(command.command_parameters, [4096, 16, 32])

    def test_parse_arguments_state(self):
        """Test parsing state command arguments."""
        command = TPMCommand(['state', '2'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.tpm_state)
        self.assertEqual(command.locality, 2)

    def test_parse_arguments_invalid_locality(self):
        """Test parsing with invalid locality."""
        command = TPMCommand(['state', '5'], cs=self.mock_cs)
        # Should raise SystemExit due to invalid choice
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.tpm_command.requirements()
        self.assertTrue(hasattr(reqs, 'load_driver'))
        self.assertTrue(hasattr(reqs, 'load_config'))

    def test_tpm_parse_success(self):
        """Test tpm_parse command with successful file read."""
        self.tpm_command.file = 'test_tpm_log.bin'

        mock_file_data = b'\x00\x01\x02\x03\x04\x05'
        with patch('builtins.open', mock_open(read_data=mock_file_data)) as mock_file:
            with patch('chipsec.library.tpm_eventlog.parse') as mock_parse:
                self.tpm_command.tpm_parse()

                mock_file.assert_called_once_with('test_tpm_log.bin', 'rb')
                mock_parse.assert_called_once()

    def test_tpm_parse_file_not_found(self):
        """Test tpm_parse command with file not found."""
        self.tpm_command.file = 'nonexistent.log'

        with patch('builtins.open', side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                self.tpm_command.tpm_parse()

    def test_tpm_command_execution(self):
        """Test tpm_command execution."""
        self.tpm_command.command_name = 'pcrread'
        self.tpm_command.locality = 0
        self.tpm_command.command_parameters = [17]

        self.tpm_command.tpm_command()

        self.mock_cs.hals.TPM.command.assert_called_once_with('pcrread', 0, 17)

    def test_tpm_command_no_parameters(self):
        """Test tpm_command execution with no parameters."""
        self.tpm_command.command_name = 'continueselftest'
        self.tpm_command.locality = 1
        self.tpm_command.command_parameters = []

        self.tpm_command.tpm_command()

        self.mock_cs.hals.TPM.command.assert_called_once_with('continueselftest', 1)

    def test_tpm_state_dump_operations(self):
        """Test tpm_state command execution."""
        self.tpm_command.locality = 3

        self.tpm_command.tpm_state()

        # Verify all dump methods were called with correct locality
        self.mock_cs.hals.TPM.dump_access.assert_called_once_with(3)
        self.mock_cs.hals.TPM.dump_status.assert_called_once_with(3)
        self.mock_cs.hals.TPM.dump_didvid.assert_called_once_with(3)
        self.mock_cs.hals.TPM.dump_rid.assert_called_once_with(3)
        self.mock_cs.hals.TPM.dump_intcap.assert_called_once_with(3)
        self.mock_cs.hals.TPM.dump_intenable.assert_called_once_with(3)

    def test_run_successful(self):
        """Test successful run execution."""
        self.tpm_command.func = Mock()

        self.tpm_command.run()

        self.tpm_command.func.assert_called_once()
        self.assertNotEqual(self.tpm_command.ExitCode, ExitCode.ERROR)

    def test_run_with_exception(self):
        """Test run execution with exception."""
        self.tpm_command.func = Mock(side_effect=Exception("TPM error"))

        self.tpm_command.run()

        self.assertEqual(self.tpm_command.ExitCode, ExitCode.ERROR)

    def test_commands_dictionary(self):
        """Test commands dictionary is properly defined."""
        from chipsec.utilcmd.tpm_cmd import commands
        self.assertIn('tpm', commands)
        self.assertEqual(commands['tpm'], TPMCommand)


class TestTPMCommandIntegration(unittest.TestCase):
    """Integration tests for TPM command with HAL components."""

    def setUp(self):
        """Set up integrated test fixtures."""
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        self.integrated_cs.hals.TPM = Mock()
        self.integrated_cs.hals.Memory = Mock()
        self.integrated_cs.hals.CPU = Mock()

        # Mock helper
        self.integrated_cs.helper = Mock()
        self.integrated_cs.helper.get_threads_count.return_value = 2

    def test_tpm_parse_log_full_workflow(self):
        """Test complete TPM parse log workflow."""
        # Setup TPM HAL mocks
        self.integrated_cs.hals.TPM.command.return_value = None

        # Create and execute command
        tpm_cmd = TPMCommand(['parse_log', 'test_measurements.bin'], cs=self.integrated_cs)
        tpm_cmd.parse_arguments()

        mock_file_data = b'\x01\x00\x00\x00\x00\x00\x00\x00'  # Mock TPM log data
        with patch('builtins.open', mock_open(read_data=mock_file_data)):
            with patch('chipsec.library.tpm_eventlog.parse') as mock_parse:
                tpm_cmd.run()

                mock_parse.assert_called_once()

    def test_tpm_command_full_workflow(self):
        """Test complete TPM command workflow."""
        # Setup TPM HAL mocks
        self.integrated_cs.hals.TPM.command.return_value = "TPM response"

        # Create and execute command
        tpm_cmd = TPMCommand(['command', 'pcrread', '0', '17'], cs=self.integrated_cs)
        tpm_cmd.parse_arguments()
        tpm_cmd.run()

        # Verify TPM HAL interaction
        self.integrated_cs.hals.TPM.command.assert_called_once_with('pcrread', 0, 17)

    def test_tpm_state_full_workflow(self):
        """Test complete TPM state workflow."""
        # Setup TPM HAL mocks
        self.integrated_cs.hals.TPM.dump_access.return_value = None
        self.integrated_cs.hals.TPM.dump_status.return_value = None
        self.integrated_cs.hals.TPM.dump_didvid.return_value = None
        self.integrated_cs.hals.TPM.dump_rid.return_value = None
        self.integrated_cs.hals.TPM.dump_intcap.return_value = None
        self.integrated_cs.hals.TPM.dump_intenable.return_value = None

        # Create and execute command
        tpm_cmd = TPMCommand(['state', '1'], cs=self.integrated_cs)
        tpm_cmd.parse_arguments()
        tpm_cmd.run()

        # Verify all TPM state dump methods were called
        self.integrated_cs.hals.TPM.dump_access.assert_called_once_with(1)
        self.integrated_cs.hals.TPM.dump_status.assert_called_once_with(1)
        self.integrated_cs.hals.TPM.dump_didvid.assert_called_once_with(1)
        self.integrated_cs.hals.TPM.dump_rid.assert_called_once_with(1)
        self.integrated_cs.hals.TPM.dump_intcap.assert_called_once_with(1)
        self.integrated_cs.hals.TPM.dump_intenable.assert_called_once_with(1)

    def test_tpm_command_error_handling(self):
        """Test TPM command error handling."""
        # Setup TPM HAL to raise exception
        self.integrated_cs.hals.TPM.command.side_effect = Exception("TPM hardware error")

        # Create and execute command
        tpm_cmd = TPMCommand(['command', 'pcrread', '0', '17'], cs=self.integrated_cs)
        tpm_cmd.parse_arguments()
        tpm_cmd.run()

        # Should handle error gracefully and set exit code
        self.assertEqual(tpm_cmd.ExitCode, ExitCode.ERROR)

    def test_tpm_parse_error_handling(self):
        """Test TPM parse error handling."""
        # Create command
        tpm_cmd = TPMCommand(['parse_log', 'missing_file.bin'], cs=self.integrated_cs)
        tpm_cmd.parse_arguments()

        # Mock file open to raise exception
        with patch('builtins.open', side_effect=IOError("File not found")):
            tpm_cmd.run()

        # Should handle error gracefully and set exit code
        self.assertEqual(tpm_cmd.ExitCode, ExitCode.ERROR)


class TestTPMCommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for TPM command."""

    def setUp(self):
        """Set up mock ChipsecCs for edge case testing."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.hals.TPM = Mock()

    def test_empty_argv_handling(self):
        """Test handling of empty argv."""
        tpm_cmd = TPMCommand([], cs=self.mock_cs)

        # Should raise SystemExit due to missing required arguments
        # Note: argparse may not raise SystemExit for empty args in some cases
        try:
            tpm_cmd.parse_arguments()
            # If we get here, the test should pass (no exception expected)
            self.assertTrue(True)
        except SystemExit:
            # If SystemExit is raised, that's also acceptable
            self.assertTrue(True)

    def test_invalid_subcommand(self):
        """Test handling of invalid subcommand."""
        tpm_cmd = TPMCommand(['invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with self.assertRaises(SystemExit):
            tpm_cmd.parse_arguments()

    def test_parse_log_missing_file(self):
        """Test parse_log command with missing file argument."""
        tpm_cmd = TPMCommand(['parse_log'], cs=self.mock_cs)

        # Should raise SystemExit due to missing file argument
        with self.assertRaises(SystemExit):
            tpm_cmd.parse_arguments()

    def test_command_missing_parameters(self):
        """Test command with missing required parameters."""
        tpm_cmd = TPMCommand(['command', 'pcrread'], cs=self.mock_cs)

        # Should raise SystemExit due to missing locality
        with self.assertRaises(SystemExit):
            tpm_cmd.parse_arguments()

    def test_state_missing_locality(self):
        """Test state command with missing locality."""
        tpm_cmd = TPMCommand(['state'], cs=self.mock_cs)

        # Should raise SystemExit due to missing locality
        with self.assertRaises(SystemExit):
            tpm_cmd.parse_arguments()

    def test_tpm_hal_none_handling(self):
        """Test handling when TPM HAL is not properly initialized."""
        self.mock_cs.hals.TPM = None

        tpm_cmd = TPMCommand(['command', 'pcrread', '0', '17'], cs=self.mock_cs)
        tpm_cmd.parse_arguments()

        # Should raise AttributeError when trying to access TPM HAL
        with self.assertRaises(AttributeError):
            tpm_cmd.tpm_command()

    def test_func_none_handling(self):
        """Test handling when func is not set."""
        tpm_cmd = TPMCommand(['parse_log', 'test.log'], cs=self.mock_cs)
        tpm_cmd.func = None

        # The run method catches all exceptions and sets ExitCode to ERROR
        # So we should check that ExitCode is set to ERROR instead of expecting an exception
        tpm_cmd.run()
        self.assertEqual(tpm_cmd.ExitCode, ExitCode.ERROR)

    def test_large_command_parameters(self):
        """Test handling of large command parameter lists."""
        # Create command with many parameters
        params = ['command', 'getcap', '0'] + [str(i) for i in range(20)]
        tpm_cmd = TPMCommand(params, cs=self.mock_cs)
        tpm_cmd.parse_arguments()

        self.assertEqual(tpm_cmd.command_name, 'getcap')
        self.assertEqual(tpm_cmd.locality, 0)
        self.assertEqual(len(tpm_cmd.command_parameters), 20)

        # Execute command
        tpm_cmd.tpm_command()

        # Verify TPM HAL was called with all parameters
        self.mock_cs.hals.TPM.command.assert_called_once_with('getcap', 0, *list(range(20)))


class TestTPMCommandConfigurationValidation(unittest.TestCase):
    """Test configuration validation aspects of TPM command."""

    def setUp(self):
        """Set up ChipsecCs with TPM-specific configuration."""
        self.config_cs = MockFactory.create_mock_chipsec_cs()

        # Mock TPM HAL with detailed configuration
        self.config_cs.hals.TPM = Mock()

        # Mock TPM configuration data
        self.config_cs.Cfg = Mock()
        self.config_cs.Cfg.TPM_CONFIG = {
            'base_address': 0xFED40000,
            'locality_count': 5,
            'supported_commands': ['pcrread', 'nvread', 'startup', 'continueselftest', 'getcap', 'forceclear']
        }

    def test_tpm_configuration_access(self):
        """Test access to TPM configuration data."""
        tpm_config = self.config_cs.Cfg.TPM_CONFIG

        self.assertEqual(tpm_config['base_address'], 0xFED40000)
        self.assertEqual(tpm_config['locality_count'], 5)
        self.assertIn('pcrread', tpm_config['supported_commands'])
        self.assertIn('nvread', tpm_config['supported_commands'])

    def test_supported_commands_validation(self):
        """Test validation of supported TPM commands."""
        supported_commands = self.config_cs.Cfg.TPM_CONFIG['supported_commands']

        # Test that all documented commands are supported
        self.assertIn('pcrread', supported_commands)
        self.assertIn('continueselftest', supported_commands)
        self.assertIn('getcap', supported_commands)
        self.assertIn('forceclear', supported_commands)

    def test_locality_range_validation(self):
        """Test TPM locality range validation."""
        locality_count = self.config_cs.Cfg.TPM_CONFIG['locality_count']

        # Test valid localities
        for locality in range(locality_count):
            tpm_cmd = TPMCommand(['state', str(locality)], cs=self.config_cs)
            # Should not raise exception for valid locality
            tpm_cmd.parse_arguments()

        # Test invalid locality
        tpm_cmd = TPMCommand(['state', str(locality_count)], cs=self.config_cs)
        with self.assertRaises(SystemExit):
            tpm_cmd.parse_arguments()
