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

"""
This test module verifies the ACPI command implementation
"""

import unittest
from unittest.mock import Mock, patch
from chipsec.utilcmd.acpi_cmd import ACPICommand
from tests.test_utils import MockFactory


class TestACPICommand(unittest.TestCase):
    """Comprehensive tests for ACPI utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock ChipsecCs object for ACPI testing
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        # Mock ACPI HAL
        self.mock_cs.hals.ACPI = Mock()

        # Create ACPICommand instance
        self.acpi_command = ACPICommand(['list'], cs=self.mock_cs)

    def test_acpi_command_initialization(self):
        """Test ACPICommand initialization."""
        self.assertEqual(self.acpi_command.cs, self.mock_cs)
        self.assertEqual(self.acpi_command.argv, ['list'])

    def test_parse_arguments_list(self):
        """Test parsing list command arguments."""
        command = ACPICommand(['list'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.acpi_list)

    def test_parse_arguments_table_by_name(self):
        """Test parsing table command with table name."""
        command = ACPICommand(['table', 'XSDT'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.acpi_table)
        self.assertFalse(command._file)
        self.assertEqual(command._name, ['XSDT'])

    def test_parse_arguments_table_from_file(self):
        """Test parsing table command with file option."""
        command = ACPICommand(['table', '-f', 'acpi_table.bin'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.acpi_table)
        self.assertTrue(command._file)
        self.assertEqual(command._name, ['acpi_table.bin'])

    def test_requirements_list_command(self):
        """Test requirements for list command."""
        self.acpi_command.func = self.acpi_command.acpi_list
        reqs = self.acpi_command.requirements()
        self.assertTrue(hasattr(reqs, 'load_driver'))
        self.assertTrue(hasattr(reqs, 'load_config'))

    def test_requirements_table_command_no_file(self):
        """Test requirements for table command without file."""
        self.acpi_command.func = self.acpi_command.acpi_table
        self.acpi_command._file = False
        reqs = self.acpi_command.requirements()
        self.assertTrue(hasattr(reqs, 'load_driver'))
        self.assertTrue(hasattr(reqs, 'load_config'))

    def test_requirements_table_command_with_file(self):
        """Test requirements for table command with file."""
        self.acpi_command.func = self.acpi_command.acpi_table
        self.acpi_command._file = True
        reqs = self.acpi_command.requirements()
        # Should return toLoad.Nil for file-based operations
        self.assertIsNotNone(reqs)

    def test_set_up(self):
        """Test set_up method."""
        # Use our enhanced mock infrastructure
        mock_acpi_instance = Mock()
        self.mock_cs.hals.ACPI = mock_acpi_instance

        self.acpi_command.set_up()

        # Verify ACPI HAL was instantiated
        self.assertIsNotNone(self.acpi_command._acpi)
        self.assertTrue(hasattr(self.acpi_command, '_acpi'))

    def test_acpi_list(self):
        """Test acpi_list command execution."""
        mock_acpi = Mock()
        self.acpi_command._acpi = mock_acpi

        self.acpi_command.acpi_list()

        mock_acpi.print_ACPI_table_list.assert_called_once()

    def test_acpi_table_by_name_present(self):
        """Test acpi_table command with table name when table is present."""
        self.acpi_command._name = ['XSDT']
        self.acpi_command._file = False

        mock_acpi = Mock()
        mock_acpi.is_ACPI_table_present.return_value = True
        self.acpi_command._acpi = mock_acpi

        self.acpi_command.acpi_table()

        mock_acpi.is_ACPI_table_present.assert_called_once_with('XSDT')
        mock_acpi.dump_ACPI_table.assert_called_once_with('XSDT', False)

    def test_acpi_table_by_name_not_present(self):
        """Test acpi_table command with table name when table is not present."""
        self.acpi_command._name = ['INVALID']
        self.acpi_command._file = False

        mock_acpi = Mock()
        mock_acpi.is_ACPI_table_present.return_value = False
        mock_acpi.tableList = {'XSDT': [0x12345678]}
        self.acpi_command._acpi = mock_acpi

        self.acpi_command.acpi_table()

        mock_acpi.is_ACPI_table_present.assert_called_once_with('INVALID')
        # Should not call dump_ACPI_table
        mock_acpi.dump_ACPI_table.assert_not_called()

    def test_acpi_table_from_file_exists(self):
        """Test acpi_table command with file that exists."""
        self.acpi_command._name = ['acpi_table.bin']
        self.acpi_command._file = True

        mock_acpi = Mock()
        self.acpi_command._acpi = mock_acpi

        with patch('chipsec.utilcmd.acpi_cmd.path_exists', return_value=True), \
             patch('chipsec.library.file.read_file', return_value=b'test_acpi_data'):
            self.acpi_command.acpi_table()
            mock_acpi.dump_ACPI_table.assert_called_once_with('acpi_table.bin', True)

    def test_acpi_table_from_file_not_exists(self):
        """Test acpi_table command with file that doesn't exist."""
        self.acpi_command._name = ['nonexistent.bin']
        self.acpi_command._file = True

        mock_acpi = Mock()
        self.acpi_command._acpi = mock_acpi

        with patch('os.path.exists', return_value=False):
            self.acpi_command.acpi_table()
            # Should not call dump_ACPI_table
            mock_acpi.dump_ACPI_table.assert_not_called()

    def test_commands_dictionary(self):
        """Test commands dictionary is properly defined."""
        from chipsec.utilcmd.acpi_cmd import commands
        self.assertIn('acpi', commands)
        self.assertEqual(commands['acpi'], ACPICommand)


class TestACPICommandIntegration(unittest.TestCase):
    """Integration tests for ACPI command with HAL components."""

    def setUp(self):
        """Set up test fixtures."""
        # Create integrated ChipsecCs for ACPI testing
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        self.integrated_cs.hals.ACPI = Mock()
        self.integrated_cs.hals.Memory = Mock()
        self.integrated_cs.hals.CPU = Mock()

        # Mock helper with proper configuration
        self.integrated_cs.helper = Mock()
        self.integrated_cs.helper.get_threads_count.return_value = 2
        self.integrated_cs.helper.enum_ACPI_tables.return_value = [b'FACP', b'APIC', b'MCFG', b'XSDT']
        self.integrated_cs.helper.get_ACPI_table.return_value = b'FACP\x84\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00INTL\x00\x00\x00\x00' + b'\x00' * 116

    def test_acpi_command_full_workflow_list(self):
        """Test complete ACPI list command workflow."""
        # Setup HAL mocks
        self.integrated_cs.hals.ACPI.print_ACPI_table_list.return_value = None

        # Create and execute command
        acpi_cmd = ACPICommand(['list'], cs=self.integrated_cs)
        acpi_cmd.parse_arguments()

        # Mock the ACPI HAL creation to return our mock
        with patch('chipsec.utilcmd.acpi_cmd.ACPI', return_value=self.integrated_cs.hals.ACPI):
            acpi_cmd.set_up()
            acpi_cmd.acpi_list()

        # Verify HAL interactions
        self.integrated_cs.hals.ACPI.print_ACPI_table_list.assert_called_once()

    def test_acpi_command_full_workflow_table(self):
        """Test complete ACPI table command workflow."""
        # Setup HAL mocks
        self.integrated_cs.hals.ACPI.is_ACPI_table_present.return_value = True
        self.integrated_cs.hals.ACPI.dump_ACPI_table.return_value = None

        # Create and execute command
        acpi_cmd = ACPICommand(['table', 'FACP'], cs=self.integrated_cs)
        acpi_cmd.parse_arguments()

        # Mock the ACPI HAL creation to return our mock
        with patch('chipsec.utilcmd.acpi_cmd.ACPI', return_value=self.integrated_cs.hals.ACPI):
            acpi_cmd.set_up()
            acpi_cmd.acpi_table()

        # Verify HAL interactions
        self.integrated_cs.hals.ACPI.is_ACPI_table_present.assert_called_once_with('FACP')
        self.integrated_cs.hals.ACPI.dump_ACPI_table.assert_called_once_with('FACP', False)

    def test_acpi_command_error_handling(self):
        """Test ACPI command error handling."""
        # Test invalid table name
        self.integrated_cs.hals.ACPI.is_ACPI_table_present.return_value = False
        self.integrated_cs.hals.ACPI.tableList = {'XSDT': [0x12345678]}

        acpi_cmd = ACPICommand(['table', 'INVALID'], cs=self.integrated_cs)
        acpi_cmd.parse_arguments()
        acpi_cmd.set_up()
        acpi_cmd.acpi_table()

        # Should not attempt to dump invalid table
        self.integrated_cs.hals.ACPI.dump_ACPI_table.assert_not_called()

    def test_acpi_command_file_operations(self):
        """Test ACPI command file operations."""
        # Test with existing file
        self.integrated_cs.hals.ACPI.dump_ACPI_table.return_value = None

        with patch('chipsec.utilcmd.acpi_cmd.path_exists', return_value=True), \
             patch('chipsec.library.file.read_file', return_value=b'test_acpi_data'):
            acpi_cmd = ACPICommand(['table', '-f', 'test.bin'], cs=self.integrated_cs)
            acpi_cmd.parse_arguments()

            # Mock the ACPI HAL creation to return our mock
            with patch('chipsec.utilcmd.acpi_cmd.ACPI', return_value=self.integrated_cs.hals.ACPI):
                acpi_cmd.set_up()
                acpi_cmd.acpi_table()

            self.integrated_cs.hals.ACPI.dump_ACPI_table.assert_called_once_with('test.bin', True)

        # Reset mock
        self.integrated_cs.hals.ACPI.dump_ACPI_table.reset_mock()

        # Test with non-existing file
        with patch('chipsec.utilcmd.acpi_cmd.path_exists', return_value=False):
            acpi_cmd2 = ACPICommand(['table', '-f', 'missing.bin'], cs=self.integrated_cs)
            acpi_cmd2.parse_arguments()

            # Mock the ACPI HAL creation to return our mock
            with patch('chipsec.utilcmd.acpi_cmd.ACPI', return_value=self.integrated_cs.hals.ACPI):
                acpi_cmd2.set_up()
                acpi_cmd2.acpi_table()

            # Should not attempt to dump missing file
            self.integrated_cs.hals.ACPI.dump_ACPI_table.assert_not_called()


class TestACPICommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for ACPI command."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock ChipsecCs for edge case testing
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.hals.ACPI = Mock()

    def test_empty_argv_handling(self):
        """Test handling of empty argv."""
        # This should not crash but may not work as expected
        acpi_cmd = ACPICommand([], cs=self.mock_cs)
        # Just ensure it doesn't crash during initialization
        self.assertEqual(acpi_cmd.argv, [])

    def test_invalid_subcommand(self):
        """Test handling of invalid subcommand."""
        acpi_cmd = ACPICommand(['invalid'], cs=self.mock_cs)

        # This should raise SystemExit due to argparse error
        with self.assertRaises(SystemExit):
            acpi_cmd.parse_arguments()

    def test_table_command_missing_name(self):
        """Test table command with missing table name."""
        acpi_cmd = ACPICommand(['table'], cs=self.mock_cs)

        # This should raise SystemExit due to argparse error
        with self.assertRaises(SystemExit):
            acpi_cmd.parse_arguments()

    def test_file_option_without_name(self):
        """Test file option without table name."""
        acpi_cmd = ACPICommand(['table', '-f'], cs=self.mock_cs)

        # This should raise SystemExit due to argparse error
        with self.assertRaises(SystemExit):
            acpi_cmd.parse_arguments()

    def test_acpi_hal_none_handling(self):
        """Test handling when ACPI HAL is not properly initialized."""
        acpi_cmd = ACPICommand(['list'], cs=self.mock_cs)
        acpi_cmd.parse_arguments()
        # Don't call set_up(), so _acpi remains None

        # This should handle the None case gracefully
        with self.assertRaises(AttributeError):
            acpi_cmd.acpi_list()


if __name__ == '__main__':
    unittest.main()
