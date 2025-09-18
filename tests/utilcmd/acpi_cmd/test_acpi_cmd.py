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
from chipsec.utilcmd.acpi_cmd import ACPICommand
from tests.test_utils import MockFactory


class TestACPICommand:
    """Comprehensive tests for ACPI utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for ACPI testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        # Mock ACPI HAL
        cs_mock.hals.ACPI = Mock()
        return cs_mock

    @pytest.fixture
    def acpi_command(self, mock_cs):
        """Create ACPICommand instance."""
        return ACPICommand(['list'], cs=mock_cs)

    @pytest.mark.unit
    def test_acpi_command_initialization(self, acpi_command, mock_cs):
        """Test ACPICommand initialization."""
        assert acpi_command.cs == mock_cs
        assert acpi_command.argv == ['list']

    @pytest.mark.unit
    def test_parse_arguments_list(self, mock_cs):
        """Test parsing list command arguments."""
        command = ACPICommand(['list'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.acpi_list

    @pytest.mark.unit
    def test_parse_arguments_table_by_name(self, mock_cs):
        """Test parsing table command with table name."""
        command = ACPICommand(['table', 'XSDT'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.acpi_table
        assert command._file is False
        assert command._name == ['XSDT']

    @pytest.mark.unit
    def test_parse_arguments_table_from_file(self, mock_cs):
        """Test parsing table command with file option."""
        command = ACPICommand(['table', '-f', 'acpi_table.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.acpi_table
        assert command._file is True
        assert command._name == ['acpi_table.bin']

    @pytest.mark.unit
    def test_requirements_list_command(self, acpi_command):
        """Test requirements for list command."""
        acpi_command.func = acpi_command.acpi_list
        reqs = acpi_command.requirements()
        assert hasattr(reqs, 'load_driver')
        assert hasattr(reqs, 'load_config')

    @pytest.mark.unit
    def test_requirements_table_command_no_file(self, acpi_command):
        """Test requirements for table command without file."""
        acpi_command.func = acpi_command.acpi_table
        acpi_command._file = False
        reqs = acpi_command.requirements()
        assert hasattr(reqs, 'load_driver')
        assert hasattr(reqs, 'load_config')

    @pytest.mark.unit
    def test_requirements_table_command_with_file(self, acpi_command):
        """Test requirements for table command with file."""
        acpi_command.func = acpi_command.acpi_table
        acpi_command._file = True
        reqs = acpi_command.requirements()
        # Should return toLoad.Nil for file-based operations
        assert reqs is not None

    @pytest.mark.unit
    def test_set_up(self, acpi_command, mock_cs):
        """Test set_up method."""
        with patch('chipsec.hal.common.acpi.ACPI') as mock_acpi_class:
            mock_acpi_instance = Mock()
            mock_acpi_class.return_value = mock_acpi_instance

            acpi_command.set_up()

            mock_acpi_class.assert_called_once_with(mock_cs)
            assert acpi_command._acpi == mock_acpi_instance

    @pytest.mark.unit
    def test_acpi_list(self, acpi_command, mock_cs):
        """Test acpi_list command execution."""
        mock_acpi = Mock()
        acpi_command._acpi = mock_acpi

        acpi_command.acpi_list()

        mock_acpi.print_ACPI_table_list.assert_called_once()

    @pytest.mark.unit
    def test_acpi_table_by_name_present(self, acpi_command, mock_cs):
        """Test acpi_table command with table name when table is present."""
        acpi_command._name = ['XSDT']
        acpi_command._file = False

        mock_acpi = Mock()
        mock_acpi.is_ACPI_table_present.return_value = True
        acpi_command._acpi = mock_acpi

        acpi_command.acpi_table()

        mock_acpi.is_ACPI_table_present.assert_called_once_with('XSDT')
        mock_acpi.dump_ACPI_table.assert_called_once_with('XSDT', False)

    @pytest.mark.unit
    def test_acpi_table_by_name_not_present(self, acpi_command, mock_cs):
        """Test acpi_table command with table name when table is not present."""
        acpi_command._name = ['INVALID']
        acpi_command._file = False

        mock_acpi = Mock()
        mock_acpi.is_ACPI_table_present.return_value = False
        mock_acpi.tableList = {'XSDT': [0x12345678]}
        acpi_command._acpi = mock_acpi

        acpi_command.acpi_table()

        mock_acpi.is_ACPI_table_present.assert_called_once_with('INVALID')
        # Should not call dump_ACPI_table
        mock_acpi.dump_ACPI_table.assert_not_called()

    @pytest.mark.unit
    def test_acpi_table_from_file_exists(self, acpi_command, mock_cs):
        """Test acpi_table command with file that exists."""
        acpi_command._name = ['acpi_table.bin']
        acpi_command._file = True

        mock_acpi = Mock()
        acpi_command._acpi = mock_acpi

        with patch('os.path.exists', return_value=True):
            acpi_command.acpi_table()

            mock_acpi.dump_ACPI_table.assert_called_once_with('acpi_table.bin', True)

    @pytest.mark.unit
    def test_acpi_table_from_file_not_exists(self, acpi_command, mock_cs):
        """Test acpi_table command with file that doesn't exist."""
        acpi_command._name = ['nonexistent.bin']
        acpi_command._file = True

        mock_acpi = Mock()
        acpi_command._acpi = mock_acpi

        with patch('os.path.exists', return_value=False):
            acpi_command.acpi_table()

            # Should not call dump_ACPI_table
            mock_acpi.dump_ACPI_table.assert_not_called()

    @pytest.mark.unit
    def test_commands_dictionary(self):
        """Test commands dictionary is properly defined."""
        from chipsec.utilcmd.acpi_cmd import commands
        assert 'acpi' in commands
        assert commands['acpi'] == ACPICommand


class TestACPICommandIntegration:
    """Integration tests for ACPI command with HAL components."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for ACPI testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        cs_mock.hals.ACPI = Mock()
        cs_mock.hals.Memory = Mock()
        cs_mock.hals.CPU = Mock()

        # Mock helper
        cs_mock.helper = Mock()
        cs_mock.helper.get_threads_count.return_value = 2

        return cs_mock

    @pytest.mark.integration
    def test_acpi_command_full_workflow_list(self, integrated_cs):
        """Test complete ACPI list command workflow."""
        # Setup HAL mocks
        integrated_cs.hals.ACPI.print_ACPI_table_list.return_value = None

        # Create and execute command
        acpi_cmd = ACPICommand(['list'], cs=integrated_cs)
        acpi_cmd.parse_arguments()
        acpi_cmd.set_up()
        acpi_cmd.acpi_list()

        # Verify HAL interactions
        integrated_cs.hals.ACPI.print_ACPI_table_list.assert_called_once()

    @pytest.mark.integration
    def test_acpi_command_full_workflow_table(self, integrated_cs):
        """Test complete ACPI table command workflow."""
        # Setup HAL mocks
        integrated_cs.hals.ACPI.is_ACPI_table_present.return_value = True
        integrated_cs.hals.ACPI.dump_ACPI_table.return_value = None

        # Create and execute command
        acpi_cmd = ACPICommand(['table', 'FACP'], cs=integrated_cs)
        acpi_cmd.parse_arguments()
        acpi_cmd.set_up()
        acpi_cmd.acpi_table()

        # Verify HAL interactions
        integrated_cs.hals.ACPI.is_ACPI_table_present.assert_called_once_with('FACP')
        integrated_cs.hals.ACPI.dump_ACPI_table.assert_called_once_with('FACP', False)

    @pytest.mark.integration
    def test_acpi_command_error_handling(self, integrated_cs):
        """Test ACPI command error handling."""
        # Test invalid table name
        integrated_cs.hals.ACPI.is_ACPI_table_present.return_value = False
        integrated_cs.hals.ACPI.tableList = {'XSDT': [0x12345678]}

        acpi_cmd = ACPICommand(['table', 'INVALID'], cs=integrated_cs)
        acpi_cmd.parse_arguments()
        acpi_cmd.set_up()
        acpi_cmd.acpi_table()

        # Should not attempt to dump invalid table
        integrated_cs.hals.ACPI.dump_ACPI_table.assert_not_called()

    @pytest.mark.integration
    def test_acpi_command_file_operations(self, integrated_cs):
        """Test ACPI command file operations."""
        # Test with existing file
        integrated_cs.hals.ACPI.dump_ACPI_table.return_value = None

        with patch('os.path.exists', return_value=True):
            acpi_cmd = ACPICommand(['table', '-f', 'test.bin'], cs=integrated_cs)
            acpi_cmd.parse_arguments()
            acpi_cmd.set_up()
            acpi_cmd.acpi_table()

            integrated_cs.hals.ACPI.dump_ACPI_table.assert_called_once_with('test.bin', True)

        # Reset mock
        integrated_cs.hals.ACPI.dump_ACPI_table.reset_mock()

        # Test with non-existing file
        with patch('os.path.exists', return_value=False):
            acpi_cmd2 = ACPICommand(['table', '-f', 'missing.bin'], cs=integrated_cs)
            acpi_cmd2.parse_arguments()
            acpi_cmd2.set_up()
            acpi_cmd2.acpi_table()

            # Should not attempt to dump missing file
            integrated_cs.hals.ACPI.dump_ACPI_table.assert_not_called()


class TestACPICommandEdgeCases:
    """Test edge cases and error conditions for ACPI command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals.ACPI = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        # This should not crash but may not work as expected
        acpi_cmd = ACPICommand([], cs=mock_cs)
        # Just ensure it doesn't crash during initialization
        assert acpi_cmd.argv == []

    @pytest.mark.unit
    def test_invalid_subcommand(self, mock_cs):
        """Test handling of invalid subcommand."""
        acpi_cmd = ACPICommand(['invalid'], cs=mock_cs)

        # This should raise SystemExit due to argparse error
        with pytest.raises(SystemExit):
            acpi_cmd.parse_arguments()

    @pytest.mark.unit
    def test_table_command_missing_name(self, mock_cs):
        """Test table command with missing table name."""
        acpi_cmd = ACPICommand(['table'], cs=mock_cs)

        # This should raise SystemExit due to argparse error
        with pytest.raises(SystemExit):
            acpi_cmd.parse_arguments()

    @pytest.mark.unit
    def test_file_option_without_name(self, mock_cs):
        """Test file option without table name."""
        acpi_cmd = ACPICommand(['table', '-f'], cs=mock_cs)

        # This should raise SystemExit due to argparse error
        with pytest.raises(SystemExit):
            acpi_cmd.parse_arguments()

    @pytest.mark.unit
    def test_acpi_hal_none_handling(self, mock_cs):
        """Test handling when ACPI HAL is not properly initialized."""
        acpi_cmd = ACPICommand(['list'], cs=mock_cs)
        acpi_cmd.parse_arguments()
        # Don't call set_up(), so _acpi remains None

        # This should handle the None case gracefully
        with pytest.raises(AttributeError):
            acpi_cmd.acpi_list()


if __name__ == '__main__':
    pytest.main([__file__])
