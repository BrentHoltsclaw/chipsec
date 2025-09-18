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
from chipsec.utilcmd.ec_cmd import ECCommand
from tests.test_utils import MockFactory


class TestECCommand:
    """Comprehensive tests for EC utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for EC testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock EC HAL component
        cs_mock.hals = Mock()
        cs_mock.hals.ec = Mock()

        return cs_mock

    @pytest.fixture
    def ec_command(self, mock_cs):
        """Create ECCommand instance."""
        return ECCommand(['dump'], cs=mock_cs)

    @pytest.mark.unit
    def test_ec_command_initialization(self, ec_command, mock_cs):
        """Test ECCommand initialization."""
        assert ec_command.cs == mock_cs
        assert ec_command.argv == ['dump']

    @pytest.mark.unit
    def test_requirements_without_func(self, mock_cs):
        """Test requirements method without func attribute."""
        command = ECCommand(['dump'], cs=mock_cs)
        reqs = command.requirements()
        assert reqs == command.toLoad.Nil

    @pytest.mark.unit
    def test_requirements_with_func(self, mock_cs):
        """Test requirements method with func attribute."""
        command = ECCommand(['dump'], cs=mock_cs)
        command.func = Mock()
        reqs = command.requirements()
        assert reqs == command.toLoad.Driver

    @pytest.mark.unit
    def test_parse_arguments_dump(self, mock_cs):
        """Test parsing dump command."""
        command = ECCommand(['dump', '0x100'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.dump
        assert command.size == 0x100

    @pytest.mark.unit
    def test_parse_arguments_dump_default(self, mock_cs):
        """Test parsing dump command with default size."""
        command = ECCommand(['dump'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.dump
        assert command.size == 0x160

    @pytest.mark.unit
    def test_parse_arguments_command(self, mock_cs):
        """Test parsing command subcommand."""
        command = ECCommand(['command', '0x001'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.command
        assert command.cmd == 0x001

    @pytest.mark.unit
    def test_parse_arguments_read_single(self, mock_cs):
        """Test parsing read command for single byte."""
        command = ECCommand(['read', '0x2F'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.read
        assert command.offset == 0x2F
        assert command.size is None

    @pytest.mark.unit
    def test_parse_arguments_read_range(self, mock_cs):
        """Test parsing read command for range."""
        command = ECCommand(['read', '0x2F', '0x10'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.read
        assert command.offset == 0x2F
        assert command.size == 0x10

    @pytest.mark.unit
    def test_parse_arguments_write_standard(self, mock_cs):
        """Test parsing write command for standard memory."""
        command = ECCommand(['write', '0x2F', '0x00'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.write
        assert command.offset == 0x2F
        assert command.wval == 0x00

    @pytest.mark.unit
    def test_parse_arguments_write_extended(self, mock_cs):
        """Test parsing write command for extended memory."""
        command = ECCommand(['write', '0x200', '0xFF'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.write
        assert command.offset == 0x200
        assert command.wval == 0xFF

    @pytest.mark.unit
    def test_parse_arguments_index_with_offset(self, mock_cs):
        """Test parsing index command with offset."""
        command = ECCommand(['index', '0x100'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.index
        assert command.offset == 0x100

    @pytest.mark.unit
    def test_parse_arguments_index_default(self, mock_cs):
        """Test parsing index command with default offset."""
        command = ECCommand(['index'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.index
        assert command.offset == 0

    @pytest.mark.unit
    def test_parse_arguments_invalid(self, mock_cs):
        """Test parsing invalid command."""
        command = ECCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_set_up(self, ec_command, mock_cs):
        """Test set_up method."""
        ec_command.set_up()
        # Should create EC instance
        assert hasattr(ec_command, '_ec')

    @pytest.mark.unit
    def test_dump(self, ec_command, mock_cs):
        """Test dump method."""
        ec_command.size = 0x160
        test_buffer = b'\x00' * 0x160
        ec_command._ec.read_range.return_value = test_buffer

        with patch('chipsec.utilcmd.ec_cmd.print_buffer_bytes') as mock_print_buffer, \
             patch.object(ec_command.logger, 'log') as mock_log:
            ec_command.dump()

            ec_command._ec.read_range.assert_called_once_with(0, 0x160)
            mock_log.assert_called_with('[CHIPSEC] EC dump')
            mock_print_buffer.assert_called_once_with(test_buffer)

    @pytest.mark.unit
    def test_command(self, ec_command, mock_cs):
        """Test command method."""
        ec_command.cmd = 0x001

        with patch.object(ec_command.logger, 'log') as mock_log:
            ec_command.command()

            ec_command._ec.write_command.assert_called_once_with(0x001)
            mock_log.assert_called_with('[CHIPSEC] Sending EC command 0x1')

    @pytest.mark.unit
    def test_read_single_standard(self, ec_command, mock_cs):
        """Test read method for single byte in standard memory."""
        ec_command.offset = 0x2F
        ec_command.size = None
        ec_command._ec.read_memory.return_value = 0xAB

        with patch.object(ec_command.logger, 'log') as mock_log:
            ec_command.read()

            ec_command._ec.read_memory.assert_called_once_with(0x2F)
            mock_log.assert_called_with('[CHIPSEC] EC memory read: offset 0x2F = 0xAB')

    @pytest.mark.unit
    def test_read_single_extended(self, ec_command, mock_cs):
        """Test read method for single byte in extended memory."""
        ec_command.offset = 0x200
        ec_command.size = None
        ec_command._ec.read_memory_extended.return_value = 0xCD

        with patch.object(ec_command.logger, 'log') as mock_log:
            ec_command.read()

            ec_command._ec.read_memory_extended.assert_called_once_with(0x200)
            mock_log.assert_called_with('[CHIPSEC] EC memory read: offset 0x200 = 0xCD')

    @pytest.mark.unit
    def test_read_range(self, ec_command, mock_cs):
        """Test read method for memory range."""
        ec_command.offset = 0x2F
        ec_command.size = 0x10
        test_buffer = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
        ec_command._ec.read_range.return_value = test_buffer

        with patch('chipsec.utilcmd.ec_cmd.print_buffer_bytes') as mock_print_buffer, \
             patch.object(ec_command.logger, 'log') as mock_log:
            ec_command.read()

            ec_command._ec.read_range.assert_called_once_with(0x2F, 0x10)
            mock_log.assert_called_with('[CHIPSEC] EC memory read: offset 0x2F size 0x10')
            mock_print_buffer.assert_called_once_with(test_buffer)

    @pytest.mark.unit
    def test_write_standard_memory(self, ec_command, mock_cs):
        """Test write method for standard memory."""
        ec_command.offset = 0x2F
        ec_command.wval = 0x00

        with patch.object(ec_command.logger, 'log') as mock_log:
            ec_command.write()

            ec_command._ec.write_memory.assert_called_once_with(0x2F, 0x00)
            mock_log.assert_called_with('[CHIPSEC] EC memory write: offset 0x2F = 0x0')

    @pytest.mark.unit
    def test_write_extended_memory(self, ec_command, mock_cs):
        """Test write method for extended memory."""
        ec_command.offset = 0x200
        ec_command.wval = 0xFF

        with patch.object(ec_command.logger, 'log') as mock_log:
            ec_command.write()

            ec_command._ec.write_memory_extended.assert_called_once_with(0x200, 0xFF)
            mock_log.assert_called_with('[CHIPSEC] EC memory write: offset 0x200 = 0xFF')

    @pytest.mark.unit
    def test_index_with_offset(self, ec_command, mock_cs):
        """Test index method with specific offset."""
        ec_command.offset = 0x100
        ec_command._ec.read_idx.return_value = 0x42

        with patch.object(ec_command.logger, 'log') as mock_log:
            ec_command.index()

            ec_command._ec.read_idx.assert_called_once_with(0x100)
            mock_log.assert_called_with('[CHIPSEC] EC index I/O: reading memory offset 0x100: 0x42')

    @pytest.mark.unit
    def test_index_dump_all(self, ec_command, mock_cs):
        """Test index method to dump all memory."""
        ec_command.offset = 0
        # Mock read_idx to return different values for each call
        ec_command._ec.read_idx.side_effect = [i % 256 for i in range(0x10000)]

        with patch('chipsec.utilcmd.ec_cmd.print_buffer_bytes') as mock_print_buffer, \
             patch.object(ec_command.logger, 'log') as mock_log:
            ec_command.index()

            # Should call read_idx for all 0x10000 addresses
            assert ec_command._ec.read_idx.call_count == 0x10000
            mock_log.assert_called_with('[CHIPSEC] EC index I/O: dumping memory...')
            mock_print_buffer.assert_called_once()

    @pytest.mark.unit
    def test_run(self, ec_command, mock_cs):
        """Test run method."""
        ec_command.func = Mock()

        ec_command.run()

        ec_command.func.assert_called_once()


class TestECCommandIntegration:
    """Integration tests for EC command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for EC testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock EC components with realistic data
        cs_mock.hals = Mock()
        cs_mock.hals.ec = Mock()

        return cs_mock

    @pytest.mark.integration
    def test_ec_dump_integration(self, integrated_cs):
        """Test complete ec_dump workflow."""
        ec_cmd = ECCommand(['dump', '0x100'], cs=integrated_cs)
        ec_cmd.set_up()

        test_buffer = b'\x00' * 0x100
        ec_cmd._ec.read_range.return_value = test_buffer

        with patch('chipsec.utilcmd.ec_cmd.print_buffer_bytes'), \
             patch.object(ec_cmd.logger, 'log'):
            ec_cmd.run()

            ec_cmd._ec.read_range.assert_called_once_with(0, 0x100)

    @pytest.mark.integration
    def test_ec_command_integration(self, integrated_cs):
        """Test complete ec_command workflow."""
        ec_cmd = ECCommand(['command', '0x001'], cs=integrated_cs)
        ec_cmd.set_up()

        with patch.object(ec_cmd.logger, 'log'):
            ec_cmd.run()

            ec_cmd._ec.write_command.assert_called_once_with(0x001)

    @pytest.mark.integration
    def test_ec_read_write_integration(self, integrated_cs):
        """Test complete read-write workflow."""
        # Test write operation
        write_cmd = ECCommand(['write', '0x2F', '0x00'], cs=integrated_cs)
        write_cmd.set_up()

        with patch.object(write_cmd.logger, 'log'):
            write_cmd.run()

            write_cmd._ec.write_memory.assert_called_once_with(0x2F, 0x00)

        # Test read operation
        read_cmd = ECCommand(['read', '0x2F'], cs=integrated_cs)
        read_cmd.set_up()

        read_cmd._ec.read_memory.return_value = 0x00

        with patch.object(read_cmd.logger, 'log'):
            read_cmd.run()

            read_cmd._ec.read_memory.assert_called_once_with(0x2F)

    @pytest.mark.integration
    def test_ec_index_integration(self, integrated_cs):
        """Test complete ec_index workflow."""
        ec_cmd = ECCommand(['index', '0x100'], cs=integrated_cs)
        ec_cmd.set_up()

        ec_cmd._ec.read_idx.return_value = 0x42

        with patch.object(ec_cmd.logger, 'log'):
            ec_cmd.run()

            ec_cmd._ec.read_idx.assert_called_once_with(0x100)


class TestECCommandEdgeCases:
    """Test edge cases and error conditions for EC command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        cs_mock.hals.ec = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        command = ECCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_dump_large_size(self, mock_cs):
        """Test dump method with large size."""
        command = ECCommand(['dump', '0x1000'], cs=mock_cs)
        command.set_up()

        large_buffer = b'\x00' * 0x1000
        command._ec.read_range.return_value = large_buffer

        with patch('chipsec.utilcmd.ec_cmd.print_buffer_bytes'), \
             patch.object(command.logger, 'log'):
            command.run()

            command._ec.read_range.assert_called_once_with(0, 0x1000)

    @pytest.mark.unit
    def test_read_boundary_offsets(self, mock_cs):
        """Test read method with boundary offset values."""
        test_cases = [
            (0x0, 'read_memory'),
            (0xFF, 'read_memory'),
            (0x100, 'read_memory_extended'),
            (0xFFFF, 'read_memory_extended')
        ]

        for offset, expected_method in test_cases:
            command = ECCommand(['read', f'0x{offset:X}'], cs=mock_cs)
            command.set_up()

            if expected_method == 'read_memory':
                command._ec.read_memory.return_value = 0xAB
            else:
                command._ec.read_memory_extended.return_value = 0xCD

            with patch.object(command.logger, 'log'):
                command.run()

                getattr(command._ec, expected_method).assert_called_with(offset)

    @pytest.mark.unit
    def test_write_boundary_offsets(self, mock_cs):
        """Test write method with boundary offset values."""
        test_cases = [
            (0x0, 'write_memory'),
            (0xFF, 'write_memory'),
            (0x100, 'write_memory_extended'),
            (0xFFFF, 'write_memory_extended')
        ]

        for offset, expected_method in test_cases:
            command = ECCommand(['write', f'0x{offset:X}', '0xAB'], cs=mock_cs)
            command.set_up()

            with patch.object(command.logger, 'log'):
                command.run()

                getattr(command._ec, expected_method).assert_called_with(offset, 0xAB)

    @pytest.mark.unit
    def test_read_range_various_sizes(self, mock_cs):
        """Test read method with various range sizes."""
        test_sizes = [0x1, 0x10, 0x100, 0x1000]

        for size in test_sizes:
            command = ECCommand(['read', '0x2F', f'0x{size:X}'], cs=mock_cs)
            command.set_up()

            test_buffer = b'\x00' * size
            command._ec.read_range.return_value = test_buffer

            with patch('chipsec.utilcmd.ec_cmd.print_buffer_bytes'), \
                 patch.object(command.logger, 'log'):
                command.run()

                command._ec.read_range.assert_called_with(0x2F, size)

    @pytest.mark.unit
    def test_write_various_values(self, mock_cs):
        """Test write method with various byte values."""
        test_values = [0x00, 0xFF, 0xAB, 0x42]

        for value in test_values:
            command = ECCommand(['write', '0x2F', f'0x{value:X}'], cs=mock_cs)
            command.set_up()

            with patch.object(command.logger, 'log'):
                command.run()

                command._ec.write_memory.assert_called_with(0x2F, value)

    @pytest.mark.unit
    def test_command_various_values(self, mock_cs):
        """Test command method with various command values."""
        test_commands = [0x000, 0x001, 0x0FF, 0x100, 0xFFF]

        for cmd in test_commands:
            command = ECCommand(['command', f'0x{cmd:X}'], cs=mock_cs)
            command.set_up()

            with patch.object(command.logger, 'log'):
                command.run()

                command._ec.write_command.assert_called_with(cmd)

    @pytest.mark.unit
    def test_index_offset_range(self, mock_cs):
        """Test index method with various offset values."""
        test_offsets = [0x0, 0x100, 0x1000, 0xFFFF]

        for offset in test_offsets:
            command = ECCommand(['index', f'0x{offset:X}'], cs=mock_cs)
            command.set_up()

            command._ec.read_idx.return_value = 0x42

            with patch.object(command.logger, 'log'):
                command.run()

                command._ec.read_idx.assert_called_with(offset)

    @pytest.mark.unit
    def test_hex_parsing_various_formats(self, mock_cs):
        """Test hex parsing with various formats."""
        test_cases = [
            ('0x2F', 0x2F),
            ('2F', 0x2F),
            ('0x0', 0x0),
            ('0', 0x0),
            ('FF', 0xFF),
            ('0xFF', 0xFF),
            ('100', 0x100),
            ('0x100', 0x100)
        ]

        for hex_str, expected_value in test_cases:
            command = ECCommand(['read', hex_str], cs=mock_cs)
            command.parse_arguments()
            assert command.offset == expected_value


class TestECCommandConfigurationValidation:
    """Test configuration validation aspects of EC command."""

    @pytest.fixture
    def ec_cs(self):
        """Create ChipsecCs with EC-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock EC configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.EC = {
            'BASE_ADDRESS': 0x62,
            'DATA_ADDRESS': 0x66,
            'MEMORY_SIZE': 0x10000,
            'INDEX_SIZE': 0x10000
        }

        cs_mock.hals = Mock()
        cs_mock.hals.ec = Mock()

        return cs_mock

    @pytest.mark.unit
    def test_ec_configuration_structure(self, ec_cs):
        """Test EC configuration structure."""
        ec_config = ec_cs.Cfg.EC

        # Test that required EC configuration exists
        assert 'BASE_ADDRESS' in ec_config
        assert 'DATA_ADDRESS' in ec_config

        # Test configuration values are reasonable
        assert ec_config['BASE_ADDRESS'] > 0
        assert ec_config['DATA_ADDRESS'] > 0

    @pytest.mark.unit
    def test_ec_offset_validation(self, ec_cs):
        """Test EC offset validation."""
        # Test various offset formats
        test_cases = [
            ('0x2F', 0x2F),
            ('0x200', 0x200),
            ('0x0', 0x0),
            ('0xFFFF', 0xFFFF)
        ]

        for offset_str, expected_offset in test_cases:
            command = ECCommand(['read', offset_str], cs=ec_cs)
            command.parse_arguments()

            assert command.offset == expected_offset

    @pytest.mark.unit
    def test_ec_size_validation(self, ec_cs):
        """Test EC size validation."""
        # Test various size formats
        test_cases = [
            ('0x10', 0x10),
            ('0x100', 0x100),
            ('0x1000', 0x1000),
            ('0x1', 0x1)
        ]

        for size_str, expected_size in test_cases:
            command = ECCommand(['dump', size_str], cs=ec_cs)
            command.parse_arguments()

            assert command.size == expected_size

    @pytest.mark.unit
    def test_ec_command_validation(self, ec_cs):
        """Test EC command validation."""
        # Test various command formats
        test_cases = [
            ('0x001', 0x001),
            ('0x0', 0x0),
            ('0xFF', 0xFF),
            ('0x100', 0x100)
        ]

        for cmd_str, expected_cmd in test_cases:
            command = ECCommand(['command', cmd_str], cs=ec_cs)
            command.parse_arguments()

            assert command.cmd == expected_cmd

    @pytest.mark.unit
    def test_ec_write_value_validation(self, ec_cs):
        """Test EC write value validation."""
        # Test various write value formats
        test_cases = [
            ('0x00', 0x00),
            ('0xFF', 0xFF),
            ('0xAB', 0xAB),
            ('0x42', 0x42)
        ]

        for value_str, expected_value in test_cases:
            command = ECCommand(['write', '0x2F', value_str], cs=ec_cs)
            command.parse_arguments()

            assert command.wval == expected_value

    @pytest.mark.unit
    def test_ec_memory_access_boundary_checking(self, ec_cs):
        """Test EC memory access boundary checking."""
        # Test standard memory range (0x00-0xFF)
        command_standard = ECCommand(['write', '0x2F', '0x00'], cs=ec_cs)
        command_standard.set_up()

        with patch.object(command_standard.logger, 'log'):
            command_standard.run()

            command_standard._ec.write_memory.assert_called_with(0x2F, 0x00)

        # Test extended memory range (0x100+)
        command_extended = ECCommand(['write', '0x200', '0xFF'], cs=ec_cs)
        command_extended.set_up()

        with patch.object(command_extended.logger, 'log'):
            command_extended.run()

            command_extended._ec.write_memory_extended.assert_called_with(0x200, 0xFF)

    @pytest.mark.unit
    def test_ec_error_handling(self, ec_cs):
        """Test EC error handling."""
        command = ECCommand(['read', '0x2F'], cs=ec_cs)

        # Mock EC read to raise exception
        command._ec.read_memory.side_effect = Exception("EC access failed")

        # Should handle the exception gracefully
        with pytest.raises(Exception):
            command.read()

    @pytest.mark.unit
    def test_ec_index_error_handling(self, ec_cs):
        """Test EC index error handling."""
        command = ECCommand(['index', '0x100'], cs=ec_cs)

        # Mock EC index read to raise exception
        command._ec.read_idx.side_effect = Exception("EC index access failed")

        # Should handle the exception gracefully
        with pytest.raises(Exception):
            command.index()


if __name__ == '__main__':
    pytest.main([__file__])
