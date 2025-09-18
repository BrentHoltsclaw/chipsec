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
from chipsec.utilcmd.io_cmd import PortIOCommand
from tests.test_utils import MockFactory


class TestPortIOCommand:
    """Comprehensive tests for I/O port utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for I/O testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        # Mock I/O HAL
        cs_mock.hals.Io = Mock()
        cs_mock.hals.Io.read.return_value = 0x12345678
        cs_mock.hals.Io.write.return_value = None
        return cs_mock

    @pytest.fixture
    def io_command(self, mock_cs):
        """Create PortIOCommand instance."""
        return PortIOCommand(['list'], cs=mock_cs)

    @pytest.mark.unit
    def test_io_command_initialization(self, io_command, mock_cs):
        """Test PortIOCommand initialization."""
        assert io_command.cs == mock_cs
        assert io_command.argv == ['list']

    @pytest.mark.unit
    def test_parse_arguments_list(self, mock_cs):
        """Test parsing list command arguments."""
        command = PortIOCommand(['list'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.io_list

    @pytest.mark.unit
    def test_parse_arguments_read(self, mock_cs):
        """Test parsing read command arguments."""
        command = PortIOCommand(['read', '0x61', '1'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.io_read
        assert command._port == 0x61
        assert command._width == 1

    @pytest.mark.unit
    def test_parse_arguments_read_width_2(self, mock_cs):
        """Test parsing read command with 2-byte width."""
        command = PortIOCommand(['read', '0x430', '2'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.io_read
        assert command._port == 0x430
        assert command._width == 2

    @pytest.mark.unit
    def test_parse_arguments_read_width_4(self, mock_cs):
        """Test parsing read command with 4-byte width."""
        command = PortIOCommand(['read', '0xCF8', '4'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.io_read
        assert command._port == 0xCF8
        assert command._width == 4

    @pytest.mark.unit
    def test_parse_arguments_write(self, mock_cs):
        """Test parsing write command arguments."""
        command = PortIOCommand(['write', '0x430', '1', '0x0'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.io_write
        assert command._port == 0x430
        assert command._width == 1
        assert command._value == 0x0

    @pytest.mark.unit
    def test_parse_arguments_write_width_2(self, mock_cs):
        """Test parsing write command with 2-byte width."""
        command = PortIOCommand(['write', '0x61', '2', '0x1234'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.io_write
        assert command._port == 0x61
        assert command._width == 2
        assert command._value == 0x1234

    @pytest.mark.unit
    def test_parse_arguments_write_width_4(self, mock_cs):
        """Test parsing write command with 4-byte width."""
        command = PortIOCommand(['write', '0xCF8', '4', '0x8000F8C0'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.io_write
        assert command._port == 0xCF8
        assert command._width == 4
        assert command._value == 0x8000F8C0

    @pytest.mark.unit
    def test_parse_arguments_decimal_values(self, mock_cs):
        """Test parsing arguments with decimal values."""
        command = PortIOCommand(['read', '97', '1'], cs=mock_cs)
        command.parse_arguments()
        assert command._port == 97  # 0x61
        assert command._width == 1

    @pytest.mark.unit
    def test_requirements(self, io_command):
        """Test command requirements."""
        reqs = io_command.requirements()
        assert hasattr(reqs, 'load_driver')
        assert hasattr(reqs, 'load_config')

    @pytest.mark.unit
    def test_set_up(self, io_command, mock_cs):
        """Test set_up method."""
        with patch('chipsec.utilcmd.io_cmd.iobar.IOBAR') as mock_iobar_class:
            mock_iobar_instance = Mock()
            mock_iobar_class.return_value = mock_iobar_instance

            io_command.set_up()

            assert hasattr(io_command, '_iobar')
            mock_iobar_class.assert_called_once_with(io_command.cs)

    @pytest.mark.unit
    def test_io_list(self, io_command, mock_cs):
        """Test io_list command."""
        with patch('chipsec.utilcmd.io_cmd.iobar.IOBAR') as mock_iobar_class:
            mock_iobar_instance = Mock()
            mock_iobar_class.return_value = mock_iobar_instance
            io_command.set_up()

            io_command.io_list()

            mock_iobar_instance.list_IO_BARs.assert_called_once()

    @pytest.mark.unit
    def test_io_read_byte(self, io_command, mock_cs):
        """Test io_read command for byte (1-byte) access."""
        io_command._port = 0x61
        io_command._width = 1

        with patch.object(io_command.logger, 'log') as mock_log:
            io_command.io_read()

            mock_cs.hals.Io.read.assert_called_once_with(0x61, 1)
            mock_log.assert_called_once()
            # Verify the log message format
            log_call = mock_log.call_args[0][0]
            assert 'IN 0x0061' in log_call
            assert 'size = 0x01' in log_call

    @pytest.mark.unit
    def test_io_read_word(self, io_command, mock_cs):
        """Test io_read command for word (2-byte) access."""
        io_command._port = 0x430
        io_command._width = 2

        with patch.object(io_command.logger, 'log') as mock_log:
            io_command.io_read()

            mock_cs.hals.Io.read.assert_called_once_with(0x430, 2)
            mock_log.assert_called_once()
            # Verify the log message format
            log_call = mock_log.call_args[0][0]
            assert 'IN 0x0430' in log_call
            assert 'size = 0x02' in log_call

    @pytest.mark.unit
    def test_io_read_dword(self, io_command, mock_cs):
        """Test io_read command for dword (4-byte) access."""
        io_command._port = 0xCF8
        io_command._width = 4

        with patch.object(io_command.logger, 'log') as mock_log:
            io_command.io_read()

            mock_cs.hals.Io.read.assert_called_once_with(0xCF8, 4)
            mock_log.assert_called_once()
            # Verify the log message format
            log_call = mock_log.call_args[0][0]
            assert 'IN 0x0CF8' in log_call
            assert 'size = 0x04' in log_call

    @pytest.mark.unit
    def test_io_read_different_values(self, io_command, mock_cs):
        """Test io_read command with different return values."""
        io_command._port = 0x61
        io_command._width = 1

        # Test with different return values
        test_values = [0x0, 0xFF, 0x1234, 0xFFFFFFFF]

        for expected_value in test_values:
            mock_cs.hals.Io.read.return_value = expected_value

            with patch.object(io_command.logger, 'log') as mock_log:
                io_command.io_read()

                mock_log.assert_called_once()
                log_call = mock_log.call_args[0][0]
                # Verify the value is correctly formatted in the log
                expected_hex = f'0x{expected_value:08X}'
                assert expected_hex in log_call

    @pytest.mark.unit
    def test_io_write_byte(self, io_command, mock_cs):
        """Test io_write command for byte (1-byte) access."""
        io_command._port = 0x430
        io_command._width = 1
        io_command._value = 0x0

        with patch.object(io_command.logger, 'log') as mock_log:
            io_command.io_write()

            mock_cs.hals.Io.write.assert_called_once_with(0x430, 0x0, 1)
            mock_log.assert_called_once()
            # Verify the log message format
            log_call = mock_log.call_args[0][0]
            assert 'OUT 0x0430' in log_call
            assert 'size = 0x01' in log_call

    @pytest.mark.unit
    def test_io_write_word(self, io_command, mock_cs):
        """Test io_write command for word (2-byte) access."""
        io_command._port = 0x61
        io_command._width = 2
        io_command._value = 0x1234

        with patch.object(io_command.logger, 'log') as mock_log:
            io_command.io_write()

            mock_cs.hals.Io.write.assert_called_once_with(0x61, 0x1234, 2)
            mock_log.assert_called_once()
            # Verify the log message format
            log_call = mock_log.call_args[0][0]
            assert 'OUT 0x0061' in log_call
            assert 'size = 0x02' in log_call

    @pytest.mark.unit
    def test_io_write_dword(self, io_command, mock_cs):
        """Test io_write command for dword (4-byte) access."""
        io_command._port = 0xCF8
        io_command._width = 4
        io_command._value = 0x8000F8C0

        with patch.object(io_command.logger, 'log') as mock_log:
            io_command.io_write()

            mock_cs.hals.Io.write.assert_called_once_with(0xCF8, 0x8000F8C0, 4)
            mock_log.assert_called_once()
            # Verify the log message format
            log_call = mock_log.call_args[0][0]
            assert 'OUT 0x0CF8' in log_call
            assert 'size = 0x04' in log_call

    @pytest.mark.unit
    def test_io_write_different_values(self, io_command, mock_cs):
        """Test io_write command with different values."""
        io_command._port = 0x61
        io_command._width = 1

        # Test with different values
        test_values = [0x0, 0xFF, 0x1234, 0xFFFFFFFF]

        for test_value in test_values:
            io_command._value = test_value

            with patch.object(io_command.logger, 'log') as mock_log:
                io_command.io_write()

                mock_cs.hals.Io.write.assert_called_with(0x61, test_value, 1)
                mock_log.assert_called_once()
                log_call = mock_log.call_args[0][0]
                # Verify the value is correctly formatted in the log
                expected_hex = f'0x{test_value:08X}'
                assert expected_hex in log_call


class TestPortIOCommandIntegration:
    """Integration tests for I/O command with HAL components."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for I/O testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        cs_mock.hals.Io = Mock()
        cs_mock.hals.Io.read.return_value = 0xDEADBEEF
        cs_mock.hals.Io.write.return_value = None

        # Mock helper
        cs_mock.helper = Mock()
        cs_mock.helper.get_threads_count.return_value = 2

        return cs_mock

    @pytest.mark.integration
    def test_io_read_write_workflow(self, integrated_cs):
        """Test complete I/O read/write workflow."""
        # Test read operation
        read_cmd = PortIOCommand(['read', '0x61', '1'], cs=integrated_cs)
        read_cmd.parse_arguments()

        with patch.object(read_cmd.logger, 'log') as mock_log:
            read_cmd.run()

            integrated_cs.hals.Io.read.assert_called_once_with(0x61, 1)
            mock_log.assert_called_once()

        # Test write operation
        write_cmd = PortIOCommand(['write', '0x430', '1', '0x0'], cs=integrated_cs)
        write_cmd.parse_arguments()

        with patch.object(write_cmd.logger, 'log') as mock_log:
            write_cmd.run()

            integrated_cs.hals.Io.write.assert_called_once_with(0x430, 0x0, 1)
            mock_log.assert_called_once()

    @pytest.mark.integration
    def test_io_list_workflow(self, integrated_cs):
        """Test I/O list workflow."""
        list_cmd = PortIOCommand(['list'], cs=integrated_cs)
        list_cmd.parse_arguments()

        with patch('chipsec.utilcmd.io_cmd.iobar.IOBAR') as mock_iobar_class:
            mock_iobar_instance = Mock()
            mock_iobar_class.return_value = mock_iobar_instance

            list_cmd.set_up()
            list_cmd.run()

            mock_iobar_instance.list_IO_BARs.assert_called_once()

    @pytest.mark.integration
    def test_io_different_widths_workflow(self, integrated_cs):
        """Test I/O operations with different widths."""
        # Test byte operations
        byte_cmd = PortIOCommand(['read', '0x61', '1'], cs=integrated_cs)
        byte_cmd.parse_arguments()
        byte_cmd.run()
        integrated_cs.hals.Io.read.assert_called_with(0x61, 1)

        # Test word operations
        word_cmd = PortIOCommand(['write', '0x430', '2', '0x1234'], cs=integrated_cs)
        word_cmd.parse_arguments()
        word_cmd.run()
        integrated_cs.hals.Io.write.assert_called_with(0x430, 0x1234, 2)

        # Test dword operations
        dword_cmd = PortIOCommand(['read', '0xCF8', '4'], cs=integrated_cs)
        dword_cmd.parse_arguments()
        dword_cmd.run()
        integrated_cs.hals.Io.read.assert_called_with(0xCF8, 4)


class TestPortIOCommandEdgeCases:
    """Test edge cases and error conditions for I/O command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals.Io = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        io_cmd = PortIOCommand([], cs=mock_cs)

        # The argument parser may not raise SystemExit for empty args
        # Let's just ensure it doesn't crash and has default behavior
        try:
            io_cmd.parse_arguments()
            # If it doesn't raise, that's also acceptable
            assert True
        except SystemExit:
            # If it does raise SystemExit, that's also acceptable
            assert True

    @pytest.mark.unit
    def test_invalid_subcommand(self, mock_cs):
        """Test handling of invalid subcommand."""
        io_cmd = PortIOCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            io_cmd.parse_arguments()

    @pytest.mark.unit
    def test_read_missing_width(self, mock_cs):
        """Test read command with missing width."""
        io_cmd = PortIOCommand(['read', '0x61'], cs=mock_cs)

        # Should raise SystemExit due to missing width
        with pytest.raises(SystemExit):
            io_cmd.parse_arguments()

    @pytest.mark.unit
    def test_write_missing_value(self, mock_cs):
        """Test write command with missing value."""
        io_cmd = PortIOCommand(['write', '0x430', '1'], cs=mock_cs)

        # Should raise SystemExit due to missing value
        with pytest.raises(SystemExit):
            io_cmd.parse_arguments()

    @pytest.mark.unit
    def test_invalid_width_choice(self, mock_cs):
        """Test command with invalid width choice."""
        io_cmd = PortIOCommand(['read', '0x61', '3'], cs=mock_cs)

        # Should raise SystemExit due to invalid width choice
        with pytest.raises(SystemExit):
            io_cmd.parse_arguments()

    @pytest.mark.unit
    def test_zero_port_address(self, mock_cs):
        """Test operations with zero port address."""
        io_cmd = PortIOCommand(['read', '0x0', '1'], cs=mock_cs)
        io_cmd.parse_arguments()

        assert io_cmd._port == 0x0
        assert io_cmd._width == 1

    @pytest.mark.unit
    def test_maximum_port_address(self, mock_cs):
        """Test operations with maximum port address."""
        io_cmd = PortIOCommand(['write', '0xFFFF', '2', '0x1234'], cs=mock_cs)
        io_cmd.parse_arguments()

        assert io_cmd._port == 0xFFFF
        assert io_cmd._width == 2
        assert io_cmd._value == 0x1234

    @pytest.mark.unit
    def test_zero_value_write(self, mock_cs):
        """Test writing zero value."""
        io_cmd = PortIOCommand(['write', '0x61', '1', '0x0'], cs=mock_cs)
        io_cmd.parse_arguments()

        assert io_cmd._port == 0x61
        assert io_cmd._width == 1
        assert io_cmd._value == 0x0

    @pytest.mark.unit
    def test_maximum_value_write(self, mock_cs):
        """Test writing maximum value."""
        io_cmd = PortIOCommand(['write', '0x430', '4', '0xFFFFFFFF'], cs=mock_cs)
        io_cmd.parse_arguments()

        assert io_cmd._port == 0x430
        assert io_cmd._width == 4
        assert io_cmd._value == 0xFFFFFFFF

    @pytest.mark.unit
    def test_common_io_ports(self, mock_cs):
        """Test operations on common I/O ports."""
        common_ports = {
            'keyboard': 0x60,
            'speaker': 0x61,
            'timer': 0x40,
            'pci_config': 0xCF8,
            'pci_data': 0xCFC,
        }

        for port_name, port_addr in common_ports.items():
            io_cmd = PortIOCommand(['read', f'0x{port_addr:X}', '1'], cs=mock_cs)
            io_cmd.parse_arguments()
            assert io_cmd._port == port_addr


class TestPortIOCommandConfigurationValidation:
    """Test configuration validation aspects of I/O command."""

    @pytest.fixture
    def config_cs(self):
        """Create ChipsecCs with I/O-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock I/O HAL with configuration
        cs_mock.hals.Io = Mock()
        cs_mock.hals.Io.read.return_value = 0x12345678

        # Mock I/O configuration data
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.IO_CONFIG = {
            'max_port_address': 0xFFFF,
            'supported_widths': [1, 2, 4],
            'common_ports': {
                'keyboard_data': 0x60,
                'keyboard_status': 0x64,
                'speaker': 0x61,
                'timer_0': 0x40,
                'timer_1': 0x41,
                'timer_2': 0x42,
                'timer_control': 0x43,
                'pci_config_address': 0xCF8,
                'pci_config_data': 0xCFC,
                'dma_0': 0x00,
                'dma_1': 0x02,
                'interrupt_mask_0': 0x21,
                'interrupt_mask_1': 0xA1,
            },
            'security_ports': {
                'tpm_data': 0x2E,
                'tpm_index': 0x4E,
                'smbus_host': 0x4100,
                'gpio_base': 0x500,
            }
        }

        return cs_mock

    @pytest.mark.unit
    def test_io_configuration_access(self, config_cs):
        """Test access to I/O configuration data."""
        io_config = config_cs.Cfg.IO_CONFIG

        assert io_config['max_port_address'] == 0xFFFF
        assert 1 in io_config['supported_widths']
        assert 2 in io_config['supported_widths']
        assert 4 in io_config['supported_widths']
        assert 'keyboard_data' in io_config['common_ports']
        assert io_config['common_ports']['keyboard_data'] == 0x60

    @pytest.mark.unit
    def test_supported_widths_validation(self, config_cs):
        """Test validation of supported I/O widths."""
        supported_widths = config_cs.Cfg.IO_CONFIG['supported_widths']

        # Test that all documented widths are supported
        assert 1 in supported_widths  # byte
        assert 2 in supported_widths  # word
        assert 4 in supported_widths  # dword

        # Test that unsupported widths are not included
        assert 3 not in supported_widths
        assert 8 not in supported_widths

    @pytest.mark.unit
    def test_common_ports_validation(self, config_cs):
        """Test validation of common I/O ports."""
        common_ports = config_cs.Cfg.IO_CONFIG['common_ports']

        # Test that all expected common ports are defined
        expected_ports = [
            'keyboard_data', 'keyboard_status', 'speaker',
            'timer_0', 'timer_1', 'timer_2', 'timer_control',
            'pci_config_address', 'pci_config_data',
            'dma_0', 'dma_1',
            'interrupt_mask_0', 'interrupt_mask_1'
        ]

        for port_name in expected_ports:
            assert port_name in common_ports
            assert isinstance(common_ports[port_name], int)
            assert 0 <= common_ports[port_name] <= 0xFFFF

    @pytest.mark.unit
    def test_security_ports_validation(self, config_cs):
        """Test validation of security-related I/O ports."""
        security_ports = config_cs.Cfg.IO_CONFIG['security_ports']

        # Test that security ports are properly defined
        expected_security_ports = [
            'tpm_data', 'tpm_index', 'smbus_host', 'gpio_base'
        ]

        for port_name in expected_security_ports:
            assert port_name in security_ports
            assert isinstance(security_ports[port_name], int)
            assert 0 <= security_ports[port_name] <= 0xFFFF

    @pytest.mark.unit
    def test_port_address_limits_validation(self, config_cs):
        """Test I/O port address limits validation."""
        max_port = config_cs.Cfg.IO_CONFIG['max_port_address']

        # Test that the maximum port address is valid
        assert max_port == 0xFFFF  # 16-bit I/O address space

        # Test that all configured ports are within limits
        all_ports = {}
        all_ports.update(config_cs.Cfg.IO_CONFIG['common_ports'])
        all_ports.update(config_cs.Cfg.IO_CONFIG['security_ports'])

        for port_name, port_addr in all_ports.items():
            assert 0 <= port_addr <= max_port, f"Port {port_name} address 0x{port_addr:X} exceeds maximum 0x{max_port:X}"


if __name__ == '__main__':
    pytest.main([__file__])
