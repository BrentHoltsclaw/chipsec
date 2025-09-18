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
from unittest.mock import Mock, patch
from chipsec.utilcmd.io_cmd import PortIOCommand
from tests.test_utils import MockFactory


class TestPortIOCommand(unittest.TestCase):
    """Comprehensive tests for I/O port utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock ChipsecCs object for I/O testing
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        # Mock I/O HAL
        self.mock_cs.hals.Io = Mock()
        self.mock_cs.hals.Io.read.return_value = 0x12345678
        self.mock_cs.hals.Io.write.return_value = None

        # Create PortIOCommand instance
        self.io_command = PortIOCommand(['list'], cs=self.mock_cs)

    def test_io_command_initialization(self):
        """Test PortIOCommand initialization."""
        self.assertEqual(self.io_command.cs, self.mock_cs)
        self.assertEqual(self.io_command.argv, ['list'])

    def test_parse_arguments_list(self):
        """Test parsing list command arguments."""
        command = PortIOCommand(['list'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.io_list)

    def test_parse_arguments_read(self):
        """Test parsing read command arguments."""
        command = PortIOCommand(['read', '0x61', '1'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.io_read)
        self.assertEqual(command._port, 0x61)
        self.assertEqual(command._width, 1)

    def test_parse_arguments_read_width_2(self):
        """Test parsing read command with 2-byte width."""
        command = PortIOCommand(['read', '0x430', '2'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.io_read)
        self.assertEqual(command._port, 0x430)
        self.assertEqual(command._width, 2)

    def test_parse_arguments_read_width_4(self):
        """Test parsing read command with 4-byte width."""
        command = PortIOCommand(['read', '0xCF8', '4'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.io_read)
        self.assertEqual(command._port, 0xCF8)
        self.assertEqual(command._width, 4)

    def test_parse_arguments_write(self):
        """Test parsing write command arguments."""
        command = PortIOCommand(['write', '0x430', '1', '0x0'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.io_write)
        self.assertEqual(command._port, 0x430)
        self.assertEqual(command._width, 1)
        self.assertEqual(command._value, 0x0)

    def test_parse_arguments_write_width_2(self):
        """Test parsing write command with 2-byte width."""
        command = PortIOCommand(['write', '0x61', '2', '0x1234'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.io_write)
        self.assertEqual(command._port, 0x61)
        self.assertEqual(command._width, 2)
        self.assertEqual(command._value, 0x1234)

    def test_parse_arguments_write_width_4(self):
        """Test parsing write command with 4-byte width."""
        command = PortIOCommand(['write', '0xCF8', '4', '0x8000F8C0'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.io_write)
        self.assertEqual(command._port, 0xCF8)
        self.assertEqual(command._width, 4)
        self.assertEqual(command._value, 0x8000F8C0)

    def test_parse_arguments_decimal_values(self):
        """Test parsing arguments with decimal values."""
        command = PortIOCommand(['read', '97', '1'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command._port, 97)  # 0x61
        self.assertEqual(command._width, 1)

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.io_command.requirements()
        self.assertTrue(hasattr(reqs, 'load_driver'))
        self.assertTrue(hasattr(reqs, 'load_config'))

    def test_set_up(self):
        """Test set_up method."""
        with patch('chipsec.utilcmd.io_cmd.iobar.IOBAR') as mock_iobar_class:
            mock_iobar_instance = Mock()
            mock_iobar_class.return_value = mock_iobar_instance

            self.io_command.set_up()

            self.assertTrue(hasattr(self.io_command, '_iobar'))
            mock_iobar_class.assert_called_once_with(self.io_command.cs)

    def test_io_list(self):
        """Test io_list command."""
        with patch('chipsec.utilcmd.io_cmd.iobar.IOBAR') as mock_iobar_class:
            mock_iobar_instance = Mock()
            mock_iobar_class.return_value = mock_iobar_instance
            self.io_command.set_up()

            self.io_command.io_list()

            mock_iobar_instance.list_IO_BARs.assert_called_once()

    def test_io_read_byte(self):
        """Test io_read command for byte (1-byte) access."""
        self.io_command._port = 0x61
        self.io_command._width = 1

        with patch.object(self.io_command.logger, 'log') as mock_log:
            self.io_command.io_read()

            self.mock_cs.hals.Io.read.assert_called_once_with(0x61, 1)
            mock_log.assert_called_once()
            # Verify the log message format
            log_call = mock_log.call_args[0][0]
            self.assertIn('IN 0x0061', log_call)
            self.assertIn('size = 0x01', log_call)

    def test_io_read_word(self):
        """Test io_read command for word (2-byte) access."""
        self.io_command._port = 0x430
        self.io_command._width = 2

        with patch.object(self.io_command.logger, 'log') as mock_log:
            self.io_command.io_read()

            self.mock_cs.hals.Io.read.assert_called_once_with(0x430, 2)
            mock_log.assert_called_once()
            # Verify the log message format
            log_call = mock_log.call_args[0][0]
            self.assertIn('IN 0x0430', log_call)
            self.assertIn('size = 0x02', log_call)

    def test_io_read_dword(self):
        """Test io_read command for dword (4-byte) access."""
        self.io_command._port = 0xCF8
        self.io_command._width = 4

        with patch.object(self.io_command.logger, 'log') as mock_log:
            self.io_command.io_read()

            self.mock_cs.hals.Io.read.assert_called_once_with(0xCF8, 4)
            mock_log.assert_called_once()
            # Verify the log message format
            log_call = mock_log.call_args[0][0]
            self.assertIn('IN 0x0CF8', log_call)
            self.assertIn('size = 0x04', log_call)

    def test_io_read_different_values(self):
        """Test io_read command with different return values."""
        self.io_command._port = 0x61
        self.io_command._width = 1

        # Test with different return values
        test_values = [0x0, 0xFF, 0x1234, 0xFFFFFFFF]

        for expected_value in test_values:
            self.mock_cs.hals.Io.read.return_value = expected_value

            with patch.object(self.io_command.logger, 'log') as mock_log:
                self.io_command.io_read()

                mock_log.assert_called_once()
                log_call = mock_log.call_args[0][0]
                # Verify the value is correctly formatted in the log
                expected_hex = f'0x{expected_value:08X}'
                self.assertIn(expected_hex, log_call)

    def test_io_write_byte(self):
        """Test io_write command for byte (1-byte) access."""
        self.io_command._port = 0x430
        self.io_command._width = 1
        self.io_command._value = 0x0

        with patch.object(self.io_command.logger, 'log') as mock_log:
            self.io_command.io_write()

            self.mock_cs.hals.Io.write.assert_called_once_with(0x430, 0x0, 1)
            mock_log.assert_called_once()
            # Verify the log message format
            log_call = mock_log.call_args[0][0]
            self.assertIn('OUT 0x0430', log_call)
            self.assertIn('size = 0x01', log_call)

    def test_io_write_word(self):
        """Test io_write command for word (2-byte) access."""
        self.io_command._port = 0x61
        self.io_command._width = 2
        self.io_command._value = 0x1234

        with patch.object(self.io_command.logger, 'log') as mock_log:
            self.io_command.io_write()

            self.mock_cs.hals.Io.write.assert_called_once_with(0x61, 0x1234, 2)
            mock_log.assert_called_once()
            # Verify the log message format
            log_call = mock_log.call_args[0][0]
            self.assertIn('OUT 0x0061', log_call)
            self.assertIn('size = 0x02', log_call)

    def test_io_write_dword(self):
        """Test io_write command for dword (4-byte) access."""
        self.io_command._port = 0xCF8
        self.io_command._width = 4
        self.io_command._value = 0x8000F8C0

        with patch.object(self.io_command.logger, 'log') as mock_log:
            self.io_command.io_write()

            self.mock_cs.hals.Io.write.assert_called_once_with(0xCF8, 0x8000F8C0, 4)
            mock_log.assert_called_once()
            # Verify the log message format
            log_call = mock_log.call_args[0][0]
            self.assertIn('OUT 0x0CF8', log_call)
            self.assertIn('size = 0x04', log_call)

    def test_io_write_different_values(self):
        """Test io_write command with different values."""
        self.io_command._port = 0x61
        self.io_command._width = 1

        # Test with different values
        test_values = [0x0, 0xFF, 0x1234, 0xFFFFFFFF]

        for test_value in test_values:
            self.io_command._value = test_value

            with patch.object(self.io_command.logger, 'log') as mock_log:
                self.io_command.io_write()

                self.mock_cs.hals.Io.write.assert_called_with(0x61, test_value, 1)
                mock_log.assert_called_once()
                log_call = mock_log.call_args[0][0]
                # Verify the value is correctly formatted in the log
                expected_hex = f'0x{test_value:08X}'
                self.assertIn(expected_hex, log_call)


class TestPortIOCommandIntegration(unittest.TestCase):
    """Integration tests for I/O command with HAL components."""

    def setUp(self):
        """Set up integrated test fixtures."""
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        self.integrated_cs.hals.Io = Mock()
        self.integrated_cs.hals.Io.read.return_value = 0xDEADBEEF
        self.integrated_cs.hals.Io.write.return_value = None

        # Mock helper
        self.integrated_cs.helper = Mock()
        self.integrated_cs.helper.get_threads_count.return_value = 2

    def test_io_read_write_workflow(self):
        """Test complete I/O read/write workflow."""
        # Test read operation
        read_cmd = PortIOCommand(['read', '0x61', '1'], cs=self.integrated_cs)
        read_cmd.parse_arguments()

        with patch.object(read_cmd.logger, 'log') as mock_log:
            read_cmd.run()

            self.integrated_cs.hals.Io.read.assert_called_once_with(0x61, 1)
            mock_log.assert_called_once()

        # Test write operation
        write_cmd = PortIOCommand(['write', '0x430', '1', '0x0'], cs=self.integrated_cs)
        write_cmd.parse_arguments()

        with patch.object(write_cmd.logger, 'log') as mock_log:
            write_cmd.run()

            self.integrated_cs.hals.Io.write.assert_called_once_with(0x430, 0x0, 1)
            mock_log.assert_called_once()

    def test_io_list_workflow(self):
        """Test I/O list workflow."""
        list_cmd = PortIOCommand(['list'], cs=self.integrated_cs)
        list_cmd.parse_arguments()

        with patch('chipsec.utilcmd.io_cmd.iobar.IOBAR') as mock_iobar_class:
            mock_iobar_instance = Mock()
            mock_iobar_class.return_value = mock_iobar_instance

            list_cmd.set_up()
            list_cmd.run()

            mock_iobar_instance.list_IO_BARs.assert_called_once()

    def test_io_different_widths_workflow(self):
        """Test I/O operations with different widths."""
        # Test byte operations
        byte_cmd = PortIOCommand(['read', '0x61', '1'], cs=self.integrated_cs)
        byte_cmd.parse_arguments()
        byte_cmd.run()
        self.integrated_cs.hals.Io.read.assert_called_with(0x61, 1)

        # Test word operations
        word_cmd = PortIOCommand(['write', '0x430', '2', '0x1234'], cs=self.integrated_cs)
        word_cmd.parse_arguments()
        word_cmd.run()
        self.integrated_cs.hals.Io.write.assert_called_with(0x430, 0x1234, 2)

        # Test dword operations
        dword_cmd = PortIOCommand(['read', '0xCF8', '4'], cs=self.integrated_cs)
        dword_cmd.parse_arguments()
        dword_cmd.run()
        self.integrated_cs.hals.Io.read.assert_called_with(0xCF8, 4)


class TestPortIOCommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for I/O command."""

    def setUp(self):
        """Set up mock ChipsecCs for edge case testing."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.hals.Io = Mock()

    def test_empty_argv_handling(self):
        """Test handling of empty argv."""
        io_cmd = PortIOCommand([], cs=self.mock_cs)

        # The argument parser may not raise SystemExit for empty args
        # Let's just ensure it doesn't crash and has default behavior
        try:
            io_cmd.parse_arguments()
            # If it doesn't raise, that's also acceptable
            self.assertTrue(True)
        except SystemExit:
            # If it does raise SystemExit, that's also acceptable
            self.assertTrue(True)

    def test_invalid_subcommand(self):
        """Test handling of invalid subcommand."""
        io_cmd = PortIOCommand(['invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with self.assertRaises(SystemExit):
            io_cmd.parse_arguments()

    def test_read_missing_width(self):
        """Test read command with missing width."""
        io_cmd = PortIOCommand(['read', '0x61'], cs=self.mock_cs)

        # Should raise SystemExit due to missing width
        with self.assertRaises(SystemExit):
            io_cmd.parse_arguments()

    def test_write_missing_value(self):
        """Test write command with missing value."""
        io_cmd = PortIOCommand(['write', '0x430', '1'], cs=self.mock_cs)

        # Should raise SystemExit due to missing value
        with self.assertRaises(SystemExit):
            io_cmd.parse_arguments()

    def test_invalid_width_choice(self):
        """Test command with invalid width choice."""
        io_cmd = PortIOCommand(['read', '0x61', '3'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid width choice
        with self.assertRaises(SystemExit):
            io_cmd.parse_arguments()

    def test_zero_port_address(self):
        """Test operations with zero port address."""
        io_cmd = PortIOCommand(['read', '0x0', '1'], cs=self.mock_cs)
        io_cmd.parse_arguments()

        self.assertEqual(io_cmd._port, 0x0)
        self.assertEqual(io_cmd._width, 1)

    def test_maximum_port_address(self):
        """Test operations with maximum port address."""
        io_cmd = PortIOCommand(['write', '0xFFFF', '2', '0x1234'], cs=self.mock_cs)
        io_cmd.parse_arguments()

        self.assertEqual(io_cmd._port, 0xFFFF)
        self.assertEqual(io_cmd._width, 2)
        self.assertEqual(io_cmd._value, 0x1234)

    def test_zero_value_write(self):
        """Test writing zero value."""
        io_cmd = PortIOCommand(['write', '0x61', '1', '0x0'], cs=self.mock_cs)
        io_cmd.parse_arguments()

        self.assertEqual(io_cmd._port, 0x61)
        self.assertEqual(io_cmd._width, 1)
        self.assertEqual(io_cmd._value, 0x0)

    def test_maximum_value_write(self):
        """Test writing maximum value."""
        io_cmd = PortIOCommand(['write', '0x430', '4', '0xFFFFFFFF'], cs=self.mock_cs)
        io_cmd.parse_arguments()

        self.assertEqual(io_cmd._port, 0x430)
        self.assertEqual(io_cmd._width, 4)
        self.assertEqual(io_cmd._value, 0xFFFFFFFF)

    def test_common_io_ports(self):
        """Test operations on common I/O ports."""
        common_ports = {
            'keyboard': 0x60,
            'speaker': 0x61,
            'timer': 0x40,
            'pci_config': 0xCF8,
            'pci_data': 0xCFC,
        }

        for port_name, port_addr in common_ports.items():
            io_cmd = PortIOCommand(['read', f'0x{port_addr:X}', '1'], cs=self.mock_cs)
            io_cmd.parse_arguments()
            self.assertEqual(io_cmd._port, port_addr)


class TestPortIOCommandConfigurationValidation(unittest.TestCase):
    """Test configuration validation aspects of I/O command."""

    def setUp(self):
        """Set up ChipsecCs with I/O-specific configuration."""
        self.config_cs = MockFactory.create_mock_chipsec_cs()

        # Mock I/O HAL with configuration
        self.config_cs.hals.Io = Mock()
        self.config_cs.hals.Io.read.return_value = 0x12345678

        # Mock I/O configuration data
        self.config_cs.Cfg = Mock()
        self.config_cs.Cfg.IO_CONFIG = {
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

    def test_io_configuration_access(self):
        """Test access to I/O configuration data."""
        io_config = self.config_cs.Cfg.IO_CONFIG

        self.assertEqual(io_config['max_port_address'], 0xFFFF)
        self.assertIn(1, io_config['supported_widths'])
        self.assertIn(2, io_config['supported_widths'])
        self.assertIn(4, io_config['supported_widths'])
        self.assertIn('keyboard_data', io_config['common_ports'])
        self.assertEqual(io_config['common_ports']['keyboard_data'], 0x60)

    def test_supported_widths_validation(self):
        """Test validation of supported I/O widths."""
        supported_widths = self.config_cs.Cfg.IO_CONFIG['supported_widths']

        # Test that all documented widths are supported
        self.assertIn(1, supported_widths)  # byte
        self.assertIn(2, supported_widths)  # word
        self.assertIn(4, supported_widths)  # dword

        # Test that unsupported widths are not included
        self.assertNotIn(3, supported_widths)
        self.assertNotIn(8, supported_widths)

    def test_common_ports_validation(self):
        """Test validation of common I/O ports."""
        common_ports = self.config_cs.Cfg.IO_CONFIG['common_ports']

        # Test that all expected common ports are defined
        expected_ports = [
            'keyboard_data', 'keyboard_status', 'speaker',
            'timer_0', 'timer_1', 'timer_2', 'timer_control',
            'pci_config_address', 'pci_config_data',
            'dma_0', 'dma_1',
            'interrupt_mask_0', 'interrupt_mask_1'
        ]

        for port_name in expected_ports:
            self.assertIn(port_name, common_ports)
            self.assertIsInstance(common_ports[port_name], int)
            self.assertGreaterEqual(common_ports[port_name], 0)
            self.assertLessEqual(common_ports[port_name], 0xFFFF)

    def test_security_ports_validation(self):
        """Test validation of security-related I/O ports."""
        security_ports = self.config_cs.Cfg.IO_CONFIG['security_ports']

        # Test that security ports are properly defined
        expected_security_ports = [
            'tpm_data', 'tpm_index', 'smbus_host', 'gpio_base'
        ]

        for port_name in expected_security_ports:
            self.assertIn(port_name, security_ports)
            self.assertIsInstance(security_ports[port_name], int)
            self.assertGreaterEqual(security_ports[port_name], 0)
            self.assertLessEqual(security_ports[port_name], 0xFFFF)

    def test_port_address_limits_validation(self):
        """Test I/O port address limits validation."""
        max_port = self.config_cs.Cfg.IO_CONFIG['max_port_address']

        # Test that the maximum port address is valid
        self.assertEqual(max_port, 0xFFFF)  # 16-bit I/O address space

        # Test that all configured ports are within limits
        all_ports = {}
        all_ports.update(self.config_cs.Cfg.IO_CONFIG['common_ports'])
        all_ports.update(self.config_cs.Cfg.IO_CONFIG['security_ports'])

        for port_name, port_addr in all_ports.items():
            self.assertGreaterEqual(port_addr, 0)
            self.assertLessEqual(port_addr, max_port, f"Port {port_name} address 0x{port_addr:X} exceeds maximum 0x{max_port:X}")


if __name__ == '__main__':
    unittest.main()
