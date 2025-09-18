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
from chipsec.utilcmd.cmos_cmd import CMOSCommand
from tests.test_utils import MockFactory


class TestCMOSCommand(unittest.TestCase):
    """Comprehensive tests for CMOS utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()

        # Mock CMOS HAL component
        self.mock_cs.hals.CMOS = Mock()
        self.mock_cs.hals.CMOS.dump.return_value = None
        self.mock_cs.hals.CMOS.read_cmos_low.return_value = 0x12
        self.mock_cs.hals.CMOS.write_cmos_low.return_value = None
        self.mock_cs.hals.CMOS.read_cmos_high.return_value = 0x34
        self.mock_cs.hals.CMOS.write_cmos_high.return_value = None

        self.cmos_command = CMOSCommand(['dump'], cs=self.mock_cs)

    def test_cmos_command_initialization(self):
        """Test CMOSCommand initialization."""
        self.assertEqual(self.cmos_command.cs, self.mock_cs)
        self.assertEqual(self.cmos_command.argv, ['dump'])

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.cmos_command.requirements()
        self.assertTrue(hasattr(reqs, 'load_driver'))

    def test_parse_arguments_dump(self):
        """Test parsing dump command arguments."""
        command = CMOSCommand(['dump'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.cmos_dump)

    def test_parse_arguments_readl(self):
        """Test parsing readl command arguments."""
        command = CMOSCommand(['readl', '0x10'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.cmos_readl)
        self.assertEqual(command.offset, 0x10)

    def test_parse_arguments_writel(self):
        """Test parsing writel command arguments."""
        command = CMOSCommand(['writel', '0x10', '0xAB'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.cmos_writel)
        self.assertEqual(command.offset, 0x10)
        self.assertEqual(command.value, 0xAB)

    def test_parse_arguments_readh(self):
        """Test parsing readh command arguments."""
        command = CMOSCommand(['readh', '0x20'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.cmos_readh)
        self.assertEqual(command.offset, 0x20)

    def test_parse_arguments_writeh(self):
        """Test parsing writeh command arguments."""
        command = CMOSCommand(['writeh', '0x20', '0xCD'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.cmos_writeh)
        self.assertEqual(command.offset, 0x20)
        self.assertEqual(command.value, 0xCD)

    def test_parse_arguments_decimal_values(self):
        """Test parsing arguments with decimal values."""
        command = CMOSCommand(['readl', '16'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.offset, 16)  # 0x10

        command2 = CMOSCommand(['writel', '32', '171'], cs=self.mock_cs)
        command2.parse_arguments()
        self.assertEqual(command2.offset, 32)  # 0x20
        self.assertEqual(command2.value, 171)  # 0xAB

    def test_set_up(self):
        """Test set_up method."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance

            self.cmos_command.set_up()

            self.assertTrue(hasattr(self.cmos_command, '_cmos'))
            mock_cmos_class.assert_called_once_with(self.cmos_command.cs)

    def test_cmos_dump(self):
        """Test cmos_dump command."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance
            self.cmos_command.set_up()

            with patch.object(self.cmos_command.logger, 'log') as mock_log:
                self.cmos_command.cmos_dump()

                mock_log.assert_called_once_with('[CHIPSEC] Dumping CMOS memory..')
                mock_cmos_instance.dump.assert_called_once()

    def test_cmos_readl(self):
        """Test cmos_readl command."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_instance.read_cmos_low.return_value = 0xAB
            mock_cmos_class.return_value = mock_cmos_instance
            self.cmos_command.set_up()
            self.cmos_command.offset = 0x10

            with patch.object(self.cmos_command.logger, 'log') as mock_log:
                self.cmos_command.cmos_readl()

                mock_log.assert_called_once_with('[CHIPSEC] CMOS low byte 0x10 = 0xAB')
                mock_cmos_instance.read_cmos_low.assert_called_once_with(0x10)

    def test_cmos_writel(self):
        """Test cmos_writel command."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_instance.write_cmos_low.return_value = None
            mock_cmos_class.return_value = mock_cmos_instance
            self.cmos_command.set_up()
            self.cmos_command.offset = 0x10
            self.cmos_command.value = 0xAB

            with patch.object(self.cmos_command.logger, 'log') as mock_log:
                self.cmos_command.cmos_writel()

                mock_log.assert_called_once_with('[CHIPSEC] CMOS low byte 0x10 = 0xAB')
                mock_cmos_instance.write_cmos_low.assert_called_once_with(0x10, 0xAB)

    def test_cmos_readh(self):
        """Test cmos_readh command."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_instance.read_cmos_high.return_value = 0xCD
            mock_cmos_class.return_value = mock_cmos_instance
            self.cmos_command.set_up()
            self.cmos_command.offset = 0x20

            with patch.object(self.cmos_command.logger, 'log') as mock_log:
                self.cmos_command.cmos_readh()

                mock_log.assert_called_once_with('[CHIPSEC] CMOS high byte 0x20 = 0xCD')
                mock_cmos_instance.read_cmos_high.assert_called_once_with(0x20)

    def test_cmos_writeh(self):
        """Test cmos_writeh command."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_instance.write_cmos_high.return_value = None
            mock_cmos_class.return_value = mock_cmos_instance
            self.cmos_command.set_up()
            self.cmos_command.offset = 0x20
            self.cmos_command.value = 0xCD

            with patch.object(self.cmos_command.logger, 'log') as mock_log:
                self.cmos_command.cmos_writeh()

                mock_log.assert_called_once_with('[CHIPSEC] Writing CMOS high byte 0x20 <- 0xCD')
                mock_cmos_instance.write_cmos_high.assert_called_once_with(0x20, 0xCD)

    def test_cmos_readl_different_values(self):
        """Test cmos_readl with different return values."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance
            self.cmos_command.set_up()
            self.cmos_command.offset = 0x10

            # Test with different return values
            test_values = [0x0, 0xFF, 0x12, 0xAB]

            for expected_value in test_values:
                mock_cmos_instance.read_cmos_low.return_value = expected_value

                with patch.object(self.cmos_command.logger, 'log') as mock_log:
                    self.cmos_command.cmos_readl()

                    log_call = mock_log.call_args[0][0]
                    expected_hex = f'0x{expected_value:X}'
                    self.assertIn(expected_hex, log_call)

    def test_cmos_readh_different_values(self):
        """Test cmos_readh with different return values."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance
            self.cmos_command.set_up()
            self.cmos_command.offset = 0x20

            # Test with different return values
            test_values = [0x0, 0xFF, 0x34, 0xCD]

            for expected_value in test_values:
                mock_cmos_instance.read_cmos_high.return_value = expected_value

                with patch.object(self.cmos_command.logger, 'log') as mock_log:
                    self.cmos_command.cmos_readh()

                    log_call = mock_log.call_args[0][0]
                    expected_hex = f'0x{expected_value:X}'
                    self.assertIn(expected_hex, log_call)

    def test_cmos_writel_different_values(self):
        """Test cmos_writel with different values."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance
            self.cmos_command.set_up()
            self.cmos_command.offset = 0x10

            # Test with different values
            test_values = [0x0, 0xFF, 0xAB, 0x12]

            for test_value in test_values:
                self.cmos_command.value = test_value

                with patch.object(self.cmos_command.logger, 'log') as mock_log:
                    self.cmos_command.cmos_writel()

                    log_call = mock_log.call_args[0][0]
                    expected_hex = f'0x{test_value:X}'
                    self.assertIn(expected_hex, log_call)
                    mock_cmos_instance.write_cmos_low.assert_called_with(0x10, test_value)

    def test_cmos_writeh_different_values(self):
        """Test cmos_writeh with different values."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance
            self.cmos_command.set_up()
            self.cmos_command.offset = 0x20

            # Test with different values
            test_values = [0x0, 0xFF, 0xCD, 0x34]

            for test_value in test_values:
                self.cmos_command.value = test_value

                with patch.object(self.cmos_command.logger, 'log') as mock_log:
                    self.cmos_command.cmos_writeh()

                    mock_log.assert_called_once_with(f'[CHIPSEC] Writing CMOS high byte 0x20 <- 0x{test_value:X}')
                    mock_cmos_instance.write_cmos_high.assert_called_with(0x20, test_value)


class TestCMOSCommandIntegration(unittest.TestCase):
    """Integration tests for CMOS command with HAL components."""

    def setUp(self):
        """Set up test fixtures."""
        # Create integrated ChipsecCs for CMOS testing
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        self.integrated_cs.hals.CMOS = Mock()
        self.integrated_cs.hals.CMOS.dump.return_value = None
        self.integrated_cs.hals.CMOS.read_cmos_low.return_value = 0xDE
        self.integrated_cs.hals.CMOS.write_cmos_low.return_value = None
        self.integrated_cs.hals.CMOS.read_cmos_high.return_value = 0xAD
        self.integrated_cs.hals.CMOS.write_cmos_high.return_value = None

        # Mock helper
        self.integrated_cs.helper = Mock()
        self.integrated_cs.helper.get_threads_count.return_value = 2

    def test_cmos_read_write_workflow(self):
        """Test complete CMOS read/write workflow."""
        # Test dump operation
        dump_cmd = CMOSCommand(['dump'], cs=self.integrated_cs)
        dump_cmd.parse_arguments()

        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance

            with patch.object(dump_cmd.logger, 'log') as mock_log:
                dump_cmd.run()

                mock_log.assert_called_once_with('[CHIPSEC] Dumping CMOS memory..')
                mock_cmos_instance.dump.assert_called_once()

        # Test readl operation
        readl_cmd = CMOSCommand(['readl', '0x10'], cs=self.integrated_cs)
        readl_cmd.parse_arguments()

        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_instance.read_cmos_low.return_value = 0xAB
            mock_cmos_class.return_value = mock_cmos_instance

            with patch.object(readl_cmd.logger, 'log') as mock_log:
                readl_cmd.run()

                mock_log.assert_called_once_with('[CHIPSEC] CMOS low byte 0x10 = 0xAB')
                mock_cmos_instance.read_cmos_low.assert_called_once_with(0x10)

        # Test writel operation
        writel_cmd = CMOSCommand(['writel', '0x10', '0xAB'], cs=self.integrated_cs)
        writel_cmd.parse_arguments()

        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance

            with patch.object(writel_cmd.logger, 'log') as mock_log:
                writel_cmd.run()

                mock_log.assert_called_once_with('[CHIPSEC] CMOS low byte 0x10 = 0xAB')
                mock_cmos_instance.write_cmos_low.assert_called_once_with(0x10, 0xAB)

    def test_cmos_high_byte_operations_workflow(self):
        """Test CMOS high byte operations workflow."""
        # Test readh operation
        readh_cmd = CMOSCommand(['readh', '0x20'], cs=self.integrated_cs)
        readh_cmd.parse_arguments()

        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_instance.read_cmos_high.return_value = 0xCD
            mock_cmos_class.return_value = mock_cmos_instance

            with patch.object(readh_cmd.logger, 'log') as mock_log:
                readh_cmd.run()

                mock_log.assert_called_once_with('[CHIPSEC] CMOS high byte 0x20 = 0xCD')
                mock_cmos_instance.read_cmos_high.assert_called_once_with(0x20)

        # Test writeh operation
        writeh_cmd = CMOSCommand(['writeh', '0x20', '0xCD'], cs=self.integrated_cs)
        writeh_cmd.parse_arguments()

        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance

            with patch.object(writeh_cmd.logger, 'log') as mock_log:
                writeh_cmd.run()

                mock_log.assert_called_once_with('[CHIPSEC] Writing CMOS high byte 0x20 <- 0xCD')
                mock_cmos_instance.write_cmos_high.assert_called_once_with(0x20, 0xCD)

    def test_cmos_mixed_operations_workflow(self):
        """Test CMOS mixed operations workflow."""
        # Test sequence of operations
        operations = [
            ('dump', ['dump']),
            ('readl', ['readl', '0x0']),
            ('readh', ['readh', '0x1']),
            ('writel', ['writel', '0x2', '0xFF']),
            ('writeh', ['writeh', '0x3', '0xAA']),
        ]

        for op_name, args in operations:
            cmd = CMOSCommand(args, cs=self.integrated_cs)
            cmd.parse_arguments()

            with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
                mock_cmos_instance = Mock()
                mock_cmos_class.return_value = mock_cmos_instance

                with patch.object(cmd.logger, 'log') as mock_log:
                    cmd.run()

                    # Verify that the appropriate method was called
                    if op_name == 'dump':
                        mock_cmos_instance.dump.assert_called_once()
                    elif op_name == 'readl':
                        mock_cmos_instance.read_cmos_low.assert_called_once_with(0x0)
                    elif op_name == 'readh':
                        mock_cmos_instance.read_cmos_high.assert_called_once_with(0x1)
                    elif op_name == 'writel':
                        mock_cmos_instance.write_cmos_low.assert_called_once_with(0x2, 0xFF)
                    elif op_name == 'writeh':
                        mock_cmos_instance.write_cmos_high.assert_called_once_with(0x3, 0xAA)


class TestCMOSCommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for CMOS command."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.hals.CMOS = Mock()

    def test_empty_argv_handling(self):
        """Test handling of empty argv."""
        command = CMOSCommand([], cs=self.mock_cs)

        # Should raise SystemExit due to missing required arguments
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_invalid_subcommand(self):
        """Test handling of invalid subcommand."""
        command = CMOSCommand(['invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_readl_missing_offset(self):
        """Test readl command with missing offset."""
        command = CMOSCommand(['readl'], cs=self.mock_cs)

        # Should raise SystemExit due to missing offset
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_writel_missing_value(self):
        """Test writel command with missing value."""
        command = CMOSCommand(['writel', '0x10'], cs=self.mock_cs)

        # Should raise SystemExit due to missing value
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_readh_missing_offset(self):
        """Test readh command with missing offset."""
        command = CMOSCommand(['readh'], cs=self.mock_cs)

        # Should raise SystemExit due to missing offset
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_writeh_missing_value(self):
        """Test writeh command with missing value."""
        command = CMOSCommand(['writeh', '0x20'], cs=self.mock_cs)

        # Should raise SystemExit due to missing value
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_zero_offset_values(self):
        """Test operations with zero offset values."""
        # Test readl with zero offset
        readl_cmd = CMOSCommand(['readl', '0x0'], cs=self.mock_cs)
        readl_cmd.parse_arguments()
        self.assertEqual(readl_cmd.offset, 0x0)

        # Test readh with zero offset
        readh_cmd = CMOSCommand(['readh', '0x0'], cs=self.mock_cs)
        readh_cmd.parse_arguments()
        self.assertEqual(readh_cmd.offset, 0x0)

    def test_maximum_offset_values(self):
        """Test operations with maximum offset values."""
        # CMOS memory is typically 256 bytes (0x00-0xFF)
        max_offset = 0xFF

        # Test readl with maximum offset
        readl_cmd = CMOSCommand(['readl', f'0x{max_offset:X}'], cs=self.mock_cs)
        readl_cmd.parse_arguments()
        self.assertEqual(readl_cmd.offset, max_offset)

        # Test readh with maximum offset
        readh_cmd = CMOSCommand(['readh', f'0x{max_offset:X}'], cs=self.mock_cs)
        readh_cmd.parse_arguments()
        self.assertEqual(readh_cmd.offset, max_offset)

    def test_zero_value_writes(self):
        """Test write operations with zero values."""
        # Test writel with zero value
        writel_cmd = CMOSCommand(['writel', '0x10', '0x0'], cs=self.mock_cs)
        writel_cmd.parse_arguments()
        self.assertEqual(writel_cmd.value, 0x0)

        # Test writeh with zero value
        writeh_cmd = CMOSCommand(['writeh', '0x20', '0x0'], cs=self.mock_cs)
        writeh_cmd.parse_arguments()
        self.assertEqual(writeh_cmd.value, 0x0)

    def test_maximum_value_writes(self):
        """Test write operations with maximum values."""
        # Test writel with maximum byte value
        writel_cmd = CMOSCommand(['writel', '0x10', '0xFF'], cs=self.mock_cs)
        writel_cmd.parse_arguments()
        self.assertEqual(writel_cmd.value, 0xFF)

        # Test writeh with maximum byte value
        writeh_cmd = CMOSCommand(['writeh', '0x20', '0xFF'], cs=self.mock_cs)
        writeh_cmd.parse_arguments()
        self.assertEqual(writeh_cmd.value, 0xFF)

    def test_hex_value_parsing(self):
        """Test hex value parsing in various commands."""
        # Test writel with hex value
        writel_cmd = CMOSCommand(['writel', '0x10', '0xAB'], cs=self.mock_cs)
        writel_cmd.parse_arguments()
        self.assertEqual(writel_cmd.value, 0xAB)

        # Test writel with decimal value
        writel_cmd2 = CMOSCommand(['writel', '0x10', '171'], cs=self.mock_cs)
        writel_cmd2.parse_arguments()
        self.assertEqual(writel_cmd2.value, 171)

        # Test writeh with hex value
        writeh_cmd = CMOSCommand(['writeh', '0x20', '0xCD'], cs=self.mock_cs)
        writeh_cmd.parse_arguments()
        self.assertEqual(writeh_cmd.value, 0xCD)

    def test_case_insensitive_hex_parsing(self):
        """Test case insensitive hex value parsing."""
        # Test with uppercase hex
        writel_cmd1 = CMOSCommand(['writel', '0x10', '0xAB'], cs=self.mock_cs)
        writel_cmd1.parse_arguments()
        self.assertEqual(writel_cmd1.value, 0xAB)

        # Test with lowercase hex
        writel_cmd2 = CMOSCommand(['writel', '0x10', '0xab'], cs=self.mock_cs)
        writel_cmd2.parse_arguments()
        self.assertEqual(writel_cmd2.value, 0xAB)

        # Test with mixed case hex
        writel_cmd3 = CMOSCommand(['writel', '0x10', '0xAb'], cs=self.mock_cs)
        writel_cmd3.parse_arguments()
        self.assertEqual(writel_cmd3.value, 0xAB)

    def test_common_cmos_offsets(self):
        """Test operations on common CMOS offsets."""
        common_offsets = {
            'rtc_seconds': 0x00,
            'rtc_minutes': 0x02,
            'rtc_hours': 0x04,
            'rtc_day': 0x07,
            'rtc_month': 0x08,
            'rtc_year': 0x09,
            'floppy_type': 0x10,
            'hd0_type': 0x12,
            'hd1_type': 0x13,
            'equipment_byte': 0x14,
        }

        for offset_name, offset_addr in common_offsets.items():
            # Test readl operation
            readl_cmd = CMOSCommand(['readl', f'0x{offset_addr:X}'], cs=self.mock_cs)
            readl_cmd.parse_arguments()
            self.assertEqual(readl_cmd.offset, offset_addr)

            # Test readh operation
            readh_cmd = CMOSCommand(['readh', f'0x{offset_addr:X}'], cs=self.mock_cs)
            readh_cmd.parse_arguments()
            self.assertEqual(readh_cmd.offset, offset_addr)


class TestCMOSCommandConfigurationValidation(unittest.TestCase):
    """Test configuration validation aspects of CMOS command."""

    def setUp(self):
        """Set up test fixtures."""
        # Create ChipsecCs with CMOS-specific configuration
        self.config_cs = MockFactory.create_mock_chipsec_cs()

        # Mock CMOS configuration
        self.config_cs.Cfg = Mock()
        self.config_cs.Cfg.CMOS_CONFIG = {
            'max_offset': 0xFF,
            'cmos_size': 256,
            'supported_operations': ['dump', 'readl', 'writel', 'readh', 'writeh'],
            'common_offsets': {
                'rtc_seconds': 0x00,
                'rtc_minutes': 0x02,
                'rtc_hours': 0x04,
                'rtc_day': 0x07,
                'rtc_month': 0x08,
                'rtc_year': 0x09,
                'floppy_type': 0x10,
                'hd0_type': 0x12,
                'hd1_type': 0x13,
                'equipment_byte': 0x14,
            },
            'security_offsets': {
                'bios_checksum_low': 0x2E,
                'bios_checksum_high': 0x2F,
                'extended_memory_low': 0x30,
                'extended_memory_high': 0x31,
                'century_byte': 0x32,
                'boot_flags': 0x38,
            },
            'nvram_area': {
                'start': 0x0E,
                'end': 0x7F,
                'description': 'Non-volatile RAM area for BIOS settings'
            }
        }

        self.config_cs.hals.CMOS = Mock()
        self.config_cs.hals.CMOS.read_cmos_low.return_value = 0x12

    def test_cmos_configuration_structure(self):
        """Test CMOS configuration structure."""
        cmos_config = self.config_cs.Cfg.CMOS_CONFIG

        # Test that required CMOS configuration exists
        self.assertIn('max_offset', cmos_config)
        self.assertIn('cmos_size', cmos_config)
        self.assertIn('supported_operations', cmos_config)
        self.assertIn('common_offsets', cmos_config)

        # Test configuration values are reasonable
        self.assertEqual(cmos_config['max_offset'], 0xFF)
        self.assertEqual(cmos_config['cmos_size'], 256)
        self.assertIn('dump', cmos_config['supported_operations'])
        self.assertIn('readl', cmos_config['supported_operations'])
        self.assertIsInstance(cmos_config['common_offsets'], dict)

    def test_supported_operations_validation(self):
        """Test validation of supported CMOS operations."""
        supported_ops = self.config_cs.Cfg.CMOS_CONFIG['supported_operations']

        # Test that all documented operations are supported
        expected_ops = ['dump', 'readl', 'writel', 'readh', 'writeh']
        for op in expected_ops:
            self.assertIn(op, supported_ops)

        # Test that operations list is not empty
        self.assertGreater(len(supported_ops), 0)

    def test_common_offsets_validation(self):
        """Test validation of common CMOS offsets."""
        common_offsets = self.config_cs.Cfg.CMOS_CONFIG['common_offsets']

        # Test that all expected common offsets are defined
        expected_offsets = [
            'rtc_seconds', 'rtc_minutes', 'rtc_hours', 'rtc_day',
            'rtc_month', 'rtc_year', 'floppy_type', 'hd0_type',
            'hd1_type', 'equipment_byte'
        ]

        for offset_name in expected_offsets:
            self.assertIn(offset_name, common_offsets)
            self.assertIsInstance(common_offsets[offset_name], int)
            self.assertGreaterEqual(common_offsets[offset_name], 0)
            self.assertLessEqual(common_offsets[offset_name], 0xFF)

        # Test specific offset values
        self.assertEqual(common_offsets['rtc_seconds'], 0x00)
        self.assertEqual(common_offsets['rtc_hours'], 0x04)
        self.assertEqual(common_offsets['equipment_byte'], 0x14)

    def test_security_offsets_validation(self):
        """Test validation of security-related CMOS offsets."""
        security_offsets = self.config_cs.Cfg.CMOS_CONFIG['security_offsets']

        # Test that all expected security offsets are defined
        expected_security_offsets = [
            'bios_checksum_low', 'bios_checksum_high',
            'extended_memory_low', 'extended_memory_high',
            'century_byte', 'boot_flags'
        ]

        for offset_name in expected_security_offsets:
            self.assertIn(offset_name, security_offsets)
            self.assertIsInstance(security_offsets[offset_name], int)
            self.assertGreaterEqual(security_offsets[offset_name], 0)
            self.assertLessEqual(security_offsets[offset_name], 0xFF)

        # Test specific security offset values
        self.assertEqual(security_offsets['bios_checksum_low'], 0x2E)
        self.assertEqual(security_offsets['bios_checksum_high'], 0x2F)
        self.assertEqual(security_offsets['century_byte'], 0x32)

    def test_nvram_area_validation(self):
        """Test validation of NVRAM area configuration."""
        nvram_area = self.config_cs.Cfg.CMOS_CONFIG['nvram_area']

        # Test NVRAM area configuration
        self.assertIn('start', nvram_area)
        self.assertIn('end', nvram_area)
        self.assertIn('description', nvram_area)
        self.assertEqual(nvram_area['start'], 0x0E)
        self.assertEqual(nvram_area['end'], 0x7F)
        self.assertLess(nvram_area['start'], nvram_area['end'])

        # Test that NVRAM area is within valid CMOS range
        max_offset = self.config_cs.Cfg.CMOS_CONFIG['max_offset']
        self.assertGreaterEqual(nvram_area['start'], 0)
        self.assertLessEqual(nvram_area['start'], max_offset)
        self.assertGreaterEqual(nvram_area['end'], 0)
        self.assertLessEqual(nvram_area['end'], max_offset)

    def test_offset_range_validation(self):
        """Test CMOS offset range validation."""
        max_offset = self.config_cs.Cfg.CMOS_CONFIG['max_offset']
        cmos_size = self.config_cs.Cfg.CMOS_CONFIG['cmos_size']

        # Test that maximum offset matches CMOS size - 1
        self.assertEqual(max_offset, cmos_size - 1)

        # Test that all configured offsets are within valid range
        all_offsets = {}
        all_offsets.update(self.config_cs.Cfg.CMOS_CONFIG['common_offsets'])
        all_offsets.update(self.config_cs.Cfg.CMOS_CONFIG['security_offsets'])

        for offset_name, offset_addr in all_offsets.items():
            self.assertGreaterEqual(offset_addr, 0, f"CMOS offset {offset_name} address 0x{offset_addr:X} is negative")
            self.assertLessEqual(offset_addr, max_offset, f"CMOS offset {offset_name} address 0x{offset_addr:X} exceeds maximum 0x{max_offset:X}")

        # Test NVRAM area bounds
        nvram_start = self.config_cs.Cfg.CMOS_CONFIG['nvram_area']['start']
        nvram_end = self.config_cs.Cfg.CMOS_CONFIG['nvram_area']['end']
        self.assertGreaterEqual(nvram_start, 0, f"NVRAM start address 0x{nvram_start:X} is negative")
        self.assertLessEqual(nvram_start, max_offset, f"NVRAM start address 0x{nvram_start:X} exceeds maximum 0x{max_offset:X}")
        self.assertGreaterEqual(nvram_end, 0, f"NVRAM end address 0x{nvram_end:X} is negative")
        self.assertLessEqual(nvram_end, max_offset, f"NVRAM end address 0x{nvram_end:X} exceeds maximum 0x{max_offset:X}")


if __name__ == '__main__':
    unittest.main()
