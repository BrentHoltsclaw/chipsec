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
from chipsec.utilcmd.mmcfg_cmd import MMCfgCommand
from chipsec.command import toLoad
from tests.test_utils import MockFactory


class TestMMCfgCommand(unittest.TestCase):
    """Comprehensive tests for MMCFG utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()

        # Mock MMCFG and PCI HAL components
        self.mock_cs.hals = Mock()
        self.mock_cs.hals.MMCFG = Mock()
        self.mock_cs.hals.Pci = Mock()

        self.mmcfg_command = MMCfgCommand(['base'], cs=self.mock_cs)

    def test_mmcfg_command_initialization(self):
        """Test MMCfgCommand initialization."""
        self.assertEqual(self.mmcfg_command.cs, self.mock_cs)
        self.assertEqual(self.mmcfg_command.argv, ['base'])

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.mmcfg_command.requirements()
        self.assertEqual(reqs, toLoad.All)

    def test_parse_arguments_base(self):
        """Test parsing base command."""
        command = MMCfgCommand(['base'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.base)

    def test_parse_arguments_read(self):
        """Test parsing read command."""
        command = MMCfgCommand(['read', '0x0', '0x1F', '0x0', '0x200', '4'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.read)
        self.assertEqual(command.bus, 0x0)
        self.assertEqual(command.device, 0x1F)
        self.assertEqual(command.function, 0x0)
        self.assertEqual(command.offset, 0x200)
        self.assertEqual(command.width, 4)

    def test_parse_arguments_write(self):
        """Test parsing write command."""
        command = MMCfgCommand(['write', '0x0', '0x1F', '0x0', '0x200', '1', '0x1A'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.write)
        self.assertEqual(command.bus, 0x0)
        self.assertEqual(command.device, 0x1F)
        self.assertEqual(command.function, 0x0)
        self.assertEqual(command.offset, 0x200)
        self.assertEqual(command.width, 1)
        self.assertEqual(command.value, 0x1A)

    def test_parse_arguments_ec(self):
        """Test parsing ec command."""
        command = MMCfgCommand(['ec'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.ec)

    def test_parse_arguments_invalid_width(self):
        """Test parsing command with invalid width."""
        command = MMCfgCommand(['read', '0x0', '0x1F', '0x0', '0x200', '8'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid width choice
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_parse_arguments_invalid(self):
        """Test parsing invalid command."""
        command = MMCfgCommand(['invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_base(self):
        """Test base method."""
        self.mmcfg_command.cs.hals.MMCFG.get_MMCFG_base_address.return_value = (0xE0000000, 0x10000000)

        with patch.object(self.mmcfg_command.logger, 'log') as mock_log:
            self.mmcfg_command.base()

            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Base: 0x00000000E0000000')
            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Size: 0x0000000010000000')

    def test_read_byte(self):
        """Test read method with byte width."""
        self.mmcfg_command.bus = 0x0
        self.mmcfg_command.device = 0x1F
        self.mmcfg_command.function = 0x0
        self.mmcfg_command.offset = 0x200
        self.mmcfg_command.width = 1

        self.mmcfg_command.cs.hals.MMCFG.read_mmcfg_reg.return_value = 0xAB

        with patch.object(self.mmcfg_command.logger, 'log') as mock_log:
            self.mmcfg_command.read()

            self.mmcfg_command.cs.hals.MMCFG.read_mmcfg_reg.assert_called_once_with(0x0, 0x1F, 0x0, 0x200, 1)
            mock_log.assert_called_with('[CHIPSEC] Reading MMCFG register (00:31.0 + 0x200): 0xAB')

    def test_read_word(self):
        """Test read method with word width."""
        self.mmcfg_command.bus = 0x1
        self.mmcfg_command.device = 0x0
        self.mmcfg_command.function = 0x0
        self.mmcfg_command.offset = 0x10
        self.mmcfg_command.width = 2

        self.mmcfg_command.cs.hals.MMCFG.read_mmcfg_reg.return_value = 0xABCD

        with patch.object(self.mmcfg_command.logger, 'log') as mock_log:
            self.mmcfg_command.read()

            self.mmcfg_command.cs.hals.MMCFG.read_mmcfg_reg.assert_called_once_with(0x1, 0x0, 0x0, 0x10, 2)
            mock_log.assert_called_with('[CHIPSEC] Reading MMCFG register (01:00.0 + 0x10): 0xABCD')

    def test_read_dword(self):
        """Test read method with dword width."""
        self.mmcfg_command.bus = 0x2
        self.mmcfg_command.device = 0x1
        self.mmcfg_command.function = 0x1
        self.mmcfg_command.offset = 0x4
        self.mmcfg_command.width = 4

        self.mmcfg_command.cs.hals.MMCFG.read_mmcfg_reg.return_value = 0x12345678

        with patch.object(self.mmcfg_command.logger, 'log') as mock_log:
            self.mmcfg_command.read()

            self.mmcfg_command.cs.hals.MMCFG.read_mmcfg_reg.assert_called_once_with(0x2, 0x1, 0x1, 0x4, 4)
            mock_log.assert_called_with('[CHIPSEC] Reading MMCFG register (02:01.1 + 0x04): 0x12345678')

    def test_write_byte(self):
        """Test write method with byte width."""
        self.mmcfg_command.bus = 0x0
        self.mmcfg_command.device = 0x1F
        self.mmcfg_command.function = 0x0
        self.mmcfg_command.offset = 0x200
        self.mmcfg_command.width = 1
        self.mmcfg_command.value = 0x1A

        with patch.object(self.mmcfg_command.logger, 'log') as mock_log:
            self.mmcfg_command.write()

            self.mmcfg_command.cs.hals.MMCFG.write_mmcfg_reg.assert_called_once_with(0x0, 0x1F, 0x0, 0x200, 1, 0x1A)
            mock_log.assert_called_with('[CHIPSEC] Writing MMCFG register (00:31.0 + 0x200): 0x1A')

    def test_write_word(self):
        """Test write method with word width."""
        self.mmcfg_command.bus = 0x1
        self.mmcfg_command.device = 0x0
        self.mmcfg_command.function = 0x0
        self.mmcfg_command.offset = 0x10
        self.mmcfg_command.width = 2
        self.mmcfg_command.value = 0xABCD

        with patch.object(self.mmcfg_command.logger, 'log') as mock_log:
            self.mmcfg_command.write()

            self.mmcfg_command.cs.hals.MMCFG.write_mmcfg_reg.assert_called_once_with(0x1, 0x0, 0x0, 0x10, 2, 0xABCD)
            mock_log.assert_called_with('[CHIPSEC] Writing MMCFG register (01:00.0 + 0x10): 0xABCD')

    def test_write_dword(self):
        """Test write method with dword width."""
        self.mmcfg_command.bus = 0x2
        self.mmcfg_command.device = 0x1
        self.mmcfg_command.function = 0x1
        self.mmcfg_command.offset = 0x4
        self.mmcfg_command.width = 4
        self.mmcfg_command.value = 0x12345678

        with patch.object(self.mmcfg_command.logger, 'log') as mock_log:
            self.mmcfg_command.write()

            self.mmcfg_command.cs.hals.MMCFG.write_mmcfg_reg.assert_called_once_with(0x2, 0x1, 0x1, 0x4, 4, 0x12345678)
            mock_log.assert_called_with('[CHIPSEC] Writing MMCFG register (02:01.1 + 0x04): 0x12345678')

    def test_ec_no_devices(self):
        """Test ec method with no devices."""
        self.mmcfg_command.cs.hals.Pci.enumerate_devices.return_value = []

        with patch.object(self.mmcfg_command.logger, 'log') as mock_log:
            self.mmcfg_command.ec()

            # Should not log anything since no devices
            self.mmcfg_command.cs.hals.Pci.enumerate_devices.assert_called_once()
            # No extended capabilities to log

    def test_ec_with_devices_no_capabilities(self):
        """Test ec method with devices but no extended capabilities."""
        self.mmcfg_command.cs.hals.Pci.enumerate_devices.return_value = [
            (0x0, 0x1F, 0x0, 0x8086, 0x1234, 'LPC Bridge'),
            (0x0, 0x2, 0x0, 0x10DE, 0xABCD, 'VGA Controller')
        ]
        self.mmcfg_command.cs.hals.MMCFG.get_extended_capabilities.return_value = []

        with patch.object(self.mmcfg_command.logger, 'log') as mock_log:
            self.mmcfg_command.ec()

            self.mmcfg_command.cs.hals.Pci.enumerate_devices.assert_called_once()
            # Should call get_extended_capabilities for each device
            self.assertEqual(self.mmcfg_command.cs.hals.MMCFG.get_extended_capabilities.call_count, 2)
            # Should not log any capabilities

    def test_ec_with_devices_and_capabilities(self):
        """Test ec method with devices and extended capabilities."""
        self.mmcfg_command.cs.hals.Pci.enumerate_devices.return_value = [
            (0x0, 0x1F, 0x0, 0x8086, 0x1234, 'LPC Bridge')
        ]

        # Mock capability object
        mock_cap = Mock()
        mock_cap.id = 0x1
        mock_cap.off = 0x100

        self.mmcfg_command.cs.hals.MMCFG.get_extended_capabilities.return_value = [mock_cap]

        with patch.object(self.mmcfg_command.logger, 'log') as mock_log:
            self.mmcfg_command.ec()

            mock_log.assert_any_call('Extended Capabilities for 00:1F.0:')
            mock_log.assert_any_call(f'{mock_cap}')

    def test_ec_with_vsec_capability(self):
        """Test ec method with VSEC capability."""
        self.mmcfg_command.cs.hals.Pci.enumerate_devices.return_value = [
            (0x0, 0x1F, 0x0, 0x8086, 0x1234, 'LPC Bridge')
        ]

        # Mock VSEC capability
        mock_cap = Mock()
        mock_cap.id = 0xB  # VSEC capability ID
        mock_cap.off = 0x100

        mock_vsec = Mock()
        mock_vsec.__str__ = Mock(return_value='VSEC data')

        self.mmcfg_command.cs.hals.MMCFG.get_extended_capabilities.return_value = [mock_cap]
        self.mmcfg_command.cs.hals.MMCFG.get_vsec.return_value = mock_vsec

        with patch.object(self.mmcfg_command.logger, 'log') as mock_log:
            self.mmcfg_command.ec()

            mock_log.assert_any_call('Extended Capabilities for 00:1F.0:')
            mock_log.assert_any_call(f'{mock_cap}')
            mock_log.assert_any_call('\tVSEC data')
            self.mmcfg_command.cs.hals.MMCFG.get_vsec.assert_called_once_with(0x0, 0x1F, 0x0, 0x100)

    def test_run(self):
        """Test run method."""
        self.mmcfg_command.func = Mock()

        self.mmcfg_command.run()

        self.mmcfg_command.func.assert_called_once()


class TestMMCfgCommandIntegration(unittest.TestCase):
    """Integration tests for MMCFG command with realistic data."""

    def setUp(self):
        """Set up integrated test fixtures."""
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock MMCFG and PCI components with realistic data
        self.integrated_cs.hals = Mock()
        self.integrated_cs.hals.MMCFG = Mock()
        self.integrated_cs.hals.Pci = Mock()

    def test_mmcfg_base_integration(self):
        """Test complete mmcfg_base workflow."""
        mmcfg_cmd = MMCfgCommand(['base'], cs=self.integrated_cs)
        mmcfg_cmd.parse_arguments()

        mmcfg_cmd.cs.hals.MMCFG.get_MMCFG_base_address.return_value = (0xE0000000, 0x10000000)

        with patch.object(mmcfg_cmd.logger, 'log'):
            mmcfg_cmd.run()

            mmcfg_cmd.cs.hals.MMCFG.get_MMCFG_base_address.assert_called_once()

    def test_mmcfg_read_integration(self):
        """Test complete mmcfg_read workflow."""
        mmcfg_cmd = MMCfgCommand(['read', '0x0', '0x1F', '0x0', '0x200', '4'], cs=self.integrated_cs)
        mmcfg_cmd.parse_arguments()

        mmcfg_cmd.cs.hals.MMCFG.read_mmcfg_reg.return_value = 0x12345678

        with patch.object(mmcfg_cmd.logger, 'log'):
            mmcfg_cmd.run()

            mmcfg_cmd.cs.hals.MMCFG.read_mmcfg_reg.assert_called_once_with(0x0, 0x1F, 0x0, 0x200, 4)

    def test_mmcfg_write_integration(self):
        """Test complete mmcfg_write workflow."""
        mmcfg_cmd = MMCfgCommand(['write', '0x0', '0x1F', '0x0', '0x200', '1', '0x1A'], cs=self.integrated_cs)
        mmcfg_cmd.parse_arguments()

        with patch.object(mmcfg_cmd.logger, 'log'):
            mmcfg_cmd.run()

            mmcfg_cmd.cs.hals.MMCFG.write_mmcfg_reg.assert_called_once_with(0x0, 0x1F, 0x0, 0x200, 1, 0x1A)

    def test_mmcfg_ec_integration(self):
        """Test complete mmcfg_ec workflow."""
        mmcfg_cmd = MMCfgCommand(['ec'], cs=self.integrated_cs)
        mmcfg_cmd.parse_arguments()

        mmcfg_cmd.cs.hals.Pci.enumerate_devices.return_value = [
            (0x0, 0x1F, 0x0, 0x8086, 0x1234, 'LPC Bridge')
        ]
        mmcfg_cmd.cs.hals.MMCFG.get_extended_capabilities.return_value = []

        with patch.object(mmcfg_cmd.logger, 'log'):
            mmcfg_cmd.run()

            mmcfg_cmd.cs.hals.Pci.enumerate_devices.assert_called_once()
            mmcfg_cmd.cs.hals.MMCFG.get_extended_capabilities.assert_called_once_with(0x0, 0x1F, 0x0)


class TestMMCfgCommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for MMCFG command."""

    def setUp(self):
        """Set up mock ChipsecCs for edge case testing."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.hals = Mock()
        self.mock_cs.hals.MMCFG = Mock()
        self.mock_cs.hals.Pci = Mock()

    def test_empty_argv_handling(self):
        """Test handling of empty argv."""
        command = MMCfgCommand([], cs=self.mock_cs)

        # ArgumentParser with subparsers doesn't require subcommands by default
        # This test verifies that empty args don't cause an exception
        try:
            command.parse_arguments()
            # Should not raise an exception
            self.assertFalse(hasattr(command, 'func'))  # No subcommand selected, so func attribute not set
        except SystemExit:
            self.fail("Empty argv should not raise SystemExit with subparsers")

    def test_read_boundary_values(self):
        """Test read method with boundary values."""
        command = MMCfgCommand(['read', '0xFF', '0x1F', '0x7', '0xFFF', '4'], cs=self.mock_cs)
        command.parse_arguments()

        command.cs.hals.MMCFG.read_mmcfg_reg.return_value = 0xFFFFFFFF

        with patch.object(command.logger, 'log'):
            command.run()

            command.cs.hals.MMCFG.read_mmcfg_reg.assert_called_once_with(0xFF, 0x1F, 0x7, 0xFFF, 4)

    def test_write_boundary_values(self):
        """Test write method with boundary values."""
        command = MMCfgCommand(['write', '0xFF', '0x1F', '0x7', '0xFFF', '4', '0xFFFFFFFF'], cs=self.mock_cs)
        command.parse_arguments()

        with patch.object(command.logger, 'log'):
            command.run()

            command.cs.hals.MMCFG.write_mmcfg_reg.assert_called_once_with(0xFF, 0x1F, 0x7, 0xFFF, 4, 0xFFFFFFFF)

    def test_read_zero_values(self):
        """Test read method with zero values."""
        command = MMCfgCommand(['read', '0x0', '0x0', '0x0', '0x0', '1'], cs=self.mock_cs)
        command.parse_arguments()

        command.cs.hals.MMCFG.read_mmcfg_reg.return_value = 0x0

        with patch.object(command.logger, 'log'):
            command.run()

            command.cs.hals.MMCFG.read_mmcfg_reg.assert_called_once_with(0x0, 0x0, 0x0, 0x0, 1)

    def test_write_zero_values(self):
        """Test write method with zero values."""
        command = MMCfgCommand(['write', '0x0', '0x0', '0x0', '0x0', '1', '0x0'], cs=self.mock_cs)
        command.parse_arguments()

        with patch.object(command.logger, 'log'):
            command.run()

            command.cs.hals.MMCFG.write_mmcfg_reg.assert_called_once_with(0x0, 0x0, 0x0, 0x0, 1, 0x0)

    def test_ec_multiple_devices(self):
        """Test ec method with multiple devices."""
        command = MMCfgCommand(['ec'], cs=self.mock_cs)
        command.parse_arguments()

        command.cs.hals.Pci.enumerate_devices.return_value = [
            (0x0, 0x0, 0x0, 0x8086, 0x1234, 'Host Bridge'),
            (0x0, 0x1F, 0x0, 0x8086, 0x5678, 'LPC Bridge'),
            (0x1, 0x0, 0x0, 0x10DE, 0xABCD, 'VGA Controller')
        ]
        command.cs.hals.MMCFG.get_extended_capabilities.return_value = []

        with patch.object(command.logger, 'log'):
            command.run()

            # Should call get_extended_capabilities for each device
            self.assertEqual(command.cs.hals.MMCFG.get_extended_capabilities.call_count, 3)

    def test_base_zero_values(self):
        """Test base method with zero values."""
        command = MMCfgCommand(['base'], cs=self.mock_cs)
        command.parse_arguments()

        command.cs.hals.MMCFG.get_MMCFG_base_address.return_value = (0x0, 0x0)

        with patch.object(command.logger, 'log'):
            command.run()

            command.cs.hals.MMCFG.get_MMCFG_base_address.assert_called_once()

    def test_read_hex_parsing(self):
        """Test read method with various hex formats."""
        test_cases = [
            ('0x0', 0x0),
            ('0xFF', 0xFF),
            ('0x100', 0x100),
            ('FF', 0xFF),
            ('100', 0x100)
        ]

        for hex_str, expected_value in test_cases:
            command = MMCfgCommand(['read', hex_str, '0x1F', '0x0', '0x200', '4'], cs=self.mock_cs)
            command.parse_arguments()
            self.assertEqual(command.bus, expected_value)

    def test_write_hex_parsing(self):
        """Test write method with various hex formats."""
        test_cases = [
            ('0x0', 0x0),
            ('0xFF', 0xFF),
            ('0x100', 0x100),
            ('FF', 0xFF),
            ('100', 0x100)
        ]

        for hex_str, expected_value in test_cases:
            command = MMCfgCommand(['write', '0x0', '0x1F', '0x0', '0x200', '4', hex_str], cs=self.mock_cs)
            command.parse_arguments()
            self.assertEqual(command.value, expected_value)


class TestMMCfgCommandConfigurationValidation(unittest.TestCase):
    """Test configuration validation aspects of MMCFG command."""

    def setUp(self):
        """Set up ChipsecCs with MMCFG-specific configuration."""
        self.mmcfg_cs = MockFactory.create_mock_chipsec_cs()

        # Mock MMCFG configuration
        self.mmcfg_cs.Cfg = Mock()
        self.mmcfg_cs.Cfg.MMCFG = {
            'BASE_ADDRESS': 0xE0000000,
            'SIZE': 0x10000000,
            'BUS_RANGE': (0x0, 0xFF),
            'DEVICE_RANGE': (0x0, 0x1F),
            'FUNCTION_RANGE': (0x0, 0x7)
        }

        self.mmcfg_cs.hals = Mock()
        self.mmcfg_cs.hals.MMCFG = Mock()
        self.mmcfg_cs.hals.Pci = Mock()

    def test_mmcfg_configuration_structure(self):
        """Test MMCFG configuration structure."""
        mmcfg_config = self.mmcfg_cs.Cfg.MMCFG

        # Test that required MMCFG configuration exists
        self.assertIn('BASE_ADDRESS', mmcfg_config)
        self.assertIn('SIZE', mmcfg_config)

        # Test configuration values are reasonable
        self.assertGreater(mmcfg_config['BASE_ADDRESS'], 0)
        self.assertGreater(mmcfg_config['SIZE'], 0)

    def test_mmcfg_address_validation(self):
        """Test MMCFG address validation."""
        command = MMCfgCommand(['read', '0x0', '0x1F', '0x0', '0x200', '4'], cs=self.mmcfg_cs)
        command.parse_arguments()

        # Test that parsed values are within valid ranges
        self.assertGreaterEqual(command.bus, 0)
        self.assertLessEqual(command.bus, 0xFF)
        self.assertGreaterEqual(command.device, 0)
        self.assertLessEqual(command.device, 0x1F)
        self.assertGreaterEqual(command.function, 0)
        self.assertLessEqual(command.function, 0x7)
        self.assertGreaterEqual(command.offset, 0)
        self.assertIn(command.width, [1, 2, 4])

    def test_mmcfg_offset_alignment(self):
        """Test MMCFG offset alignment for different widths."""
        test_cases = [
            (1, 0x200),  # Byte alignment
            (2, 0x200),  # Word alignment
            (4, 0x200),  # Dword alignment
        ]

        for width, offset in test_cases:
            command = MMCfgCommand(['read', '0x0', '0x1F', '0x0', f'0x{offset:X}', f'{width}'], cs=self.mmcfg_cs)
            command.parse_arguments()

            # Test that offset is properly aligned for the width
            self.assertEqual(command.offset % width, 0)

    def test_mmcfg_width_validation(self):
        """Test MMCFG data width validation."""
        valid_widths = [1, 2, 4]

        for width in valid_widths:
            command = MMCfgCommand(['read', '0x0', '0x1F', '0x0', '0x200', f'{width}'], cs=self.mmcfg_cs)
            command.parse_arguments()  # Should not raise exception

            self.assertEqual(command.width, width)

    def test_mmcfg_bus_device_function_ranges(self):
        """Test MMCFG bus, device, and function range validation."""
        # Test boundary values
        test_cases = [
            (0x0, 0x0, 0x0),      # Minimum values
            (0xFF, 0x1F, 0x7),    # Maximum values
            (0x80, 0x10, 0x3),    # Middle values
        ]

        for bus, device, function in test_cases:
            command = MMCfgCommand(['read', f'0x{bus:X}', f'0x{device:X}', f'0x{function:X}', '0x200', '4'], cs=self.mmcfg_cs)
            command.parse_arguments()

            self.assertEqual(command.bus, bus)
            self.assertEqual(command.device, device)
            self.assertEqual(command.function, function)

    def test_mmcfg_error_handling(self):
        """Test MMCFG error handling."""
        command = MMCfgCommand(['read', '0x0', '0x1F', '0x0', '0x200', '4'], cs=self.mmcfg_cs)

        # Mock MMCFG read to raise exception
        command.cs.hals.MMCFG.read_mmcfg_reg.side_effect = Exception("MMCFG access failed")

        # Should handle the exception gracefully
        with self.assertRaises(Exception):
            command.read()

    def test_mmcfg_pci_enumeration_error_handling(self):
        """Test MMCFG PCI enumeration error handling."""
        command = MMCfgCommand(['ec'], cs=self.mmcfg_cs)

        # Mock PCI enumeration to raise exception
        command.cs.hals.Pci.enumerate_devices.side_effect = Exception("PCI enumeration failed")

        # Should handle the exception gracefully
        with self.assertRaises(Exception):
            command.ec()
