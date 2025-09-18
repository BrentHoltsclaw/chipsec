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
from chipsec.utilcmd.pci_cmd import PCICommand
from tests.test_utils import MockFactory


class TestPCICommand(unittest.TestCase):
    """Comprehensive tests for PCI utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()

        # Mock PCI HAL
        self.mock_cs.hals.Pci = Mock()
        self.mock_cs.hals.Pci.enumerate_devices.return_value = [
            (0x00, 0x00, 0x00, 0x8086, 0x1234, 0x01),
            (0x00, 0x1F, 0x00, 0x8086, 0x5678, 0x02),
            (0x01, 0x00, 0x00, 0x10DE, 0xABCD, 0x03),
        ]
        self.mock_cs.hals.Pci.dump_pci_config.return_value = b'\xFF' * 256
        self.mock_cs.hals.Pci.print_pci_config_all.return_value = None
        self.mock_cs.hals.Pci.read_byte.return_value = 0x12
        self.mock_cs.hals.Pci.read_word.return_value = 0x1234
        self.mock_cs.hals.Pci.read_dword.return_value = 0x12345678
        self.mock_cs.hals.Pci.write_byte.return_value = None
        self.mock_cs.hals.Pci.write_word.return_value = None
        self.mock_cs.hals.Pci.write_dword.return_value = None
        self.mock_cs.hals.Pci.find_XROM.return_value = (True, Mock(en=1, base=0xFEDF0000, size=0x10000, header=b'XROM_HEADER'))
        self.mock_cs.hals.Pci.enumerate_xroms.return_value = [
            Mock(bus=0x00, device=0x00, function=0x00, en=1, base=0xFEDF0000, size=0x10000),
        ]

        self.pci_command = PCICommand(['enumerate'], cs=self.mock_cs)

    def test_pci_command_initialization(self):
        """Test PCICommand initialization."""
        self.assertEqual(self.pci_command.cs, self.mock_cs)
        self.assertEqual(self.pci_command.argv, ['enumerate'])

    def test_parse_arguments_enumerate(self):
        """Test parsing enumerate command arguments."""
        command = PCICommand(['enumerate'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.pci_enumerate)

    def test_parse_arguments_read(self):
        """Test parsing read command arguments."""
        command = PCICommand(['read', '0', '0', '0', '0x00'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.pci_read)
        self.assertEqual(command.bus, 0x0)
        self.assertEqual(command.device, 0x0)
        self.assertEqual(command.function, 0x0)
        self.assertEqual(command.offset, 0x0)
        self.assertIsNone(command.size)

    def test_parse_arguments_read_with_size(self):
        """Test parsing read command with size arguments."""
        command = PCICommand(['read', '0', '0', '0', '0x88', 'byte'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.pci_read)
        self.assertEqual(command.bus, 0x0)
        self.assertEqual(command.device, 0x0)
        self.assertEqual(command.function, 0x0)
        self.assertEqual(command.offset, 0x88)
        self.assertEqual(command.size, 'byte')

    def test_parse_arguments_write(self):
        """Test parsing write command arguments."""
        command = PCICommand(['write', '0', '0x1F', '0', '0xDC', '1', '0x1'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.pci_write)
        self.assertEqual(command.bus, 0x0)
        self.assertEqual(command.device, 0x1F)
        self.assertEqual(command.function, 0x0)
        self.assertEqual(command.offset, 0xDC)
        self.assertEqual(command.size, '1')
        self.assertEqual(command.value, 0x1)

    def test_parse_arguments_dump(self):
        """Test parsing dump command arguments."""
        command = PCICommand(['dump'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.pci_dump)
        self.assertIsNone(command.bus)
        self.assertIsNone(command.device)
        self.assertIsNone(command.function)

    def test_parse_arguments_dump_with_args(self):
        """Test parsing dump command with specific device arguments."""
        command = PCICommand(['dump', '0', '0', '0'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.pci_dump)
        self.assertEqual(command.bus, 0x0)
        self.assertEqual(command.device, 0x0)
        self.assertEqual(command.function, 0x0)

    def test_parse_arguments_xrom(self):
        """Test parsing xrom command arguments."""
        command = PCICommand(['xrom'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.pci_xrom)
        self.assertIsNone(command.bus)
        self.assertIsNone(command.device)
        self.assertIsNone(command.function)
        self.assertIsNone(command.xrom_addr)

    def test_parse_arguments_xrom_with_args(self):
        """Test parsing xrom command with arguments."""
        command = PCICommand(['xrom', '3', '0', '0', '0xFEDF0000'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.pci_xrom)
        self.assertEqual(command.bus, 0x3)
        self.assertEqual(command.device, 0x0)
        self.assertEqual(command.function, 0x0)
        self.assertEqual(command.xrom_addr, 0xFEDF0000)

    def test_parse_arguments_cmd(self):
        """Test parsing cmd command arguments."""
        command = PCICommand(['cmd'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.pci_cmd)
        self.assertEqual(command.cmd_mask, 0xFFFF)
        self.assertIsNone(command.pci_class)
        self.assertIsNone(command.pci_sub_class)

    def test_parse_arguments_cmd_with_args(self):
        """Test parsing cmd command with arguments."""
        command = PCICommand(['cmd', '1', '0x06', '0x00'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.pci_cmd)
        self.assertEqual(command.cmd_mask, 0x1)
        self.assertEqual(command.pci_class, 0x06)
        self.assertEqual(command.pci_sub_class, 0x00)

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.pci_command.requirements()
        self.assertTrue(hasattr(reqs, 'load_driver'))

    def test_pci_enumerate(self):
        """Test pci_enumerate command."""
        with patch('chipsec.library.pci.print_pci_devices') as mock_print:
            self.pci_command.pci_enumerate()

            mock_print.assert_called_once_with(self.mock_cs.hals.Pci.enumerate_devices.return_value)

    def test_pci_dump_all_devices(self):
        """Test pci_dump with no specific device."""
        self.pci_command.bus = None
        self.pci_command.device = None
        self.pci_command.function = None

        with patch.object(self.pci_command.logger, 'log') as mock_log:
            self.pci_command.pci_dump()

            mock_log.assert_called_once_with('[CHIPSEC] Dumping configuration of available PCI devices...')
            self.mock_cs.hals.Pci.print_pci_config_all.assert_called_once()

    def test_pci_dump_specific_device(self):
        """Test pci_dump with specific device."""
        self.pci_command.bus = 0x0
        self.pci_command.device = 0x0
        self.pci_command.function = 0x0

        with patch.object(self.pci_command.logger, 'log') as mock_log, \
             patch('chipsec.library.logger.pretty_print_hex_buffer') as mock_print:
            self.pci_command.pci_dump()

            mock_log.assert_called_once_with('[CHIPSEC] PCI device 00:00.0 configuration:')
            mock_print.assert_called_once_with(b'\xFF' * 256)

    def test_pci_dump_partial_device_info(self):
        """Test pci_dump with partial device information."""
        self.pci_command.bus = 0x0
        self.pci_command.device = None
        self.pci_command.function = None

        with patch.object(self.pci_command.logger, 'log') as mock_log, \
             patch('chipsec.library.logger.pretty_print_hex_buffer') as mock_print:
            self.pci_command.pci_dump()

            # Should enumerate devices and dump each one
            self.mock_cs.hals.Pci.enumerate_devices.assert_called_once_with(0x0, None, None)
            self.assertEqual(mock_print.call_count, 3)  # One for each enumerated device

    def test_pci_xrom_all_devices(self):
        """Test pci_xrom with no specific device."""
        self.pci_command.bus = None
        self.pci_command.device = None
        self.pci_command.function = None
        self.pci_command.xrom_addr = None

        with patch.object(self.pci_command.logger, 'log') as mock_log, \
             patch('chipsec.library.pci.print_pci_XROMs') as mock_print:
            self.pci_command.pci_xrom()

            mock_log.assert_any_call('[CHIPSEC] Enumerating PCI expansion ROMs...')
            mock_log.assert_any_call('[CHIPSEC] found 1 PCI expansion ROMs')
            mock_print.assert_called_once()

    def test_pci_xrom_specific_device(self):
        """Test pci_xrom with specific device."""
        self.pci_command.bus = 0x0
        self.pci_command.device = 0x0
        self.pci_command.function = 0x0
        self.pci_command.xrom_addr = None

        with patch.object(self.pci_command.logger, 'log') as mock_log:
            self.pci_command.pci_xrom()

            mock_log.assert_any_call('[CHIPSEC] Locating PCI expansion ROM (XROM) of 00:00.0...')
            mock_log.assert_any_call('[CHIPSEC] Found XROM of 00:00.0')
            mock_log.assert_any_call('[CHIPSEC] XROM enabled = 1, base = 0xFEDF0000, size = 0x10000')

    def test_pci_xrom_no_xrom_found(self):
        """Test pci_xrom when no XROM is found."""
        self.pci_command.bus = 0x0
        self.pci_command.device = 0x0
        self.pci_command.function = 0x0
        self.pci_command.xrom_addr = None

        # Mock no XROM found
        self.mock_cs.hals.Pci.find_XROM.return_value = (False, None)

        with patch.object(self.pci_command.logger, 'log') as mock_log:
            self.pci_command.pci_xrom()

            mock_log.assert_any_call('[CHIPSEC] Locating PCI expansion ROM (XROM) of 00:00.0...')
            mock_log.assert_any_call("[CHIPSEC] Couldn't find XROM of 00:00.0")

    def test_pci_read_byte(self):
        """Test pci_read with byte width."""
        self.pci_command.bus = 0x0
        self.pci_command.device = 0x0
        self.pci_command.function = 0x0
        self.pci_command.offset = 0x0
        self.pci_command.size = 'byte'

        with patch.object(self.pci_command.logger, 'log') as mock_log:
            self.pci_command.pci_read()

            self.mock_cs.hals.Pci.read_byte.assert_called_once_with(0x0, 0x0, 0x0, 0x0)
            mock_log.assert_called_once_with('[CHIPSEC] PCI 00:00.0 + 0x00: 0x12')

    def test_pci_read_word(self):
        """Test pci_read with word width."""
        self.pci_command.bus = 0x0
        self.pci_command.device = 0x0
        self.pci_command.function = 0x0
        self.pci_command.offset = 0x88
        self.pci_command.size = 'word'

        with patch.object(self.pci_command.logger, 'log') as mock_log:
            self.pci_command.pci_read()

            self.mock_cs.hals.Pci.read_word.assert_called_once_with(0x0, 0x0, 0x0, 0x88)
            mock_log.assert_called_once_with('[CHIPSEC] PCI 00:00.0 + 0x88: 0x1234')

    def test_pci_read_dword(self):
        """Test pci_read with dword width."""
        self.pci_command.bus = 0x0
        self.pci_command.device = 0x0
        self.pci_command.function = 0x0
        self.pci_command.offset = 0x98
        self.pci_command.size = 'dword'

        with patch.object(self.pci_command.logger, 'log') as mock_log:
            self.pci_command.pci_read()

            self.mock_cs.hals.Pci.read_dword.assert_called_once_with(0x0, 0x0, 0x0, 0x98)
            mock_log.assert_called_once_with('[CHIPSEC] PCI 00:00.0 + 0x98: 0x12345678')

    def test_pci_read_default_width(self):
        """Test pci_read with default width (dword)."""
        self.pci_command.bus = 0x0
        self.pci_command.device = 0x0
        self.pci_command.function = 0x0
        self.pci_command.offset = 0x0
        self.pci_command.size = None

        with patch.object(self.pci_command.logger, 'log') as mock_log:
            self.pci_command.pci_read()

            self.mock_cs.hals.Pci.read_dword.assert_called_once_with(0x0, 0x0, 0x0, 0x0)
            mock_log.assert_called_once_with('[CHIPSEC] PCI 00:00.0 + 0x00: 0x12345678')

    def test_pci_read_invalid_width(self):
        """Test pci_read with invalid width."""
        self.pci_command.bus = 0x0
        self.pci_command.device = 0x0
        self.pci_command.function = 0x0
        self.pci_command.offset = 0x0
        self.pci_command.size = 'invalid'

        with patch.object(self.pci_command.logger, 'log_error') as mock_error:
            self.pci_command.pci_read()

            mock_error.assert_called_once()
            # Should not call any read methods
            self.mock_cs.hals.Pci.read_byte.assert_not_called()
            self.mock_cs.hals.Pci.read_word.assert_not_called()
            self.mock_cs.hals.Pci.read_dword.assert_not_called()

    def test_pci_write_byte(self):
        """Test pci_write with byte width."""
        self.pci_command.bus = 0x0
        self.pci_command.device = 0x1F
        self.pci_command.function = 0x0
        self.pci_command.offset = 0xDC
        self.pci_command.size = '1'
        self.pci_command.value = 0x1

        with patch.object(self.pci_command.logger, 'log') as mock_log:
            self.pci_command.pci_write()

            self.mock_cs.hals.Pci.write_byte.assert_called_once_with(0x0, 0x1F, 0x0, 0xDC, 0x1)
            mock_log.assert_called_once_with('[CHIPSEC] Write 0x1 to PCI 00:1F.0 + 0xDC')

    def test_pci_write_word(self):
        """Test pci_write with word width."""
        self.pci_command.bus = 0x0
        self.pci_command.device = 0x0
        self.pci_command.function = 0x0
        self.pci_command.offset = 0x88
        self.pci_command.size = '2'
        self.pci_command.value = 0x1234

        with patch.object(self.pci_command.logger, 'log') as mock_log:
            self.pci_command.pci_write()

            self.mock_cs.hals.Pci.write_word.assert_called_once_with(0x0, 0x0, 0x0, 0x88, 0x1234)
            mock_log.assert_called_once_with('[CHIPSEC] Write 0x1234 to PCI 00:00.0 + 0x88')

    def test_pci_write_dword(self):
        """Test pci_write with dword width."""
        self.pci_command.bus = 0x0
        self.pci_command.device = 0x0
        self.pci_command.function = 0x0
        self.pci_command.offset = 0x98
        self.pci_command.size = '4'
        self.pci_command.value = 0x004E0040

        with patch.object(self.pci_command.logger, 'log') as mock_log:
            self.pci_command.pci_write()

            self.mock_cs.hals.Pci.write_dword.assert_called_once_with(0x0, 0x0, 0x0, 0x98, 0x004E0040)
            mock_log.assert_called_once_with('[CHIPSEC] Write 0x4E0040 to PCI 00:00.0 + 0x98')

    def test_pci_write_invalid_width(self):
        """Test pci_write with invalid width."""
        self.pci_command.bus = 0x0
        self.pci_command.device = 0x0
        self.pci_command.function = 0x0
        self.pci_command.offset = 0x0
        self.pci_command.size = '8'
        self.pci_command.value = 0x12345678

        with patch.object(self.pci_command.logger, 'log_error') as mock_error:
            self.pci_command.pci_write()

            mock_error.assert_called_once()
            # Should not call any write methods
            self.mock_cs.hals.Pci.write_byte.assert_not_called()
            self.mock_cs.hals.Pci.write_word.assert_not_called()
            self.mock_cs.hals.Pci.write_dword.assert_not_called()

    def test_pci_cmd_no_filters(self):
        """Test pci_cmd with no filters."""
        self.pci_command.cmd_mask = 0xFFFF
        self.pci_command.pci_class = None
        self.pci_command.pci_sub_class = None

        # Mock PCI register reads
        self.mock_cs.hals.Pci.read_byte.side_effect = [0x06, 0x00, 0x06, 0x01, 0x06, 0x02]  # Class and subclass values
        self.mock_cs.hals.Pci.read_word.return_value = 0x0006  # Command register

        with patch.object(self.pci_command.logger, 'log') as mock_log:
            self.pci_command.pci_cmd()

            # Should log header and device information
            self.assertGreaterEqual(mock_log.call_count, 4)  # Header + 3 devices

    def test_pci_cmd_with_class_filter(self):
        """Test pci_cmd with class filter."""
        self.pci_command.cmd_mask = 0xFFFF
        self.pci_command.pci_class = 0x06  # Bridge device
        self.pci_command.pci_sub_class = None

        # Mock PCI register reads - only first device matches class
        self.mock_cs.hals.Pci.read_byte.side_effect = [0x06, 0x00]  # Class and subclass for first device
        self.mock_cs.hals.Pci.read_word.return_value = 0x0006

        with patch.object(self.pci_command.logger, 'log') as mock_log:
            self.pci_command.pci_cmd()

            # Should only log devices that match the class filter
            self.assertGreaterEqual(mock_log.call_count, 2)  # Header + matching device

    def test_pci_cmd_with_subclass_filter(self):
        """Test pci_cmd with subclass filter."""
        self.pci_command.cmd_mask = 0xFFFF
        self.pci_command.pci_class = None
        self.pci_command.pci_sub_class = 0x00  # Host bridge

        # Mock PCI register reads
        self.mock_cs.hals.Pci.read_byte.side_effect = [0x06, 0x00]  # Class and subclass
        self.mock_cs.hals.Pci.read_word.return_value = 0x0006

        with patch.object(self.pci_command.logger, 'log') as mock_log:
            self.pci_command.pci_cmd()

            # Should only log devices that match the subclass filter
            self.assertGreaterEqual(mock_log.call_count, 2)  # Header + matching device

    def test_pci_cmd_with_cmd_mask_filter(self):
        """Test pci_cmd with command mask filter."""
        self.pci_command.cmd_mask = 0x0001  # Only devices with I/O space enabled
        self.pci_command.pci_class = None
        self.pci_command.pci_sub_class = None

        # Mock PCI register reads
        self.mock_cs.hals.Pci.read_byte.side_effect = [0x06, 0x00]  # Class and subclass
        self.mock_cs.hals.Pci.read_word.return_value = 0x0007  # Command register with I/O space enabled

        with patch.object(self.pci_command.logger, 'log') as mock_log:
            self.pci_command.pci_cmd()

            # Should only log devices that match the command mask
            self.assertGreaterEqual(mock_log.call_count, 2)  # Header + matching device


class TestPCICommandIntegration(unittest.TestCase):
    """Integration tests for PCI command with HAL components."""

    def setUp(self):
        """Set up test fixtures."""
        # Create integrated ChipsecCs for PCI testing
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        self.integrated_cs.hals.Pci = Mock()
        self.integrated_cs.hals.Pci.enumerate_devices.return_value = [
            (0x00, 0x00, 0x00, 0x8086, 0x1234, 0x01),
            (0x00, 0x1F, 0x00, 0x8086, 0x5678, 0x02),
        ]
        self.integrated_cs.hals.Pci.dump_pci_config.return_value = b'\x86\x80\x34\x12\x00\x00\x00\x00' * 32
        self.integrated_cs.hals.Pci.read_dword.return_value = 0x80861234
        self.integrated_cs.hals.Pci.write_dword.return_value = None
        self.integrated_cs.hals.Pci.find_XROM.return_value = (True, Mock(en=1, base=0xFEDF0000, size=0x10000, header=None))

        # Mock helper
        self.integrated_cs.helper = Mock()
        self.integrated_cs.helper.get_threads_count.return_value = 2

    def test_pci_read_write_workflow(self):
        """Test complete PCI read/write workflow."""
        # Test read operation
        read_cmd = PCICommand(['read', '0', '0', '0', '0x00'], cs=self.integrated_cs)
        read_cmd.parse_arguments()

        with patch.object(read_cmd.logger, 'log') as mock_log:
            read_cmd.run()

            self.integrated_cs.hals.Pci.read_dword.assert_called_once_with(0x0, 0x0, 0x0, 0x0)
            mock_log.assert_called_once_with('[CHIPSEC] PCI 00:00.0 + 0x00: 0x80861234')

        # Test write operation
        write_cmd = PCICommand(['write', '0', '0', '0', '0x98', '4', '0x004E0040'], cs=self.integrated_cs)
        write_cmd.parse_arguments()

        with patch.object(write_cmd.logger, 'log') as mock_log:
            write_cmd.run()

            self.integrated_cs.hals.Pci.write_dword.assert_called_once_with(0x0, 0x0, 0x0, 0x98, 0x4E0040)
            mock_log.assert_called_once_with('[CHIPSEC] Write 0x4E0040 to PCI 00:00.0 + 0x98')

    def test_pci_enumerate_dump_workflow(self):
        """Test PCI enumerate and dump workflow."""
        # Test enumerate operation
        enum_cmd = PCICommand(['enumerate'], cs=self.integrated_cs)
        enum_cmd.parse_arguments()

        with patch('chipsec.library.pci.print_pci_devices') as mock_print:
            enum_cmd.run()

            mock_print.assert_called_once_with(self.integrated_cs.hals.Pci.enumerate_devices.return_value)

        # Test dump operation
        dump_cmd = PCICommand(['dump', '0', '0', '0'], cs=self.integrated_cs)
        dump_cmd.parse_arguments()

        with patch.object(dump_cmd.logger, 'log') as mock_log, \
             patch('chipsec.library.logger.pretty_print_hex_buffer') as mock_print:
            dump_cmd.run()

            mock_log.assert_called_once_with('[CHIPSEC] PCI device 00:00.0 configuration:')
            mock_print.assert_called_once()

    def test_pci_xrom_workflow(self):
        """Test PCI XROM workflow."""
        xrom_cmd = PCICommand(['xrom', '0', '0', '0'], cs=self.integrated_cs)
        xrom_cmd.parse_arguments()

        with patch.object(xrom_cmd.logger, 'log') as mock_log:
            xrom_cmd.run()

            mock_log.assert_any_call('[CHIPSEC] Locating PCI expansion ROM (XROM) of 00:00.0...')
            mock_log.assert_any_call('[CHIPSEC] Found XROM of 00:00.0')
            mock_log.assert_any_call('[CHIPSEC] XROM enabled = 1, base = 0xFEDF0000, size = 0x10000')

    def test_pci_cmd_workflow(self):
        """Test PCI command register workflow."""
        cmd_cmd = PCICommand(['cmd', '1'], cs=self.integrated_cs)
        cmd_cmd.parse_arguments()

        # Mock PCI register reads
        self.integrated_cs.hals.Pci.read_byte.side_effect = [0x06, 0x00, 0x06, 0x01]  # Class and subclass values
        self.integrated_cs.hals.Pci.read_word.return_value = 0x0007  # Command register

        with patch.object(cmd_cmd.logger, 'log') as mock_log:
            cmd_cmd.run()

            # Should log header and device information
            self.assertGreaterEqual(mock_log.call_count, 3)  # Header + devices


class TestPCICommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for PCI command."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock ChipsecCs for edge case testing
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.hals.Pci = Mock()

    def test_empty_argv_handling(self):
        """Test handling of empty argv."""
        pci_cmd = PCICommand([], cs=self.mock_cs)

        # Should raise SystemExit due to missing required arguments
        with self.assertRaises(SystemExit):
            pci_cmd.parse_arguments()

    def test_invalid_subcommand(self):
        """Test handling of invalid subcommand."""
        pci_cmd = PCICommand(['invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with self.assertRaises(SystemExit):
            pci_cmd.parse_arguments()

    def test_read_missing_arguments(self):
        """Test read command with missing arguments."""
        pci_cmd = PCICommand(['read'], cs=self.mock_cs)

        # Should raise SystemExit due to missing required arguments
        with self.assertRaises(SystemExit):
            pci_cmd.parse_arguments()

    def test_write_missing_arguments(self):
        """Test write command with missing arguments."""
        pci_cmd = PCICommand(['write', '0', '0', '0'], cs=self.mock_cs)

        # Should raise SystemExit due to missing required arguments
        with self.assertRaises(SystemExit):
            pci_cmd.parse_arguments()

    def test_zero_bus_device_function(self):
        """Test operations with zero bus/device/function values."""
        # Test read with zero values
        read_cmd = PCICommand(['read', '0', '0', '0', '0x0'], cs=self.mock_cs)
        read_cmd.parse_arguments()
        self.assertEqual(read_cmd.bus, 0x0)
        self.assertEqual(read_cmd.device, 0x0)
        self.assertEqual(read_cmd.function, 0x0)
        self.assertEqual(read_cmd.offset, 0x0)

        # Test write with zero values
        write_cmd = PCICommand(['write', '0', '0', '0', '0x0', '4', '0x0'], cs=self.mock_cs)
        write_cmd.parse_arguments()
        self.assertEqual(write_cmd.bus, 0x0)
        self.assertEqual(write_cmd.device, 0x0)
        self.assertEqual(write_cmd.function, 0x0)
        self.assertEqual(write_cmd.offset, 0x0)
        self.assertEqual(write_cmd.value, 0x0)

    def test_maximum_bus_device_function(self):
        """Test operations with maximum bus/device/function values."""
        # PCI maximum values
        max_bus = 0xFF
        max_device = 0x1F
        max_function = 0x7

        # Test read with maximum values
        read_cmd = PCICommand(['read', f'{max_bus:X}', f'{max_device:X}', f'{max_function:X}', '0xFFC'], cs=self.mock_cs)
        read_cmd.parse_arguments()
        self.assertEqual(read_cmd.bus, max_bus)
        self.assertEqual(read_cmd.device, max_device)
        self.assertEqual(read_cmd.function, max_function)
        self.assertEqual(read_cmd.offset, 0xFFC)

    def test_zero_offset(self):
        """Test operations with zero offset."""
        read_cmd = PCICommand(['read', '0', '0', '0', '0x0'], cs=self.mock_cs)
        read_cmd.parse_arguments()
        self.assertEqual(read_cmd.offset, 0x0)

    def test_maximum_offset(self):
        """Test operations with maximum offset."""
        # PCI configuration space is 256 bytes (0x00-0xFF)
        max_offset = 0xFFC  # Maximum DWORD-aligned offset

        read_cmd = PCICommand(['read', '0', '0', '0', f'0x{max_offset:X}'], cs=self.mock_cs)
        read_cmd.parse_arguments()
        self.assertEqual(read_cmd.offset, max_offset)

    def test_zero_value_writes(self):
        """Test write operations with zero values."""
        write_cmd = PCICommand(['write', '0', '0', '0', '0x0', '4', '0x0'], cs=self.mock_cs)
        write_cmd.parse_arguments()
        self.assertEqual(write_cmd.value, 0x0)

    def test_maximum_value_writes(self):
        """Test write operations with maximum values."""
        # Test with maximum 32-bit value
        max_value = 0xFFFFFFFF
        write_cmd = PCICommand(['write', '0', '0', '0', '0x0', '4', f'0x{max_value:X}'], cs=self.mock_cs)
        write_cmd.parse_arguments()
        self.assertEqual(write_cmd.value, max_value)

    def test_hex_value_parsing(self):
        """Test hex value parsing in various commands."""
        # Test write with hex value
        write_cmd = PCICommand(['write', '0', '0', '0', '0x98', '4', '0x004E0040'], cs=self.mock_cs)
        write_cmd.parse_arguments()
        self.assertEqual(write_cmd.value, 0x004E0040)

        # Test write with decimal value
        write_cmd2 = PCICommand(['write', '0', '0', '0', '0x98', '4', '7819264'], cs=self.mock_cs)
        write_cmd2.parse_arguments()
        self.assertEqual(write_cmd2.value, 7819264)

    def test_case_insensitive_hex_parsing(self):
        """Test case insensitive hex value parsing."""
        # Test with uppercase hex
        write_cmd1 = PCICommand(['write', '0', '0', '0', '0x98', '4', '0xABCD1234'], cs=self.mock_cs)
        write_cmd1.parse_arguments()
        self.assertEqual(write_cmd1.value, 0xABCD1234)

        # Test with lowercase hex
        write_cmd2 = PCICommand(['write', '0', '0', '0', '0x98', '4', '0xabcd1234'], cs=self.mock_cs)
        write_cmd2.parse_arguments()
        self.assertEqual(write_cmd2.value, 0xABCD1234)

        # Test with mixed case hex
        write_cmd3 = PCICommand(['write', '0', '0', '0', '0x98', '4', '0xAbCd1234'], cs=self.mock_cs)
        write_cmd3.parse_arguments()
        self.assertEqual(write_cmd3.value, 0xABCD1234)

    def test_width_string_parsing(self):
        """Test width string parsing."""
        # Test various width strings
        test_cases = [
            ('byte', 1),
            ('word', 2),
            ('dword', 4),
            ('1', 1),
            ('2', 2),
            ('4', 4),
        ]

        for width_str, expected_width in test_cases:
            read_cmd = PCICommand(['read', '0', '0', '0', '0x0', width_str], cs=self.mock_cs)
            read_cmd.parse_arguments()
            self.assertEqual(read_cmd.size, width_str)

    def test_pci_device_addressing(self):
        """Test PCI device addressing patterns."""
        # Test various PCI device addresses
        test_addresses = [
            ('00', '00', '0'),  # Root complex
            ('00', '1F', '0'),  # PCH
            ('01', '00', '0'),  # PCIe device
            ('02', '00', '1'),  # PCIe function
            ('FF', '1F', '7'),  # Maximum values
        ]

        for bus, device, function in test_addresses:
            read_cmd = PCICommand(['read', bus, device, function, '0x0'], cs=self.mock_cs)
            read_cmd.parse_arguments()
            self.assertEqual(read_cmd.bus, int(bus, 16))
            self.assertEqual(read_cmd.device, int(device, 16))
            self.assertEqual(read_cmd.function, int(function, 16))

    def test_pci_configuration_offsets(self):
        """Test PCI configuration space offsets."""
        # Test standard PCI configuration offsets
        standard_offsets = {
            'vendor_id': 0x00,
            'device_id': 0x02,
            'command': 0x04,
            'status': 0x06,
            'revision_id': 0x08,
            'class_code': 0x09,
            'subclass': 0x0A,
            'prog_if': 0x0B,
            'header_type': 0x0E,
            'bar0': 0x10,
            'bar1': 0x14,
            'secondary_bus': 0x19,
            'subordinate_bus': 0x1A,
            'capabilities': 0x34,
        }

        for offset_name, offset_addr in standard_offsets.items():
            read_cmd = PCICommand(['read', '0', '0', '0', f'0x{offset_addr:X}'], cs=self.mock_cs)
            read_cmd.parse_arguments()
            self.assertEqual(read_cmd.offset, offset_addr)


if __name__ == '__main__':
    unittest.main()
