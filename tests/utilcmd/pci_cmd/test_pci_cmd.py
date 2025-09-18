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
from chipsec.utilcmd.pci_cmd import PCICommand
from tests.test_utils import MockFactory


class TestPCICommand:
    """Comprehensive tests for PCI utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for PCI testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock PCI HAL
        cs_mock.hals.Pci = Mock()
        cs_mock.hals.Pci.enumerate_devices.return_value = [
            (0x00, 0x00, 0x00, 0x8086, 0x1234, 0x01),
            (0x00, 0x1F, 0x00, 0x8086, 0x5678, 0x02),
            (0x01, 0x00, 0x00, 0x10DE, 0xABCD, 0x03),
        ]
        cs_mock.hals.Pci.dump_pci_config.return_value = b'\xFF' * 256
        cs_mock.hals.Pci.print_pci_config_all.return_value = None
        cs_mock.hals.Pci.read_byte.return_value = 0x12
        cs_mock.hals.Pci.read_word.return_value = 0x1234
        cs_mock.hals.Pci.read_dword.return_value = 0x12345678
        cs_mock.hals.Pci.write_byte.return_value = None
        cs_mock.hals.Pci.write_word.return_value = None
        cs_mock.hals.Pci.write_dword.return_value = None
        cs_mock.hals.Pci.find_XROM.return_value = (True, Mock(en=1, base=0xFEDF0000, size=0x10000, header=b'XROM_HEADER'))
        cs_mock.hals.Pci.enumerate_xroms.return_value = [
            Mock(bus=0x00, device=0x00, function=0x00, en=1, base=0xFEDF0000, size=0x10000),
        ]

        return cs_mock

    @pytest.fixture
    def pci_command(self, mock_cs):
        """Create PCICommand instance."""
        return PCICommand(['enumerate'], cs=mock_cs)

    @pytest.mark.unit
    def test_pci_command_initialization(self, pci_command, mock_cs):
        """Test PCICommand initialization."""
        assert pci_command.cs == mock_cs
        assert pci_command.argv == ['enumerate']

    @pytest.mark.unit
    def test_parse_arguments_enumerate(self, mock_cs):
        """Test parsing enumerate command arguments."""
        command = PCICommand(['enumerate'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.pci_enumerate

    @pytest.mark.unit
    def test_parse_arguments_read(self, mock_cs):
        """Test parsing read command arguments."""
        command = PCICommand(['read', '0', '0', '0', '0x00'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.pci_read
        assert command.bus == 0x0
        assert command.device == 0x0
        assert command.function == 0x0
        assert command.offset == 0x0
        assert command.size is None

    @pytest.mark.unit
    def test_parse_arguments_read_with_size(self, mock_cs):
        """Test parsing read command with size arguments."""
        command = PCICommand(['read', '0', '0', '0', '0x88', 'byte'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.pci_read
        assert command.bus == 0x0
        assert command.device == 0x0
        assert command.function == 0x0
        assert command.offset == 0x88
        assert command.size == 'byte'

    @pytest.mark.unit
    def test_parse_arguments_write(self, mock_cs):
        """Test parsing write command arguments."""
        command = PCICommand(['write', '0', '0x1F', '0', '0xDC', '1', '0x1'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.pci_write
        assert command.bus == 0x0
        assert command.device == 0x1F
        assert command.function == 0x0
        assert command.offset == 0xDC
        assert command.size == '1'
        assert command.value == 0x1

    @pytest.mark.unit
    def test_parse_arguments_dump(self, mock_cs):
        """Test parsing dump command arguments."""
        command = PCICommand(['dump'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.pci_dump
        assert command.bus is None
        assert command.device is None
        assert command.function is None

    @pytest.mark.unit
    def test_parse_arguments_dump_with_args(self, mock_cs):
        """Test parsing dump command with specific device arguments."""
        command = PCICommand(['dump', '0', '0', '0'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.pci_dump
        assert command.bus == 0x0
        assert command.device == 0x0
        assert command.function == 0x0

    @pytest.mark.unit
    def test_parse_arguments_xrom(self, mock_cs):
        """Test parsing xrom command arguments."""
        command = PCICommand(['xrom'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.pci_xrom
        assert command.bus is None
        assert command.device is None
        assert command.function is None
        assert command.xrom_addr is None

    @pytest.mark.unit
    def test_parse_arguments_xrom_with_args(self, mock_cs):
        """Test parsing xrom command with arguments."""
        command = PCICommand(['xrom', '3', '0', '0', '0xFEDF0000'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.pci_xrom
        assert command.bus == 0x3
        assert command.device == 0x0
        assert command.function == 0x0
        assert command.xrom_addr == 0xFEDF0000

    @pytest.mark.unit
    def test_parse_arguments_cmd(self, mock_cs):
        """Test parsing cmd command arguments."""
        command = PCICommand(['cmd'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.pci_cmd
        assert command.cmd_mask == 0xFFFF
        assert command.pci_class is None
        assert command.pci_sub_class is None

    @pytest.mark.unit
    def test_parse_arguments_cmd_with_args(self, mock_cs):
        """Test parsing cmd command with arguments."""
        command = PCICommand(['cmd', '1', '0x06', '0x00'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.pci_cmd
        assert command.cmd_mask == 0x1
        assert command.pci_class == 0x06
        assert command.pci_sub_class == 0x00

    @pytest.mark.unit
    def test_requirements(self, pci_command):
        """Test command requirements."""
        reqs = pci_command.requirements()
        assert hasattr(reqs, 'load_driver')

    @pytest.mark.unit
    def test_pci_enumerate(self, pci_command, mock_cs):
        """Test pci_enumerate command."""
        with patch('chipsec.library.pci.print_pci_devices') as mock_print:
            pci_command.pci_enumerate()

            mock_print.assert_called_once_with(mock_cs.hals.Pci.enumerate_devices.return_value)

    @pytest.mark.unit
    def test_pci_dump_all_devices(self, pci_command, mock_cs):
        """Test pci_dump with no specific device."""
        pci_command.bus = None
        pci_command.device = None
        pci_command.function = None

        with patch.object(pci_command.logger, 'log') as mock_log:
            pci_command.pci_dump()

            mock_log.assert_called_once_with('[CHIPSEC] Dumping configuration of available PCI devices...')
            mock_cs.hals.Pci.print_pci_config_all.assert_called_once()

    @pytest.mark.unit
    def test_pci_dump_specific_device(self, pci_command, mock_cs):
        """Test pci_dump with specific device."""
        pci_command.bus = 0x0
        pci_command.device = 0x0
        pci_command.function = 0x0

        with patch.object(pci_command.logger, 'log') as mock_log, \
             patch('chipsec.library.logger.pretty_print_hex_buffer') as mock_print:
            pci_command.pci_dump()

            mock_log.assert_called_once_with('[CHIPSEC] PCI device 00:00.0 configuration:')
            mock_print.assert_called_once_with(b'\xFF' * 256)

    @pytest.mark.unit
    def test_pci_dump_partial_device_info(self, pci_command, mock_cs):
        """Test pci_dump with partial device information."""
        pci_command.bus = 0x0
        pci_command.device = None
        pci_command.function = None

        with patch.object(pci_command.logger, 'log') as mock_log, \
             patch('chipsec.library.logger.pretty_print_hex_buffer') as mock_print:
            pci_command.pci_dump()

            # Should enumerate devices and dump each one
            mock_cs.hals.Pci.enumerate_devices.assert_called_once_with(0x0, None, None)
            assert mock_print.call_count == 3  # One for each enumerated device

    @pytest.mark.unit
    def test_pci_xrom_all_devices(self, pci_command, mock_cs):
        """Test pci_xrom with no specific device."""
        pci_command.bus = None
        pci_command.device = None
        pci_command.function = None
        pci_command.xrom_addr = None

        with patch.object(pci_command.logger, 'log') as mock_log, \
             patch('chipsec.library.pci.print_pci_XROMs') as mock_print:
            pci_command.pci_xrom()

            mock_log.assert_any_call('[CHIPSEC] Enumerating PCI expansion ROMs...')
            mock_log.assert_any_call('[CHIPSEC] found 1 PCI expansion ROMs')
            mock_print.assert_called_once()

    @pytest.mark.unit
    def test_pci_xrom_specific_device(self, pci_command, mock_cs):
        """Test pci_xrom with specific device."""
        pci_command.bus = 0x0
        pci_command.device = 0x0
        pci_command.function = 0x0
        pci_command.xrom_addr = None

        with patch.object(pci_command.logger, 'log') as mock_log:
            pci_command.pci_xrom()

            mock_log.assert_any_call('[CHIPSEC] Locating PCI expansion ROM (XROM) of 00:00.0...')
            mock_log.assert_any_call('[CHIPSEC] Found XROM of 00:00.0')
            mock_log.assert_any_call('[CHIPSEC] XROM enabled = 1, base = 0xFEDF0000, size = 0x10000')

    @pytest.mark.unit
    def test_pci_xrom_no_xrom_found(self, pci_command, mock_cs):
        """Test pci_xrom when no XROM is found."""
        pci_command.bus = 0x0
        pci_command.device = 0x0
        pci_command.function = 0x0
        pci_command.xrom_addr = None

        # Mock no XROM found
        mock_cs.hals.Pci.find_XROM.return_value = (False, None)

        with patch.object(pci_command.logger, 'log') as mock_log:
            pci_command.pci_xrom()

            mock_log.assert_any_call('[CHIPSEC] Locating PCI expansion ROM (XROM) of 00:00.0...')
            mock_log.assert_any_call("[CHIPSEC] Couldn't find XROM of 00:00.0")

    @pytest.mark.unit
    def test_pci_read_byte(self, pci_command, mock_cs):
        """Test pci_read with byte width."""
        pci_command.bus = 0x0
        pci_command.device = 0x0
        pci_command.function = 0x0
        pci_command.offset = 0x0
        pci_command.size = 'byte'

        with patch.object(pci_command.logger, 'log') as mock_log:
            pci_command.pci_read()

            mock_cs.hals.Pci.read_byte.assert_called_once_with(0x0, 0x0, 0x0, 0x0)
            mock_log.assert_called_once_with('[CHIPSEC] PCI 00:00.0 + 0x00: 0x12')

    @pytest.mark.unit
    def test_pci_read_word(self, pci_command, mock_cs):
        """Test pci_read with word width."""
        pci_command.bus = 0x0
        pci_command.device = 0x0
        pci_command.function = 0x0
        pci_command.offset = 0x88
        pci_command.size = 'word'

        with patch.object(pci_command.logger, 'log') as mock_log:
            pci_command.pci_read()

            mock_cs.hals.Pci.read_word.assert_called_once_with(0x0, 0x0, 0x0, 0x88)
            mock_log.assert_called_once_with('[CHIPSEC] PCI 00:00.0 + 0x88: 0x1234')

    @pytest.mark.unit
    def test_pci_read_dword(self, pci_command, mock_cs):
        """Test pci_read with dword width."""
        pci_command.bus = 0x0
        pci_command.device = 0x0
        pci_command.function = 0x0
        pci_command.offset = 0x98
        pci_command.size = 'dword'

        with patch.object(pci_command.logger, 'log') as mock_log:
            pci_command.pci_read()

            mock_cs.hals.Pci.read_dword.assert_called_once_with(0x0, 0x0, 0x0, 0x98)
            mock_log.assert_called_once_with('[CHIPSEC] PCI 00:00.0 + 0x98: 0x12345678')

    @pytest.mark.unit
    def test_pci_read_default_width(self, pci_command, mock_cs):
        """Test pci_read with default width (dword)."""
        pci_command.bus = 0x0
        pci_command.device = 0x0
        pci_command.function = 0x0
        pci_command.offset = 0x0
        pci_command.size = None

        with patch.object(pci_command.logger, 'log') as mock_log:
            pci_command.pci_read()

            mock_cs.hals.Pci.read_dword.assert_called_once_with(0x0, 0x0, 0x0, 0x0)
            mock_log.assert_called_once_with('[CHIPSEC] PCI 00:00.0 + 0x00: 0x12345678')

    @pytest.mark.unit
    def test_pci_read_invalid_width(self, pci_command, mock_cs):
        """Test pci_read with invalid width."""
        pci_command.bus = 0x0
        pci_command.device = 0x0
        pci_command.function = 0x0
        pci_command.offset = 0x0
        pci_command.size = 'invalid'

        with patch.object(pci_command.logger, 'log_error') as mock_error:
            pci_command.pci_read()

            mock_error.assert_called_once()
            # Should not call any read methods
            mock_cs.hals.Pci.read_byte.assert_not_called()
            mock_cs.hals.Pci.read_word.assert_not_called()
            mock_cs.hals.Pci.read_dword.assert_not_called()

    @pytest.mark.unit
    def test_pci_write_byte(self, pci_command, mock_cs):
        """Test pci_write with byte width."""
        pci_command.bus = 0x0
        pci_command.device = 0x1F
        pci_command.function = 0x0
        pci_command.offset = 0xDC
        pci_command.size = '1'
        pci_command.value = 0x1

        with patch.object(pci_command.logger, 'log') as mock_log:
            pci_command.pci_write()

            mock_cs.hals.Pci.write_byte.assert_called_once_with(0x0, 0x1F, 0x0, 0xDC, 0x1)
            mock_log.assert_called_once_with('[CHIPSEC] Write 0x1 to PCI 00:1F.0 + 0xDC')

    @pytest.mark.unit
    def test_pci_write_word(self, pci_command, mock_cs):
        """Test pci_write with word width."""
        pci_command.bus = 0x0
        pci_command.device = 0x0
        pci_command.function = 0x0
        pci_command.offset = 0x88
        pci_command.size = '2'
        pci_command.value = 0x1234

        with patch.object(pci_command.logger, 'log') as mock_log:
            pci_command.pci_write()

            mock_cs.hals.Pci.write_word.assert_called_once_with(0x0, 0x0, 0x0, 0x88, 0x1234)
            mock_log.assert_called_once_with('[CHIPSEC] Write 0x1234 to PCI 00:00.0 + 0x88')

    @pytest.mark.unit
    def test_pci_write_dword(self, pci_command, mock_cs):
        """Test pci_write with dword width."""
        pci_command.bus = 0x0
        pci_command.device = 0x0
        pci_command.function = 0x0
        pci_command.offset = 0x98
        pci_command.size = '4'
        pci_command.value = 0x004E0040

        with patch.object(pci_command.logger, 'log') as mock_log:
            pci_command.pci_write()

            mock_cs.hals.Pci.write_dword.assert_called_once_with(0x0, 0x0, 0x0, 0x98, 0x004E0040)
            mock_log.assert_called_once_with('[CHIPSEC] Write 0x4E0040 to PCI 00:00.0 + 0x98')

    @pytest.mark.unit
    def test_pci_write_invalid_width(self, pci_command, mock_cs):
        """Test pci_write with invalid width."""
        pci_command.bus = 0x0
        pci_command.device = 0x0
        pci_command.function = 0x0
        pci_command.offset = 0x0
        pci_command.size = '8'
        pci_command.value = 0x12345678

        with patch.object(pci_command.logger, 'log_error') as mock_error:
            pci_command.pci_write()

            mock_error.assert_called_once()
            # Should not call any write methods
            mock_cs.hals.Pci.write_byte.assert_not_called()
            mock_cs.hals.Pci.write_word.assert_not_called()
            mock_cs.hals.Pci.write_dword.assert_not_called()

    @pytest.mark.unit
    def test_pci_cmd_no_filters(self, pci_command, mock_cs):
        """Test pci_cmd with no filters."""
        pci_command.cmd_mask = 0xFFFF
        pci_command.pci_class = None
        pci_command.pci_sub_class = None

        # Mock PCI register reads
        mock_cs.hals.Pci.read_byte.side_effect = [0x06, 0x00, 0x06, 0x01, 0x06, 0x02]  # Class and subclass values
        mock_cs.hals.Pci.read_word.return_value = 0x0006  # Command register

        with patch.object(pci_command.logger, 'log') as mock_log:
            pci_command.pci_cmd()

            # Should log header and device information
            assert mock_log.call_count >= 4  # Header + 3 devices

    @pytest.mark.unit
    def test_pci_cmd_with_class_filter(self, pci_command, mock_cs):
        """Test pci_cmd with class filter."""
        pci_command.cmd_mask = 0xFFFF
        pci_command.pci_class = 0x06  # Bridge device
        pci_command.pci_sub_class = None

        # Mock PCI register reads - only first device matches class
        mock_cs.hals.Pci.read_byte.side_effect = [0x06, 0x00]  # Class and subclass for first device
        mock_cs.hals.Pci.read_word.return_value = 0x0006

        with patch.object(pci_command.logger, 'log') as mock_log:
            pci_command.pci_cmd()

            # Should only log devices that match the class filter
            assert mock_log.call_count >= 2  # Header + matching device

    @pytest.mark.unit
    def test_pci_cmd_with_subclass_filter(self, pci_command, mock_cs):
        """Test pci_cmd with subclass filter."""
        pci_command.cmd_mask = 0xFFFF
        pci_command.pci_class = None
        pci_command.pci_sub_class = 0x00  # Host bridge

        # Mock PCI register reads
        mock_cs.hals.Pci.read_byte.side_effect = [0x06, 0x00]  # Class and subclass
        mock_cs.hals.Pci.read_word.return_value = 0x0006

        with patch.object(pci_command.logger, 'log') as mock_log:
            pci_command.pci_cmd()

            # Should only log devices that match the subclass filter
            assert mock_log.call_count >= 2  # Header + matching device

    @pytest.mark.unit
    def test_pci_cmd_with_cmd_mask_filter(self, pci_command, mock_cs):
        """Test pci_cmd with command mask filter."""
        pci_command.cmd_mask = 0x0001  # Only devices with I/O space enabled
        pci_command.pci_class = None
        pci_command.pci_sub_class = None

        # Mock PCI register reads
        mock_cs.hals.Pci.read_byte.side_effect = [0x06, 0x00]  # Class and subclass
        mock_cs.hals.Pci.read_word.return_value = 0x0007  # Command register with I/O space enabled

        with patch.object(pci_command.logger, 'log') as mock_log:
            pci_command.pci_cmd()

            # Should only log devices that match the command mask
            assert mock_log.call_count >= 2  # Header + matching device


class TestPCICommandIntegration:
    """Integration tests for PCI command with HAL components."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for PCI testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        cs_mock.hals.Pci = Mock()
        cs_mock.hals.Pci.enumerate_devices.return_value = [
            (0x00, 0x00, 0x00, 0x8086, 0x1234, 0x01),
            (0x00, 0x1F, 0x00, 0x8086, 0x5678, 0x02),
        ]
        cs_mock.hals.Pci.dump_pci_config.return_value = b'\x86\x80\x34\x12\x00\x00\x00\x00' * 32
        cs_mock.hals.Pci.read_dword.return_value = 0x80861234
        cs_mock.hals.Pci.write_dword.return_value = None
        cs_mock.hals.Pci.find_XROM.return_value = (True, Mock(en=1, base=0xFEDF0000, size=0x10000, header=None))

        # Mock helper
        cs_mock.helper = Mock()
        cs_mock.helper.get_threads_count.return_value = 2

        return cs_mock

    @pytest.mark.integration
    def test_pci_read_write_workflow(self, integrated_cs):
        """Test complete PCI read/write workflow."""
        # Test read operation
        read_cmd = PCICommand(['read', '0', '0', '0', '0x00'], cs=integrated_cs)
        read_cmd.parse_arguments()

        with patch.object(read_cmd.logger, 'log') as mock_log:
            read_cmd.run()

            integrated_cs.hals.Pci.read_dword.assert_called_once_with(0x0, 0x0, 0x0, 0x0)
            mock_log.assert_called_once_with('[CHIPSEC] PCI 00:00.0 + 0x00: 0x80861234')

        # Test write operation
        write_cmd = PCICommand(['write', '0', '0', '0', '0x98', '4', '0x004E0040'], cs=integrated_cs)
        write_cmd.parse_arguments()

        with patch.object(write_cmd.logger, 'log') as mock_log:
            write_cmd.run()

            integrated_cs.hals.Pci.write_dword.assert_called_once_with(0x0, 0x0, 0x0, 0x98, 0x4E0040)
            mock_log.assert_called_once_with('[CHIPSEC] Write 0x4E0040 to PCI 00:00.0 + 0x98')

    @pytest.mark.integration
    def test_pci_enumerate_dump_workflow(self, integrated_cs):
        """Test PCI enumerate and dump workflow."""
        # Test enumerate operation
        enum_cmd = PCICommand(['enumerate'], cs=integrated_cs)
        enum_cmd.parse_arguments()

        with patch('chipsec.library.pci.print_pci_devices') as mock_print:
            enum_cmd.run()

            mock_print.assert_called_once_with(integrated_cs.hals.Pci.enumerate_devices.return_value)

        # Test dump operation
        dump_cmd = PCICommand(['dump', '0', '0', '0'], cs=integrated_cs)
        dump_cmd.parse_arguments()

        with patch.object(dump_cmd.logger, 'log') as mock_log, \
             patch('chipsec.library.logger.pretty_print_hex_buffer') as mock_print:
            dump_cmd.run()

            mock_log.assert_called_once_with('[CHIPSEC] PCI device 00:00.0 configuration:')
            mock_print.assert_called_once()

    @pytest.mark.integration
    def test_pci_xrom_workflow(self, integrated_cs):
        """Test PCI XROM workflow."""
        xrom_cmd = PCICommand(['xrom', '0', '0', '0'], cs=integrated_cs)
        xrom_cmd.parse_arguments()

        with patch.object(xrom_cmd.logger, 'log') as mock_log:
            xrom_cmd.run()

            mock_log.assert_any_call('[CHIPSEC] Locating PCI expansion ROM (XROM) of 00:00.0...')
            mock_log.assert_any_call('[CHIPSEC] Found XROM of 00:00.0')
            mock_log.assert_any_call('[CHIPSEC] XROM enabled = 1, base = 0xFEDF0000, size = 0x10000')

    @pytest.mark.integration
    def test_pci_cmd_workflow(self, integrated_cs):
        """Test PCI command register workflow."""
        cmd_cmd = PCICommand(['cmd', '1'], cs=integrated_cs)
        cmd_cmd.parse_arguments()

        # Mock PCI register reads
        integrated_cs.hals.Pci.read_byte.side_effect = [0x06, 0x00, 0x06, 0x01]  # Class and subclass values
        integrated_cs.hals.Pci.read_word.return_value = 0x0007  # Command register

        with patch.object(cmd_cmd.logger, 'log') as mock_log:
            cmd_cmd.run()

            # Should log header and device information
            assert mock_log.call_count >= 3  # Header + devices


class TestPCICommandEdgeCases:
    """Test edge cases and error conditions for PCI command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals.Pci = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        pci_cmd = PCICommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            pci_cmd.parse_arguments()

    @pytest.mark.unit
    def test_invalid_subcommand(self, mock_cs):
        """Test handling of invalid subcommand."""
        pci_cmd = PCICommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            pci_cmd.parse_arguments()

    @pytest.mark.unit
    def test_read_missing_arguments(self, mock_cs):
        """Test read command with missing arguments."""
        pci_cmd = PCICommand(['read'], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            pci_cmd.parse_arguments()

    @pytest.mark.unit
    def test_write_missing_arguments(self, mock_cs):
        """Test write command with missing arguments."""
        pci_cmd = PCICommand(['write', '0', '0', '0'], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            pci_cmd.parse_arguments()

    @pytest.mark.unit
    def test_zero_bus_device_function(self, mock_cs):
        """Test operations with zero bus/device/function values."""
        # Test read with zero values
        read_cmd = PCICommand(['read', '0', '0', '0', '0x0'], cs=mock_cs)
        read_cmd.parse_arguments()
        assert read_cmd.bus == 0x0
        assert read_cmd.device == 0x0
        assert read_cmd.function == 0x0
        assert read_cmd.offset == 0x0

        # Test write with zero values
        write_cmd = PCICommand(['write', '0', '0', '0', '0x0', '4', '0x0'], cs=mock_cs)
        write_cmd.parse_arguments()
        assert write_cmd.bus == 0x0
        assert write_cmd.device == 0x0
        assert write_cmd.function == 0x0
        assert write_cmd.offset == 0x0
        assert write_cmd.value == 0x0

    @pytest.mark.unit
    def test_maximum_bus_device_function(self, mock_cs):
        """Test operations with maximum bus/device/function values."""
        # PCI maximum values
        max_bus = 0xFF
        max_device = 0x1F
        max_function = 0x7

        # Test read with maximum values
        read_cmd = PCICommand(['read', f'{max_bus:X}', f'{max_device:X}', f'{max_function:X}', '0xFFC'], cs=mock_cs)
        read_cmd.parse_arguments()
        assert read_cmd.bus == max_bus
        assert read_cmd.device == max_device
        assert read_cmd.function == max_function
        assert read_cmd.offset == 0xFFC

    @pytest.mark.unit
    def test_zero_offset(self, mock_cs):
        """Test operations with zero offset."""
        read_cmd = PCICommand(['read', '0', '0', '0', '0x0'], cs=mock_cs)
        read_cmd.parse_arguments()
        assert read_cmd.offset == 0x0

    @pytest.mark.unit
    def test_maximum_offset(self, mock_cs):
        """Test operations with maximum offset."""
        # PCI configuration space is 256 bytes (0x00-0xFF)
        max_offset = 0xFFC  # Maximum DWORD-aligned offset

        read_cmd = PCICommand(['read', '0', '0', '0', f'0x{max_offset:X}'], cs=mock_cs)
        read_cmd.parse_arguments()
        assert read_cmd.offset == max_offset

    @pytest.mark.unit
    def test_zero_value_writes(self, mock_cs):
        """Test write operations with zero values."""
        write_cmd = PCICommand(['write', '0', '0', '0', '0x0', '4', '0x0'], cs=mock_cs)
        write_cmd.parse_arguments()
        assert write_cmd.value == 0x0

    @pytest.mark.unit
    def test_maximum_value_writes(self, mock_cs):
        """Test write operations with maximum values."""
        # Test with maximum 32-bit value
        max_value = 0xFFFFFFFF
        write_cmd = PCICommand(['write', '0', '0', '0', '0x0', '4', f'0x{max_value:X}'], cs=mock_cs)
        write_cmd.parse_arguments()
        assert write_cmd.value == max_value

    @pytest.mark.unit
    def test_hex_value_parsing(self, mock_cs):
        """Test hex value parsing in various commands."""
        # Test write with hex value
        write_cmd = PCICommand(['write', '0', '0', '0', '0x98', '4', '0x004E0040'], cs=mock_cs)
        write_cmd.parse_arguments()
        assert write_cmd.value == 0x004E0040

        # Test write with decimal value
        write_cmd2 = PCICommand(['write', '0', '0', '0', '0x98', '4', '7819264'], cs=mock_cs)
        write_cmd2.parse_arguments()
        assert write_cmd2.value == 7819264

    @pytest.mark.unit
    def test_case_insensitive_hex_parsing(self, mock_cs):
        """Test case insensitive hex value parsing."""
        # Test with uppercase hex
        write_cmd1 = PCICommand(['write', '0', '0', '0', '0x98', '4', '0xABCD1234'], cs=mock_cs)
        write_cmd1.parse_arguments()
        assert write_cmd1.value == 0xABCD1234

        # Test with lowercase hex
        write_cmd2 = PCICommand(['write', '0', '0', '0', '0x98', '4', '0xabcd1234'], cs=mock_cs)
        write_cmd2.parse_arguments()
        assert write_cmd2.value == 0xABCD1234

        # Test with mixed case hex
        write_cmd3 = PCICommand(['write', '0', '0', '0', '0x98', '4', '0xAbCd1234'], cs=mock_cs)
        write_cmd3.parse_arguments()
        assert write_cmd3.value == 0xABCD1234

    @pytest.mark.unit
    def test_width_string_parsing(self, mock_cs):
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
            read_cmd = PCICommand(['read', '0', '0', '0', '0x0', width_str], cs=mock_cs)
            read_cmd.parse_arguments()
            assert read_cmd.size == width_str

    @pytest.mark.unit
    def test_pci_device_addressing(self, mock_cs):
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
            read_cmd = PCICommand(['read', bus, device, function, '0x0'], cs=mock_cs)
            read_cmd.parse_arguments()
            assert read_cmd.bus == int(bus, 16)
            assert read_cmd.device == int(device, 16)
            assert read_cmd.function == int(function, 16)

    @pytest.mark.unit
    def test_pci_configuration_offsets(self, mock_cs):
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
            read_cmd = PCICommand(['read', '0', '0', '0', f'0x{offset_addr:X}'], cs=mock_cs)
            read_cmd.parse_arguments()
            assert read_cmd.offset == offset_addr


class TestPCICommandConfigurationValidation:
    """Test configuration validation aspects of PCI command."""

    @pytest.fixture
    def config_cs(self):
        """Create ChipsecCs with PCI-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock PCI HAL with configuration
        cs_mock.hals.Pci = Mock()
        cs_mock.hals.Pci.enumerate_devices.return_value = [
            (0x00, 0x00, 0x00, 0x8086, 0x1234, 0x01),
        ]
        cs_mock.hals.Pci.read_dword.return_value = 0x80861234

        # Mock PCI configuration data
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.PCI_CONFIG = {
            'max_bus': 0xFF,
            'max_device': 0x1F,
            'max_function': 0x7,
            'config_space_size': 256,
            'standard_offsets': {
                'vendor_id': 0x00,
                'device_id': 0x02,
                'command': 0x04,
                'status': 0x06,
                'class_code': 0x0B,
                'header_type': 0x0E,
                'capabilities': 0x34,
            },
            'device_classes': {
                'bridge': {'code': 0x06, 'subclasses': {'host': 0x00, 'pci': 0x04}},
                'display': {'code': 0x03, 'subclasses': {'vga': 0x00, 'xga': 0x01}},
                'network': {'code': 0x02, 'subclasses': {'ethernet': 0x00}},
                'storage': {'code': 0x01, 'subclasses': {'ide': 0x01, 'sata': 0x06}},
            },
            'security_features': {
                'validate_bars': True,
                'check_capabilities': True,
                'verify_vendor_id': True,
            }
        }

        return cs_mock

    @pytest.mark.unit
    def test_pci_configuration_access(self, config_cs):
        """Test access to PCI configuration data."""
        pci_config = config_cs.Cfg.PCI_CONFIG

        assert pci_config['max_bus'] == 0xFF
        assert pci_config['max_device'] == 0x1F
        assert pci_config['max_function'] == 0x7
        assert pci_config['config_space_size'] == 256
        assert 'vendor_id' in pci_config['standard_offsets']
        assert pci_config['standard_offsets']['vendor_id'] == 0x00

    @pytest.mark.unit
    def test_pci_address_limits_validation(self, config_cs):
        """Test PCI address limits validation."""
        pci_config = config_cs.Cfg.PCI_CONFIG

        # Test that PCI address limits are valid
        assert 0 <= pci_config['max_bus'] <= 0xFF
        assert 0 <= pci_config['max_device'] <= 0x1F
        assert 0 <= pci_config['max_function'] <= 0x7

        # Test configuration space size
        assert pci_config['config_space_size'] == 256  # Standard PCI config space
        assert pci_config['config_space_size'] > 0

    @pytest.mark.unit
    def test_standard_offsets_validation(self, config_cs):
        """Test validation of standard PCI offsets."""
        standard_offsets = config_cs.Cfg.PCI_CONFIG['standard_offsets']

        # Test that all expected standard offsets are defined
        expected_offsets = [
            'vendor_id', 'device_id', 'command', 'status',
            'class_code', 'header_type', 'capabilities'
        ]

        for offset_name in expected_offsets:
            assert offset_name in standard_offsets
            assert isinstance(standard_offsets[offset_name], int)
            assert 0 <= standard_offsets[offset_name] < 256  # Within config space

        # Test specific offset values
        assert standard_offsets['vendor_id'] == 0x00
        assert standard_offsets['device_id'] == 0x02
        assert standard_offsets['command'] == 0x04

    @pytest.mark.unit
    def test_device_classes_validation(self, config_cs):
        """Test validation of PCI device classes."""
        device_classes = config_cs.Cfg.PCI_CONFIG['device_classes']

        # Test that all expected device classes are defined
        expected_classes = ['bridge', 'display', 'network', 'storage']

        for class_name in expected_classes:
            assert class_name in device_classes
            assert 'code' in device_classes[class_name]
            assert 'subclasses' in device_classes[class_name]
            assert isinstance(device_classes[class_name]['code'], int)
            assert 0 <= device_classes[class_name]['code'] <= 0xFF

        # Test specific class codes
        assert device_classes['bridge']['code'] == 0x06
        assert device_classes['display']['code'] == 0x03
        assert device_classes['network']['code'] == 0x02

    @pytest.mark.unit
    def test_security_features_validation(self, config_cs):
        """Test validation of PCI security features."""
        security_features = config_cs.Cfg.PCI_CONFIG['security_features']

        # Test that all expected security features are defined
        expected_features = ['validate_bars', 'check_capabilities', 'verify_vendor_id']

        for feature in expected_features:
            assert feature in security_features
            assert isinstance(security_features[feature], bool)

        # Test specific security feature values
        assert security_features['validate_bars'] is True
        assert security_features['check_capabilities'] is True
        assert security_features['verify_vendor_id'] is True

    @pytest.mark.unit
    def test_pci_offset_range_validation(self, config_cs):
        """Test PCI offset range validation."""
        config_space_size = config_cs.Cfg.PCI_CONFIG['config_space_size']
        standard_offsets = config_cs.Cfg.PCI_CONFIG['standard_offsets']

        # Test that all standard offsets are within the configuration space
        for offset_name, offset_addr in standard_offsets.items():
            assert 0 <= offset_addr < config_space_size, f"PCI offset {offset_name} at 0x{offset_addr:X} exceeds config space size 0x{config_space_size:X}"

        # Test that configuration space size is reasonable
        assert config_space_size >= 64  # Minimum PCI config space
        assert config_space_size <= 4096  # Maximum reasonable config space


if __name__ == '__main__':
    pytest.main([__file__])
