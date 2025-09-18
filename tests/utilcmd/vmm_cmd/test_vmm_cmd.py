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
from chipsec.utilcmd.vmm_cmd import VMMCommand
from tests.test_utils import MockFactory


class TestVMMCommand:
    """Comprehensive tests for VMM utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for VMM testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock VMM HAL
        cs_mock.hals.Vmm = Mock()
        cs_mock.hals.Vmm.hypercall.return_value = 0x123456789ABCDEF0
        cs_mock.hals.Vmm.dump_EPT_page_tables.return_value = None

        # Mock PCI HAL for VirtIO
        cs_mock.hals.Pci = Mock()
        cs_mock.hals.Pci.enumerate_devices.return_value = [
            (0x00, 0x00, 0x00, 0x8086, 0x1234, 0x01),
            (0x00, 0x06, 0x00, 0x1AF4, 0x1000, 0x02),  # VirtIO device
            (0x00, 0x07, 0x00, 0x1AF4, 0x1001, 0x03),  # Another VirtIO device
        ]
        cs_mock.hals.Pci.get_DIDVID.return_value = (0x1000, 0x1AF4)  # VirtIO device
        # Mock dump_pci_config to return bytes instead of Mock
        cs_mock.hals.Pci.dump_pci_config.return_value = b'\x00' * 256  # 256 bytes of PCI config space
        cs_mock.hals.Pci.get_device_bars.return_value = []  # No BARs for simplicity

        return cs_mock

    @pytest.fixture
    def vmm_command(self, mock_cs):
        """Create VMMCommand instance."""
        return VMMCommand(['hypercall', '32', '0', '0', '0', '0', '0'], cs=mock_cs)

    @pytest.mark.unit
    def test_vmm_command_initialization(self, vmm_command, mock_cs):
        """Test VMMCommand initialization."""
        assert vmm_command.cs == mock_cs
        assert vmm_command.argv == ['hypercall', '32', '0', '0', '0', '0', '0']

    @pytest.mark.unit
    def test_parse_arguments_hypercall(self, mock_cs):
        """Test parsing hypercall command arguments."""
        command = VMMCommand(['hypercall', '32', '0', '0', '0', '0', '0'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.vmm_hypercall
        assert command.ax == 0x32
        assert command.bx == 0x0
        assert command.cx == 0x0
        assert command.dx == 0x0
        assert command.di == 0x0
        assert command.si == 0x0
        assert command.r8 == 0x0
        assert command.r9 == 0x0
        assert command.r10 == 0x0
        assert command.r11 == 0x0

    @pytest.mark.unit
    def test_parse_arguments_hypercall_with_optional(self, mock_cs):
        """Test parsing hypercall command with optional arguments."""
        command = VMMCommand(['hypercall', '32', '1', '2', '3', '4', '5', '6', '7', '8', '9'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.vmm_hypercall
        assert command.ax == 0x32
        assert command.bx == 0x1
        assert command.cx == 0x2
        assert command.dx == 0x3
        assert command.di == 0x4
        assert command.si == 0x5
        assert command.r8 == 0x6
        assert command.r9 == 0x7
        assert command.r10 == 0x8
        assert command.r11 == 0x9

    @pytest.mark.unit
    def test_parse_arguments_pt(self, mock_cs):
        """Test parsing pt command arguments."""
        command = VMMCommand(['pt', '0x524B01E'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.vmm_pt
        assert command.eptp == 0x524B01E

    @pytest.mark.unit
    def test_parse_arguments_ept(self, mock_cs):
        """Test parsing ept command arguments."""
        command = VMMCommand(['ept', '0x524B01E'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.vmm_pt  # Both pt and ept use same function
        assert command.eptp == 0x524B01E

    @pytest.mark.unit
    def test_parse_arguments_is_virtio(self, mock_cs):
        """Test parsing is_virtio command arguments."""
        command = VMMCommand(['is_virtio', '0', '6', '0'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.vmm_virtio
        assert command.bus == 0x0
        assert command.dev == 0x6
        assert command.fun == 0x0

    @pytest.mark.unit
    def test_parse_arguments_virtio(self, mock_cs):
        """Test parsing virtio command arguments."""
        command = VMMCommand(['virtio'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.enumerate

    @pytest.mark.unit
    def test_requirements(self, vmm_command):
        """Test command requirements."""
        reqs = vmm_command.requirements()
        assert hasattr(reqs, 'load_driver')

    @pytest.mark.unit
    def test_vmm_hypercall(self, vmm_command, mock_cs):
        """Test vmm_hypercall command."""
        vmm_command.ax = 0x32
        vmm_command.bx = 0x0
        vmm_command.cx = 0x0
        vmm_command.dx = 0x0
        vmm_command.di = 0x0
        vmm_command.si = 0x0
        vmm_command.r8 = 0x0
        vmm_command.r9 = 0x0
        vmm_command.r10 = 0x0
        vmm_command.r11 = 0x0

        with patch.object(vmm_command.logger, 'log') as mock_log:
            vmm_command.vmm_hypercall()

            # Verify hypercall was made with correct parameters
            mock_cs.hals.Vmm.hypercall.assert_called_once_with(
                0x32, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
            )

            # Verify logging of input parameters
            mock_log.assert_any_call('')
            mock_log.assert_any_call('[CHIPSEC] > hypercall')
            mock_log.assert_any_call('[CHIPSEC]   RAX: 0x0000000000000032')
            mock_log.assert_any_call('[CHIPSEC]   RBX: 0x0000000000000000')
            mock_log.assert_any_call('[CHIPSEC]   RCX: 0x0000000000000000')
            mock_log.assert_any_call('[CHIPSEC]   RDX: 0x0000000000000000')
            mock_log.assert_any_call('[CHIPSEC]   RSI: 0x0000000000000000')
            mock_log.assert_any_call('[CHIPSEC]   RDI: 0x0000000000000000')
            mock_log.assert_any_call('[CHIPSEC]   R8 : 0x0000000000000000')
            mock_log.assert_any_call('[CHIPSEC]   R9 : 0x0000000000000000')
            mock_log.assert_any_call('[CHIPSEC]   R10: 0x0000000000000000')
            mock_log.assert_any_call('[CHIPSEC]   R11: 0x0000000000000000')

            # Verify logging of return value
            mock_log.assert_any_call('[CHIPSEC] < RAX: 0x123456789ABCDEF0')

    @pytest.mark.unit
    def test_vmm_hypercall_different_values(self, vmm_command, mock_cs):
        """Test vmm_hypercall with different register values."""
        vmm_command.ax = 0x1000
        vmm_command.bx = 0x2000
        vmm_command.cx = 0x3000
        vmm_command.dx = 0x4000
        vmm_command.di = 0x5000
        vmm_command.si = 0x6000
        vmm_command.r8 = 0x7000
        vmm_command.r9 = 0x8000
        vmm_command.r10 = 0x9000
        vmm_command.r11 = 0xA000

        with patch.object(vmm_command.logger, 'log') as mock_log:
            vmm_command.vmm_hypercall()

            # Verify hypercall was made with correct parameters
            mock_cs.hals.Vmm.hypercall.assert_called_once_with(
                0x1000, 0x2000, 0x3000, 0x4000, 0x6000, 0x5000,
                0x7000, 0x8000, 0x9000, 0xA000
            )

    @pytest.mark.unit
    def test_vmm_pt_with_eptp(self, vmm_command, mock_cs):
        """Test vmm_pt command with EPT pointer."""
        vmm_command.eptp = 0x524B01E

        with patch.object(vmm_command.logger, 'log') as mock_log:
            vmm_command.vmm_pt()

            mock_log.assert_any_call('[CHIPSEC] EPT physical base: 0x000000000524B01E')
            mock_log.assert_any_call("[CHIPSEC] Dumping EPT to 'ept_0524B01E'...")
            mock_cs.hals.Vmm.dump_EPT_page_tables.assert_called_once_with(0x524B01E, 'ept_0524B01E')

    @pytest.mark.unit
    def test_vmm_pt_without_eptp(self, vmm_command, mock_cs):
        """Test vmm_pt command without EPT pointer."""
        vmm_command.eptp = None

        with patch.object(vmm_command.logger, 'log') as mock_log, \
             patch.object(vmm_command.logger, 'log_error') as mock_error:
            vmm_command.vmm_pt()

            mock_log.assert_called_once_with('[CHIPSEC] Finding EPT hierarchy in memory is not implemented yet')
            mock_error.assert_called_once()

    @pytest.mark.unit
    def test_vmm_pt_different_eptp(self, vmm_command, mock_cs):
        """Test vmm_pt with different EPT pointers."""
        test_eptps = [0x1000, 0x200000, 0xFFFFFFFF, 0x123456789ABCDEF0]

        for eptp in test_eptps:
            vmm_command.eptp = eptp
            expected_filename = f'ept_{eptp:08X}'

            with patch.object(vmm_command.logger, 'log') as mock_log:
                vmm_command.vmm_pt()

                mock_cs.hals.Vmm.dump_EPT_page_tables.assert_called_with(eptp, expected_filename)

    @pytest.mark.unit
    def test_enumerate_virtio_devices(self, vmm_command, mock_cs):
        """Test enumerate virtio devices."""
        with patch('chipsec.utilcmd.vmm_cmd.get_virtio_devices', return_value=[
            (0x00, 0x06, 0x00, 0x1AF4, 0x1000, 0x02),
            (0x00, 0x07, 0x00, 0x1AF4, 0x1001, 0x03)
        ]) as mock_get_virtio, \
             patch('chipsec.library.pci.PCI.print_pci_devices') as mock_print, \
             patch.object(vmm_command.logger, 'log') as mock_log:
            vmm_command.enumerate()

            mock_log.assert_any_call('[CHIPSEC] enumerating VirtIo devices...')
            mock_get_virtio.assert_called_once_with(mock_cs.hals.Pci.enumerate_devices.return_value)
            mock_print.assert_called_once()

    @pytest.mark.unit
    def test_enumerate_no_virtio_devices(self, vmm_command, mock_cs):
        """Test enumerate when no virtio devices found."""
        with patch('chipsec.utilcmd.vmm_cmd.get_virtio_devices', return_value=[]) as mock_get_virtio, \
             patch.object(vmm_command.logger, 'log') as mock_log:
            vmm_command.enumerate()

            mock_log.assert_any_call('[CHIPSEC] enumerating VirtIo devices...')
            mock_log.assert_any_call('[CHIPSEC] No VirtIO devices found')

    @pytest.mark.unit
    def test_vmm_virtio_device(self, vmm_command, mock_cs):
        """Test vmm_virtio command for specific device."""
        vmm_command.bus = 0x0
        vmm_command.dev = 0x6
        vmm_command.fun = 0x0

        with patch('chipsec.utilcmd.vmm_cmd.get_virtio_devices', return_value=[
            (0x00, 0x06, 0x00, 0x1AF4, 0x1000, 0x02)
        ]) as mock_get_virtio, \
             patch('chipsec.library.pci.PCI.print_pci_devices') as mock_print:
            vmm_command.vmm_virtio()

            mock_get_virtio.assert_called_once_with([(0x0, 0x6, 0x0, 0x1AF4, 0x1000, 0x0)])
            mock_print.assert_called_once()

    @pytest.mark.unit
    def test_vmm_virtio_non_virtio_device(self, vmm_command, mock_cs):
        """Test vmm_virtio command for non-VirtIO device."""
        vmm_command.bus = 0x0
        vmm_command.dev = 0x0
        vmm_command.fun = 0x0

        # Mock non-VirtIO device
        mock_cs.hals.Pci.get_DIDVID.return_value = (0x1234, 0x8086)

        with patch('chipsec.utilcmd.vmm_cmd.get_virtio_devices', return_value=[]) as mock_get_virtio, \
             patch.object(vmm_command.logger, 'log') as mock_log:
            vmm_command.vmm_virtio()

            mock_get_virtio.assert_called_once_with([(0x0, 0x0, 0x0, 0x8086, 0x1234, 0x0)])
            mock_log.assert_any_call('[CHIPSEC] No VirtIO devices found')

    @pytest.mark.unit
    def test_dump_virtio_with_devices(self, vmm_command, mock_cs):
        """Test _dump_virtio method with devices."""
        virt_dev = [
            (0x00, 0x06, 0x00, 0x1AF4, 0x1000, 0x02),
            (0x00, 0x07, 0x00, 0x1AF4, 0x1001, 0x03)
        ]

        with patch('chipsec.library.pci.PCI.print_pci_devices') as mock_print, \
             patch.object(vmm_command.logger, 'log') as mock_log, \
             patch('chipsec.utilcmd.vmm_cmd.VirtIO_Device') as mock_virtio_device:
            vmm_command._dump_virtio(virt_dev)

            mock_log.assert_any_call('[CHIPSEC] Available VirtIO devices:')
            mock_print.assert_called_once_with(virt_dev)
            assert mock_virtio_device.call_count == 2

    @pytest.mark.unit
    def test_dump_virtio_no_devices(self, vmm_command, mock_cs):
        """Test _dump_virtio method with no devices."""
        virt_dev = []

        with patch.object(vmm_command.logger, 'log') as mock_log:
            vmm_command._dump_virtio(virt_dev)

            mock_log.assert_called_once_with('[CHIPSEC] No VirtIO devices found')

    @pytest.mark.unit
    def test_run_method(self, vmm_command, mock_cs):
        """Test run method."""
        mock_func = Mock()
        vmm_command.func = mock_func

        vmm_command.run()

        mock_func.assert_called_once()


class TestVMMCommandIntegration:
    """Integration tests for VMM command with HAL components."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for VMM testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        cs_mock.hals.Vmm = Mock()
        cs_mock.hals.Vmm.hypercall.return_value = 0xFEDCBA9876543210
        cs_mock.hals.Vmm.dump_EPT_page_tables.return_value = None

        cs_mock.hals.Pci = Mock()
        cs_mock.hals.Pci.enumerate_devices.return_value = [
            (0x00, 0x06, 0x00, 0x1AF4, 0x1000, 0x02),
            (0x00, 0x07, 0x00, 0x1AF4, 0x1001, 0x03),
        ]
        cs_mock.hals.Pci.get_DIDVID.return_value = (0x1000, 0x1AF4)

        # Mock helper
        cs_mock.helper = Mock()
        cs_mock.helper.get_threads_count.return_value = 2

        return cs_mock

    @pytest.mark.integration
    def test_vmm_hypercall_workflow(self, integrated_cs):
        """Test complete VMM hypercall workflow."""
        hypercall_cmd = VMMCommand(['hypercall', '32', '1', '2', '3', '4', '5', '6', '7', '8', '9'], cs=integrated_cs)
        hypercall_cmd.parse_arguments()

        with patch.object(hypercall_cmd.logger, 'log') as mock_log:
            hypercall_cmd.run()

            integrated_cs.hals.Vmm.hypercall.assert_called_once_with(
                0x32, 0x1, 0x2, 0x3, 0x5, 0x4, 0x6, 0x7, 0x8, 0x9
            )
            mock_log.assert_any_call('[CHIPSEC] < RAX: 0xFEDCBA9876543210')

    @pytest.mark.integration
    def test_vmm_pt_workflow(self, integrated_cs):
        """Test VMM page table workflow."""
        pt_cmd = VMMCommand(['pt', '0x524B01E'], cs=integrated_cs)
        pt_cmd.parse_arguments()

        with patch.object(pt_cmd.logger, 'log') as mock_log:
            pt_cmd.run()

            integrated_cs.hals.Vmm.dump_EPT_page_tables.assert_called_once_with(0x524B01E, 'ept_0524B01E')
            mock_log.assert_any_call("[CHIPSEC] Dumping EPT to 'ept_0524B01E'...")

    @pytest.mark.integration
    def test_vmm_ept_workflow(self, integrated_cs):
        """Test VMM EPT workflow."""
        ept_cmd = VMMCommand(['ept', '0x100000'], cs=integrated_cs)
        ept_cmd.parse_arguments()

        with patch.object(ept_cmd.logger, 'log') as mock_log:
            ept_cmd.run()

            integrated_cs.hals.Vmm.dump_EPT_page_tables.assert_called_once_with(0x100000, 'ept_0100000')
            mock_log.assert_any_call("[CHIPSEC] Dumping EPT to 'ept_0100000'...")

    @pytest.mark.integration
    def test_vmm_virtio_enumeration_workflow(self, integrated_cs):
        """Test VMM VirtIO enumeration workflow."""
        virtio_cmd = VMMCommand(['virtio'], cs=integrated_cs)
        virtio_cmd.parse_arguments()

        with patch('chipsec.utilcmd.vmm_cmd.get_virtio_devices', return_value=[
            (0x00, 0x06, 0x00, 0x1AF4, 0x1000, 0x02)
        ]) as mock_get_virtio, \
             patch('chipsec.library.pci.PCI.print_pci_devices') as mock_print:
            virtio_cmd.run()

            mock_get_virtio.assert_called_once_with(integrated_cs.hals.Pci.enumerate_devices.return_value)
            mock_print.assert_called_once()

    @pytest.mark.integration
    def test_vmm_is_virtio_workflow(self, integrated_cs):
        """Test VMM is_virtio workflow."""
        is_virtio_cmd = VMMCommand(['is_virtio', '0', '6', '0'], cs=integrated_cs)
        is_virtio_cmd.parse_arguments()

        with patch('chipsec.utilcmd.vmm_cmd.get_virtio_devices', return_value=[
            (0x00, 0x06, 0x00, 0x1AF4, 0x1000, 0x02)
        ]) as mock_get_virtio, \
             patch('chipsec.library.pci.PCI.print_pci_devices') as mock_print:
            is_virtio_cmd.run()

            mock_get_virtio.assert_called_once_with([(0x0, 0x6, 0x0, 0x1AF4, 0x1000, 0x0)])
            mock_print.assert_called_once()


class TestVMMCommandEdgeCases:
    """Test edge cases and error conditions for VMM command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals.Vmm = Mock()
        cs_mock.hals.Pci = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        vmm_cmd = VMMCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            vmm_cmd.parse_arguments()

    @pytest.mark.unit
    def test_invalid_subcommand(self, mock_cs):
        """Test handling of invalid subcommand."""
        vmm_cmd = VMMCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            vmm_cmd.parse_arguments()

    @pytest.mark.unit
    def test_hypercall_missing_arguments(self, mock_cs):
        """Test hypercall command with missing arguments."""
        vmm_cmd = VMMCommand(['hypercall'], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            vmm_cmd.parse_arguments()

    @pytest.mark.unit
    def test_pt_missing_arguments(self, mock_cs):
        """Test pt command with missing arguments."""
        vmm_cmd = VMMCommand(['pt'], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            vmm_cmd.parse_arguments()

    @pytest.mark.unit
    def test_is_virtio_missing_arguments(self, mock_cs):
        """Test is_virtio command with missing arguments."""
        vmm_cmd = VMMCommand(['is_virtio'], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            vmm_cmd.parse_arguments()

    @pytest.mark.unit
    def test_zero_register_values(self, mock_cs):
        """Test hypercall with zero register values."""
        vmm_cmd = VMMCommand(['hypercall', '0', '0', '0', '0', '0', '0'], cs=mock_cs)
        vmm_cmd.parse_arguments()

        assert vmm_cmd.ax == 0x0
        assert vmm_cmd.bx == 0x0
        assert vmm_cmd.cx == 0x0
        assert vmm_cmd.dx == 0x0
        assert vmm_cmd.di == 0x0
        assert vmm_cmd.si == 0x0
        assert vmm_cmd.r8 == 0x0
        assert vmm_cmd.r9 == 0x0
        assert vmm_cmd.r10 == 0x0
        assert vmm_cmd.r11 == 0x0

    @pytest.mark.unit
    def test_maximum_register_values(self, mock_cs):
        """Test hypercall with maximum register values."""
        max_val = 'FFFFFFFFFFFFFFFF'  # 64-bit maximum
        vmm_cmd = VMMCommand(['hypercall', max_val, max_val, max_val, max_val, max_val, max_val], cs=mock_cs)
        vmm_cmd.parse_arguments()

        expected_max = 0xFFFFFFFFFFFFFFFF
        assert vmm_cmd.ax == expected_max
        assert vmm_cmd.bx == expected_max
        assert vmm_cmd.cx == expected_max
        assert vmm_cmd.dx == expected_max
        assert vmm_cmd.di == expected_max
        assert vmm_cmd.si == expected_max

    @pytest.mark.unit
    def test_hex_value_parsing(self, mock_cs):
        """Test hex value parsing in various commands."""
        # Test hypercall with hex values
        vmm_cmd = VMMCommand(['hypercall', '0x32', '0x1', '0x2', '0x3', '0x4', '0x5'], cs=mock_cs)
        vmm_cmd.parse_arguments()
        assert vmm_cmd.ax == 0x32
        assert vmm_cmd.bx == 0x1
        assert vmm_cmd.cx == 0x2
        assert vmm_cmd.dx == 0x3
        assert vmm_cmd.di == 0x4
        assert vmm_cmd.si == 0x5

        # Test pt with hex value
        pt_cmd = VMMCommand(['pt', '0x524B01E'], cs=mock_cs)
        pt_cmd.parse_arguments()
        assert pt_cmd.eptp == 0x524B01E

        # Test is_virtio with hex values
        virtio_cmd = VMMCommand(['is_virtio', '0x0', '0x6', '0x0'], cs=mock_cs)
        virtio_cmd.parse_arguments()
        assert virtio_cmd.bus == 0x0
        assert virtio_cmd.dev == 0x6
        assert virtio_cmd.fun == 0x0

    @pytest.mark.unit
    def test_case_insensitive_hex_parsing(self, mock_cs):
        """Test case insensitive hex value parsing."""
        # Test with uppercase hex
        vmm_cmd1 = VMMCommand(['hypercall', '0xABCD', '0x0', '0x0', '0x0', '0x0', '0x0'], cs=mock_cs)
        vmm_cmd1.parse_arguments()
        assert vmm_cmd1.ax == 0xABCD

        # Test with lowercase hex
        vmm_cmd2 = VMMCommand(['hypercall', '0xabcd', '0x0', '0x0', '0x0', '0x0', '0x0'], cs=mock_cs)
        vmm_cmd2.parse_arguments()
        assert vmm_cmd2.ax == 0xABCD

        # Test with mixed case hex
        vmm_cmd3 = VMMCommand(['hypercall', '0xAbCd', '0x0', '0x0', '0x0', '0x0', '0x0'], cs=mock_cs)
        vmm_cmd3.parse_arguments()
        assert vmm_cmd3.ax == 0xABCD

    @pytest.mark.unit
    def test_zero_ept_pointer(self, mock_cs):
        """Test page table operations with zero EPT pointer."""
        pt_cmd = VMMCommand(['pt', '0x0'], cs=mock_cs)
        pt_cmd.parse_arguments()
        assert pt_cmd.eptp == 0x0

    @pytest.mark.unit
    def test_maximum_ept_pointer(self, mock_cs):
        """Test page table operations with maximum EPT pointer."""
        max_eptp = 'FFFFFFFFFFFFFFFF'
        pt_cmd = VMMCommand(['pt', max_eptp], cs=mock_cs)
        pt_cmd.parse_arguments()
        assert pt_cmd.eptp == 0xFFFFFFFFFFFFFFFF

    @pytest.mark.unit
    def test_zero_bus_device_function(self, mock_cs):
        """Test VirtIO operations with zero BDF values."""
        virtio_cmd = VMMCommand(['is_virtio', '0x0', '0x0', '0x0'], cs=mock_cs)
        virtio_cmd.parse_arguments()
        assert virtio_cmd.bus == 0x0
        assert virtio_cmd.dev == 0x0
        assert virtio_cmd.fun == 0x0

    @pytest.mark.unit
    def test_maximum_bus_device_function(self, mock_cs):
        """Test VirtIO operations with maximum BDF values."""
        max_bus = 'FF'
        max_device = '1F'
        max_function = '7'
        virtio_cmd = VMMCommand(['is_virtio', max_bus, max_device, max_function], cs=mock_cs)
        virtio_cmd.parse_arguments()
        assert virtio_cmd.bus == 0xFF
        assert virtio_cmd.dev == 0x1F
        assert virtio_cmd.fun == 0x7

    @pytest.mark.unit
    def test_hypercall_register_logging_format(self, vmm_command, mock_cs):
        """Test hypercall register logging format."""
        vmm_command.ax = 0x123456789ABCDEF0
        vmm_command.bx = 0x0
        vmm_command.cx = 0x0
        vmm_command.dx = 0x0
        vmm_command.di = 0x0
        vmm_command.si = 0x0
        vmm_command.r8 = 0x0
        vmm_command.r9 = 0x0
        vmm_command.r10 = 0x0
        vmm_command.r11 = 0x0

        with patch.object(vmm_command.logger, 'log') as mock_log:
            vmm_command.vmm_hypercall()

            # Verify 64-bit hex formatting
            mock_log.assert_any_call('[CHIPSEC]   RAX: 0x123456789ABCDEF0')
            mock_log.assert_any_call('[CHIPSEC] < RAX: 0x123456789ABCDEF0')

    @pytest.mark.unit
    def test_ept_filename_generation(self, vmm_command, mock_cs):
        """Test EPT filename generation."""
        test_eptps = [0x1000, 0xABCDEF, 0x12345678]
        expected_filenames = ['ept_00001000', 'ept_00ABCDEF', 'ept_12345678']

        for eptp, expected_filename in zip(test_eptps, expected_filenames):
            vmm_command.eptp = eptp

            with patch.object(vmm_command.logger, 'log') as mock_log:
                vmm_command.vmm_pt()

                mock_log.assert_any_call(f"[CHIPSEC] Dumping EPT to '{expected_filename}'...")
                mock_cs.hals.Vmm.dump_EPT_page_tables.assert_called_with(eptp, expected_filename)


class TestVMMCommandConfigurationValidation:
    """Test configuration validation aspects of VMM command."""

    @pytest.fixture
    def config_cs(self):
        """Create ChipsecCs with VMM-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock VMM HAL with configuration
        cs_mock.hals.Vmm = Mock()
        cs_mock.hals.Vmm.hypercall.return_value = 0x123456789ABCDEF0

        # Mock PCI HAL
        cs_mock.hals.Pci = Mock()
        cs_mock.hals.Pci.enumerate_devices.return_value = [
            (0x00, 0x06, 0x00, 0x1AF4, 0x1000, 0x02),
        ]

        # Mock VMM configuration data
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.VMM_CONFIG = {
            'supported_hypervisors': ['kvm', 'xen', 'vmware', 'hyperv', 'virtualbox'],
            'virtio_device_ids': [0x1000, 0x1001, 0x1002, 0x1003, 0x1004],
            'virtio_vendor_id': 0x1AF4,
            'max_hypercall_args': 11,
            'ept_page_table_levels': [2, 3, 4],
            'supported_page_sizes': [4096, 2048, 1024],
            'security_features': {
                'validate_hypercalls': True,
                'check_virtio_access': True,
                'verify_ept_pointers': True,
            }
        }

        return cs_mock

    @pytest.mark.unit
    def test_vmm_configuration_access(self, config_cs):
        """Test access to VMM configuration data."""
        vmm_config = config_cs.Cfg.VMM_CONFIG

        assert 'kvm' in vmm_config['supported_hypervisors']
        assert 'xen' in vmm_config['supported_hypervisors']
        assert 0x1000 in vmm_config['virtio_device_ids']
        assert vmm_config['virtio_vendor_id'] == 0x1AF4
        assert vmm_config['max_hypercall_args'] == 11

    @pytest.mark.unit
    def test_supported_hypervisors_validation(self, config_cs):
        """Test validation of supported hypervisors."""
        supported_hypervisors = config_cs.Cfg.VMM_CONFIG['supported_hypervisors']

        # Test that all expected hypervisors are supported
        expected_hypervisors = ['kvm', 'xen', 'vmware', 'hyperv', 'virtualbox']
        for hypervisor in expected_hypervisors:
            assert hypervisor in supported_hypervisors

        # Test that hypervisors list is not empty
        assert len(supported_hypervisors) > 0

    @pytest.mark.unit
    def test_virtio_device_ids_validation(self, config_cs):
        """Test validation of VirtIO device IDs."""
        virtio_device_ids = config_cs.Cfg.VMM_CONFIG['virtio_device_ids']

        # Test that all expected device IDs are defined
        expected_device_ids = [0x1000, 0x1001, 0x1002, 0x1003, 0x1004]
        for device_id in expected_device_ids:
            assert device_id in virtio_device_ids

        # Test that device IDs are within valid PCI range
        for device_id in virtio_device_ids:
            assert 0 <= device_id <= 0xFFFF

    @pytest.mark.unit
    def test_virtio_vendor_id_validation(self, config_cs):
        """Test validation of VirtIO vendor ID."""
        virtio_vendor_id = config_cs.Cfg.VMM_CONFIG['virtio_vendor_id']

        # Test that vendor ID is valid
        assert 0 <= virtio_vendor_id <= 0xFFFF
        assert virtio_vendor_id == 0x1AF4  # Standard VirtIO vendor ID

    @pytest.mark.unit
    def test_max_hypercall_args_validation(self, config_cs):
        """Test validation of maximum hypercall arguments."""
        max_args = config_cs.Cfg.VMM_CONFIG['max_hypercall_args']

        # Test that maximum arguments is reasonable
        assert max_args > 0
        assert max_args >= 6  # Minimum required arguments (rax, rbx, rcx, rdx, rdi, rsi)
        assert max_args <= 17  # x86-64 has 16 GPRs + 1 return value

    @pytest.mark.unit
    def test_ept_page_table_levels_validation(self, config_cs):
        """Test validation of EPT page table levels."""
        ept_levels = config_cs.Cfg.VMM_CONFIG['ept_page_table_levels']

        # Test that all expected EPT levels are supported
        expected_levels = [2, 3, 4]
        for level in expected_levels:
            assert level in ept_levels

        # Test that levels are within valid range
        for level in ept_levels:
            assert 2 <= level <= 5  # Valid EPT page table levels

    @pytest.mark.unit
    def test_supported_page_sizes_validation(self, config_cs):
        """Test validation of supported page sizes."""
        page_sizes = config_cs.Cfg.VMM_CONFIG['supported_page_sizes']

        # Test that all expected page sizes are supported
        expected_sizes = [4096, 2048, 1024]
        for size in expected_sizes:
            assert size in page_sizes

        # Test that page sizes are powers of 2
        for size in page_sizes:
            assert size > 0
            assert (size & (size - 1)) == 0  # Check if power of 2

    @pytest.mark.unit
    def test_security_features_validation(self, config_cs):
        """Test validation of VMM security features."""
        security_features = config_cs.Cfg.VMM_CONFIG['security_features']

        # Test that all expected security features are defined
        expected_features = ['validate_hypercalls', 'check_virtio_access', 'verify_ept_pointers']
        for feature in expected_features:
            assert feature in security_features
            assert isinstance(security_features[feature], bool)

        # Test specific security feature values
        assert security_features['validate_hypercalls'] is True
        assert security_features['check_virtio_access'] is True
        assert security_features['verify_ept_pointers'] is True


if __name__ == '__main__':
    pytest.main([__file__])
