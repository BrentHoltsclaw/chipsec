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

import os
import pytest
from unittest.mock import Mock, patch, mock_open
from chipsec.utilcmd.vmem_cmd import VMemCommand
from tests.test_utils import MockFactory


class TestVMemCommand:
    """Comprehensive tests for VMem utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for VMem testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock VirtMemory component
        cs_mock.hals = Mock()
        cs_mock.hals.virtmem = Mock()

        return cs_mock

    @pytest.fixture
    def vmem_command(self, mock_cs):
        """Create VMemCommand instance."""
        return VMemCommand(['read', '0x1000', '0x100'], cs=mock_cs)

    @pytest.mark.unit
    def test_vmem_command_initialization(self, vmem_command, mock_cs):
        """Test VMemCommand initialization."""
        assert vmem_command.cs == mock_cs
        assert vmem_command.argv == ['read', '0x1000', '0x100']

    @pytest.mark.unit
    def test_requirements(self, vmem_command):
        """Test command requirements."""
        reqs = vmem_command.requirements()
        assert reqs == vmem_command.toLoad.Driver

    @pytest.mark.unit
    def test_parse_arguments_read(self, mock_cs):
        """Test parsing read command."""
        command = VMemCommand(['read', '0xFED40000', '0x20', 'buffer.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.vmem_read
        assert command.virt_address == 0xFED40000
        assert command.size == 0x20
        assert command.buf_file == 'buffer.bin'

    @pytest.mark.unit
    def test_parse_arguments_readval(self, mock_cs):
        """Test parsing readval command."""
        command = VMemCommand(['readval', '0xFED40000', 'dword'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.vmem_readval
        assert command.virt_address == 0xFED40000
        assert command.length == 'dword'

    @pytest.mark.unit
    def test_parse_arguments_write(self, mock_cs):
        """Test parsing write command."""
        command = VMemCommand(['write', '0x100000000', '0x1000', 'buffer.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.vmem_write
        assert command.virt_address == 0x100000000
        assert command.size == 0x1000
        assert command.buf_file == 'buffer.bin'

    @pytest.mark.unit
    def test_parse_arguments_writeval(self, mock_cs):
        """Test parsing writeval command."""
        command = VMemCommand(['writeval', '0xA0000', 'dword', '0x9090CCCC'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.vmem_writeval
        assert command.virt_address == 0xA0000
        assert command.length == 'dword'
        assert command.value == 0x9090CCCC

    @pytest.mark.unit
    def test_parse_arguments_search(self, mock_cs):
        """Test parsing search command."""
        command = VMemCommand(['search', '0xF0000', '0x10000', '_SM_'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.vmem_search
        assert command.virt_address == 0xF0000
        assert command.size == 0x10000
        assert command.value == '_SM_'

    @pytest.mark.unit
    def test_parse_arguments_allocate(self, mock_cs):
        """Test parsing allocate command."""
        command = VMemCommand(['allocate', '0x1000'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.vmem_allocate
        assert command.size == 0x1000

    @pytest.mark.unit
    def test_parse_arguments_getphys(self, mock_cs):
        """Test parsing getphys command."""
        command = VMemCommand(['getphys', '0xFED00000'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.vmem_getphys
        assert command.virt_address == 0xFED00000

    @pytest.mark.unit
    def test_parse_arguments_invalid(self, mock_cs):
        """Test parsing invalid command."""
        command = VMemCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_set_up(self, vmem_command, mock_cs):
        """Test set_up method."""
        vmem_command.set_up()
        # Should create VirtMemory instance
        assert hasattr(vmem_command, '_vmem')

    @pytest.mark.unit
    def test_vmem_read_with_file(self, vmem_command, mock_cs):
        """Test vmem_read method with file output."""
        vmem_command.virt_address = 0xFED40000
        vmem_command.size = 0x20
        vmem_command.buf_file = 'buffer.bin'

        # Mock VirtMemory
        vmem_command._vmem = Mock()
        test_buffer = b'\x01\x02\x03\x04' * 8  # 32 bytes
        vmem_command._vmem.read_virtual_mem.return_value = test_buffer

        with patch('chipsec.utilcmd.vmem_cmd.write_file') as mock_write, \
             patch.object(vmem_command.logger, 'log') as mock_log:
            vmem_command.vmem_read()

            mock_cs.hals.virtmem.read_virtual_mem.assert_called_once_with(0xFED40000, 0x20)
            mock_write.assert_called_once_with('buffer.bin', test_buffer)
            mock_log.assert_any_call("[CHIPSEC] Written 0x20 bytes to 'buffer.bin'")

    @pytest.mark.unit
    def test_vmem_read_without_file(self, vmem_command, mock_cs):
        """Test vmem_read method without file output."""
        vmem_command.virt_address = 0xFED40000
        vmem_command.size = 0x10
        vmem_command.buf_file = ''

        # Mock VirtMemory
        vmem_command._vmem = Mock()
        test_buffer = b'\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11' * 2  # 16 bytes
        vmem_command._vmem.read_virtual_mem.return_value = test_buffer

        with patch('chipsec.utilcmd.vmem_cmd.print_buffer_bytes') as mock_print, \
             patch.object(vmem_command.logger, 'log') as mock_log:
            vmem_command.vmem_read()

            mock_cs.hals.virtmem.read_virtual_mem.assert_called_once_with(0xFED40000, 0x10)
            mock_print.assert_called_once_with(test_buffer)

    @pytest.mark.unit
    def test_vmem_read_error(self, vmem_command, mock_cs):
        """Test vmem_read method with error."""
        vmem_command.virt_address = 0xFED40000
        vmem_command.size = 0x20
        vmem_command.buf_file = 'buffer.bin'

        # Mock VirtMemory to raise error
        vmem_command._vmem = Mock()
        vmem_command._vmem.read_virtual_mem.side_effect = OSError("Mapping failed")

        with patch.object(vmem_command.logger, 'log_error') as mock_log_error:
            vmem_command.vmem_read()

            mock_log_error.assert_called_with('Error mapping VA to PA.')

    @pytest.mark.unit
    def test_vmem_readval_byte(self, vmem_command, mock_cs):
        """Test vmem_readval method with byte length."""
        vmem_command.virt_address = 0xFED40000
        vmem_command.length = 'byte'

        # Mock VirtMemory
        vmem_command._vmem = Mock()
        vmem_command._vmem.read_virtual_mem_byte.return_value = 0xAB

        with patch.object(vmem_command.logger, 'log') as mock_log:
            vmem_command.vmem_readval()

            vmem_command._vmem.read_virtual_mem_byte.assert_called_once_with(0xFED40000)
            mock_log.assert_any_call('[CHIPSEC] value = 0xAB')

    @pytest.mark.unit
    def test_vmem_readval_word(self, vmem_command, mock_cs):
        """Test vmem_readval method with word length."""
        vmem_command.virt_address = 0xFED40000
        vmem_command.length = 'word'

        # Mock VirtMemory
        vmem_command._vmem = Mock()
        vmem_command._vmem.read_virtual_mem_word.return_value = 0xABCD

        with patch.object(vmem_command.logger, 'log') as mock_log:
            vmem_command.vmem_readval()

            vmem_command._vmem.read_virtual_mem_word.assert_called_once_with(0xFED40000)
            mock_log.assert_any_call('[CHIPSEC] value = 0xABCD')

    @pytest.mark.unit
    def test_vmem_readval_dword(self, vmem_command, mock_cs):
        """Test vmem_readval method with dword length."""
        vmem_command.virt_address = 0xFED40000
        vmem_command.length = 'dword'

        # Mock VirtMemory
        vmem_command._vmem = Mock()
        vmem_command._vmem.read_virtual_mem_dword.return_value = 0xABCD1234

        with patch.object(vmem_command.logger, 'log') as mock_log:
            vmem_command.vmem_readval()

            vmem_command._vmem.read_virtual_mem_dword.assert_called_once_with(0xFED40000)
            mock_log.assert_any_call('[CHIPSEC] value = 0xABCD1234')

    @pytest.mark.unit
    def test_vmem_readval_hex_length(self, vmem_command, mock_cs):
        """Test vmem_readval method with hex length."""
        vmem_command.virt_address = 0xFED40000
        vmem_command.length = '0x8'

        # Mock VirtMemory
        vmem_command._vmem = Mock()
        vmem_command._vmem.read_virtual_mem_dword.return_value = 0x12345678

        with patch.object(vmem_command.logger, 'log') as mock_log:
            vmem_command.vmem_readval()

            vmem_command._vmem.read_virtual_mem_dword.assert_called_once_with(0xFED40000)
            mock_log.assert_any_call('[CHIPSEC] value = 0x12345678')

    @pytest.mark.unit
    def test_vmem_readval_invalid_length(self, vmem_command, mock_cs):
        """Test vmem_readval method with invalid length."""
        vmem_command.virt_address = 0xFED40000
        vmem_command.length = 'invalid'

        # Mock VirtMemory
        vmem_command._vmem = Mock()

        with patch.object(vmem_command.logger, 'log_error') as mock_log_error:
            vmem_command.vmem_readval()

            mock_log_error.assert_called_with("Must specify <length> argument in 'mem readval' as one of {}".format(vmem_command._vmem.CMD_OPTS_WIDTH))

    @pytest.mark.unit
    def test_vmem_readval_error(self, vmem_command, mock_cs):
        """Test vmem_readval method with error."""
        vmem_command.virt_address = 0xFED40000
        vmem_command.length = 'dword'

        # Mock VirtMemory to raise error
        vmem_command._vmem = Mock()
        vmem_command._vmem.read_virtual_mem_dword.side_effect = OSError("Mapping failed")

        with patch.object(vmem_command.logger, 'log_error') as mock_log_error:
            vmem_command.vmem_readval()

            mock_log_error.assert_called_with('Error mapping VA to PA.')

    @pytest.mark.unit
    def test_vmem_write_from_file(self, vmem_command, mock_cs):
        """Test vmem_write method with file input."""
        vmem_command.virt_address = 0x100000000
        vmem_command.size = 0x1000
        vmem_command.buf_file = 'buffer.bin'

        # Mock VirtMemory
        vmem_command._vmem = Mock()
        test_buffer = b'\x01\x02\x03\x04' * 0x400  # 4096 bytes
        vmem_command._vmem.write_virtual_mem = Mock()

        with patch('chipsec.utilcmd.vmem_cmd.os.path.exists') as mock_exists, \
             patch('chipsec.utilcmd.vmem_cmd.read_file') as mock_read, \
             patch.object(vmem_command.logger, 'log') as mock_log:
            mock_exists.return_value = True
            mock_read.return_value = test_buffer

            vmem_command.vmem_write()

            mock_read.assert_called_once_with('buffer.bin')
            vmem_command._vmem.write_virtual_mem.assert_called_once_with(0x100000000, 0x1000, test_buffer)
            mock_log.assert_any_call("[CHIPSEC] Read 0x1000 bytes from file 'buffer.bin'")

    @pytest.mark.unit
    def test_vmem_write_from_hex(self, vmem_command, mock_cs):
        """Test vmem_write method with hex string input."""
        vmem_command.virt_address = 0x100000000
        vmem_command.size = 0x10
        vmem_command.buf_file = '000102030405060708090A0B0C0D0E0F'

        # Mock VirtMemory
        vmem_command._vmem = Mock()
        vmem_command._vmem.write_virtual_mem = Mock()

        with patch('chipsec.utilcmd.vmem_cmd.os.path.exists') as mock_exists, \
             patch.object(vmem_command.logger, 'log') as mock_log:
            mock_exists.return_value = False

            vmem_command.vmem_write()

            expected_buffer = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
            vmem_command._vmem.write_virtual_mem.assert_called_once_with(0x100000000, 0x10, expected_buffer)
            mock_log.assert_any_call("[CHIPSEC] Read 0x10 hex bytes from command-line: '000102030405060708090A0B0C0D0E0F'")

    @pytest.mark.unit
    def test_vmem_write_invalid_hex(self, vmem_command, mock_cs):
        """Test vmem_write method with invalid hex string."""
        vmem_command.virt_address = 0x100000000
        vmem_command.size = 0x10
        vmem_command.buf_file = 'invalid_hex_string'

        # Mock VirtMemory
        vmem_command._vmem = Mock()

        with patch('chipsec.utilcmd.vmem_cmd.os.path.exists') as mock_exists, \
             patch.object(vmem_command.logger, 'log_error') as mock_log_error:
            mock_exists.return_value = False

            vmem_command.vmem_write()

            mock_log_error.assert_called_with("Incorrect <value> specified: 'invalid_hex_string'")

    @pytest.mark.unit
    def test_vmem_write_insufficient_data(self, vmem_command, mock_cs):
        """Test vmem_write method with insufficient data."""
        vmem_command.virt_address = 0x100000000
        vmem_command.size = 0x1000
        vmem_command.buf_file = 'small_buffer.bin'

        # Mock VirtMemory
        vmem_command._vmem = Mock()

        with patch('chipsec.utilcmd.vmem_cmd.os.path.exists') as mock_exists, \
             patch('chipsec.utilcmd.vmem_cmd.read_file') as mock_read, \
             patch.object(vmem_command.logger, 'log_error') as mock_log_error:
            mock_exists.return_value = True
            mock_read.return_value = b'\x01\x02\x03\x04'  # Only 4 bytes

            vmem_command.vmem_write()

            mock_log_error.assert_called_with("Number of bytes read (0x4) is less than the specified <length> (0x1000)")

    @pytest.mark.unit
    def test_vmem_writeval_byte(self, vmem_command, mock_cs):
        """Test vmem_writeval method with byte value."""
        vmem_command.virt_address = 0xA0000
        vmem_command.length = 'byte'
        vmem_command.value = 0xAB

        # Mock VirtMemory
        vmem_command._vmem = Mock()

        with patch.object(vmem_command.logger, 'log') as mock_log:
            vmem_command.vmem_writeval()

            vmem_command._vmem.write_virtual_mem_byte.assert_called_once_with(0xA0000, 0xAB)
            mock_log.assert_any_call('[CHIPSEC] Writing 1-byte value 0xAB to VA 0xA0000..')

    @pytest.mark.unit
    def test_vmem_writeval_word(self, vmem_command, mock_cs):
        """Test vmem_writeval method with word value."""
        vmem_command.virt_address = 0xA0000
        vmem_command.length = 'word'
        vmem_command.value = 0xABCD

        # Mock VirtMemory
        vmem_command._vmem = Mock()

        with patch.object(vmem_command.logger, 'log') as mock_log:
            vmem_command.vmem_writeval()

            vmem_command._vmem.write_virtual_mem_word.assert_called_once_with(0xA0000, 0xABCD)
            mock_log.assert_any_call('[CHIPSEC] Writing 2-byte value 0xABCD to VA 0xA0000..')

    @pytest.mark.unit
    def test_vmem_writeval_dword(self, vmem_command, mock_cs):
        """Test vmem_writeval method with dword value."""
        vmem_command.virt_address = 0xA0000
        vmem_command.length = 'dword'
        vmem_command.value = 0xABCD1234

        # Mock VirtMemory
        vmem_command._vmem = Mock()

        with patch.object(vmem_command.logger, 'log') as mock_log:
            vmem_command.vmem_writeval()

            vmem_command._vmem.write_virtual_mem_dword.assert_called_once_with(0xA0000, 0xABCD1234)
            mock_log.assert_any_call('[CHIPSEC] Writing 4-byte value 0xABCD1234 to VA 0xA0000..')

    @pytest.mark.unit
    def test_vmem_writeval_hex_length(self, vmem_command, mock_cs):
        """Test vmem_writeval method with hex length."""
        vmem_command.virt_address = 0xA0000
        vmem_command.length = '0x8'
        vmem_command.value = 0x12345678

        # Mock VirtMemory
        vmem_command._vmem = Mock()

        with patch.object(vmem_command.logger, 'log') as mock_log:
            vmem_command.vmem_writeval()

            vmem_command._vmem.write_virtual_mem_dword.assert_called_once_with(0xA0000, 0x12345678)

    @pytest.mark.unit
    def test_vmem_writeval_invalid_length(self, vmem_command, mock_cs):
        """Test vmem_writeval method with invalid length."""
        vmem_command.virt_address = 0xA0000
        vmem_command.length = 'invalid'
        vmem_command.value = 0xABCD

        # Mock VirtMemory
        vmem_command._vmem = Mock()

        with patch.object(vmem_command.logger, 'log_error') as mock_log_error:
            vmem_command.vmem_writeval()

            mock_log_error.assert_called_with("Must specify <length> argument in 'mem writeval' as one of {}".format(vmem_command._vmem.CMD_OPTS_WIDTH))

    @pytest.mark.unit
    def test_vmem_writeval_error(self, vmem_command, mock_cs):
        """Test vmem_writeval method with error."""
        vmem_command.virt_address = 0xA0000
        vmem_command.length = 'dword'
        vmem_command.value = 0xABCD1234

        # Mock VirtMemory to raise error
        vmem_command._vmem = Mock()
        vmem_command._vmem.write_virtual_mem_dword.side_effect = OSError("Mapping failed")

        with patch.object(vmem_command.logger, 'log_error') as mock_log_error:
            vmem_command.vmem_writeval()

            mock_log_error.assert_called_with('Error mapping VA to PA.')

    @pytest.mark.unit
    def test_vmem_search_found(self, vmem_command, mock_cs):
        """Test vmem_search method when pattern is found."""
        vmem_command.virt_address = 0xF0000
        vmem_command.size = 0x10000
        vmem_command.value = '_SM_'

        # Mock VirtMemory
        vmem_command._vmem = Mock()
        test_buffer = b'\x00' * 1000 + b'_SM_' + b'\x00' * 1000
        vmem_command._vmem.read_virtual_mem.return_value = test_buffer

        with patch.object(vmem_command.logger, 'log') as mock_log:
            vmem_command.vmem_search()

            mock_cs.hals.virtmem.read_virtual_mem.assert_called_once_with(0xF0000, 0x10000)
            mock_log.assert_any_call('[CHIPSEC] Target address = 0xF03E8.')

    @pytest.mark.unit
    def test_vmem_search_not_found(self, vmem_command, mock_cs):
        """Test vmem_search method when pattern is not found."""
        vmem_command.virt_address = 0xF0000
        vmem_command.size = 0x10000
        vmem_command.value = '_SM_'

        # Mock VirtMemory
        vmem_command._vmem = Mock()
        test_buffer = b'\x00' * 0x10000  # No pattern
        vmem_command._vmem.read_virtual_mem.return_value = test_buffer

        with patch.object(vmem_command.logger, 'log') as mock_log:
            vmem_command.vmem_search()

            mock_log.assert_any_call('[CHIPSEC] Could not find the target in the searched range.')

    @pytest.mark.unit
    def test_vmem_search_error(self, vmem_command, mock_cs):
        """Test vmem_search method with error."""
        vmem_command.virt_address = 0xF0000
        vmem_command.size = 0x10000
        vmem_command.value = '_SM_'

        # Mock VirtMemory to raise error
        vmem_command._vmem = Mock()
        vmem_command._vmem.read_virtual_mem.side_effect = OSError("Mapping failed")

        with patch.object(vmem_command.logger, 'log_error') as mock_log_error:
            vmem_command.vmem_search()

            mock_log_error.assert_called_with('Error mapping VA to PA.')

    @pytest.mark.unit
    def test_vmem_allocate_success(self, vmem_command, mock_cs):
        """Test vmem_allocate method with success."""
        vmem_command.size = 0x1000

        # Mock VirtMemory
        vmem_command._vmem = Mock()
        vmem_command._vmem.alloc_virtual_mem.return_value = (0x100000, 0x200000)

        with patch.object(vmem_command.logger, 'log') as mock_log:
            vmem_command.vmem_allocate()

            vmem_command._vmem.alloc_virtual_mem.assert_called_once_with(0x1000)
            mock_log.assert_any_call('[CHIPSEC] Allocated 1000 bytes of virtual memory:')
            mock_log.assert_any_call('          VA = 0x0000000000100000')
            mock_log.assert_any_call('          PA = 0x0000000000200000')

    @pytest.mark.unit
    def test_vmem_allocate_error(self, vmem_command, mock_cs):
        """Test vmem_allocate method with error."""
        vmem_command.size = 0x1000

        # Mock VirtMemory to raise error
        vmem_command._vmem = Mock()
        vmem_command._vmem.alloc_virtual_mem.side_effect = OSError("Allocation failed")

        with patch.object(vmem_command.logger, 'log_error') as mock_log_error:
            vmem_command.vmem_allocate()

            mock_log_error.assert_called_with('Error mapping VA to PA.')

    @pytest.mark.unit
    def test_vmem_getphys_success(self, vmem_command, mock_cs):
        """Test vmem_getphys method with success."""
        vmem_command.virt_address = 0xFED00000

        # Mock VirtMemory
        vmem_command._vmem = Mock()
        vmem_command._vmem.va2pa.return_value = 0xFED00000

        with patch.object(vmem_command.logger, 'log') as mock_log:
            vmem_command.vmem_getphys()

            vmem_command._vmem.va2pa.assert_called_once_with(0xFED00000)
            mock_log.assert_any_call('[CHIPSEC] Virtual memory:')
            mock_log.assert_any_call('          VA = 0x00000000FED00000')
            mock_log.assert_any_call('          PA = 0x00000000FED00000')

    @pytest.mark.unit
    def test_vmem_getphys_none(self, vmem_command, mock_cs):
        """Test vmem_getphys method when PA is None."""
        vmem_command.virt_address = 0xFED00000

        # Mock VirtMemory
        vmem_command._vmem = Mock()
        vmem_command._vmem.va2pa.return_value = None

        with patch.object(vmem_command.logger, 'log') as mock_log:
            vmem_command.vmem_getphys()

            vmem_command._vmem.va2pa.assert_called_once_with(0xFED00000)
            # Should not log PA when it's None
            assert mock_log.call_count == 2  # Only VA and header

    @pytest.mark.unit
    def test_vmem_getphys_error(self, vmem_command, mock_cs):
        """Test vmem_getphys method with error."""
        vmem_command.virt_address = 0xFED00000

        # Mock VirtMemory to raise error
        vmem_command._vmem = Mock()
        vmem_command._vmem.va2pa.side_effect = OSError("Mapping failed")

        with patch.object(vmem_command.logger, 'log_error') as mock_log_error:
            vmem_command.vmem_getphys()

            mock_log_error.assert_called_with('Error mapping VA to PA.')

    @pytest.mark.unit
    def test_run_success(self, vmem_command, mock_cs):
        """Test run method with successful execution."""
        # Mock successful function execution
        vmem_command.func = Mock()

        vmem_command.run()

        # Should call the function and set exit code to OK
        vmem_command.func.assert_called_once()
        assert vmem_command.ExitCode.name == "OK"

    @pytest.mark.unit
    def test_run_exception(self, vmem_command, mock_cs):
        """Test run method with exception during execution."""
        # Mock function to raise exception
        vmem_command.func = Mock(side_effect=Exception("Test exception"))

        vmem_command.run()

        # Should call the function and set exit code to ERROR
        vmem_command.func.assert_called_once()
        assert vmem_command.ExitCode.name == "ERROR"


class TestVMemCommandIntegration:
    """Integration tests for VMem command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for VMem testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock VirtMemory components with realistic data
        cs_mock.hals = Mock()
        cs_mock.hals.virtmem = Mock()

        return cs_mock

    @pytest.mark.integration
    def test_vmem_read_write_workflow(self, integrated_cs):
        """Test complete read-write workflow."""
        # Test write operation
        write_cmd = VMemCommand(['write', '0x100000000', '0x10', '000102030405060708090A0B0C0D0E0F'], cs=integrated_cs)
        write_cmd.parse_arguments()
        write_cmd.set_up()

        with patch('chipsec.utilcmd.vmem_cmd.os.path.exists') as mock_exists:
            mock_exists.return_value = False
            write_cmd.run()

            # Verify write operation
            write_cmd._vmem.write_virtual_mem.assert_called_once()

        # Test read operation
        read_cmd = VMemCommand(['read', '0x100000000', '0x10'], cs=integrated_cs)
        read_cmd.parse_arguments()
        read_cmd.set_up()

        expected_buffer = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
        read_cmd._vmem.read_virtual_mem.return_value = expected_buffer

        with patch('chipsec.utilcmd.vmem_cmd.print_buffer_bytes') as mock_print:
            read_cmd.run()

            # Verify read operation
            read_cmd._vmem.read_virtual_mem.assert_called_once_with(0x100000000, 0x10)
            mock_print.assert_called_once_with(expected_buffer)

    @pytest.mark.integration
    def test_vmem_allocate_getphys_workflow(self, integrated_cs):
        """Test allocate and getphys workflow."""
        # Test allocate operation
        alloc_cmd = VMemCommand(['allocate', '0x1000'], cs=integrated_cs)
        alloc_cmd.parse_arguments()
        alloc_cmd.set_up()

        alloc_cmd._vmem.alloc_virtual_mem.return_value = (0x100000, 0x200000)

        with patch.object(alloc_cmd.logger, 'log'):
            alloc_cmd.run()

            alloc_cmd._vmem.alloc_virtual_mem.assert_called_once_with(0x1000)

        # Test getphys operation
        getphys_cmd = VMemCommand(['getphys', '0x100000'], cs=integrated_cs)
        getphys_cmd.parse_arguments()
        getphys_cmd.set_up()

        getphys_cmd._vmem.va2pa.return_value = 0x200000

        with patch.object(getphys_cmd.logger, 'log'):
            getphys_cmd.run()

            getphys_cmd._vmem.va2pa.assert_called_once_with(0x100000)


class TestVMemCommandEdgeCases:
    """Test edge cases and error conditions for VMem command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        cs_mock.hals.virtmem = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_vmem_read_default_size(self, mock_cs):
        """Test vmem_read with default size."""
        command = VMemCommand(['read', '0x1000'], cs=mock_cs)
        command.parse_arguments()
        command.set_up()

        command._vmem.read_virtual_mem.return_value = b'\x00' * 0x100

        with patch('chipsec.utilcmd.vmem_cmd.print_buffer_bytes'):
            command.run()

            command._vmem.read_virtual_mem.assert_called_once_with(0x1000, 0x100)

    @pytest.mark.unit
    def test_vmem_writeval_hex_parsing(self, mock_cs):
        """Test vmem_writeval with various hex formats."""
        test_cases = [
            ('0xAB', 0xAB),
            ('0xABCD', 0xABCD),
            ('0xABCD1234', 0xABCD1234),
            ('FF', 0xFF),
        ]

        for hex_str, expected_value in test_cases:
            command = VMemCommand(['writeval', '0x1000', 'byte', hex_str], cs=mock_cs)
            command.parse_arguments()
            assert command.value == expected_value

    @pytest.mark.unit
    def test_vmem_search_empty_pattern(self, mock_cs):
        """Test vmem_search with empty pattern."""
        command = VMemCommand(['search', '0x1000', '0x100', ''], cs=mock_cs)
        command.parse_arguments()
        command.set_up()

        command._vmem.read_virtual_mem.return_value = b'\x00' * 0x100

        with patch.object(command.logger, 'log'):
            command.run()

            # Empty pattern should be found at offset 0
            command._vmem.read_virtual_mem.assert_called_once_with(0x1000, 0x100)

    @pytest.mark.unit
    def test_vmem_readval_none_length(self, mock_cs):
        """Test vmem_readval with None length (should default to dword)."""
        command = VMemCommand(['readval', '0x1000'], cs=mock_cs)
        command.parse_arguments()
        command.set_up()

        command._vmem.read_virtual_mem_dword.return_value = 0x12345678

        with patch.object(command.logger, 'log'):
            command.run()

            command._vmem.read_virtual_mem_dword.assert_called_once_with(0x1000)

    @pytest.mark.unit
    def test_vmem_write_exact_size_match(self, mock_cs):
        """Test vmem_write with exact size match."""
        command = VMemCommand(['write', '0x1000', '0x4', 'test.bin'], cs=mock_cs)
        command.parse_arguments()
        command.set_up()

        test_data = b'\x01\x02\x03\x04'

        with patch('chipsec.utilcmd.vmem_cmd.os.path.exists') as mock_exists, \
             patch('chipsec.utilcmd.vmem_cmd.read_file') as mock_read:
            mock_exists.return_value = True
            mock_read.return_value = test_data

            command.run()

            command._vmem.write_virtual_mem.assert_called_once_with(0x1000, 0x4, test_data)

    @pytest.mark.unit
    def test_vmem_write_large_buffer(self, mock_cs):
        """Test vmem_write with large buffer."""
        command = VMemCommand(['write', '0x1000', '0x10000', 'large.bin'], cs=mock_cs)
        command.parse_arguments()
        command.set_up()

        large_data = b'\xAA' * 0x10000

        with patch('chipsec.utilcmd.vmem_cmd.os.path.exists') as mock_exists, \
             patch('chipsec.utilcmd.vmem_cmd.read_file') as mock_read:
            mock_exists.return_value = True
            mock_read.return_value = large_data

            command.run()

            command._vmem.write_virtual_mem.assert_called_once_with(0x1000, 0x10000, large_data)


class TestVMemCommandConfigurationValidation:
    """Test configuration validation aspects of VMem command."""

    @pytest.fixture
    def vmem_cs(self):
        """Create ChipsecCs with VMem-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock VMem configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.VMEM = {
            'VMEM_BASE': 0x100000,
            'VMEM_SIZE': 0x100000,
            'PAGE_SIZE': 0x1000
        }

        cs_mock.hals = Mock()
        cs_mock.hals.virtmem = Mock()

        return cs_mock

    @pytest.mark.unit
    def test_vmem_configuration_structure(self, vmem_cs):
        """Test VMem configuration structure."""
        vmem_config = vmem_cs.Cfg.VMEM

        # Test that required VMem configuration exists
        assert 'VMEM_BASE' in vmem_config
        assert 'VMEM_SIZE' in vmem_config

        # Test configuration values are reasonable
        assert vmem_config['VMEM_BASE'] > 0
        assert vmem_config['VMEM_SIZE'] > 0
        assert vmem_config['VMEM_SIZE'] >= vmem_config.get('PAGE_SIZE', 0x1000)

    @pytest.mark.unit
    def test_vmem_address_validation(self, vmem_cs):
        """Test VMem address validation."""
        command = VMemCommand(['read', '0x1000', '0x100'], cs=vmem_cs)
        command.parse_arguments()
        command.set_up()

        # Test that addresses are properly parsed as integers
        assert isinstance(command.virt_address, int)
        assert command.virt_address == 0x1000
        assert isinstance(command.size, int)
        assert command.size == 0x100

    @pytest.mark.unit
    def test_vmem_size_validation(self, vmem_cs):
        """Test VMem size validation."""
        # Test various size formats
        test_cases = [
            ('0x100', 0x100),
            ('0x1000', 0x1000),
            ('0x10000', 0x10000),
            ('4096', 0x1000),  # Decimal
        ]

        for size_str, expected_size in test_cases:
            command = VMemCommand(['read', '0x1000', size_str], cs=vmem_cs)
            command.parse_arguments()
            assert command.size == expected_size


if __name__ == '__main__':
    pytest.main([__file__])
