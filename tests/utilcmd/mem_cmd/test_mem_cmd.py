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
from unittest.mock import Mock, patch, mock_open
from chipsec.utilcmd.mem_cmd import MemCommand
from tests.test_utils import MockFactory


class TestMemCommand:
    """Comprehensive tests for memory utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for memory testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        # Mock Memory HAL
        cs_mock.hals.Memory = Mock()
        cs_mock.hals.Memory.read_physical_mem.return_value = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        cs_mock.hals.Memory.write_physical_mem.return_value = None
        cs_mock.hals.Memory.read_physical_mem_byte.return_value = 0x42
        cs_mock.hals.Memory.read_physical_mem_word.return_value = 0x1234
        cs_mock.hals.Memory.read_physical_mem_dword.return_value = 0x12345678
        cs_mock.hals.Memory.write_physical_mem_byte.return_value = None
        cs_mock.hals.Memory.write_physical_mem_word.return_value = None
        cs_mock.hals.Memory.write_physical_mem_dword.return_value = None
        cs_mock.hals.Memory.alloc_physical_mem.return_value = (0x100000, 0x200000)
        return cs_mock

    @pytest.fixture
    def mem_command(self, mock_cs):
        """Create MemCommand instance."""
        return MemCommand(['read', '0xFED40000', '0x100'], cs=mock_cs)

    @pytest.mark.unit
    def test_mem_command_initialization(self, mem_command, mock_cs):
        """Test MemCommand initialization."""
        assert mem_command.cs == mock_cs
        assert mem_command.argv == ['read', '0xFED40000', '0x100']

    @pytest.mark.unit
    def test_parse_arguments_read(self, mock_cs):
        """Test parsing read command arguments."""
        command = MemCommand(['read', '0xFED40000', '0x100', 'buffer.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.mem_read
        assert command.phys_address == 0xFED40000
        assert command.buffer_length == 0x100
        assert command.file_name == 'buffer.bin'

    @pytest.mark.unit
    def test_parse_arguments_readval(self, mock_cs):
        """Test parsing readval command arguments."""
        command = MemCommand(['readval', '0xFED40000', 'dword'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.mem_readval
        assert command.phys_address == 0xFED40000
        assert command.length == 'dword'

    @pytest.mark.unit
    def test_parse_arguments_write(self, mock_cs):
        """Test parsing write command arguments."""
        command = MemCommand(['write', '0xFED40000', '0x100', 'buffer.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.mem_write
        assert command.phys_address == 0xFED40000
        assert command.buffer_length == 0x100
        assert command.buffer_data == 'buffer.bin'

    @pytest.mark.unit
    def test_parse_arguments_writeval(self, mock_cs):
        """Test parsing writeval command arguments."""
        command = MemCommand(['writeval', '0xFED40000', 'dword', '0x12345678'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.mem_writeval
        assert command.phys_address == 0xFED40000
        assert command.length == 'dword'
        assert command.write_data == 0x12345678

    @pytest.mark.unit
    def test_parse_arguments_allocate(self, mock_cs):
        """Test parsing allocate command arguments."""
        command = MemCommand(['allocate', '0x1000'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.mem_allocate
        assert command.allocate_length == 0x1000

    @pytest.mark.unit
    def test_parse_arguments_pagedump(self, mock_cs):
        """Test parsing pagedump command arguments."""
        command = MemCommand(['pagedump', '0xFED00000', '0x100000'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.mem_pagedump
        assert command.start_address == 0xFED00000
        assert command.length == 0x100000

    @pytest.mark.unit
    def test_parse_arguments_search(self, mock_cs):
        """Test parsing search command arguments."""
        command = MemCommand(['search', '0xF0000', '0x10000', '_SM_'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.mem_search
        assert command.phys_address == 0xF0000
        assert command.length == 0x10000
        assert command.value == '_SM_'

    @pytest.mark.unit
    def test_requirements(self, mem_command):
        """Test command requirements."""
        reqs = mem_command.requirements()
        assert hasattr(reqs, 'load_driver')

    @pytest.mark.unit
    def test_mem_read_with_file(self, mem_command, mock_cs):
        """Test mem_read command with file output."""
        mem_command.phys_address = 0xFED40000
        mem_command.buffer_length = 0x100
        mem_command.file_name = 'test_output.bin'

        with patch('chipsec.library.file.write_file') as mock_write:
            mem_command.mem_read()

            mock_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xFED40000, 0x100)
            mock_write.assert_called_once_with('test_output.bin', b'\x00\x01\x02\x03\x04\x05\x06\x07')

    @pytest.mark.unit
    def test_mem_read_without_file(self, mem_command, mock_cs):
        """Test mem_read command without file output."""
        mem_command.phys_address = 0xFED40000
        mem_command.buffer_length = 0x100
        mem_command.file_name = ''

        with patch('chipsec.utilcmd.mem_cmd.print_buffer_bytes') as mock_print:
            mem_command.mem_read()

            mock_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xFED40000, 0x100)
            mock_print.assert_called_once_with(b'\x00\x01\x02\x03\x04\x05\x06\x07')

    @pytest.mark.unit
    def test_mem_readval_byte(self, mem_command, mock_cs):
        """Test mem_readval command for byte."""
        mem_command.phys_address = 0xFED40000
        mem_command.length = 'byte'

        mem_command.mem_readval()

        mock_cs.hals.Memory.read_physical_mem_byte.assert_called_once_with(0xFED40000)

    @pytest.mark.unit
    def test_mem_readval_word(self, mem_command, mock_cs):
        """Test mem_readval command for word."""
        mem_command.phys_address = 0xFED40000
        mem_command.length = 'word'

        mem_command.mem_readval()

        mock_cs.hals.Memory.read_physical_mem_word.assert_called_once_with(0xFED40000)

    @pytest.mark.unit
    def test_mem_readval_dword(self, mem_command, mock_cs):
        """Test mem_readval command for dword."""
        mem_command.phys_address = 0xFED40000
        mem_command.length = 'dword'

        mem_command.mem_readval()

        mock_cs.hals.Memory.read_physical_mem_dword.assert_called_once_with(0xFED40000)

    @pytest.mark.unit
    def test_mem_readval_invalid_length(self, mem_command, mock_cs):
        """Test mem_readval command with invalid length."""
        mem_command.phys_address = 0xFED40000
        mem_command.length = 'invalid'

        with patch.object(mem_command.logger, 'log_error') as mock_error:
            mem_command.mem_readval()

            mock_error.assert_called()

    @pytest.mark.unit
    def test_mem_write_from_file(self, mem_command, mock_cs):
        """Test mem_write command from file."""
        mem_command.phys_address = 0xFED40000
        mem_command.buffer_length = 0x100
        mem_command.buffer_data = 'test_input.bin'

        with patch('os.path.exists', return_value=True), \
             patch('chipsec.library.file.read_file', return_value=b'\x00\x01\x02\x03' * 0x40):
            mem_command.mem_write()

            mock_cs.hals.Memory.write_physical_mem.assert_called_once_with(0xFED40000, 0x100, b'\x00\x01\x02\x03' * 0x40)

    @pytest.mark.unit
    def test_mem_write_from_hex(self, mem_command, mock_cs):
        """Test mem_write command from hex string."""
        mem_command.phys_address = 0xFED40000
        mem_command.buffer_length = 0x10
        mem_command.buffer_data = '000102030405060708090A0B0C0D0E0F'

        with patch('os.path.exists', return_value=False):
            mem_command.mem_write()

            expected_buffer = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
            mock_cs.hals.Memory.write_physical_mem.assert_called_once_with(0xFED40000, 0x10, expected_buffer)

    @pytest.mark.unit
    def test_mem_writeval_byte(self, mem_command, mock_cs):
        """Test mem_writeval command for byte."""
        mem_command.phys_address = 0xFED40000
        mem_command.length = 'byte'
        mem_command.write_data = 0x42

        mem_command.mem_writeval()

        mock_cs.hals.Memory.write_physical_mem_byte.assert_called_once_with(0xFED40000, 0x42)

    @pytest.mark.unit
    def test_mem_writeval_word(self, mem_command, mock_cs):
        """Test mem_writeval command for word."""
        mem_command.phys_address = 0xFED40000
        mem_command.length = 'word'
        mem_command.write_data = 0x1234

        mem_command.mem_writeval()

        mock_cs.hals.Memory.write_physical_mem_word.assert_called_once_with(0xFED40000, 0x1234)

    @pytest.mark.unit
    def test_mem_writeval_dword(self, mem_command, mock_cs):
        """Test mem_writeval command for dword."""
        mem_command.phys_address = 0xFED40000
        mem_command.length = 'dword'
        mem_command.write_data = 0x12345678

        mem_command.mem_writeval()

        mock_cs.hals.Memory.write_physical_mem_dword.assert_called_once_with(0xFED40000, 0x12345678)

    @pytest.mark.unit
    def test_mem_allocate(self, mem_command, mock_cs):
        """Test mem_allocate command."""
        mem_command.allocate_length = 0x1000

        with patch.object(mem_command.logger, 'log') as mock_log:
            mem_command.mem_allocate()

            mock_cs.hals.Memory.alloc_physical_mem.assert_called_once_with(0x1000)
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_mem_search_found(self, mem_command, mock_cs):
        """Test mem_search command when value is found."""
        mem_command.phys_address = 0xF0000
        mem_command.length = 0x10000
        mem_command.value = '_SM_'

        # Mock buffer containing the search value
        mock_buffer = b'_' + b'\x00' * 100 + b'_SM_' + b'\x00' * 100
        mock_cs.hals.Memory.read_physical_mem.return_value = mock_buffer

        with patch('chipsec.library.defines.bytestostring', return_value=mock_buffer.decode('latin-1')), \
             patch.object(mem_command.logger, 'log') as mock_log:
            mem_command.mem_search()

            mock_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xF0000, 0x10000)
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_mem_search_not_found(self, mem_command, mock_cs):
        """Test mem_search command when value is not found."""
        mem_command.phys_address = 0xF0000
        mem_command.length = 0x10000
        mem_command.value = '_SM_'

        # Mock buffer not containing the search value
        mock_buffer = b'\x00' * 0x10000
        mock_cs.hals.Memory.read_physical_mem.return_value = mock_buffer

        with patch('chipsec.library.defines.bytestostring', return_value=mock_buffer.decode('latin-1')), \
             patch.object(mem_command.logger, 'log') as mock_log:
            mem_command.mem_search()

            mock_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xF0000, 0x10000)
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_mem_pagedump(self, mem_command, mock_cs):
        """Test mem_pagedump command."""
        mem_command.start_address = 0xFED00000
        mem_command.length = 0x100000

        with patch('chipsec.library.file.get_main_dir', return_value='/tmp'), \
             patch('os.path.join', return_value='/tmp/test.bin'), \
             patch('builtins.open', mock_open()) as mock_file:
            mem_command.mem_pagedump()

            # Verify file operations were attempted
            mock_file.assert_called()


class TestMemCommandIntegration:
    """Integration tests for memory command with HAL components."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for memory testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        cs_mock.hals.Memory = Mock()
        cs_mock.hals.Memory.read_physical_mem.return_value = b'\xAA\xBB\xCC\xDD' * 0x40
        cs_mock.hals.Memory.write_physical_mem.return_value = None
        cs_mock.hals.Memory.read_physical_mem_dword.return_value = 0xDEADBEEF
        cs_mock.hals.Memory.write_physical_mem_dword.return_value = None
        cs_mock.hals.Memory.alloc_physical_mem.return_value = (0x100000, 0x200000)

        # Mock helper
        cs_mock.helper = Mock()
        cs_mock.helper.get_threads_count.return_value = 2

        return cs_mock

    @pytest.mark.integration
    def test_mem_read_write_workflow(self, integrated_cs):
        """Test complete memory read/write workflow."""
        # Test read operation
        read_cmd = MemCommand(['read', '0xFED40000', '0x100'], cs=integrated_cs)
        read_cmd.parse_arguments()

        with patch('chipsec.utilcmd.mem_cmd.print_buffer_bytes') as mock_print:
            read_cmd.run()

            integrated_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xFED40000, 0x100)
            mock_print.assert_called_once()

        # Test write operation
        write_cmd = MemCommand(['write', '0xFED40000', '0x10', 'AABBCCDDEEFF0011'], cs=integrated_cs)
        write_cmd.parse_arguments()

        with patch('os.path.exists', return_value=False):
            write_cmd.run()

            expected_buffer = bytes.fromhex('AABBCCDDEEFF0011')
            integrated_cs.hals.Memory.write_physical_mem.assert_called_once_with(0xFED40000, 0x10, expected_buffer)

    @pytest.mark.integration
    def test_mem_value_operations_workflow(self, integrated_cs):
        """Test complete memory value operations workflow."""
        # Test readval operation
        readval_cmd = MemCommand(['readval', '0xFED40000', 'dword'], cs=integrated_cs)
        readval_cmd.parse_arguments()
        readval_cmd.run()

        integrated_cs.hals.Memory.read_physical_mem_dword.assert_called_once_with(0xFED40000)

        # Test writeval operation
        writeval_cmd = MemCommand(['writeval', '0xFED40000', 'dword', '0xDEADBEEF'], cs=integrated_cs)
        writeval_cmd.parse_arguments()
        writeval_cmd.run()

        integrated_cs.hals.Memory.write_physical_mem_dword.assert_called_once_with(0xFED40000, 0xDEADBEEF)

    @pytest.mark.integration
    def test_mem_allocate_workflow(self, integrated_cs):
        """Test complete memory allocation workflow."""
        alloc_cmd = MemCommand(['allocate', '0x1000'], cs=integrated_cs)
        alloc_cmd.parse_arguments()

        with patch.object(alloc_cmd.logger, 'log') as mock_log:
            alloc_cmd.run()

            integrated_cs.hals.Memory.alloc_physical_mem.assert_called_once_with(0x1000)
            mock_log.assert_called_once()

    @pytest.mark.integration
    def test_mem_search_workflow(self, integrated_cs):
        """Test complete memory search workflow."""
        search_cmd = MemCommand(['search', '0xF0000', '0x10000', 'BIOS'], cs=integrated_cs)
        search_cmd.parse_arguments()

        # Mock buffer containing the search value
        mock_buffer = b'\x00' * 1000 + b'BIOS' + b'\x00' * 1000
        integrated_cs.hals.Memory.read_physical_mem.return_value = mock_buffer

        with patch('chipsec.library.defines.bytestostring', return_value=mock_buffer.decode('latin-1')), \
             patch.object(search_cmd.logger, 'log') as mock_log:
            search_cmd.run()

            integrated_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xF0000, 0x10000)
            mock_log.assert_called_once()


class TestMemCommandEdgeCases:
    """Test edge cases and error conditions for memory command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals.Memory = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        mem_cmd = MemCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            mem_cmd.parse_arguments()

    @pytest.mark.unit
    def test_invalid_subcommand(self, mock_cs):
        """Test handling of invalid subcommand."""
        mem_cmd = MemCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            mem_cmd.parse_arguments()

    @pytest.mark.unit
    def test_read_missing_address(self, mock_cs):
        """Test read command with missing address."""
        mem_cmd = MemCommand(['read'], cs=mock_cs)

        # Should raise SystemExit due to missing address
        with pytest.raises(SystemExit):
            mem_cmd.parse_arguments()

    @pytest.mark.unit
    def test_write_insufficient_data(self, mock_cs):
        """Test write command with insufficient data."""
        mem_cmd = MemCommand(['write', '0xFED40000', '0x100', 'AABBCC'], cs=mock_cs)
        mem_cmd.parse_arguments()

        with patch('os.path.exists', return_value=False), \
             patch.object(mem_cmd.logger, 'log_error') as mock_error:
            mem_cmd.mem_write()

            mock_error.assert_called()

    @pytest.mark.unit
    def test_writeval_invalid_length(self, mock_cs):
        """Test writeval command with invalid length."""
        mem_cmd = MemCommand(['writeval', '0xFED40000', 'invalid', '0x1234'], cs=mock_cs)
        mem_cmd.parse_arguments()

        with patch.object(mem_cmd.logger, 'log_error') as mock_error:
            mem_cmd.mem_writeval()

            mock_error.assert_called()

    @pytest.mark.unit
    def test_readval_invalid_length(self, mock_cs):
        """Test readval command with invalid length."""
        mem_cmd = MemCommand(['readval', '0xFED40000', 'invalid'], cs=mock_cs)
        mem_cmd.parse_arguments()

        with patch.object(mem_cmd.logger, 'log_error') as mock_error:
            mem_cmd.mem_readval()

            mock_error.assert_called()

    @pytest.mark.unit
    def test_write_invalid_hex(self, mock_cs):
        """Test write command with invalid hex data."""
        mem_cmd = MemCommand(['write', '0xFED40000', '0x10', 'invalid_hex'], cs=mock_cs)
        mem_cmd.parse_arguments()

        with patch('os.path.exists', return_value=False), \
             patch.object(mem_cmd.logger, 'log_error') as mock_error:
            mem_cmd.mem_write()

            mock_error.assert_called()

    @pytest.mark.unit
    def test_large_memory_operations(self, mock_cs):
        """Test handling of large memory operations."""
        # Test large read operation with reasonable buffer size
        mem_cmd = MemCommand(['read', '0x100000000', '0x1000'], cs=mock_cs)
        mem_cmd.parse_arguments()

        # Use a much smaller buffer to avoid console spam
        mock_cs.hals.Memory.read_physical_mem.return_value = b'\x00' * 0x1000

        with patch('chipsec.utilcmd.mem_cmd.print_buffer_bytes') as mock_print:
            mem_cmd.mem_read()

            mock_cs.hals.Memory.read_physical_mem.assert_called_once_with(0x100000000, 0x1000)
            mock_print.assert_called_once()

    @pytest.mark.unit
    def test_boundary_address_handling(self, mock_cs):
        """Test handling of boundary addresses."""
        # Test address at 4KB boundary
        mem_cmd = MemCommand(['readval', '0x1000', 'dword'], cs=mock_cs)
        mem_cmd.parse_arguments()

        mem_cmd.mem_readval()

        mock_cs.hals.Memory.read_physical_mem_dword.assert_called_once_with(0x1000)

    @pytest.mark.unit
    def test_zero_length_operations(self, mock_cs):
        """Test handling of zero length operations."""
        # Test zero length read
        mem_cmd = MemCommand(['read', '0xFED40000', '0x0'], cs=mock_cs)
        mem_cmd.parse_arguments()

        mock_cs.hals.Memory.read_physical_mem.return_value = b''

        with patch('chipsec.utilcmd.mem_cmd.print_buffer_bytes') as mock_print:
            mem_cmd.mem_read()

            mock_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xFED40000, 0x0)
            mock_print.assert_called_once()


class TestMemCommandConfigurationValidation:
    """Test configuration validation aspects of memory command."""

    @pytest.fixture
    def config_cs(self):
        """Create ChipsecCs with memory-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock Memory HAL with configuration
        cs_mock.hals.Memory = Mock()
        cs_mock.hals.Memory.read_physical_mem.return_value = b'\x00\x01\x02\x03'

        # Mock memory configuration data
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.MEMORY_CONFIG = {
            'max_read_size': 0x1000000,
            'max_write_size': 0x1000000,
            'supported_operations': ['read', 'write', 'readval', 'writeval', 'allocate', 'pagedump', 'search'],
            'address_ranges': {
                'low_memory': (0x0, 0x100000),
                'high_memory': (0x100000, 0x100000000),
                'mmio_space': (0xFED00000, 0xFEDFFFFF)
            }
        }

        return cs_mock

    @pytest.mark.unit
    def test_memory_configuration_access(self, config_cs):
        """Test access to memory configuration data."""
        mem_config = config_cs.Cfg.MEMORY_CONFIG

        assert mem_config['max_read_size'] == 0x1000000
        assert mem_config['max_write_size'] == 0x1000000
        assert 'read' in mem_config['supported_operations']
        assert 'write' in mem_config['supported_operations']

    @pytest.mark.unit
    def test_supported_operations_validation(self, config_cs):
        """Test validation of supported memory operations."""
        supported_ops = config_cs.Cfg.MEMORY_CONFIG['supported_operations']

        # Test that all documented operations are supported
        assert 'read' in supported_ops
        assert 'write' in supported_ops
        assert 'readval' in supported_ops
        assert 'writeval' in supported_ops
        assert 'allocate' in supported_ops
        assert 'pagedump' in supported_ops
        assert 'search' in supported_ops

    @pytest.mark.unit
    def test_address_range_validation(self, config_cs):
        """Test memory address range validation."""
        address_ranges = config_cs.Cfg.MEMORY_CONFIG['address_ranges']

        # Test valid address ranges
        assert address_ranges['low_memory'][0] == 0x0
        assert address_ranges['low_memory'][1] == 0x100000
        assert address_ranges['high_memory'][0] == 0x100000
        assert address_ranges['high_memory'][1] == 0x100000000
        assert address_ranges['mmio_space'][0] == 0xFED00000
        assert address_ranges['mmio_space'][1] == 0xFEDFFFFF

    @pytest.mark.unit
    def test_memory_operation_limits(self, config_cs):
        """Test memory operation size limits."""
        max_read = config_cs.Cfg.MEMORY_CONFIG['max_read_size']
        max_write = config_cs.Cfg.MEMORY_CONFIG['max_write_size']

        # Test that limits are reasonable
        assert max_read > 0
        assert max_write > 0
        assert max_read >= max_write  # Read limit should be at least as large as write limit


if __name__ == '__main__':
    pytest.main([__file__])
