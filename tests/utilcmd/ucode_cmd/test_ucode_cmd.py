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
from chipsec.utilcmd.ucode_cmd import UCodeCommand
from tests.test_utils import MockFactory


class TestUCodeCommand:
    """Comprehensive tests for UCode utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for UCode testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock UCode HAL component
        cs_mock.hals = Mock()
        cs_mock.hals.Ucode = Mock()
        cs_mock.hals.Msr = Mock()

        # Mock UCode component
        cs_mock.ucode = Mock()

        return cs_mock

    @pytest.fixture
    def ucode_command(self, mock_cs):
        """Create UCodeCommand instance."""
        return UCodeCommand(['id'], cs=mock_cs)

    @pytest.mark.unit
    def test_ucode_command_initialization(self, ucode_command, mock_cs):
        """Test UCodeCommand initialization."""
        assert ucode_command.cs == mock_cs
        assert ucode_command.argv == ['id']

    @pytest.mark.unit
    def test_requirements(self, ucode_command):
        """Test command requirements."""
        reqs = ucode_command.requirements()
        assert reqs == ucode_command.toLoad.Driver

    @pytest.mark.unit
    def test_parse_arguments_id(self, mock_cs):
        """Test parsing id command."""
        command = UCodeCommand(['id'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.ucode_id
        assert command.cpu_thread_id is None

    @pytest.mark.unit
    def test_parse_arguments_id_with_cpu(self, mock_cs):
        """Test parsing id command with CPU ID."""
        command = UCodeCommand(['id', '0x1'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.ucode_id
        assert command.cpu_thread_id == 0x1

    @pytest.mark.unit
    def test_parse_arguments_load(self, mock_cs):
        """Test parsing load command."""
        command = UCodeCommand(['load', 'ucode.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.ucode_load
        assert command.ucode_filename == 'ucode.bin'
        assert command.cpu_thread_id is None

    @pytest.mark.unit
    def test_parse_arguments_load_with_cpu(self, mock_cs):
        """Test parsing load command with CPU ID."""
        command = UCodeCommand(['load', 'ucode.bin', '0x0'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.ucode_load
        assert command.ucode_filename == 'ucode.bin'
        assert command.cpu_thread_id == 0x0

    @pytest.mark.unit
    def test_parse_arguments_decode(self, mock_cs):
        """Test parsing decode command."""
        command = UCodeCommand(['decode', 'ucode.pdb'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.ucode_decode
        assert command.ucode_filename == 'ucode.pdb'

    @pytest.mark.unit
    def test_parse_arguments_invalid(self, mock_cs):
        """Test parsing invalid command."""
        command = UCodeCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_ucode_id_all_cpus(self, ucode_command, mock_cs):
        """Test ucode_id method for all CPUs."""
        ucode_command.cpu_thread_id = None
        ucode_command._cs.hals.Msr.get_cpu_thread_count.return_value = 4

        # Mock ucode_update_id to return different values for each CPU
        ucode_command._cs.ucode.ucode_update_id.side_effect = [0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222]

        with patch.object(ucode_command.logger, 'log') as mock_log:
            ucode_command.ucode_id()

            # Should call for all CPUs
            assert ucode_command._cs.ucode.ucode_update_id.call_count == 4
            mock_log.assert_any_call('[CHIPSEC] CPU0: Microcode update ID = 0x12345678')
            mock_log.assert_any_call('[CHIPSEC] CPU1: Microcode update ID = 0x9ABCDEF0')
            mock_log.assert_any_call('[CHIPSEC] CPU2: Microcode update ID = 0x11111111')
            mock_log.assert_any_call('[CHIPSEC] CPU3: Microcode update ID = 0x22222222')

    @pytest.mark.unit
    def test_ucode_id_specific_cpu(self, ucode_command, mock_cs):
        """Test ucode_id method for specific CPU."""
        ucode_command.cpu_thread_id = 0x2
        ucode_command._cs.ucode.ucode_update_id.return_value = 0xAAAAAAAA

        with patch.object(ucode_command.logger, 'log') as mock_log:
            ucode_command.ucode_id()

            ucode_command._cs.ucode.ucode_update_id.assert_called_once_with(0x2)
            mock_log.assert_called_with('[CHIPSEC] CPU2: Microcode update ID = 0xAAAAAAAA')

    @pytest.mark.unit
    def test_ucode_load_all_cpus(self, ucode_command, mock_cs):
        """Test ucode_load method for all CPUs."""
        ucode_command.cpu_thread_id = None
        ucode_command.ucode_filename = 'ucode.bin'

        with patch.object(ucode_command.logger, 'log') as mock_log:
            ucode_command.ucode_load()

            ucode_command._cs.ucode.update_ucode_all_cpus.assert_called_once_with('ucode.bin')
            mock_log.assert_called_with("[CHIPSEC] Loading Microcode update on all cores from 'ucode.bin'")

    @pytest.mark.unit
    def test_ucode_load_specific_cpu(self, ucode_command, mock_cs):
        """Test ucode_load method for specific CPU."""
        ucode_command.cpu_thread_id = 0x1
        ucode_command.ucode_filename = 'ucode.pdb'

        with patch.object(ucode_command.logger, 'log') as mock_log:
            ucode_command.ucode_load()

            ucode_command._cs.ucode.update_ucode.assert_called_once_with(0x1, 'ucode.pdb')
            mock_log.assert_called_with("[CHIPSEC] Loading Microcode update on CPU1 from 'ucode.pdb'")

    @pytest.mark.unit
    def test_ucode_decode(self, ucode_command, mock_cs):
        """Test ucode_decode method."""
        ucode_command.ucode_filename = 'ucode.pdb'
        test_buffer = b'\x00\x01\x02\x03\x04\x05\x06\x07'

        ucode_command._cs.hals.Ucode.read_ucode_file.return_value = test_buffer

        with patch.object(ucode_command.logger, 'log') as mock_log:
            ucode_command.ucode_decode()

            ucode_command._cs.hals.Ucode.read_ucode_file.assert_called_once_with('ucode.pdb')
            ucode_command._cs.hals.Ucode.dump_ucode_update_header.assert_called_once_with(test_buffer)
            mock_log.assert_called_with("[CHIPSEC] Decoding Microcode Update header file: 'ucode.pdb'")

    @pytest.mark.unit
    def test_run(self, ucode_command, mock_cs):
        """Test run method."""
        ucode_command.func = Mock()

        ucode_command.run()

        ucode_command.func.assert_called_once()


class TestUCodeCommandIntegration:
    """Integration tests for UCode command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for UCode testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock UCode components with realistic data
        cs_mock.hals = Mock()
        cs_mock.hals.Ucode = Mock()
        cs_mock.hals.Msr = Mock()
        cs_mock.ucode = Mock()

        return cs_mock

    @pytest.mark.integration
    def test_ucode_id_integration(self, integrated_cs):
        """Test complete ucode_id workflow."""
        ucode_cmd = UCodeCommand(['id', '0x0'], cs=integrated_cs)

        ucode_cmd._cs.ucode.ucode_update_id.return_value = 0x12345678

        with patch.object(ucode_cmd.logger, 'log'):
            ucode_cmd.run()

            ucode_cmd._cs.ucode.ucode_update_id.assert_called_once_with(0x0)

    @pytest.mark.integration
    def test_ucode_load_integration(self, integrated_cs):
        """Test complete ucode_load workflow."""
        ucode_cmd = UCodeCommand(['load', 'ucode.bin', '0x1'], cs=integrated_cs)

        with patch.object(ucode_cmd.logger, 'log'):
            ucode_cmd.run()

            ucode_cmd._cs.ucode.update_ucode.assert_called_once_with(0x1, 'ucode.bin')

    @pytest.mark.integration
    def test_ucode_decode_integration(self, integrated_cs):
        """Test complete ucode_decode workflow."""
        ucode_cmd = UCodeCommand(['decode', 'ucode.pdb'], cs=integrated_cs)

        test_buffer = b'\x00\x01\x02\x03'
        ucode_cmd._cs.hals.Ucode.read_ucode_file.return_value = test_buffer

        with patch.object(ucode_cmd.logger, 'log'):
            ucode_cmd.run()

            ucode_cmd._cs.hals.Ucode.read_ucode_file.assert_called_once_with('ucode.pdb')
            ucode_cmd._cs.hals.Ucode.dump_ucode_update_header.assert_called_once_with(test_buffer)


class TestUCodeCommandEdgeCases:
    """Test edge cases and error conditions for UCode command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        cs_mock.hals.Ucode = Mock()
        cs_mock.hals.Msr = Mock()
        cs_mock.ucode = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        command = UCodeCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_ucode_id_multiple_cpus(self, mock_cs):
        """Test ucode_id with multiple CPUs."""
        command = UCodeCommand(['id'], cs=mock_cs)
        command.cpu_thread_id = None

        command._cs.hals.Msr.get_cpu_thread_count.return_value = 8
        command._cs.ucode.ucode_update_id.side_effect = [0x11111111 + i for i in range(8)]

        with patch.object(command.logger, 'log') as mock_log:
            command.ucode_id()

            # Should call for all 8 CPUs
            assert command._cs.ucode.ucode_update_id.call_count == 8
            for i in range(8):
                mock_log.assert_any_call(f'[CHIPSEC] CPU{i}: Microcode update ID = 0x{0x11111111 + i:08X}')

    @pytest.mark.unit
    def test_ucode_id_cpu_zero(self, mock_cs):
        """Test ucode_id with CPU 0."""
        command = UCodeCommand(['id', '0x0'], cs=mock_cs)
        command.cpu_thread_id = 0x0

        command._cs.ucode.ucode_update_id.return_value = 0x00000000

        with patch.object(command.logger, 'log') as mock_log:
            command.ucode_id()

            command._cs.ucode.ucode_update_id.assert_called_once_with(0x0)
            mock_log.assert_called_with('[CHIPSEC] CPU0: Microcode update ID = 0x00000000')

    @pytest.mark.unit
    def test_ucode_load_different_file_formats(self, mock_cs):
        """Test ucode_load with different file formats."""
        test_files = ['ucode.bin', 'ucode.pdb', 'microcode.dat']

        for filename in test_files:
            command = UCodeCommand(['load', filename], cs=mock_cs)
            command.cpu_thread_id = None

            with patch.object(command.logger, 'log'):
                command.ucode_load()

                command._cs.ucode.update_ucode_all_cpus.assert_called_with(filename)

    @pytest.mark.unit
    def test_ucode_decode_different_files(self, mock_cs):
        """Test ucode_decode with different files."""
        test_files = ['ucode.pdb', 'microcode.bin', 'update.dat']

        for filename in test_files:
            command = UCodeCommand(['decode', filename], cs=mock_cs)
            test_buffer = b'\xAA\xBB\xCC\xDD'

            command._cs.hals.Ucode.read_ucode_file.return_value = test_buffer

            with patch.object(command.logger, 'log'):
                command.ucode_decode()

                command._cs.hals.Ucode.read_ucode_file.assert_called_with(filename)
                command._cs.hals.Ucode.dump_ucode_update_header.assert_called_with(test_buffer)

    @pytest.mark.unit
    def test_hex_parsing_various_formats(self, mock_cs):
        """Test hex parsing with various formats."""
        test_cases = [
            ('0x0', 0x0),
            ('0x1', 0x1),
            ('0xF', 0xF),
            ('0x10', 0x10),
            ('0xFF', 0xFF),
            ('0', 0x0),
            ('1', 0x1),
            ('F', 0xF)
        ]

        for hex_str, expected_value in test_cases:
            command = UCodeCommand(['id', hex_str], cs=mock_cs)
            command.parse_arguments()
            assert command.cpu_thread_id == expected_value

    @pytest.mark.unit
    def test_ucode_load_all_cpus_vs_specific(self, mock_cs):
        """Test ucode_load behavior for all CPUs vs specific CPU."""
        # Test all CPUs
        command_all = UCodeCommand(['load', 'ucode.bin'], cs=mock_cs)
        command_all.cpu_thread_id = None

        with patch.object(command_all.logger, 'log'):
            command_all.ucode_load()

            command_all._cs.ucode.update_ucode_all_cpus.assert_called_with('ucode.bin')
            command_all._cs.ucode.update_ucode.assert_not_called()

        # Test specific CPU
        command_specific = UCodeCommand(['load', 'ucode.bin', '0x2'], cs=mock_cs)
        command_specific.cpu_thread_id = 0x2

        with patch.object(command_specific.logger, 'log'):
            command_specific.ucode_load()

            command_specific._cs.ucode.update_ucode.assert_called_with(0x2, 'ucode.bin')
            command_specific._cs.ucode.update_ucode_all_cpus.assert_not_called()

    @pytest.mark.unit
    def test_ucode_id_error_handling(self, mock_cs):
        """Test ucode_id error handling."""
        command = UCodeCommand(['id', '0x0'], cs=mock_cs)
        command.cpu_thread_id = 0x0

        # Mock ucode_update_id to raise exception
        command._cs.ucode.ucode_update_id.side_effect = Exception("UCode access failed")

        # Should handle the exception gracefully
        with pytest.raises(Exception):
            command.ucode_id()

    @pytest.mark.unit
    def test_ucode_load_error_handling(self, mock_cs):
        """Test ucode_load error handling."""
        command = UCodeCommand(['load', 'ucode.bin', '0x0'], cs=mock_cs)
        command.cpu_thread_id = 0x0

        # Mock update_ucode to raise exception
        command._cs.ucode.update_ucode.side_effect = Exception("UCode load failed")

        # Should handle the exception gracefully
        with pytest.raises(Exception):
            command.ucode_load()

    @pytest.mark.unit
    def test_ucode_decode_error_handling(self, mock_cs):
        """Test ucode_decode error handling."""
        command = UCodeCommand(['decode', 'ucode.pdb'], cs=mock_cs)

        # Mock read_ucode_file to raise exception
        command._cs.hals.Ucode.read_ucode_file.side_effect = Exception("File read failed")

        # Should handle the exception gracefully
        with pytest.raises(Exception):
            command.ucode_decode()


class TestUCodeCommandConfigurationValidation:
    """Test configuration validation aspects of UCode command."""

    @pytest.fixture
    def ucode_cs(self):
        """Create ChipsecCs with UCode-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock UCode configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.UCODE = {
            'DEFAULT_CPU_ID': 0x0,
            'SUPPORTED_FORMATS': ['.pdb', '.bin'],
            'MAX_CPU_THREADS': 64
        }

        cs_mock.hals = Mock()
        cs_mock.hals.Ucode = Mock()
        cs_mock.hals.Msr = Mock()
        cs_mock.ucode = Mock()

        return cs_mock

    @pytest.mark.unit
    def test_ucode_configuration_structure(self, ucode_cs):
        """Test UCode configuration structure."""
        ucode_config = ucode_cs.Cfg.UCODE

        # Test that required UCode configuration exists
        assert 'DEFAULT_CPU_ID' in ucode_config
        assert 'SUPPORTED_FORMATS' in ucode_config

        # Test configuration values are reasonable
        assert ucode_config['DEFAULT_CPU_ID'] >= 0
        assert isinstance(ucode_config['SUPPORTED_FORMATS'], list)

    @pytest.mark.unit
    def test_ucode_cpu_id_validation(self, ucode_cs):
        """Test UCode CPU ID validation."""
        # Test various CPU IDs
        test_cases = [
            ('0x0', 0x0),
            ('0x1', 0x1),
            ('0xF', 0xF),
            ('0x10', 0x10),
            ('0x3F', 0x3F)
        ]

        for cpu_str, expected_cpu in test_cases:
            command = UCodeCommand(['id', cpu_str], cs=ucode_cs)
            command.parse_arguments()

            assert command.cpu_thread_id == expected_cpu

    @pytest.mark.unit
    def test_ucode_filename_validation(self, ucode_cs):
        """Test UCode filename validation."""
        # Test various filename formats
        test_files = [
            'ucode.bin',
            'ucode.pdb',
            'microcode_update.bin',
            '/path/to/ucode.pdb',
            'C:\\path\\to\\ucode.bin'
        ]

        for filename in test_files:
            command = UCodeCommand(['load', filename], cs=ucode_cs)
            command.parse_arguments()

            assert command.ucode_filename == filename

    @pytest.mark.unit
    def test_ucode_file_format_support(self, ucode_cs):
        """Test UCode file format support."""
        supported_formats = ['.pdb', '.bin']

        for ext in supported_formats:
            filename = f'ucode{ext}'
            command = UCodeCommand(['decode', filename], cs=ucode_cs)
            command.parse_arguments()

            assert command.ucode_filename == filename

    @pytest.mark.unit
    def test_ucode_cpu_thread_count_handling(self, ucode_cs):
        """Test UCode CPU thread count handling."""
        command = UCodeCommand(['id'], cs=ucode_cs)
        command.cpu_thread_id = None

        # Test with different CPU thread counts
        test_counts = [1, 4, 8, 16, 32]

        for count in test_counts:
            command._cs.hals.Msr.get_cpu_thread_count.return_value = count
            command._cs.ucode.ucode_update_id.side_effect = [0x11111111 + i for i in range(count)]

            with patch.object(command.logger, 'log'):
                command.ucode_id()

                # Should call ucode_update_id for each CPU thread
                assert command._cs.ucode.ucode_update_id.call_count == count

    @pytest.mark.unit
    def test_ucode_error_recovery(self, ucode_cs):
        """Test UCode error recovery."""
        command = UCodeCommand(['id'], cs=ucode_cs)
        command.cpu_thread_id = None

        command._cs.hals.Msr.get_cpu_thread_count.return_value = 4
        # Simulate error on one CPU but success on others
        command._cs.ucode.ucode_update_id.side_effect = [0x11111111, Exception("CPU 1 failed"), 0x33333333, 0x44444444]

        with patch.object(command.logger, 'log'):
            # Should handle the exception and continue with other CPUs
            with pytest.raises(Exception):
                command.ucode_id()

    @pytest.mark.unit
    def test_ucode_boundary_cpu_ids(self, ucode_cs):
        """Test UCode boundary CPU IDs."""
        # Test minimum and maximum CPU IDs
        boundary_cases = [
            ('0x0', 0x0),      # Minimum
            ('0x3F', 0x3F),    # Maximum typical
            ('0xFF', 0xFF),    # Extended maximum
        ]

        for cpu_str, expected_cpu in boundary_cases:
            command = UCodeCommand(['id', cpu_str], cs=ucode_cs)
            command.parse_arguments()

            assert command.cpu_thread_id == expected_cpu

    @pytest.mark.unit
    def test_ucode_microcode_id_formats(self, ucode_cs):
        """Test UCode microcode ID format handling."""
        command = UCodeCommand(['id', '0x0'], cs=ucode_cs)
        command.cpu_thread_id = 0x0

        # Test various microcode ID formats
        test_ids = [
            0x00000000,  # Zero
            0x12345678,  # Normal
            0xFFFFFFFF,  # Maximum
            0xAAAAAAAA,  # Pattern
        ]

        for ucode_id in test_ids:
            command._cs.ucode.ucode_update_id.return_value = ucode_id

            with patch.object(command.logger, 'log') as mock_log:
                command.ucode_id()

                mock_log.assert_called_with(f'[CHIPSEC] CPU0: Microcode update ID = 0x{ucode_id:08X}')


if __name__ == '__main__':
    pytest.main([__file__])
