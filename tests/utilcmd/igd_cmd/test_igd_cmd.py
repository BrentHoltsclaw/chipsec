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
from chipsec.utilcmd.igd_cmd import IgdCommand
from tests.test_utils import MockFactory


class TestIgdCommand:
    """Comprehensive tests for IGD utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for IGD testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock IGD HAL component
        cs_mock.hals = Mock()
        cs_mock.hals.IGD = Mock()

        return cs_mock

    @pytest.fixture
    def igd_command(self, mock_cs):
        """Create IgdCommand instance."""
        return IgdCommand(['dmaread', '0x20000000', '0x4'], cs=mock_cs)

    @pytest.mark.unit
    def test_igd_command_initialization(self, igd_command, mock_cs):
        """Test IgdCommand initialization."""
        assert igd_command.cs == mock_cs
        assert igd_command.argv == ['dmaread', '0x20000000', '0x4']

    @pytest.mark.unit
    def test_requirements(self, igd_command):
        """Test command requirements."""
        reqs = igd_command.requirements()
        assert reqs == igd_command.toLoad.All

    @pytest.mark.unit
    def test_parse_arguments_dmaread(self, mock_cs):
        """Test parsing dmaread command."""
        command = IgdCommand(['dmaread', '0x20000000', '0x4', 'output.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.read_dma
        assert command.address == 0x20000000
        assert command.width == 0x4
        assert command.file_name == 'output.bin'

    @pytest.mark.unit
    def test_parse_arguments_dmaread_defaults(self, mock_cs):
        """Test parsing dmaread command with defaults."""
        command = IgdCommand(['dmaread', '0x20000000'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.read_dma
        assert command.address == 0x20000000
        assert command.width == 0x100
        assert command.file_name == ''

    @pytest.mark.unit
    def test_parse_arguments_dmawrite_hex(self, mock_cs):
        """Test parsing dmawrite command with hex value."""
        command = IgdCommand(['dmawrite', '0x2217F1000', '0x4', 'deadbeef'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.write_dma
        assert command.address == 0x2217F1000
        assert command.size == 0x4
        assert command.file_value == 'deadbeef'

    @pytest.mark.unit
    def test_parse_arguments_dmawrite_file(self, mock_cs):
        """Test parsing dmawrite command with file."""
        command = IgdCommand(['dmawrite', '0x2217F1000', '0x4', 'input.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.write_dma
        assert command.address == 0x2217F1000
        assert command.size == 0x4
        assert command.file_value == 'input.bin'

    @pytest.mark.unit
    def test_parse_arguments_info(self, mock_cs):
        """Test parsing info command."""
        command = IgdCommand(['info'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.print_igd_pci_info

    @pytest.mark.unit
    def test_parse_arguments_invalid(self, mock_cs):
        """Test parsing invalid command."""
        command = IgdCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_read_dma_to_file(self, igd_command, mock_cs):
        """Test read_dma method with file output."""
        igd_command.address = 0x20000000
        igd_command.width = 0x4
        igd_command.file_name = 'output.bin'

        test_buffer = b'\xDE\xAD\xBE\xEF'
        igd_command._cs.hals.IGD.gfx_aperture_dma_read_write.return_value = test_buffer

        with patch('chipsec.utilcmd.igd_cmd.write_file') as mock_write_file, \
             patch.object(igd_command.logger, 'log') as mock_log:
            igd_command.read_dma()

            igd_command._cs.hals.IGD.gfx_aperture_dma_read_write.assert_called_once_with(0x20000000, 0x4)
            mock_write_file.assert_called_once_with('output.bin', test_buffer)
            mock_log.assert_any_call('[CHIPSEC] Reading buffer from memory: PA = 0x0000000020000000, len = 0x4..')
            mock_log.assert_any_call('[CHIPSEC] Written 0x4 bytes to \'output.bin\'')

    @pytest.mark.unit
    def test_read_dma_to_stdout(self, igd_command, mock_cs):
        """Test read_dma method with stdout output."""
        igd_command.address = 0x20000000
        igd_command.width = 0x4
        igd_command.file_name = ''

        test_buffer = b'\xDE\xAD\xBE\xEF'
        igd_command._cs.hals.IGD.gfx_aperture_dma_read_write.return_value = test_buffer

        with patch('chipsec.utilcmd.igd_cmd.print_buffer_bytes') as mock_print_buffer, \
             patch.object(igd_command.logger, 'log') as mock_log:
            igd_command.read_dma()

            igd_command._cs.hals.IGD.gfx_aperture_dma_read_write.assert_called_once_with(0x20000000, 0x4)
            mock_print_buffer.assert_called_once_with(test_buffer)
            mock_log.assert_called_with('[CHIPSEC] Reading buffer from memory: PA = 0x0000000020000000, len = 0x4..')

    @pytest.mark.unit
    def test_write_dma_hex_value(self, igd_command, mock_cs):
        """Test write_dma method with hex value."""
        igd_command.address = 0x2217F1000
        igd_command.size = 0x4
        igd_command.file_value = 'deadbeef'

        with patch.object(igd_command.logger, 'log') as mock_log:
            igd_command.write_dma()

            igd_command._cs.hals.IGD.gfx_aperture_dma_read_write.assert_called_once_with(
                0x2217F1000, 0x4, b'\xde\xad\xbe\xef'
            )
            mock_log.assert_any_call('[CHIPSEC] Read 0x4 hex bytes from command-line: \'deadbeef\'')
            mock_log.assert_any_call('[CHIPSEC] Writing buffer to memory: PA = 0x00000002217F1000, len = 0x4..')

    @pytest.mark.unit
    def test_write_dma_file_input(self, igd_command, mock_cs):
        """Test write_dma method with file input."""
        igd_command.address = 0x2217F1000
        igd_command.size = 0x4
        igd_command.file_value = 'input.bin'

        test_buffer = b'\xDE\xAD\xBE\xEF\x12\x34\x56\x78'
        igd_command._cs.hals.IGD.gfx_aperture_dma_read_write.return_value = test_buffer

        with patch('chipsec.utilcmd.igd_cmd.read_file', return_value=test_buffer) as mock_read_file, \
             patch('os.path.exists', return_value=True), \
             patch.object(igd_command.logger, 'log') as mock_log:
            igd_command.write_dma()

            mock_read_file.assert_called_once_with('input.bin')
            igd_command._cs.hals.IGD.gfx_aperture_dma_read_write.assert_called_once_with(
                0x2217F1000, 0x4, test_buffer
            )
            mock_log.assert_any_call('[CHIPSEC] Read 0x8 bytes from file \'input.bin\'')
            mock_log.assert_any_call('[CHIPSEC] Writing buffer to memory: PA = 0x00000002217F1000, len = 0x4..')

    @pytest.mark.unit
    def test_write_dma_invalid_hex(self, igd_command, mock_cs):
        """Test write_dma method with invalid hex value."""
        igd_command.address = 0x2217F1000
        igd_command.size = 0x4
        igd_command.file_value = 'invalid_hex'

        with patch.object(igd_command.logger, 'log_error') as mock_log_error:
            igd_command.write_dma()

            mock_log_error.assert_any_call('Incorrect <value> specified: \'invalid_hex\'')
            # Should not call DMA write due to invalid hex
            igd_command._cs.hals.IGD.gfx_aperture_dma_read_write.assert_not_called()

    @pytest.mark.unit
    def test_write_dma_insufficient_data(self, igd_command, mock_cs):
        """Test write_dma method with insufficient data."""
        igd_command.address = 0x2217F1000
        igd_command.size = 0x8
        igd_command.file_value = 'deadbeef'  # Only 4 bytes

        with patch.object(igd_command.logger, 'log_error') as mock_log_error:
            igd_command.write_dma()

            mock_log_error.assert_any_call('Number of bytes read (0x4) is less than the specified <length> (0x8)')
            # Should not call DMA write due to insufficient data
            igd_command._cs.hals.IGD.gfx_aperture_dma_read_write.assert_not_called()

    @pytest.mark.unit
    def test_print_igd_pci_info(self, igd_command, mock_cs):
        """Test print_igd_pci_info method."""
        igd_command.print_igd_pci_info()

        igd_command._cs.hals.IGD.display_igd_pci_info.assert_called_once()

    @pytest.mark.unit
    def test_run_device_enabled(self, igd_command, mock_cs):
        """Test run method when device is enabled."""
        igd_command.func = Mock()
        igd_command._cs.hals.IGD.is_device_enabled.return_value = True

        igd_command.run()

        igd_command.func.assert_called_once()

    @pytest.mark.unit
    def test_run_device_disabled(self, igd_command, mock_cs):
        """Test run method when device is disabled."""
        igd_command.func = Mock()
        igd_command._cs.hals.IGD.is_device_enabled.return_value = False

        with patch.object(igd_command.logger, 'log') as mock_log:
            igd_command.run()

            igd_command.func.assert_not_called()
            mock_log.assert_called_with('[CHIPSEC] Looks like internal graphics device is not enabled')


class TestIgdCommandIntegration:
    """Integration tests for IGD command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for IGD testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock IGD components with realistic data
        cs_mock.hals = Mock()
        cs_mock.hals.IGD = Mock()

        return cs_mock

    @pytest.mark.integration
    def test_igd_dmaread_integration(self, integrated_cs):
        """Test complete dmaread workflow."""
        igd_cmd = IgdCommand(['dmaread', '0x20000000', '0x4'], cs=integrated_cs)
        igd_cmd.set_up()

        test_buffer = b'\xDE\xAD\xBE\xEF'
        igd_cmd._cs.hals.IGD.gfx_aperture_dma_read_write.return_value = test_buffer
        igd_cmd._cs.hals.IGD.is_device_enabled.return_value = True

        with patch('chipsec.utilcmd.igd_cmd.print_buffer_bytes'), \
             patch.object(igd_cmd.logger, 'log'):
            igd_cmd.run()

            igd_cmd._cs.hals.IGD.gfx_aperture_dma_read_write.assert_called_once_with(0x20000000, 0x4)

    @pytest.mark.integration
    def test_igd_dmawrite_integration(self, integrated_cs):
        """Test complete dmawrite workflow."""
        igd_cmd = IgdCommand(['dmawrite', '0x2217F1000', '0x4', 'deadbeef'], cs=integrated_cs)
        igd_cmd.set_up()

        igd_cmd._cs.hals.IGD.is_device_enabled.return_value = True

        with patch.object(igd_cmd.logger, 'log'):
            igd_cmd.run()

            igd_cmd._cs.hals.IGD.gfx_aperture_dma_read_write.assert_called_once_with(
                0x2217F1000, 0x4, b'\xde\xad\xbe\xef'
            )

    @pytest.mark.integration
    def test_igd_info_integration(self, integrated_cs):
        """Test complete info workflow."""
        igd_cmd = IgdCommand(['info'], cs=integrated_cs)
        igd_cmd.set_up()

        igd_cmd._cs.hals.IGD.is_device_enabled.return_value = True

        igd_cmd.run()

        igd_cmd._cs.hals.IGD.display_igd_pci_info.assert_called_once()


class TestIgdCommandEdgeCases:
    """Test edge cases and error conditions for IGD command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        cs_mock.hals.IGD = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        command = IgdCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_read_dma_large_buffer(self, mock_cs):
        """Test read_dma with large buffer."""
        command = IgdCommand(['dmaread', '0x20000000', '0x1000'], cs=mock_cs)
        command.set_up()

        large_buffer = b'\x00' * 0x1000
        command._cs.hals.IGD.gfx_aperture_dma_read_write.return_value = large_buffer
        command._cs.hals.IGD.is_device_enabled.return_value = True

        with patch('chipsec.utilcmd.igd_cmd.print_buffer_bytes'), \
             patch.object(command.logger, 'log'):
            command.run()

            command._cs.hals.IGD.gfx_aperture_dma_read_write.assert_called_once_with(0x20000000, 0x1000)

    @pytest.mark.unit
    def test_write_dma_large_file(self, mock_cs):
        """Test write_dma with large file."""
        command = IgdCommand(['dmawrite', '0x2217F1000', '0x1000', 'large.bin'], cs=mock_cs)
        command.set_up()

        large_buffer = b'\x00' * 0x1000
        command._cs.hals.IGD.is_device_enabled.return_value = True

        with patch('chipsec.utilcmd.igd_cmd.read_file', return_value=large_buffer), \
             patch('os.path.exists', return_value=True), \
             patch.object(command.logger, 'log'):
            command.run()

            command._cs.hals.IGD.gfx_aperture_dma_read_write.assert_called_once_with(
                0x2217F1000, 0x1000, large_buffer
            )

    @pytest.mark.unit
    def test_write_dma_hex_with_prefix(self, mock_cs):
        """Test write_dma with hex value including 0x prefix."""
        command = IgdCommand(['dmawrite', '0x2217F1000', '0x4', '0xdeadbeef'], cs=mock_cs)
        command.set_up()

        command._cs.hals.IGD.is_device_enabled.return_value = True

        with patch.object(command.logger, 'log'):
            command.run()

            command._cs.hals.IGD.gfx_aperture_dma_read_write.assert_called_once_with(
                0x2217F1000, 0x4, b'\xde\xad\xbe\xef'
            )

    @pytest.mark.unit
    def test_write_dma_odd_length_hex(self, mock_cs):
        """Test write_dma with odd-length hex string."""
        command = IgdCommand(['dmawrite', '0x2217F1000', '0x3', 'deadbe'], cs=mock_cs)
        command.set_up()

        command._cs.hals.IGD.is_device_enabled.return_value = True

        with patch.object(command.logger, 'log'):
            command.run()

            command._cs.hals.IGD.gfx_aperture_dma_read_write.assert_called_once_with(
                0x2217F1000, 0x3, b'\xde\xad\xbe'
            )

    @pytest.mark.unit
    def test_write_dma_uppercase_hex(self, mock_cs):
        """Test write_dma with uppercase hex value."""
        command = IgdCommand(['dmawrite', '0x2217F1000', '0x4', 'DEADBEEF'], cs=mock_cs)
        command.set_up()

        command._cs.hals.IGD.is_device_enabled.return_value = True

        with patch.object(command.logger, 'log'):
            command.run()

            command._cs.hals.IGD.gfx_aperture_dma_read_write.assert_called_once_with(
                0x2217F1000, 0x4, b'\xde\xad\xbe\xef'
            )

    @pytest.mark.unit
    def test_write_dma_empty_hex(self, mock_cs):
        """Test write_dma with empty hex value."""
        command = IgdCommand(['dmawrite', '0x2217F1000', '0x0', ''], cs=mock_cs)
        command.set_up()

        command._cs.hals.IGD.is_device_enabled.return_value = True

        with patch.object(command.logger, 'log'):
            command.run()

            command._cs.hals.IGD.gfx_aperture_dma_read_write.assert_called_once_with(
                0x2217F1000, 0x0, b''
            )

    @pytest.mark.unit
    def test_read_dma_zero_address(self, mock_cs):
        """Test read_dma with zero address."""
        command = IgdCommand(['dmaread', '0x0', '0x4'], cs=mock_cs)
        command.set_up()

        test_buffer = b'\x00\x00\x00\x00'
        command._cs.hals.IGD.gfx_aperture_dma_read_write.return_value = test_buffer
        command._cs.hals.IGD.is_device_enabled.return_value = True

        with patch('chipsec.utilcmd.igd_cmd.print_buffer_bytes'), \
             patch.object(command.logger, 'log'):
            command.run()

            command._cs.hals.IGD.gfx_aperture_dma_read_write.assert_called_once_with(0x0, 0x4)

    @pytest.mark.unit
    def test_write_dma_zero_size(self, mock_cs):
        """Test write_dma with zero size."""
        command = IgdCommand(['dmawrite', '0x2217F1000', '0x0', ''], cs=mock_cs)
        command.set_up()

        command._cs.hals.IGD.is_device_enabled.return_value = True

        with patch.object(command.logger, 'log'):
            command.run()

            command._cs.hals.IGD.gfx_aperture_dma_read_write.assert_called_once_with(
                0x2217F1000, 0x0, b''
            )

    @pytest.mark.unit
    def test_hex_parsing_various_formats(self, mock_cs):
        """Test hex parsing with various formats."""
        test_cases = [
            ('0x20000000', 0x20000000),
            ('20000000', 0x20000000),
            ('0x0', 0x0),
            ('0', 0x0),
            ('FFFFFFFF', 0xFFFFFFFF),
            ('0xFFFFFFFF', 0xFFFFFFFF)
        ]

        for hex_str, expected_value in test_cases:
            command = IgdCommand(['dmaread', hex_str, '0x4'], cs=mock_cs)
            command.parse_arguments()
            assert command.address == expected_value


class TestIgdCommandConfigurationValidation:
    """Test configuration validation aspects of IGD command."""

    @pytest.fixture
    def igd_cs(self):
        """Create ChipsecCs with IGD-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock IGD configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.IGD = {
            'BASE_ADDRESS': 0x20000000,
            'APERTURE_SIZE': 0x10000000,
            'DMA_ENABLED': True,
            'DEVICE_ID': 0x1234
        }

        cs_mock.hals = Mock()
        cs_mock.hals.IGD = Mock()

        return cs_mock

    @pytest.mark.unit
    def test_igd_configuration_structure(self, igd_cs):
        """Test IGD configuration structure."""
        igd_config = igd_cs.Cfg.IGD

        # Test that required IGD configuration exists
        assert 'BASE_ADDRESS' in igd_config
        assert 'APERTURE_SIZE' in igd_config

        # Test configuration values are reasonable
        assert igd_config['BASE_ADDRESS'] > 0
        assert igd_config['APERTURE_SIZE'] > 0

    @pytest.mark.unit
    def test_igd_address_validation(self, igd_cs):
        """Test IGD address validation."""
        command = IgdCommand(['dmaread', '0x20000000', '0x4'], cs=igd_cs)
        command.parse_arguments()

        # Test that parsed address is valid
        assert command.address == 0x20000000
        assert isinstance(command.address, int)

    @pytest.mark.unit
    def test_igd_width_validation(self, igd_cs):
        """Test IGD width validation."""
        # Test various width formats
        test_cases = [
            ('0x4', 0x4),
            ('0x100', 0x100),
            ('0x1000', 0x1000),
            ('4', 0x4)
        ]

        for width_str, expected_width in test_cases:
            command = IgdCommand(['dmaread', '0x20000000', width_str], cs=igd_cs)
            command.parse_arguments()

            assert command.width == expected_width

    @pytest.mark.unit
    def test_igd_size_validation(self, igd_cs):
        """Test IGD size validation."""
        # Test various size formats
        test_cases = [
            ('0x4', 0x4),
            ('0x100', 0x100),
            ('0x1000', 0x1000),
            ('4', 0x4)
        ]

        for size_str, expected_size in test_cases:
            command = IgdCommand(['dmawrite', '0x2217F1000', size_str, 'deadbeef'], cs=igd_cs)
            command.parse_arguments()

            assert command.size == expected_size

    @pytest.mark.unit
    def test_igd_file_name_validation(self, igd_cs):
        """Test IGD file name validation."""
        # Test various file name formats
        test_cases = [
            'output.bin',
            'test_data.txt',
            'memory_dump.raw',
            '/path/to/file.bin'
        ]

        for file_name in test_cases:
            command = IgdCommand(['dmaread', '0x20000000', '0x4', file_name], cs=igd_cs)
            command.parse_arguments()

            assert command.file_name == file_name

    @pytest.mark.unit
    def test_igd_hex_value_validation(self, igd_cs):
        """Test IGD hex value validation."""
        # Test various hex value formats
        test_cases = [
            'deadbeef',
            '0xdeadbeef',
            'DEADBEEF',
            '0XDEADBEEF',
            '12345678',
            'abcdef01'
        ]

        for hex_value in test_cases:
            command = IgdCommand(['dmawrite', '0x2217F1000', '0x4', hex_value], cs=igd_cs)
            command.parse_arguments()

            assert command.file_value == hex_value

    @pytest.mark.unit
    def test_igd_device_enabled_check(self, igd_cs):
        """Test IGD device enabled check."""
        command = IgdCommand(['dmaread', '0x20000000', '0x4'], cs=igd_cs)

        # Test when device is enabled
        command._cs.hals.IGD.is_device_enabled.return_value = True
        command.func = Mock()

        command.run()

        command.func.assert_called_once()

        # Test when device is disabled
        command._cs.hals.IGD.is_device_enabled.return_value = False
        command.func = Mock()

        with patch.object(command.logger, 'log'):
            command.run()

            command.func.assert_not_called()

    @pytest.mark.unit
    def test_igd_error_handling(self, igd_cs):
        """Test IGD error handling."""
        command = IgdCommand(['dmaread', '0x20000000', '0x4'], cs=igd_cs)

        # Mock DMA read to raise exception
        command._cs.hals.IGD.gfx_aperture_dma_read_write.side_effect = Exception("DMA operation failed")
        command._cs.hals.IGD.is_device_enabled.return_value = True

        # Should handle the exception gracefully
        with pytest.raises(Exception):
            command.read_dma()

    @pytest.mark.unit
    def test_igd_file_operation_error_handling(self, igd_cs):
        """Test IGD file operation error handling."""
        command = IgdCommand(['dmawrite', '0x2217F1000', '0x4', 'nonexistent.bin'], cs=igd_cs)

        # Mock file read to raise exception
        with patch('chipsec.utilcmd.igd_cmd.read_file', side_effect=Exception("File read failed")), \
             patch('os.path.exists', return_value=True):
            command._cs.hals.IGD.is_device_enabled.return_value = True

            # Should handle the exception gracefully
            with pytest.raises(Exception):
                command.write_dma()


if __name__ == '__main__':
    pytest.main([__file__])
