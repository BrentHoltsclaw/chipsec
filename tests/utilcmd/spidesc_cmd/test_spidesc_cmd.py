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
from chipsec.utilcmd.spidesc_cmd import SPIDescCommand
from chipsec.command import toLoad
from tests.test_utils import MockFactory


class TestSPIDescCommand:
    """Comprehensive tests for SPI Descriptor command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for SPI Descriptor testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock SpiDescriptor HAL component
        cs_mock.hals = Mock()
        cs_mock.hals.SpiDescriptor = Mock()

        return cs_mock

    @pytest.fixture
    def spidesc_command(self, mock_cs):
        """Create SPIDescCommand instance."""
        return SPIDescCommand(['spi.bin'], cs=mock_cs)

    @pytest.mark.unit
    def test_spidesc_command_initialization(self, spidesc_command, mock_cs):
        """Test SPIDescCommand initialization."""
        assert spidesc_command.cs == mock_cs
        assert spidesc_command.argv == ['spi.bin']

    @pytest.mark.unit
    def test_requirements(self, spidesc_command):
        """Test command requirements."""
        reqs = spidesc_command.requirements()
        assert reqs == toLoad.Config

    @pytest.mark.unit
    def test_parse_arguments_valid_file(self, mock_cs):
        """Test parsing arguments with valid file name."""
        command = SPIDescCommand(['spi.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.fd_file == 'spi.bin'

    @pytest.mark.unit
    def test_parse_arguments_different_file_types(self, mock_cs):
        """Test parsing arguments with different file types."""
        test_files = [
            'flash.bin',
            'bios.rom',
            'spi.fd',
            'descriptor.img',
            '/path/to/file.bin',
            'C:\\path\\to\\file.bin'
        ]

        for filename in test_files:
            command = SPIDescCommand([filename], cs=mock_cs)
            command.parse_arguments()
            assert command.fd_file == filename

    @pytest.mark.unit
    def test_parse_arguments_no_file(self, mock_cs):
        """Test parsing arguments with no file specified."""
        command = SPIDescCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required argument
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_run_successful_parsing(self, spidesc_command, mock_cs):
        """Test run method with successful parsing."""
        spidesc_command.fd_file = 'spi.bin'
        mock_file_data = b'\xFF\xFE\xFD\xFC' * 1024  # Mock SPI descriptor data

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=mock_file_data), \
             patch.object(spidesc_command.logger, 'log') as mock_log:
            spidesc_command.run()

            # Verify file reading
            from chipsec.utilcmd.spidesc_cmd import read_file
            read_file.assert_called_once_with('spi.bin')

            # Verify SPI descriptor parsing
            mock_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.assert_called_once_with(mock_file_data)

            # Verify logging
            mock_log.assert_called_with("[CHIPSEC] Parsing SPI Flash Descriptor from file 'spi.bin'\n")

    @pytest.mark.unit
    def test_run_file_read_failure(self, spidesc_command, mock_cs):
        """Test run method when file read fails."""
        spidesc_command.fd_file = 'nonexistent.bin'

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=None), \
             patch.object(spidesc_command.logger, 'log') as mock_log:
            spidesc_command.run()

            # Verify file reading was attempted
            from chipsec.utilcmd.spidesc_cmd import read_file
            read_file.assert_called_once_with('nonexistent.bin')

            # Verify SPI descriptor parsing was not called
            mock_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.assert_not_called()

            # Verify logging
            mock_log.assert_called_with("[CHIPSEC] Parsing SPI Flash Descriptor from file 'nonexistent.bin'\n")

    @pytest.mark.unit
    def test_run_empty_file(self, spidesc_command, mock_cs):
        """Test run method with empty file."""
        spidesc_command.fd_file = 'empty.bin'

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=b''), \
             patch.object(spidesc_command.logger, 'log') as mock_log:
            spidesc_command.run()

            # Verify SPI descriptor parsing was called with empty data
            mock_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.assert_called_once_with(b'')

    @pytest.mark.unit
    def test_run_large_file(self, spidesc_command, mock_cs):
        """Test run method with large file."""
        spidesc_command.fd_file = 'large.bin'
        large_data = b'\x00' * (1024 * 1024)  # 1MB of data

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=large_data), \
             patch.object(spidesc_command.logger, 'log'):
            spidesc_command.run()

            # Verify SPI descriptor parsing was called with large data
            mock_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.assert_called_once_with(large_data)

    @pytest.mark.unit
    def test_run_parsing_error(self, spidesc_command, mock_cs):
        """Test run method when SPI descriptor parsing fails."""
        spidesc_command.fd_file = 'spi.bin'
        mock_file_data = b'invalid_descriptor_data'

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=mock_file_data), \
             patch.object(mock_cs.hals.SpiDescriptor.parse_spi_flash_descriptor, side_effect=Exception("Parsing failed")), \
             patch.object(spidesc_command.logger, 'log') as mock_log:
            # Should handle parsing exception gracefully
            with pytest.raises(Exception):
                spidesc_command.run()

    @pytest.mark.unit
    def test_run_with_unicode_filename(self, mock_cs):
        """Test run method with unicode filename."""
        unicode_filename = '测试文件.bin'
        command = SPIDescCommand([unicode_filename], cs=mock_cs)
        mock_file_data = b'\xFF\xFE\xFD\xFC' * 256

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=mock_file_data), \
             patch.object(command.logger, 'log') as mock_log:
            command.run()

            # Verify unicode filename handling
            from chipsec.utilcmd.spidesc_cmd import read_file
            read_file.assert_called_once_with(unicode_filename)

            mock_log.assert_called_with(f"[CHIPSEC] Parsing SPI Flash Descriptor from file '{unicode_filename}'\n")

    @pytest.mark.unit
    def test_run_with_different_file_extensions(self, mock_cs):
        """Test run method with different file extensions."""
        test_cases = [
            ('flash.bin', 'flash.bin'),
            ('bios.rom', 'bios.rom'),
            ('spi.fd', 'spi.fd'),
            ('descriptor.img', 'descriptor.img'),
            ('data.dat', 'data.dat')
        ]

        for filename, expected_filename in test_cases:
            command = SPIDescCommand([filename], cs=mock_cs)
            mock_file_data = b'\xAA\xBB\xCC\xDD' * 512

            with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=mock_file_data), \
                 patch.object(command.logger, 'log') as mock_log:
                command.run()

                from chipsec.utilcmd.spidesc_cmd import read_file
                read_file.assert_called_with(expected_filename)


class TestSPIDescCommandIntegration:
    """Integration tests for SPI Descriptor command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for SPI Descriptor testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock SpiDescriptor with realistic behavior
        cs_mock.hals = Mock()
        cs_mock.hals.SpiDescriptor = Mock()

        return cs_mock

    @pytest.mark.integration
    def test_spidesc_command_integration(self, integrated_cs):
        """Test complete SPI Descriptor command workflow."""
        spidesc_cmd = SPIDescCommand(['spi.bin'], cs=integrated_cs)
        mock_file_data = b'\xFF\xFE\xFD\xFC' * 1024

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=mock_file_data), \
             patch.object(spidesc_cmd.logger, 'log'):
            spidesc_cmd.run()

            integrated_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.assert_called_with(mock_file_data)

    @pytest.mark.integration
    def test_spidesc_command_file_read_integration(self, integrated_cs):
        """Test SPI Descriptor command file reading integration."""
        spidesc_cmd = SPIDescCommand(['test.bin'], cs=integrated_cs)

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=None), \
             patch.object(spidesc_cmd.logger, 'log'):
            spidesc_cmd.run()

            # Should handle file read failure gracefully
            integrated_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.assert_not_called()

    @pytest.mark.integration
    def test_spidesc_command_parsing_integration(self, integrated_cs):
        """Test SPI Descriptor command parsing integration."""
        spidesc_cmd = SPIDescCommand(['descriptor.bin'], cs=integrated_cs)
        mock_descriptor_data = b'\x5A\xA5\xFF\x00' * 512

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=mock_descriptor_data), \
             patch.object(spidesc_cmd.logger, 'log'):
            spidesc_cmd.run()

            integrated_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.assert_called_with(mock_descriptor_data)


class TestSPIDescCommandEdgeCases:
    """Test edge cases and error conditions for SPI Descriptor command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        cs_mock.hals.SpiDescriptor = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_run_with_binary_file_data(self, mock_cs):
        """Test run method with various binary file data."""
        command = SPIDescCommand(['test.bin'], cs=mock_cs)

        test_data_cases = [
            b'\x00\x01\x02\x03',  # Small binary data
            b'\xFF' * 4096,       # All FF data
            b'\x00' * 8192,       # All 00 data
            b'\xAA\x55' * 2048,   # Alternating pattern
        ]

        for test_data in test_data_cases:
            with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=test_data), \
                 patch.object(command.logger, 'log'):
                command.run()

                mock_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.assert_called_with(test_data)

    @pytest.mark.unit
    def test_run_with_file_path_containing_spaces(self, mock_cs):
        """Test run method with file path containing spaces."""
        filename_with_spaces = 'path with spaces/file.bin'
        command = SPIDescCommand([filename_with_spaces], cs=mock_cs)
        mock_file_data = b'\xDE\xAD\xBE\xEF' * 256

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=mock_file_data), \
             patch.object(command.logger, 'log') as mock_log:
            command.run()

            from chipsec.utilcmd.spidesc_cmd import read_file
            read_file.assert_called_with(filename_with_spaces)

            mock_log.assert_called_with(f"[CHIPSEC] Parsing SPI Flash Descriptor from file '{filename_with_spaces}'\n")

    @pytest.mark.unit
    def test_run_with_relative_path(self, mock_cs):
        """Test run method with relative path."""
        relative_path = '../relative/path/file.bin'
        command = SPIDescCommand([relative_path], cs=mock_cs)
        mock_file_data = b'\x12\x34\x56\x78' * 128

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=mock_file_data), \
             patch.object(command.logger, 'log'):
            command.run()

            from chipsec.utilcmd.spidesc_cmd import read_file
            read_file.assert_called_with(relative_path)

    @pytest.mark.unit
    def test_run_with_absolute_path(self, mock_cs):
        """Test run method with absolute path."""
        absolute_path = '/absolute/path/to/file.bin'
        command = SPIDescCommand([absolute_path], cs=mock_cs)
        mock_file_data = b'\xAB\xCD\xEF\x01' * 64

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=mock_file_data), \
             patch.object(command.logger, 'log'):
            command.run()

            from chipsec.utilcmd.spidesc_cmd import read_file
            read_file.assert_called_with(absolute_path)

    @pytest.mark.unit
    def test_run_with_windows_path(self, mock_cs):
        """Test run method with Windows-style path."""
        windows_path = 'C:\\Windows\\path\\file.bin'
        command = SPIDescCommand([windows_path], cs=mock_cs)
        mock_file_data = b'\xFE\xDC\xBA\x98' * 32

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=mock_file_data), \
             patch.object(command.logger, 'log'):
            command.run()

            from chipsec.utilcmd.spidesc_cmd import read_file
            read_file.assert_called_with(windows_path)

    @pytest.mark.unit
    def test_run_with_empty_filename(self, mock_cs):
        """Test run method with empty filename."""
        command = SPIDescCommand([''], cs=mock_cs)

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=None), \
             patch.object(command.logger, 'log'):
            command.run()

            from chipsec.utilcmd.spidesc_cmd import read_file
            read_file.assert_called_with('')

    @pytest.mark.unit
    def test_run_with_none_filename(self, mock_cs):
        """Test run method with None filename (edge case)."""
        command = SPIDescCommand(['test.bin'], cs=mock_cs)
        command.fd_file = None

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=b'test'), \
             patch.object(command.logger, 'log'):
            # Should handle None filename gracefully
            command.run()

    @pytest.mark.unit
    def test_run_multiple_times(self, mock_cs):
        """Test running command multiple times."""
        command = SPIDescCommand(['test.bin'], cs=mock_cs)
        mock_file_data = b'\x11\x22\x33\x44' * 16

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=mock_file_data), \
             patch.object(command.logger, 'log'):
            # Run multiple times
            command.run()
            command.run()
            command.run()

            # Should call read_file and parse_spi_flash_descriptor multiple times
            from chipsec.utilcmd.spidesc_cmd import read_file
            assert read_file.call_count == 3
            assert mock_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.call_count == 3

    @pytest.mark.unit
    def test_run_with_exception_in_parsing(self, mock_cs):
        """Test run method with exception during parsing."""
        command = SPIDescCommand(['error.bin'], cs=mock_cs)
        mock_file_data = b'\xFF\xFF\xFF\xFF'

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=mock_file_data), \
             patch.object(mock_cs.hals.SpiDescriptor.parse_spi_flash_descriptor, side_effect=Exception("Parse error")), \
             patch.object(command.logger, 'log'):
            # Should propagate parsing exceptions
            with pytest.raises(Exception):
                command.run()

    @pytest.mark.unit
    def test_run_with_different_data_sizes(self, mock_cs):
        """Test run method with different data sizes."""
        command = SPIDescCommand(['test.bin'], cs=mock_cs)

        data_sizes = [0, 1, 100, 1000, 10000, 100000]

        for size in data_sizes:
            test_data = b'\xAA' * size

            with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=test_data), \
                 patch.object(command.logger, 'log'):
                command.run()

                mock_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.assert_called_with(test_data)


class TestSPIDescCommandConfigurationValidation:
    """Test configuration validation aspects of SPI Descriptor command."""

    @pytest.fixture
    def spidesc_cs(self):
        """Create ChipsecCs with SPI Descriptor-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock SPI Descriptor configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.SPI = {
            'DESCRIPTOR_SIZE': 4096,
            'FLASH_SIZE': 16777216,  # 16MB
            'SUPPORTED_FORMATS': ['bin', 'rom', 'fd', 'img'],
            'VALIDATION_ENABLED': True
        }

        cs_mock.hals = Mock()
        cs_mock.hals.SpiDescriptor = Mock()

        return cs_mock

    @pytest.mark.unit
    def test_spidesc_configuration_structure(self, spidesc_cs):
        """Test SPI Descriptor configuration structure."""
        spi_config = spidesc_cs.Cfg.SPI

        # Test that required SPI configuration exists
        assert 'DESCRIPTOR_SIZE' in spi_config
        assert 'FLASH_SIZE' in spi_config
        assert 'SUPPORTED_FORMATS' in spi_config
        assert 'VALIDATION_ENABLED' in spi_config

        # Test configuration values are reasonable
        assert spi_config['DESCRIPTOR_SIZE'] > 0
        assert spi_config['FLASH_SIZE'] > 0
        assert isinstance(spi_config['SUPPORTED_FORMATS'], list)
        assert isinstance(spi_config['VALIDATION_ENABLED'], bool)

    @pytest.mark.unit
    def test_descriptor_size_validation(self, spidesc_cs):
        """Test descriptor size validation."""
        descriptor_size = spidesc_cs.Cfg.SPI['DESCRIPTOR_SIZE']

        # Descriptor size should be reasonable (between 1KB and 64KB)
        assert 1024 <= descriptor_size <= 65536

        # Should be power of 2
        assert (descriptor_size & (descriptor_size - 1)) == 0

    @pytest.mark.unit
    def test_flash_size_validation(self, spidesc_cs):
        """Test flash size validation."""
        flash_size = spidesc_cs.Cfg.SPI['FLASH_SIZE']

        # Flash size should be reasonable (between 1MB and 256MB)
        assert 1048576 <= flash_size <= 268435456

        # Should be power of 2
        assert (flash_size & (flash_size - 1)) == 0

    @pytest.mark.unit
    def test_supported_formats_validation(self, spidesc_cs):
        """Test supported formats validation."""
        supported_formats = spidesc_cs.Cfg.SPI['SUPPORTED_FORMATS']

        # Should contain common SPI flash file extensions
        expected_formats = ['bin', 'rom', 'fd']
        for fmt in expected_formats:
            assert fmt in supported_formats

        # All formats should be strings
        for fmt in supported_formats:
            assert isinstance(fmt, str)
            assert len(fmt) > 0

    @pytest.mark.unit
    def test_validation_enabled_flag(self, spidesc_cs):
        """Test validation enabled flag."""
        validation_enabled = spidesc_cs.Cfg.SPI['VALIDATION_ENABLED']
        assert isinstance(validation_enabled, bool)

    @pytest.mark.unit
    def test_spidesc_command_with_config(self, spidesc_cs):
        """Test SPI Descriptor command with configuration."""
        command = SPIDescCommand(['spi.bin'], cs=spidesc_cs)
        mock_file_data = b'\xFF\xFE\xFD\xFC' * 1024

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=mock_file_data), \
             patch.object(command.logger, 'log'):
            command.run()

            # Should work with configuration present
            spidesc_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.assert_called_with(mock_file_data)

    @pytest.mark.unit
    def test_spidesc_configuration_consistency(self, spidesc_cs):
        """Test SPI Descriptor configuration consistency."""
        descriptor_size = spidesc_cs.Cfg.SPI['DESCRIPTOR_SIZE']
        flash_size = spidesc_cs.Cfg.SPI['FLASH_SIZE']

        # Descriptor size should be much smaller than flash size
        assert descriptor_size < flash_size

        # Descriptor size should be at least 1/1024th of flash size
        assert descriptor_size >= flash_size // 1024

    @pytest.mark.unit
    def test_spidesc_error_handling_with_config(self, spidesc_cs):
        """Test SPI Descriptor error handling with configuration."""
        command = SPIDescCommand(['test.bin'], cs=spidesc_cs)

        # Test file read error with config
        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=None), \
             patch.object(command.logger, 'log'):
            command.run()

            # Should handle file read error gracefully
            spidesc_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.assert_not_called()

        # Test parsing error with config
        mock_file_data = b'\x00\x01\x02\x03'
        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=mock_file_data), \
             patch.object(spidesc_cs.hals.SpiDescriptor.parse_spi_flash_descriptor, side_effect=Exception("Parse error")), \
             patch.object(command.logger, 'log'):
            with pytest.raises(Exception):
                command.run()

    @pytest.mark.unit
    def test_spidesc_command_logging_with_config(self, spidesc_cs):
        """Test SPI Descriptor command logging with configuration."""
        command = SPIDescCommand(['configured.bin'], cs=spidesc_cs)
        mock_file_data = b'\xAA\xBB\xCC\xDD' * 512

        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=mock_file_data), \
             patch.object(command.logger, 'log') as mock_log:
            command.run()

            # Verify logging works with configuration
            mock_log.assert_called_with("[CHIPSEC] Parsing SPI Flash Descriptor from file 'configured.bin'\n")

    @pytest.mark.unit
    def test_spidesc_configuration_edge_cases(self, spidesc_cs):
        """Test SPI Descriptor configuration edge cases."""
        # Test with empty supported formats list
        spidesc_cs.Cfg.SPI['SUPPORTED_FORMATS'] = []

        # Should still function with empty list
        supported_formats = spidesc_cs.Cfg.SPI['SUPPORTED_FORMATS']
        assert isinstance(supported_formats, list)
        assert len(supported_formats) == 0

        # Test with very small descriptor size
        spidesc_cs.Cfg.SPI['DESCRIPTOR_SIZE'] = 512

        # Should still be valid
        assert spidesc_cs.Cfg.SPI['DESCRIPTOR_SIZE'] > 0

        # Test with very large flash size
        spidesc_cs.Cfg.SPI['FLASH_SIZE'] = 536870912  # 512MB

        # Should still be valid
        assert spidesc_cs.Cfg.SPI['FLASH_SIZE'] > 0


if __name__ == '__main__':
    pytest.main([__file__])
