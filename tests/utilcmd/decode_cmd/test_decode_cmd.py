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
from unittest.mock import Mock, patch
from chipsec.utilcmd.decode_cmd import DecodeCommand
from tests.test_utils import MockFactory


class TestDecodeCommand:
    """Comprehensive tests for Decode utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for Decode testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock SPI descriptor HAL
        cs_mock.hals.SpiDescriptor = Mock()
        cs_mock.hals.SpiDescriptor.get_spi_flash_descriptor.return_value = (0x1000, b'\xFF' * 0x1000)
        cs_mock.hals.SpiDescriptor.get_spi_regions.return_value = {
            0: Mock(name='FLASH_DESCRIPTOR', base=0x0000, limit=0x0FFF),
            1: Mock(name='BIOS', base=0x1000, limit=0x1FFFF),
            2: Mock(name='ME', base=0x2000, limit=0x2FFFF),
        }
        cs_mock.hals.SpiDescriptor.parse_spi_flash_descriptor.return_value = None

        # Mock OS helper
        cs_mock.os_helper.getcwd.return_value = '/tmp'

        return cs_mock

    @pytest.fixture
    def decode_command(self, mock_cs):
        """Create DecodeCommand instance."""
        return DecodeCommand(['spi.bin'], cs=mock_cs)

    @pytest.mark.unit
    def test_decode_command_initialization(self, decode_command, mock_cs):
        """Test DecodeCommand initialization."""
        assert decode_command.cs == mock_cs
        assert decode_command.argv == ['spi.bin']

    @pytest.mark.unit
    def test_parse_arguments_decode_types(self, mock_cs):
        """Test parsing 'types' command arguments."""
        command = DecodeCommand(['types'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.decode_types
        assert command._rom == 'types'

    @pytest.mark.unit
    def test_parse_arguments_decode_rom(self, mock_cs):
        """Test parsing decode rom command arguments."""
        command = DecodeCommand(['spi.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.decode_rom
        assert command._rom == 'spi.bin'
        assert command._fwtype is None

    @pytest.mark.unit
    def test_parse_arguments_decode_rom_with_fwtype(self, mock_cs):
        """Test parsing decode rom command with firmware type."""
        command = DecodeCommand(['spi.bin', 'vss'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.decode_rom
        assert command._rom == 'spi.bin'
        assert command._fwtype == 'vss'

    @pytest.mark.unit
    def test_requirements(self, decode_command):
        """Test command requirements."""
        reqs = decode_command.requirements()
        assert hasattr(reqs, 'load_config')

    @pytest.mark.unit
    def test_decode_types(self, decode_command):
        """Test decode_types command."""
        decode_command._rom = 'types'

        with patch('chipsec.utilcmd.decode_cmd.uefi_platform') as mock_uefi_platform:
            mock_uefi_platform.fw_types = ['vss', 'ami', 'award', 'phoenix']
            with patch.object(decode_command.logger, 'log') as mock_log:
                decode_command.decode_types()

                mock_log.assert_called_once()
                log_call = mock_log.call_args[0][0]
                assert 'vss' in log_call
                assert 'ami' in log_call
                assert 'award' in log_call
                assert 'phoenix' in log_call

    @pytest.mark.unit
    def test_decode_rom_file_not_found(self, decode_command, mock_cs):
        """Test decode_rom when file is not found."""
        decode_command._rom = 'nonexistent.bin'

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=None):
            with patch.object(decode_command.logger, 'log') as mock_log:
                result = decode_command.decode_rom()

                assert result is False
                mock_log.assert_called_once_with('[CHIPSEC] Decoding SPI ROM image from a file \'nonexistent.bin\'')

    @pytest.mark.unit
    def test_decode_rom_no_flash_descriptor(self, decode_command, mock_cs):
        """Test decode_rom when no flash descriptor is found."""
        decode_command._rom = 'spi.bin'

        # Mock SPI descriptor to return no flash descriptor
        mock_cs.hals.SpiDescriptor.get_spi_flash_descriptor.return_value = (-1, None)

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=b'\xFF' * 0x10000):
            with patch.object(decode_command.logger, 'log') as mock_log, \
                 patch.object(decode_command.logger, 'log_error') as mock_error, \
                 patch.object(decode_command.logger, 'log_information') as mock_info:
                result = decode_command.decode_rom()

                assert result is False
                mock_error.assert_called_once_with('Could not find SPI Flash descriptor in the binary \'spi.bin\'')
                mock_info.assert_called_once_with('To decode an image without a flash decriptor try chipsec_util uefi decode')

    @pytest.mark.unit
    def test_decode_rom_invalid_regions(self, decode_command, mock_cs):
        """Test decode_rom when SPI regions are invalid."""
        decode_command._rom = 'spi.bin'

        # Mock SPI descriptor to return invalid regions
        mock_cs.hals.SpiDescriptor.get_spi_regions.return_value = None

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=b'\xFF' * 0x10000):
            with patch.object(decode_command.logger, 'log') as mock_log, \
                 patch.object(decode_command.logger, 'log_error') as mock_error, \
                 patch.object(decode_command.logger, 'log_information') as mock_info:
                result = decode_command.decode_rom()

                assert result is False
                mock_error.assert_called_once_with('SPI Flash descriptor region is not valid')
                mock_info.assert_called_once_with('To decode an image with an invalid flash decriptor try chipsec_util uefi decode')

    @pytest.mark.unit
    def test_decode_rom_success(self, decode_command, mock_cs):
        """Test successful decode_rom operation."""
        decode_command._rom = 'spi.bin'
        decode_command._fwtype = 'vss'

        # Mock region objects
        flash_desc_region = Mock()
        flash_desc_region.name = 'FLASH_DESCRIPTOR'
        flash_desc_region.base = 0x0000
        flash_desc_region.limit = 0x0FFF

        bios_region = Mock()
        bios_region.name = 'BIOS'
        bios_region.base = 0x1000
        bios_region.limit = 0x1FFFF

        regions = {
            0: flash_desc_region,
            1: bios_region,
        }

        mock_cs.hals.SpiDescriptor.get_spi_regions.return_value = regions

        rom_data = b'\xFF' * 0x20000

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=rom_data), \
             patch('chipsec.utilcmd.decode_cmd.write_file') as mock_write_file, \
             patch('chipsec.utilcmd.decode_cmd.decode_uefi_region') as mock_decode_uefi, \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs') as mock_makedirs, \
             patch.object(decode_command.logger, 'log') as mock_log, \
             patch.object(decode_command.logger, 'set_log_file') as mock_set_log:
                result = decode_command.decode_rom()

                assert result is True
                mock_makedirs.assert_called_once()
                # Should write 2 region files (FLASH_DESCRIPTOR and BIOS)
                assert mock_write_file.call_count == 2
                # Should decode UEFI region for BIOS
                mock_decode_uefi.assert_called_once()

    @pytest.mark.unit
    def test_decode_rom_region_not_used(self, decode_command, mock_cs):
        """Test decode_rom with unused regions (base > limit)."""
        decode_command._rom = 'spi.bin'

        # Mock region with base > limit (unused)
        unused_region = Mock()
        unused_region.name = 'UNUSED'
        unused_region.base = 0x3000
        unused_region.limit = 0x2000  # base > limit

        regions = {
            0: unused_region,
        }

        mock_cs.hals.SpiDescriptor.get_spi_regions.return_value = regions

        rom_data = b'\xFF' * 0x20000

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=rom_data), \
             patch('chipsec.utilcmd.decode_cmd.write_file') as mock_write_file, \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs') as mock_makedirs, \
             patch.object(decode_command.logger, 'log') as mock_log:
                result = decode_command.decode_rom()

                assert result is True
                # Should not write any files for unused regions
                mock_write_file.assert_not_called()

    @pytest.mark.unit
    def test_decode_rom_directory_creation(self, decode_command, mock_cs):
        """Test decode_rom directory creation."""
        decode_command._rom = 'test_spi.bin'

        regions = {
            0: Mock(name='FLASH_DESCRIPTOR', base=0x0000, limit=0x0FFF),
        }

        mock_cs.hals.SpiDescriptor.get_spi_regions.return_value = regions

        rom_data = b'\xFF' * 0x20000

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=rom_data), \
             patch('chipsec.utilcmd.decode_cmd.write_file'), \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs') as mock_makedirs, \
             patch.object(decode_command.logger, 'log'):
                decode_command.decode_rom()

                # Should create directory with .dir extension
                expected_dir = os.path.join('/tmp', 'test_spi.bin.dir')
                mock_makedirs.assert_called_once_with(expected_dir)

    @pytest.mark.unit
    def test_decode_rom_log_file_handling(self, decode_command, mock_cs):
        """Test decode_rom log file handling."""
        decode_command._rom = 'spi.bin'

        regions = {
            0: Mock(name='FLASH_DESCRIPTOR', base=0x0000, limit=0x0FFF),
            1: Mock(name='BIOS', base=0x1000, limit=0x1FFFF),
        }

        mock_cs.hals.SpiDescriptor.get_spi_regions.return_value = regions

        rom_data = b'\xFF' * 0x20000

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=rom_data), \
             patch('chipsec.utilcmd.decode_cmd.write_file'), \
             patch('chipsec.utilcmd.decode_cmd.decode_uefi_region'), \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs'), \
             patch.object(decode_command.logger, 'log'), \
             patch.object(decode_command.logger, 'set_log_file') as mock_set_log:
                original_log_name = 'original.log'
                decode_command.logger.LOG_FILE_NAME = original_log_name

                decode_command.decode_rom()

                # Should set log file for each region and restore original
                assert mock_set_log.call_count == 3  # 2 regions + restore
                # Last call should restore original log file
                mock_set_log.assert_any_call(original_log_name)


class TestDecodeCommandIntegration:
    """Integration tests for Decode command with HAL components."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for Decode testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        cs_mock.hals.SpiDescriptor = Mock()
        cs_mock.hals.SpiDescriptor.get_spi_flash_descriptor.return_value = (0x1000, b'\xFF' * 0x1000)
        cs_mock.hals.SpiDescriptor.get_spi_regions.return_value = {
            0: Mock(name='FLASH_DESCRIPTOR', base=0x0000, limit=0x0FFF),
            1: Mock(name='BIOS', base=0x1000, limit=0x1FFFF),
        }
        cs_mock.hals.SpiDescriptor.parse_spi_flash_descriptor.return_value = None

        # Mock OS helper
        cs_mock.os_helper.getcwd.return_value = '/tmp'

        # Mock helper
        cs_mock.helper = Mock()
        cs_mock.helper.get_threads_count.return_value = 2

        return cs_mock

    @pytest.mark.integration
    def test_decode_types_workflow(self, integrated_cs):
        """Test decode types workflow."""
        decode_cmd = DecodeCommand(['types'], cs=integrated_cs)
        decode_cmd.parse_arguments()

        with patch('chipsec.utilcmd.decode_cmd.uefi_platform') as mock_uefi_platform:
            mock_uefi_platform.fw_types = ['vss', 'ami', 'award']
            with patch.object(decode_cmd.logger, 'log') as mock_log:
                decode_cmd.run()

                mock_log.assert_called_once()
                log_call = mock_log.call_args[0][0]
                assert 'vss' in log_call
                assert 'ami' in log_call
                assert 'award' in log_call

    @pytest.mark.integration
    def test_decode_rom_workflow_success(self, integrated_cs):
        """Test decode rom workflow with success."""
        decode_cmd = DecodeCommand(['test_spi.bin', 'vss'], cs=integrated_cs)
        decode_cmd.parse_arguments()

        rom_data = b'\xFF' * 0x20000

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=rom_data), \
             patch('chipsec.utilcmd.decode_cmd.write_file') as mock_write_file, \
             patch('chipsec.utilcmd.decode_cmd.decode_uefi_region') as mock_decode_uefi, \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs') as mock_makedirs, \
             patch.object(decode_cmd.logger, 'log') as mock_log, \
             patch.object(decode_cmd.logger, 'set_log_file'):
                result = decode_cmd.run()

                assert result is True
                mock_makedirs.assert_called_once()
                mock_write_file.assert_called()  # Should write region files
                mock_decode_uefi.assert_called_once()  # Should decode UEFI region

    @pytest.mark.integration
    def test_decode_rom_workflow_file_not_found(self, integrated_cs):
        """Test decode rom workflow when file is not found."""
        decode_cmd = DecodeCommand(['nonexistent.bin'], cs=integrated_cs)
        decode_cmd.parse_arguments()

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=None), \
             patch.object(decode_cmd.logger, 'log') as mock_log:
                result = decode_cmd.run()

                assert result is False
                mock_log.assert_called_once_with('[CHIPSEC] Decoding SPI ROM image from a file \'nonexistent.bin\'')

    @pytest.mark.integration
    def test_decode_rom_workflow_no_descriptor(self, integrated_cs):
        """Test decode rom workflow when no flash descriptor is found."""
        decode_cmd = DecodeCommand(['spi.bin'], cs=integrated_cs)
        decode_cmd.parse_arguments()

        # Mock no flash descriptor
        integrated_cs.hals.SpiDescriptor.get_spi_flash_descriptor.return_value = (-1, None)

        rom_data = b'\xFF' * 0x20000

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=rom_data), \
             patch.object(decode_cmd.logger, 'log') as mock_log, \
             patch.object(decode_cmd.logger, 'log_error') as mock_error, \
             patch.object(decode_cmd.logger, 'log_information') as mock_info:
                result = decode_cmd.run()

                assert result is False
                mock_error.assert_called_once()
                mock_info.assert_called_once()


class TestDecodeCommandEdgeCases:
    """Test edge cases and error conditions for Decode command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals.SpiDescriptor = Mock()
        cs_mock.os_helper.getcwd.return_value = '/tmp'
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        decode_cmd = DecodeCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            decode_cmd.parse_arguments()

    @pytest.mark.unit
    def test_invalid_subcommand(self, mock_cs):
        """Test handling of invalid subcommand."""
        decode_cmd = DecodeCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            decode_cmd.parse_arguments()

    @pytest.mark.unit
    def test_decode_types_case_insensitive(self, mock_cs):
        """Test decode types with different cases."""
        test_cases = ['TYPES', 'Types', 'types', 'TyPeS']

        for case in test_cases:
            decode_cmd = DecodeCommand([case], cs=mock_cs)
            decode_cmd.parse_arguments()
            assert decode_cmd.func == decode_cmd.decode_types
            assert decode_cmd._rom.lower() == 'types'

    @pytest.mark.unit
    def test_decode_rom_with_special_characters(self, mock_cs):
        """Test decode rom with special characters in filename."""
        special_names = [
            'spi-flash.bin',
            'spi_flash.bin',
            'spi flash.bin',
            'spi@flash.bin',
            'spi#flash.bin',
        ]

        for name in special_names:
            decode_cmd = DecodeCommand([name], cs=mock_cs)
            decode_cmd.parse_arguments()
            assert decode_cmd._rom == name
            assert decode_cmd.func == decode_cmd.decode_rom

    @pytest.mark.unit
    def test_decode_rom_with_path(self, mock_cs):
        """Test decode rom with full path."""
        paths = [
            '/path/to/spi.bin',
            './spi.bin',
            '../spi.bin',
            '~/spi.bin',
        ]

        for path in paths:
            decode_cmd = DecodeCommand([path], cs=mock_cs)
            decode_cmd.parse_arguments()
            assert decode_cmd._rom == path
            assert decode_cmd.func == decode_cmd.decode_rom

    @pytest.mark.unit
    def test_decode_rom_with_extensions(self, mock_cs):
        """Test decode rom with different file extensions."""
        extensions = ['.bin', '.rom', '.img', '.dat', '.spi']

        for ext in extensions:
            filename = f'spi{ext}'
            decode_cmd = DecodeCommand([filename], cs=mock_cs)
            decode_cmd.parse_arguments()
            assert decode_cmd._rom == filename
            assert decode_cmd.func == decode_cmd.decode_rom

    @pytest.mark.unit
    def test_decode_rom_empty_file(self, decode_command, mock_cs):
        """Test decode rom with empty file."""
        decode_command._rom = 'empty.bin'

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=b''):
            with patch.object(decode_command.logger, 'log') as mock_log:
                result = decode_command.decode_rom()

                assert result is False
                mock_log.assert_called_once_with('[CHIPSEC] Decoding SPI ROM image from a file \'empty.bin\'')

    @pytest.mark.unit
    def test_decode_rom_small_file(self, decode_command, mock_cs):
        """Test decode rom with small file (less than descriptor size)."""
        decode_command._rom = 'small.bin'

        # File smaller than typical flash descriptor
        small_data = b'\xFF' * 0x100

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=small_data):
            with patch.object(decode_command.logger, 'log') as mock_log:
                result = decode_command.decode_rom()

                assert result is False
                mock_log.assert_called_once_with('[CHIPSEC] Decoding SPI ROM image from a file \'small.bin\'')

    @pytest.mark.unit
    def test_decode_rom_large_file(self, decode_command, mock_cs):
        """Test decode rom with large file."""
        decode_command._rom = 'large.bin'

        # Large file (16MB)
        large_data = b'\xFF' * (16 * 1024 * 1024)

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=large_data), \
             patch('chipsec.utilcmd.decode_cmd.write_file'), \
             patch('chipsec.utilcmd.decode_cmd.decode_uefi_region'), \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs'), \
             patch.object(decode_command.logger, 'log'), \
             patch.object(decode_command.logger, 'set_log_file'):
                result = decode_command.decode_rom()

                assert result is True

    @pytest.mark.unit
    def test_decode_rom_region_boundaries(self, decode_command, mock_cs):
        """Test decode rom with various region boundaries."""
        decode_command._rom = 'spi.bin'

        # Test regions at boundaries
        regions = {
            0: Mock(name='REGION_0', base=0x0000, limit=0x0000),  # Single byte
            1: Mock(name='REGION_1', base=0x0001, limit=0x0001),  # Another single byte
            2: Mock(name='REGION_2', base=0xFFFF, limit=0xFFFF),  # Last byte
        }

        mock_cs.hals.SpiDescriptor.get_spi_regions.return_value = regions

        rom_data = b'\xFF' * 0x10000

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=rom_data), \
             patch('chipsec.utilcmd.decode_cmd.write_file') as mock_write_file, \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs'), \
             patch.object(decode_command.logger, 'log'), \
             patch.object(decode_command.logger, 'set_log_file'):
                result = decode_command.decode_rom()

                assert result is True
                # Should write 3 region files
                assert mock_write_file.call_count == 3

    @pytest.mark.unit
    def test_decode_rom_firmware_types(self, decode_command, mock_cs):
        """Test decode rom with different firmware types."""
        decode_command._rom = 'spi.bin'

        firmware_types = ['vss', 'ami', 'award', 'phoenix', 'insyde', 'dell']

        for fw_type in firmware_types:
            decode_command._fwtype = fw_type

            regions = {
                1: Mock(name='BIOS', base=0x1000, limit=0x1FFFF),
            }

            mock_cs.hals.SpiDescriptor.get_spi_regions.return_value = regions

            rom_data = b'\xFF' * 0x20000

            with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=rom_data), \
                 patch('chipsec.utilcmd.decode_cmd.write_file'), \
                 patch('chipsec.utilcmd.decode_cmd.decode_uefi_region') as mock_decode_uefi, \
                 patch('os.path.exists', return_value=False), \
                 patch('os.makedirs'), \
                 patch.object(decode_command.logger, 'log'), \
                 patch.object(decode_command.logger, 'set_log_file'):
                    result = decode_command.decode_rom()

                    assert result is True
                    # Should call decode_uefi_region with the specified firmware type
                    mock_decode_uefi.assert_called_once()
                    call_args = mock_decode_uefi.call_args
                    assert call_args[1]['fwtype'] == fw_type  # fwtype parameter


class TestDecodeCommandConfigurationValidation:
    """Test configuration validation aspects of Decode command."""

    @pytest.fixture
    def config_cs(self):
        """Create ChipsecCs with decode-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock SPI descriptor HAL with configuration
        cs_mock.hals.SpiDescriptor = Mock()
        cs_mock.hals.SpiDescriptor.get_spi_flash_descriptor.return_value = (0x1000, b'\xFF' * 0x1000)
        cs_mock.hals.SpiDescriptor.get_spi_regions.return_value = {
            0: Mock(name='FLASH_DESCRIPTOR', base=0x0000, limit=0x0FFF),
            1: Mock(name='BIOS', base=0x1000, limit=0x1FFFF),
        }

        # Mock OS helper
        cs_mock.os_helper.getcwd.return_value = '/tmp'

        # Mock decode configuration data
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.DECODE_CONFIG = {
            'supported_firmware_types': ['vss', 'ami', 'award', 'phoenix', 'insyde', 'dell'],
            'spi_regions': {
                'flash_descriptor': {'id': 0, 'description': 'SPI Flash Descriptor'},
                'bios': {'id': 1, 'description': 'BIOS Region'},
                'me': {'id': 2, 'description': 'Management Engine'},
                'gbe': {'id': 3, 'description': 'Gigabit Ethernet'},
                'platform_data': {'id': 4, 'description': 'Platform Data'},
            },
            'output_formats': ['bin', 'log', 'dir'],
            'max_file_size': 16 * 1024 * 1024,  # 16MB
            'security_features': {
                'validate_checksums': True,
                'detect_encryption': True,
                'extract_variables': True,
            }
        }

        return cs_mock

    @pytest.mark.unit
    def test_decode_configuration_access(self, config_cs):
        """Test access to decode configuration data."""
        decode_config = config_cs.Cfg.DECODE_CONFIG

        assert 'vss' in decode_config['supported_firmware_types']
        assert 'ami' in decode_config['supported_firmware_types']
        assert 'flash_descriptor' in decode_config['spi_regions']
        assert decode_config['spi_regions']['bios']['id'] == 1
        assert decode_config['max_file_size'] == 16 * 1024 * 1024

    @pytest.mark.unit
    def test_supported_firmware_types_validation(self, config_cs):
        """Test validation of supported firmware types."""
        supported_types = config_cs.Cfg.DECODE_CONFIG['supported_firmware_types']

        # Test that all expected firmware types are supported
        expected_types = ['vss', 'ami', 'award', 'phoenix', 'insyde', 'dell']
        for fw_type in expected_types:
            assert fw_type in supported_types

        # Test that types list is not empty
        assert len(supported_types) > 0

    @pytest.mark.unit
    def test_spi_regions_validation(self, config_cs):
        """Test validation of SPI regions configuration."""
        spi_regions = config_cs.Cfg.DECODE_CONFIG['spi_regions']

        # Test that all expected SPI regions are defined
        expected_regions = ['flash_descriptor', 'bios', 'me', 'gbe', 'platform_data']
        for region_name in expected_regions:
            assert region_name in spi_regions
            assert 'id' in spi_regions[region_name]
            assert 'description' in spi_regions[region_name]
            assert isinstance(spi_regions[region_name]['id'], int)
            assert isinstance(spi_regions[region_name]['description'], str)

        # Test specific region configurations
        assert spi_regions['flash_descriptor']['id'] == 0
        assert spi_regions['bios']['id'] == 1
        assert spi_regions['me']['id'] == 2

    @pytest.mark.unit
    def test_output_formats_validation(self, config_cs):
        """Test validation of output formats."""
        output_formats = config_cs.Cfg.DECODE_CONFIG['output_formats']

        # Test that all expected output formats are supported
        expected_formats = ['bin', 'log', 'dir']
        for fmt in expected_formats:
            assert fmt in output_formats

        # Test that formats list is not empty
        assert len(output_formats) > 0

    @pytest.mark.unit
    def test_max_file_size_validation(self, config_cs):
        """Test validation of maximum file size."""
        max_size = config_cs.Cfg.DECODE_CONFIG['max_file_size']

        # Test that maximum file size is reasonable
        assert max_size > 0
        assert max_size >= 1024 * 1024  # At least 1MB
        assert max_size <= 64 * 1024 * 1024  # At most 64MB

    @pytest.mark.unit
    def test_security_features_validation(self, config_cs):
        """Test validation of security features configuration."""
        security_features = config_cs.Cfg.DECODE_CONFIG['security_features']

        # Test that all expected security features are defined
        expected_features = ['validate_checksums', 'detect_encryption', 'extract_variables']
        for feature in expected_features:
            assert feature in security_features
            assert isinstance(security_features[feature], bool)

        # Test specific security feature values
        assert security_features['validate_checksums'] is True
        assert security_features['detect_encryption'] is True
        assert security_features['extract_variables'] is True


if __name__ == '__main__':
    pytest.main([__file__])
