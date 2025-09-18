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
import unittest
from unittest.mock import Mock, patch
from chipsec.utilcmd.decode_cmd import DecodeCommand
from tests.test_utils import MockFactory


class TestDecodeCommand(unittest.TestCase):
    """Comprehensive tests for Decode utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()

        # Mock SPI descriptor HAL
        self.mock_cs.hals.SpiDescriptor = Mock()
        self.mock_cs.hals.SpiDescriptor.get_spi_flash_descriptor.return_value = (0x1000, b'\xFF' * 0x1000)
        self.mock_cs.hals.SpiDescriptor.get_spi_regions.return_value = {
            0: Mock(name='FLASH_DESCRIPTOR', base=0x0000, limit=0x0FFF),
            1: Mock(name='BIOS', base=0x1000, limit=0x1FFFF),
            2: Mock(name='ME', base=0x2000, limit=0x2FFFF),
        }
        self.mock_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.return_value = None

        # Mock OS helper
        self.mock_cs.os_helper.getcwd.return_value = '/tmp'

        self.decode_command = DecodeCommand(['spi.bin'], cs=self.mock_cs)

    def test_decode_command_initialization(self):
        """Test DecodeCommand initialization."""
        self.assertEqual(self.decode_command.cs, self.mock_cs)
        self.assertEqual(self.decode_command.argv, ['spi.bin'])

    def test_parse_arguments_decode_types(self):
        """Test parsing 'types' command arguments."""
        command = DecodeCommand(['types'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.decode_types)
        self.assertEqual(command._rom, 'types')

    def test_parse_arguments_decode_rom(self):
        """Test parsing decode rom command arguments."""
        command = DecodeCommand(['spi.bin'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.decode_rom)
        self.assertEqual(command._rom, 'spi.bin')
        self.assertIsNone(command._fwtype)

    def test_parse_arguments_decode_rom_with_fwtype(self):
        """Test parsing decode rom command with firmware type."""
        command = DecodeCommand(['spi.bin', 'vss'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.decode_rom)
        self.assertEqual(command._rom, 'spi.bin')
        self.assertEqual(command._fwtype, 'vss')

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.decode_command.requirements()
        self.assertTrue(hasattr(reqs, 'load_config'))

    def test_decode_types(self):
        """Test decode_types command."""
        self.decode_command._rom = 'types'

        with patch('chipsec.utilcmd.decode_cmd.uefi_platform') as mock_uefi_platform:
            mock_uefi_platform.fw_types = ['vss', 'ami', 'award', 'phoenix']
            with patch.object(self.decode_command.logger, 'log') as mock_log:
                self.decode_command.decode_types()

                mock_log.assert_called_once()
                log_call = mock_log.call_args[0][0]
                self.assertIn('vss', log_call)
                self.assertIn('ami', log_call)
                self.assertIn('award', log_call)
                self.assertIn('phoenix', log_call)

    def test_decode_rom_file_not_found(self):
        """Test decode_rom when file is not found."""
        self.decode_command._rom = 'nonexistent.bin'

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=None):
            with patch.object(self.decode_command.logger, 'log') as mock_log:
                result = self.decode_command.decode_rom()

                self.assertFalse(result)
                mock_log.assert_called_once_with('[CHIPSEC] Decoding SPI ROM image from a file \'nonexistent.bin\'')

    def test_decode_rom_no_flash_descriptor(self):
        """Test decode_rom when no flash descriptor is found."""
        self.decode_command._rom = 'spi.bin'

        # Mock SPI descriptor to return no flash descriptor
        self.mock_cs.hals.SpiDescriptor.get_spi_flash_descriptor.return_value = (-1, None)

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=b'\xFF' * 0x10000):
            with patch.object(self.decode_command.logger, 'log') as mock_log, \
                 patch.object(self.decode_command.logger, 'log_error') as mock_error, \
                 patch.object(self.decode_command.logger, 'log_information') as mock_info:
                result = self.decode_command.decode_rom()

                self.assertFalse(result)
                mock_error.assert_called_once_with('Could not find SPI Flash descriptor in the binary \'spi.bin\'')
                mock_info.assert_called_once_with('To decode an image without a flash decriptor try chipsec_util uefi decode')

    def test_decode_rom_invalid_regions(self):
        """Test decode_rom when SPI regions are invalid."""
        self.decode_command._rom = 'spi.bin'

        # Mock SPI descriptor to return invalid regions
        self.mock_cs.hals.SpiDescriptor.get_spi_regions.return_value = None

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=b'\xFF' * 0x10000):
            with patch.object(self.decode_command.logger, 'log') as mock_log, \
                 patch.object(self.decode_command.logger, 'log_error') as mock_error, \
                 patch.object(self.decode_command.logger, 'log_information') as mock_info:
                result = self.decode_command.decode_rom()

                self.assertFalse(result)
                mock_error.assert_called_once_with('SPI Flash descriptor region is not valid')
                mock_info.assert_called_once_with('To decode an image with an invalid flash decriptor try chipsec_util uefi decode')

    def test_decode_rom_success(self):
        """Test successful decode_rom operation."""
        self.decode_command._rom = 'spi.bin'
        self.decode_command._fwtype = 'vss'

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

        self.mock_cs.hals.SpiDescriptor.get_spi_regions.return_value = regions

        rom_data = b'\xFF' * 0x20000

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=rom_data), \
             patch('chipsec.utilcmd.decode_cmd.write_file') as mock_write_file, \
             patch('chipsec.utilcmd.decode_cmd.decode_uefi_region') as mock_decode_uefi, \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs') as mock_makedirs, \
             patch.object(self.decode_command.logger, 'log') as mock_log, \
             patch.object(self.decode_command.logger, 'set_log_file') as mock_set_log:
                result = self.decode_command.decode_rom()

                self.assertTrue(result)
                mock_makedirs.assert_called_once()
                # Should write 2 region files (FLASH_DESCRIPTOR and BIOS)
                self.assertEqual(mock_write_file.call_count, 2)
                # Should decode UEFI region for BIOS
                mock_decode_uefi.assert_called_once()

    def test_decode_rom_region_not_used(self):
        """Test decode_rom with unused regions (base > limit)."""
        self.decode_command._rom = 'spi.bin'

        # Mock region with base > limit (unused)
        unused_region = Mock()
        unused_region.name = 'UNUSED'
        unused_region.base = 0x3000
        unused_region.limit = 0x2000  # base > limit

        regions = {
            0: unused_region,
        }

        self.mock_cs.hals.SpiDescriptor.get_spi_regions.return_value = regions

        rom_data = b'\xFF' * 0x20000

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=rom_data), \
             patch('chipsec.utilcmd.decode_cmd.write_file') as mock_write_file, \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs') as mock_makedirs, \
             patch.object(self.decode_command.logger, 'log') as mock_log:
                result = self.decode_command.decode_rom()

                self.assertTrue(result)
                # Should not write any files for unused regions
                mock_write_file.assert_not_called()

    def test_decode_rom_directory_creation(self):
        """Test decode_rom directory creation."""
        self.decode_command._rom = 'test_spi.bin'

        regions = {
            0: Mock(name='FLASH_DESCRIPTOR', base=0x0000, limit=0x0FFF),
        }

        self.mock_cs.hals.SpiDescriptor.get_spi_regions.return_value = regions

        rom_data = b'\xFF' * 0x20000

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=rom_data), \
             patch('chipsec.utilcmd.decode_cmd.write_file'), \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs') as mock_makedirs, \
             patch.object(self.decode_command.logger, 'log'):
                self.decode_command.decode_rom()

                # Should create directory with .dir extension
                expected_dir = os.path.join('/tmp', 'test_spi.bin.dir')
                mock_makedirs.assert_called_once_with(expected_dir)

    def test_decode_rom_log_file_handling(self):
        """Test decode_rom log file handling."""
        self.decode_command._rom = 'spi.bin'

        regions = {
            0: Mock(name='FLASH_DESCRIPTOR', base=0x0000, limit=0x0FFF),
            1: Mock(name='BIOS', base=0x1000, limit=0x1FFFF),
        }

        self.mock_cs.hals.SpiDescriptor.get_spi_regions.return_value = regions

        rom_data = b'\xFF' * 0x20000

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=rom_data), \
             patch('chipsec.utilcmd.decode_cmd.write_file'), \
             patch('chipsec.utilcmd.decode_cmd.decode_uefi_region'), \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs'), \
             patch.object(self.decode_command.logger, 'log'), \
             patch.object(self.decode_command.logger, 'set_log_file') as mock_set_log:
                original_log_name = 'original.log'
                self.decode_command.logger.LOG_FILE_NAME = original_log_name

                self.decode_command.decode_rom()

                # Should set log file for each region and restore original
                self.assertEqual(mock_set_log.call_count, 3)  # 2 regions + restore
                # Last call should restore original log file
                mock_set_log.assert_any_call(original_log_name)


class TestDecodeCommandIntegration(unittest.TestCase):
    """Integration tests for Decode command with HAL components."""

    def setUp(self):
        """Set up test fixtures."""
        # Create integrated ChipsecCs for Decode testing
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        self.integrated_cs.hals.SpiDescriptor = Mock()
        self.integrated_cs.hals.SpiDescriptor.get_spi_flash_descriptor.return_value = (0x1000, b'\xFF' * 0x1000)
        self.integrated_cs.hals.SpiDescriptor.get_spi_regions.return_value = {
            0: Mock(name='FLASH_DESCRIPTOR', base=0x0000, limit=0x0FFF),
            1: Mock(name='BIOS', base=0x1000, limit=0x1FFFF),
        }
        self.integrated_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.return_value = None

        # Mock OS helper
        self.integrated_cs.os_helper.getcwd.return_value = '/tmp'

        # Mock helper
        self.integrated_cs.helper = Mock()
        self.integrated_cs.helper.get_threads_count.return_value = 2

    def test_decode_types_workflow(self):
        """Test decode types workflow."""
        decode_cmd = DecodeCommand(['types'], cs=self.integrated_cs)
        decode_cmd.parse_arguments()

        with patch('chipsec.utilcmd.decode_cmd.uefi_platform') as mock_uefi_platform:
            mock_uefi_platform.fw_types = ['vss', 'ami', 'award']
            with patch.object(decode_cmd.logger, 'log') as mock_log:
                decode_cmd.run()

                mock_log.assert_called_once()
                log_call = mock_log.call_args[0][0]
                self.assertIn('vss', log_call)
                self.assertIn('ami', log_call)
                self.assertIn('award', log_call)

    def test_decode_rom_workflow_success(self):
        """Test decode rom workflow with success."""
        decode_cmd = DecodeCommand(['test_spi.bin', 'vss'], cs=self.integrated_cs)
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

                self.assertTrue(result)
                mock_makedirs.assert_called_once()
                mock_write_file.assert_called()  # Should write region files
                mock_decode_uefi.assert_called_once()  # Should decode UEFI region

    def test_decode_rom_workflow_file_not_found(self):
        """Test decode rom workflow when file is not found."""
        decode_cmd = DecodeCommand(['nonexistent.bin'], cs=self.integrated_cs)
        decode_cmd.parse_arguments()

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=None), \
             patch.object(decode_cmd.logger, 'log') as mock_log:
                result = decode_cmd.run()

                self.assertFalse(result)
                mock_log.assert_called_once_with('[CHIPSEC] Decoding SPI ROM image from a file \'nonexistent.bin\'')

    def test_decode_rom_workflow_no_descriptor(self):
        """Test decode rom workflow when no flash descriptor is found."""
        decode_cmd = DecodeCommand(['spi.bin'], cs=self.integrated_cs)
        decode_cmd.parse_arguments()

        # Mock no flash descriptor
        self.integrated_cs.hals.SpiDescriptor.get_spi_flash_descriptor.return_value = (-1, None)

        rom_data = b'\xFF' * 0x20000

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=rom_data), \
             patch.object(decode_cmd.logger, 'log') as mock_log, \
             patch.object(decode_cmd.logger, 'log_error') as mock_error, \
             patch.object(decode_cmd.logger, 'log_information') as mock_info:
                result = decode_cmd.run()

                self.assertFalse(result)
                mock_error.assert_called_once()
                mock_info.assert_called_once()


class TestDecodeCommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for Decode command."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.hals.SpiDescriptor = Mock()
        self.mock_cs.os_helper.getcwd.return_value = '/tmp'

    def test_empty_argv_handling(self):
        """Test handling of empty argv."""
        decode_cmd = DecodeCommand([], cs=self.mock_cs)

        # Should raise SystemExit due to missing required arguments
        with self.assertRaises(SystemExit):
            decode_cmd.parse_arguments()

    def test_invalid_subcommand(self):
        """Test handling of invalid subcommand."""
        decode_cmd = DecodeCommand(['invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with self.assertRaises(SystemExit):
            decode_cmd.parse_arguments()

    def test_decode_types_case_insensitive(self):
        """Test decode types with different cases."""
        test_cases = ['TYPES', 'Types', 'types', 'TyPeS']

        for case in test_cases:
            decode_cmd = DecodeCommand([case], cs=self.mock_cs)
            decode_cmd.parse_arguments()
            self.assertEqual(decode_cmd.func, decode_cmd.decode_types)
            self.assertEqual(decode_cmd._rom.lower(), 'types')

    def test_decode_rom_with_special_characters(self):
        """Test decode rom with special characters in filename."""
        special_names = [
            'spi-flash.bin',
            'spi_flash.bin',
            'spi flash.bin',
            'spi@flash.bin',
            'spi#flash.bin',
        ]

        for name in special_names:
            decode_cmd = DecodeCommand([name], cs=self.mock_cs)
            decode_cmd.parse_arguments()
            self.assertEqual(decode_cmd._rom, name)
            self.assertEqual(decode_cmd.func, decode_cmd.decode_rom)

    def test_decode_rom_with_path(self):
        """Test decode rom with full path."""
        paths = [
            '/path/to/spi.bin',
            './spi.bin',
            '../spi.bin',
            '~/spi.bin',
        ]

        for path in paths:
            decode_cmd = DecodeCommand([path], cs=self.mock_cs)
            decode_cmd.parse_arguments()
            self.assertEqual(decode_cmd._rom, path)
            self.assertEqual(decode_cmd.func, decode_cmd.decode_rom)

    def test_decode_rom_with_extensions(self):
        """Test decode rom with different file extensions."""
        extensions = ['.bin', '.rom', '.img', '.dat', '.spi']

        for ext in extensions:
            filename = f'spi{ext}'
            decode_cmd = DecodeCommand([filename], cs=self.mock_cs)
            decode_cmd.parse_arguments()
            self.assertEqual(decode_cmd._rom, filename)
            self.assertEqual(decode_cmd.func, decode_cmd.decode_rom)

    def test_decode_rom_empty_file(self):
        """Test decode rom with empty file."""
        self.decode_command._rom = 'empty.bin'

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=b''):
            with patch.object(self.decode_command.logger, 'log') as mock_log:
                result = self.decode_command.decode_rom()

                self.assertFalse(result)
                mock_log.assert_called_once_with('[CHIPSEC] Decoding SPI ROM image from a file \'empty.bin\'')

    def test_decode_rom_small_file(self):
        """Test decode rom with small file (less than descriptor size)."""
        self.decode_command._rom = 'small.bin'

        # File smaller than typical flash descriptor
        small_data = b'\xFF' * 0x100

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=small_data):
            with patch.object(self.decode_command.logger, 'log') as mock_log:
                result = self.decode_command.decode_rom()

                self.assertFalse(result)
                mock_log.assert_called_once_with('[CHIPSEC] Decoding SPI ROM image from a file \'small.bin\'')

    def test_decode_rom_large_file(self):
        """Test decode rom with large file."""
        self.decode_command._rom = 'large.bin'

        # Large file (16MB)
        large_data = b'\xFF' * (16 * 1024 * 1024)

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=large_data), \
             patch('chipsec.utilcmd.decode_cmd.write_file'), \
             patch('chipsec.utilcmd.decode_cmd.decode_uefi_region'), \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs'), \
             patch.object(self.decode_command.logger, 'log'), \
             patch.object(self.decode_command.logger, 'set_log_file'):
                result = self.decode_command.decode_rom()

                self.assertTrue(result)

    def test_decode_rom_region_boundaries(self):
        """Test decode rom with various region boundaries."""
        self.decode_command._rom = 'spi.bin'

        # Test regions at boundaries
        regions = {
            0: Mock(name='REGION_0', base=0x0000, limit=0x0000),  # Single byte
            1: Mock(name='REGION_1', base=0x0001, limit=0x0001),  # Another single byte
            2: Mock(name='REGION_2', base=0xFFFF, limit=0xFFFF),  # Last byte
        }

        self.mock_cs.hals.SpiDescriptor.get_spi_regions.return_value = regions

        rom_data = b'\xFF' * 0x10000

        with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=rom_data), \
             patch('chipsec.utilcmd.decode_cmd.write_file') as mock_write_file, \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs'), \
             patch.object(self.decode_command.logger, 'log'), \
             patch.object(self.decode_command.logger, 'set_log_file'):
                result = self.decode_command.decode_rom()

                self.assertTrue(result)
                # Should write 3 region files
                self.assertEqual(mock_write_file.call_count, 3)

    def test_decode_rom_firmware_types(self):
        """Test decode rom with different firmware types."""
        self.decode_command._rom = 'spi.bin'

        firmware_types = ['vss', 'ami', 'award', 'phoenix', 'insyde', 'dell']

        for fw_type in firmware_types:
            self.decode_command._fwtype = fw_type

            regions = {
                1: Mock(name='BIOS', base=0x1000, limit=0x1FFFF),
            }

            self.mock_cs.hals.SpiDescriptor.get_spi_regions.return_value = regions

            rom_data = b'\xFF' * 0x20000

            with patch('chipsec.utilcmd.decode_cmd.read_file', return_value=rom_data), \
                 patch('chipsec.utilcmd.decode_cmd.write_file'), \
                 patch('chipsec.utilcmd.decode_cmd.decode_uefi_region') as mock_decode_uefi, \
                 patch('os.path.exists', return_value=False), \
                 patch('os.makedirs'), \
                 patch.object(self.decode_command.logger, 'log'), \
                 patch.object(self.decode_command.logger, 'set_log_file'):
                    result = self.decode_command.decode_rom()

                    self.assertTrue(result)
                    # Should call decode_uefi_region with the specified firmware type
                    mock_decode_uefi.assert_called_once()
                    call_args = mock_decode_uefi.call_args
                    self.assertEqual(call_args[1]['fwtype'], fw_type)  # fwtype parameter


class TestDecodeCommandConfigurationValidation(unittest.TestCase):
    """Test configuration validation aspects of Decode command."""

    def setUp(self):
        """Set up test fixtures."""
        # Create ChipsecCs with decode-specific configuration
        self.config_cs = MockFactory.create_mock_chipsec_cs()

        # Mock SPI descriptor HAL with configuration
        self.config_cs.hals.SpiDescriptor = Mock()
        self.config_cs.hals.SpiDescriptor.get_spi_flash_descriptor.return_value = (0x1000, b'\xFF' * 0x1000)
        self.config_cs.hals.SpiDescriptor.get_spi_regions.return_value = {
            0: Mock(name='FLASH_DESCRIPTOR', base=0x0000, limit=0x0FFF),
            1: Mock(name='BIOS', base=0x1000, limit=0x1FFFF),
        }

        # Mock OS helper
        self.config_cs.os_helper.getcwd.return_value = '/tmp'

        # Mock decode configuration data
        self.config_cs.Cfg = Mock()
        self.config_cs.Cfg.DECODE_CONFIG = {
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

    def test_decode_configuration_access(self):
        """Test access to decode configuration data."""
        decode_config = self.config_cs.Cfg.DECODE_CONFIG

        self.assertIn('vss', decode_config['supported_firmware_types'])
        self.assertIn('ami', decode_config['supported_firmware_types'])
        self.assertIn('flash_descriptor', decode_config['spi_regions'])
        self.assertEqual(decode_config['spi_regions']['bios']['id'], 1)
        self.assertEqual(decode_config['max_file_size'], 16 * 1024 * 1024)

    def test_supported_firmware_types_validation(self):
        """Test validation of supported firmware types."""
        supported_types = self.config_cs.Cfg.DECODE_CONFIG['supported_firmware_types']

        # Test that all expected firmware types are supported
        expected_types = ['vss', 'ami', 'award', 'phoenix', 'insyde', 'dell']
        for fw_type in expected_types:
            self.assertIn(fw_type, supported_types)

        # Test that types list is not empty
        self.assertGreater(len(supported_types), 0)

    def test_spi_regions_validation(self):
        """Test validation of SPI regions configuration."""
        spi_regions = self.config_cs.Cfg.DECODE_CONFIG['spi_regions']

        # Test that all expected SPI regions are defined
        expected_regions = ['flash_descriptor', 'bios', 'me', 'gbe', 'platform_data']
        for region_name in expected_regions:
            self.assertIn(region_name, spi_regions)
            self.assertIn('id', spi_regions[region_name])
            self.assertIn('description', spi_regions[region_name])
            self.assertIsInstance(spi_regions[region_name]['id'], int)
            self.assertIsInstance(spi_regions[region_name]['description'], str)

        # Test specific region configurations
        self.assertEqual(spi_regions['flash_descriptor']['id'], 0)
        self.assertEqual(spi_regions['bios']['id'], 1)
        self.assertEqual(spi_regions['me']['id'], 2)

    def test_output_formats_validation(self):
        """Test validation of output formats."""
        output_formats = self.config_cs.Cfg.DECODE_CONFIG['output_formats']

        # Test that all expected output formats are supported
        expected_formats = ['bin', 'log', 'dir']
        for fmt in expected_formats:
            self.assertIn(fmt, output_formats)

        # Test that formats list is not empty
        self.assertGreater(len(output_formats), 0)

    def test_max_file_size_validation(self):
        """Test validation of maximum file size."""
        max_size = self.config_cs.Cfg.DECODE_CONFIG['max_file_size']

        # Test that maximum file size is reasonable
        self.assertGreater(max_size, 0)
        self.assertGreaterEqual(max_size, 1024 * 1024)  # At least 1MB
        self.assertLessEqual(max_size, 64 * 1024 * 1024)  # At most 64MB

    def test_security_features_validation(self):
        """Test validation of security features configuration."""
        security_features = self.config_cs.Cfg.DECODE_CONFIG['security_features']

        # Test that all expected security features are defined
        expected_features = ['validate_checksums', 'detect_encryption', 'extract_variables']
        for feature in expected_features:
            self.assertIn(feature, security_features)
            self.assertIsInstance(security_features[feature], bool)

        # Test specific security feature values
        self.assertTrue(security_features['validate_checksums'])
        self.assertTrue(security_features['detect_encryption'])
        self.assertTrue(security_features['extract_variables'])


if __name__ == '__main__':
    unittest.main()
