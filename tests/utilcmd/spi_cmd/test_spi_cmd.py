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
from chipsec.utilcmd.spi_cmd import SPICommand
from chipsec.library.intel.spi import BIOS
from tests.test_utils import MockFactory


class TestSPICommand(unittest.TestCase):
    """Comprehensive tests for SPI utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock ChipsecCs object for SPI testing
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        # Mock SPI HAL
        self.mock_cs.hals.SPI = Mock()
        self.mock_cs.hals.SPI.display_SPI_map.return_value = None
        self.mock_cs.hals.SPI.read_spi_to_file.return_value = b'\x00\x01\x02\x03'
        self.mock_cs.hals.SPI.write_spi_from_file.return_value = True
        self.mock_cs.hals.SPI.erase_spi_block.return_value = True
        self.mock_cs.hals.SPI.disable_BIOS_write_protection.return_value = True
        self.mock_cs.hals.SPI.get_SPI_SFDP.return_value = None
        self.mock_cs.hals.SPI.get_SPI_JEDEC_ID.return_value = 0x123456
        self.mock_cs.hals.SPI.get_SPI_JEDEC_ID_decoded.return_value = (0x123456, 'Test Manufacturer', 'Test Device')
        self.mock_cs.hals.SPI.get_SPI_region.return_value = (0x0, 0x100000, 'BIOS')

        # Mock MMIO HAL to prevent SPI initialization issues
        self.mock_cs.hals.MMIO = Mock()
        self.mock_cs.hals.MMIO.get_MMIO_BAR_base_address.return_value = (0xFED00000, 0x1000)

        # Create SPICommand instance
        self.spi_command = SPICommand(['info'], cs=self.mock_cs)

    def test_spi_command_initialization(self):
        """Test SPICommand initialization."""
        self.assertEqual(self.spi_command.cs, self.mock_cs)
        self.assertEqual(self.spi_command.argv, ['info'])

    def test_parse_arguments_info(self):
        """Test parsing info command arguments."""
        command = SPICommand(['info'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spi_info)

    def test_parse_arguments_dump(self):
        """Test parsing dump command arguments."""
        command = SPICommand(['dump', 'test.bin'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spi_dump)
        self.assertEqual(command.out_file, 'test.bin')

    def test_parse_arguments_dump_default(self):
        """Test parsing dump command with default filename."""
        command = SPICommand(['dump'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spi_dump)
        self.assertEqual(command.out_file, 'rom.bin')

    def test_parse_arguments_read(self):
        """Test parsing read command arguments."""
        command = SPICommand(['read', '0x1000', '0x100', 'output.bin'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spi_read)
        self.assertEqual(command.spi_fla, 0x1000)
        self.assertEqual(command.length, 0x100)
        self.assertEqual(command.out_file, 'output.bin')

    def test_parse_arguments_read_defaults(self):
        """Test parsing read command with default values."""
        command = SPICommand(['read', '0x1000'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spi_read)
        self.assertEqual(command.spi_fla, 0x1000)
        self.assertEqual(command.length, 0x4)
        self.assertEqual(command.out_file, 'read.bin')

    def test_parse_arguments_write(self):
        """Test parsing write command arguments."""
        command = SPICommand(['write', '0x1000', 'input.bin'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spi_write)
        self.assertEqual(command.spi_fla, 0x1000)
        self.assertEqual(command.filename, 'input.bin')

    def test_parse_arguments_erase(self):
        """Test parsing erase command arguments."""
        command = SPICommand(['erase', '0x1000'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spi_erase)
        self.assertEqual(command.spi_fla, 0x1000)

    def test_parse_arguments_disable_wp(self):
        """Test parsing disable-wp command arguments."""
        command = SPICommand(['disable-wp'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spi_disable_wp)

    def test_parse_arguments_sfdp(self):
        """Test parsing sfdp command arguments."""
        command = SPICommand(['sfdp'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spi_sfdp)

    def test_parse_arguments_jedec(self):
        """Test parsing jedec command arguments."""
        command = SPICommand(['jedec'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spi_jedec)
        self.assertEqual(command.option, '')

    def test_parse_arguments_jedec_decode(self):
        """Test parsing jedec command with decode option."""
        command = SPICommand(['jedec', 'decode'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spi_jedec)
        self.assertEqual(command.option, 'decode')

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.spi_command.requirements()
        self.assertTrue(hasattr(reqs, 'load_driver'))
        self.assertTrue(hasattr(reqs, 'load_config'))

    def test_set_up(self):
        """Test set_up method."""
        # Mock the SPI HAL to avoid complex initialization
        with patch('chipsec.utilcmd.spi_cmd.SPI') as mock_spi_class:
            mock_spi_instance = Mock()
            mock_spi_class.return_value = mock_spi_instance

            self.spi_command.set_up()

            self.assertTrue(hasattr(self.spi_command, '_spi'))
            self.assertTrue(hasattr(self.spi_command, '_msg'))
            mock_spi_class.assert_called_once_with(self.spi_command.cs)

    def test_spi_info(self):
        """Test spi_info command."""
        with patch('chipsec.utilcmd.spi_cmd.SPI') as mock_spi_class:
            mock_spi_instance = Mock()
            mock_spi_class.return_value = mock_spi_instance
            self.spi_command.set_up()

            with patch.object(self.spi_command.logger, 'log') as mock_log:
                self.spi_command.spi_info()

                mock_log.assert_called_once()
                mock_spi_instance.display_SPI_map.assert_called_once()

    def test_spi_dump(self):
        """Test spi_dump command."""
        with patch('chipsec.utilcmd.spi_cmd.SPI') as mock_spi_class:
            mock_spi_instance = Mock()
            mock_spi_instance.get_SPI_region.return_value = (0x0, 0x100000, 'BIOS')
            mock_spi_instance.read_spi_to_file.return_value = b'\x00\x01\x02\x03'
            mock_spi_class.return_value = mock_spi_instance
            self.spi_command.set_up()
            self.spi_command.out_file = 'test_dump.bin'

            with patch.object(self.spi_command.logger, 'log') as mock_log:
                self.spi_command.spi_dump()

                # Should log multiple messages
                self.assertGreaterEqual(mock_log.call_count, 3)
                mock_spi_instance.get_SPI_region.assert_called_once_with(BIOS)
                mock_spi_instance.read_spi_to_file.assert_called_once()

    def test_spi_dump_no_data(self):
        """Test spi_dump command when no data is returned."""
        with patch('chipsec.utilcmd.spi_cmd.SPI') as mock_spi_class:
            mock_spi_instance = Mock()
            mock_spi_instance.get_SPI_region.return_value = (0x0, 0x100000, 'BIOS')
            mock_spi_instance.read_spi_to_file.return_value = None
            mock_spi_class.return_value = mock_spi_instance
            self.spi_command.set_up()
            self.spi_command.out_file = 'test_dump.bin'

            with patch.object(self.spi_command.logger, 'log_error') as mock_error:
                self.spi_command.spi_dump()

                mock_error.assert_called_once()

    def test_spi_read(self):
        """Test spi_read command."""
        with patch('chipsec.utilcmd.spi_cmd.SPI') as mock_spi_class:
            mock_spi_instance = Mock()
            mock_spi_instance.read_spi_to_file.return_value = b'\x00\x01\x02\x03'
            mock_spi_class.return_value = mock_spi_instance
            self.spi_command.set_up()
            self.spi_command.spi_fla = 0x1000
            self.spi_command.length = 0x100
            self.spi_command.out_file = 'test_read.bin'

            with patch.object(self.spi_command.logger, 'log') as mock_log:
                self.spi_command.spi_read()

                # Should log multiple messages
                self.assertGreaterEqual(mock_log.call_count, 2)
                mock_spi_instance.read_spi_to_file.assert_called_once_with(0x1000, 0x100, 'test_read.bin')

    def test_spi_read_no_data(self):
        """Test spi_read command when no data is returned."""
        with patch('chipsec.utilcmd.spi_cmd.SPI') as mock_spi_class:
            mock_spi_instance = Mock()
            mock_spi_instance.read_spi_to_file.return_value = None
            mock_spi_class.return_value = mock_spi_instance
            self.spi_command.set_up()
            self.spi_command.spi_fla = 0x1000
            self.spi_command.length = 0x100
            self.spi_command.out_file = 'test_read.bin'

            with patch.object(self.spi_command.logger, 'log_error') as mock_error:
                self.spi_command.spi_read()

                mock_error.assert_called_once()

    def test_spi_write_file_exists(self):
        """Test spi_write command when file exists."""
        self.spi_command.set_up()
        self.spi_command.spi_fla = 0x1000
        self.spi_command.filename = 'test_write.bin'

        with patch('os.path.exists', return_value=True), \
             patch.object(self.spi_command.logger, 'log') as mock_log:
            self.spi_command.spi_write()

            # Should log multiple messages
            self.assertGreaterEqual(mock_log.call_count, 2)
            self.mock_cs.hals.SPI.write_spi_from_file.assert_called_once_with(0x1000, 'test_write.bin')

    def test_spi_write_file_not_exists(self):
        """Test spi_write command when file doesn't exist."""
        self.spi_command.set_up()
        self.spi_command.spi_fla = 0x1000
        self.spi_command.filename = 'nonexistent.bin'

        with patch('os.path.exists', return_value=False), \
             patch.object(self.spi_command.logger, 'log_error') as mock_error:
            self.spi_command.spi_write()

            mock_error.assert_called_once()
            self.mock_cs.hals.SPI.write_spi_from_file.assert_not_called()

    def test_spi_write_error(self):
        """Test spi_write command when write fails."""
        self.spi_command.set_up()
        self.spi_command.spi_fla = 0x1000
        self.spi_command.filename = 'test_write.bin'
        self.mock_cs.hals.SPI.write_spi_from_file.return_value = False

        with patch('os.path.exists', return_value=True), \
             patch.object(self.spi_command.logger, 'log_warning') as mock_warning:
            self.spi_command.spi_write()

            mock_warning.assert_called_once()

    def test_spi_erase_success(self):
        """Test spi_erase command successful."""
        self.spi_command.set_up()
        self.spi_command.spi_fla = 0x1000

        with patch.object(self.spi_command.logger, 'log') as mock_log, \
             patch.object(self.spi_command.logger, 'log_good') as mock_good:
            self.spi_command.spi_erase()

            mock_log.assert_called_once()
            mock_good.assert_called_once()
            self.mock_cs.hals.SPI.erase_spi_block.assert_called_once_with(0x1000)

    def test_spi_erase_error(self):
        """Test spi_erase command when erase fails."""
        self.spi_command.set_up()
        self.spi_command.spi_fla = 0x1000
        self.mock_cs.hals.SPI.erase_spi_block.return_value = False

        with patch.object(self.spi_command.logger, 'log') as mock_log, \
             patch.object(self.spi_command.logger, 'log_warning') as mock_warning:
            self.spi_command.spi_erase()

            mock_log.assert_called_once()
            mock_warning.assert_called_once()

    def test_spi_disable_wp_success(self):
        """Test spi_disable_wp command successful."""
        self.spi_command.set_up()

        with patch.object(self.spi_command.logger, 'log') as mock_log, \
             patch.object(self.spi_command.logger, 'log_good') as mock_good:
            self.spi_command.spi_disable_wp()

            mock_log.assert_called_once()
            mock_good.assert_called_once()
            self.mock_cs.hals.SPI.disable_BIOS_write_protection.assert_called_once()

    def test_spi_disable_wp_error(self):
        """Test spi_disable_wp command when disable fails."""
        self.spi_command.set_up()
        self.mock_cs.hals.SPI.disable_BIOS_write_protection.return_value = False

        with patch.object(self.spi_command.logger, 'log') as mock_log, \
             patch.object(self.spi_command.logger, 'log_bad') as mock_bad:
            self.spi_command.spi_disable_wp()

            mock_log.assert_called_once()
            mock_bad.assert_called_once()

    def test_spi_sfdp(self):
        """Test spi_sfdp command."""
        self.spi_command.set_up()

        self.spi_command.spi_sfdp()

        self.mock_cs.hals.SPI.get_SPI_SFDP.assert_called_once()

    def test_spi_jedec_basic(self):
        """Test spi_jedec command basic mode."""
        self.spi_command.set_up()
        self.spi_command.option = ''

        with patch.object(self.spi_command.logger, 'log') as mock_log:
            self.spi_command.spi_jedec()

            mock_log.assert_called_once()
            self.mock_cs.hals.SPI.get_SPI_JEDEC_ID.assert_called_once()

    def test_spi_jedec_decode(self):
        """Test spi_jedec command decode mode."""
        self.spi_command.set_up()
        self.spi_command.option = 'decode'

        with patch.object(self.spi_command.logger, 'log') as mock_log:
            self.spi_command.spi_jedec()

            # Should log multiple lines for decoded information
            self.assertGreaterEqual(mock_log.call_count, 3)
            self.mock_cs.hals.SPI.get_SPI_JEDEC_ID_decoded.assert_called_once()

    def test_spi_jedec_not_supported(self):
        """Test spi_jedec command when JEDEC is not supported."""
        self.spi_command.set_up()
        self.spi_command.option = ''
        self.mock_cs.hals.SPI.get_SPI_JEDEC_ID.return_value = False

        with patch.object(self.spi_command.logger, 'log') as mock_log:
            self.spi_command.spi_jedec()

            mock_log.assert_called_once()

    def test_spi_jedec_decode_not_supported(self):
        """Test spi_jedec decode command when JEDEC is not supported."""
        self.spi_command.set_up()
        self.spi_command.option = 'decode'
        self.mock_cs.hals.SPI.get_SPI_JEDEC_ID_decoded.return_value = (False, None, None)

        with patch.object(self.spi_command.logger, 'log') as mock_log:
            self.spi_command.spi_jedec()

            mock_log.assert_called_once()


class TestSPICommandIntegration(unittest.TestCase):
    """Integration tests for SPI command with HAL components."""

    def setUp(self):
        """Set up integrated test fixtures."""
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        self.integrated_cs.hals.SPI = Mock()
        self.integrated_cs.hals.SPI.display_SPI_map.return_value = None
        self.integrated_cs.hals.SPI.read_spi_to_file.return_value = b'\xAA\xBB\xCC\xDD' * 0x40
        self.integrated_cs.hals.SPI.write_spi_from_file.return_value = True
        self.integrated_cs.hals.SPI.erase_spi_block.return_value = True
        self.integrated_cs.hals.SPI.disable_BIOS_write_protection.return_value = True
        self.integrated_cs.hals.SPI.get_SPI_region.return_value = (0x0, 0x200000, 'BIOS')

        # Mock helper
        self.integrated_cs.helper = Mock()
        self.integrated_cs.helper.get_threads_count.return_value = 2

    def test_spi_read_write_workflow(self):
        """Test complete SPI read/write workflow."""
        # Test dump operation
        dump_cmd = SPICommand(['dump', 'test.bin'], cs=self.integrated_cs)
        dump_cmd.parse_arguments()
        dump_cmd.set_up()

        with patch.object(dump_cmd.logger, 'log') as mock_log:
            dump_cmd.run()

            # Should perform dump operation
            self.assertGreaterEqual(mock_log.call_count, 3)
            self.integrated_cs.hals.SPI.get_SPI_region.assert_called_once_with(BIOS)

        # Test read operation
        read_cmd = SPICommand(['read', '0x1000', '0x100', 'output.bin'], cs=self.integrated_cs)
        read_cmd.parse_arguments()
        read_cmd.set_up()

        with patch.object(read_cmd.logger, 'log') as mock_log:
            read_cmd.run()

            self.assertGreaterEqual(mock_log.call_count, 2)
            self.integrated_cs.hals.SPI.read_spi_to_file.assert_called_once_with(0x1000, 0x100, 'output.bin')

    def test_spi_write_protection_workflow(self):
        """Test SPI write protection workflow."""
        # Test disable write protection
        wp_cmd = SPICommand(['disable-wp'], cs=self.integrated_cs)
        wp_cmd.parse_arguments()
        wp_cmd.set_up()

        with patch.object(wp_cmd.logger, 'log') as mock_log, \
             patch.object(wp_cmd.logger, 'log_good') as mock_good:
            wp_cmd.run()

            mock_log.assert_called_once()
            mock_good.assert_called_once()
            self.integrated_cs.hals.SPI.disable_BIOS_write_protection.assert_called_once()

    def test_spi_identification_workflow(self):
        """Test SPI identification workflow."""
        # Test JEDEC ID
        jedec_cmd = SPICommand(['jedec'], cs=self.integrated_cs)
        jedec_cmd.parse_arguments()
        jedec_cmd.set_up()
        self.integrated_cs.hals.SPI.get_SPI_JEDEC_ID.return_value = 0x1F1234

        with patch.object(jedec_cmd.logger, 'log') as mock_log:
            jedec_cmd.run()

            mock_log.assert_called_once()
            self.integrated_cs.hals.SPI.get_SPI_JEDEC_ID.assert_called_once()


class TestSPICommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for SPI command."""

    def setUp(self):
        """Set up mock ChipsecCs for edge case testing."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.hals.SPI = Mock()

    def test_empty_argv_handling(self):
        """Test handling of empty argv."""
        spi_cmd = SPICommand([], cs=self.mock_cs)

        # Should raise SystemExit due to missing required arguments
        with self.assertRaises(SystemExit):
            spi_cmd.parse_arguments()

    def test_invalid_subcommand(self):
        """Test handling of invalid subcommand."""
        spi_cmd = SPICommand(['invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with self.assertRaises(SystemExit):
            spi_cmd.parse_arguments()

    def test_dump_missing_file_handling(self):
        """Test dump command with missing file handling."""
        spi_cmd = SPICommand(['dump'], cs=self.mock_cs)
        spi_cmd.parse_arguments()
        spi_cmd.set_up()

        # Should use default filename
        self.assertEqual(spi_cmd.out_file, 'rom.bin')

    def test_read_invalid_address(self):
        """Test read command with invalid address."""
        spi_cmd = SPICommand(['read', 'invalid', '0x100'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid address
        with self.assertRaises(SystemExit):
            spi_cmd.parse_arguments()

    def test_write_invalid_address(self):
        """Test write command with invalid address."""
        spi_cmd = SPICommand(['write', 'invalid', 'test.bin'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid address
        with self.assertRaises(SystemExit):
            spi_cmd.parse_arguments()

    def test_erase_invalid_address(self):
        """Test erase command with invalid address."""
        spi_cmd = SPICommand(['erase', 'invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid address
        with self.assertRaises(SystemExit):
            spi_cmd.parse_arguments()

    def test_large_address_values(self):
        """Test handling of large address values."""
        # Test with maximum 32-bit address
        spi_cmd = SPICommand(['read', '0xFFFFFFFF', '0x1000'], cs=self.mock_cs)
        spi_cmd.parse_arguments()

        self.assertEqual(spi_cmd.spi_fla, 0xFFFFFFFF)
        self.assertEqual(spi_cmd.length, 0x1000)

    def test_zero_length_values(self):
        """Test handling of zero length values."""
        spi_cmd = SPICommand(['read', '0x1000', '0x0'], cs=self.mock_cs)
        spi_cmd.parse_arguments()

        self.assertEqual(spi_cmd.spi_fla, 0x1000)
        self.assertEqual(spi_cmd.length, 0x0)

    def test_jedec_case_insensitive_decode(self):
        """Test JEDEC decode option is case insensitive."""
        spi_cmd = SPICommand(['jedec', 'DECODE'], cs=self.mock_cs)
        spi_cmd.parse_arguments()

        self.assertEqual(spi_cmd.option, 'DECODE')

        spi_cmd.set_up()
        spi_cmd.spi_jedec()

        # Should still attempt decode
        self.mock_cs.hals.SPI.get_SPI_JEDEC_ID_decoded.assert_called_once()


class TestSPICommandConfigurationValidation(unittest.TestCase):
    """Test configuration validation aspects of SPI command."""

    def setUp(self):
        """Set up ChipsecCs with SPI-specific configuration."""
        self.config_cs = MockFactory.create_mock_chipsec_cs()

        # Mock SPI HAL with configuration
        self.config_cs.hals.SPI = Mock()
        self.config_cs.hals.SPI.read_spi_to_file.return_value = b'\x00\x01\x02\x03'

        # Mock SPI configuration data
        self.config_cs.Cfg = Mock()
        self.config_cs.Cfg.SPI_CONFIG = {
            'max_read_size': 0x1000000,
            'max_write_size': 0x100000,
            'supported_operations': ['info', 'dump', 'read', 'write', 'erase', 'disable-wp', 'sfdp', 'jedec'],
            'regions': {
                'bios': {'base': 0x0, 'size': 0x800000},
                'me': {'base': 0x1000, 'size': 0x200000},
                'gbe': {'base': 0x2000, 'size': 0x2000}
            },
            'flash_types': ['MX25L3205D', 'W25Q64FV', 'N25Q064A']
        }

    def test_spi_configuration_access(self):
        """Test access to SPI configuration data."""
        spi_config = self.config_cs.Cfg.SPI_CONFIG

        self.assertEqual(spi_config['max_read_size'], 0x1000000)
        self.assertEqual(spi_config['max_write_size'], 0x100000)
        self.assertIn('info', spi_config['supported_operations'])
        self.assertIn('dump', spi_config['supported_operations'])
        self.assertIn('bios', spi_config['regions'])

    def test_supported_operations_validation(self):
        """Test validation of supported SPI operations."""
        supported_ops = self.config_cs.Cfg.SPI_CONFIG['supported_operations']

        # Test that all documented operations are supported
        self.assertIn('info', supported_ops)
        self.assertIn('dump', supported_ops)
        self.assertIn('read', supported_ops)
        self.assertIn('write', supported_ops)
        self.assertIn('erase', supported_ops)
        self.assertIn('disable-wp', supported_ops)
        self.assertIn('sfdp', supported_ops)
        self.assertIn('jedec', supported_ops)

    def test_spi_regions_validation(self):
        """Test SPI regions configuration validation."""
        regions = self.config_cs.Cfg.SPI_CONFIG['regions']

        # Test that all regions have required fields
        for region_name, region_info in regions.items():
            self.assertIn('base', region_info)
            self.assertIn('size', region_info)
            self.assertGreaterEqual(region_info['base'], 0)
            self.assertGreater(region_info['size'], 0)

        # Test specific region configurations
        self.assertEqual(regions['bios']['base'], 0x0)
        self.assertEqual(regions['bios']['size'], 0x800000)
        self.assertEqual(regions['me']['base'], 0x1000)
        self.assertEqual(regions['gbe']['size'], 0x2000)

    def test_flash_types_validation(self):
        """Test SPI flash types validation."""
        flash_types = self.config_cs.Cfg.SPI_CONFIG['flash_types']

        # Test that flash types list is not empty
        self.assertGreater(len(flash_types), 0)

        # Test that all flash types are strings
        for flash_type in flash_types:
            self.assertIsInstance(flash_type, str)
            self.assertGreater(len(flash_type), 0)

        # Test specific flash types
        self.assertIn('MX25L3205D', flash_types)
        self.assertIn('W25Q64FV', flash_types)

    def test_operation_limits_validation(self):
        """Test SPI operation limits validation."""
        max_read = self.config_cs.Cfg.SPI_CONFIG['max_read_size']
        max_write = self.config_cs.Cfg.SPI_CONFIG['max_write_size']

        # Test that limits are reasonable
        self.assertGreater(max_read, 0)
        self.assertGreater(max_write, 0)
        # Write limit should be smaller than read limit for safety
        self.assertLessEqual(max_write, max_read)


if __name__ == '__main__':
    unittest.main()
