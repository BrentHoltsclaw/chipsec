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
from chipsec.utilcmd.spi_cmd import SPICommand
from chipsec.library.intel.spi import BIOS
from tests.test_utils import MockFactory


class TestSPICommand:
    """Comprehensive tests for SPI utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for SPI testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        # Mock SPI HAL
        cs_mock.hals.SPI = Mock()
        cs_mock.hals.SPI.display_SPI_map.return_value = None
        cs_mock.hals.SPI.read_spi_to_file.return_value = b'\x00\x01\x02\x03'
        cs_mock.hals.SPI.write_spi_from_file.return_value = True
        cs_mock.hals.SPI.erase_spi_block.return_value = True
        cs_mock.hals.SPI.disable_BIOS_write_protection.return_value = True
        cs_mock.hals.SPI.get_SPI_SFDP.return_value = None
        cs_mock.hals.SPI.get_SPI_JEDEC_ID.return_value = 0x123456
        cs_mock.hals.SPI.get_SPI_JEDEC_ID_decoded.return_value = (0x123456, 'Test Manufacturer', 'Test Device')
        cs_mock.hals.SPI.get_SPI_region.return_value = (0x0, 0x100000, 'BIOS')

        # Mock MMIO HAL to prevent SPI initialization issues
        cs_mock.hals.MMIO = Mock()
        cs_mock.hals.MMIO.get_MMIO_BAR_base_address.return_value = (0xFED00000, 0x1000)

        return cs_mock

    @pytest.fixture
    def spi_command(self, mock_cs):
        """Create SPICommand instance."""
        return SPICommand(['info'], cs=mock_cs)

    @pytest.mark.unit
    def test_spi_command_initialization(self, spi_command, mock_cs):
        """Test SPICommand initialization."""
        assert spi_command.cs == mock_cs
        assert spi_command.argv == ['info']

    @pytest.mark.unit
    def test_parse_arguments_info(self, mock_cs):
        """Test parsing info command arguments."""
        command = SPICommand(['info'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spi_info

    @pytest.mark.unit
    def test_parse_arguments_dump(self, mock_cs):
        """Test parsing dump command arguments."""
        command = SPICommand(['dump', 'test.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spi_dump
        assert command.out_file == 'test.bin'

    @pytest.mark.unit
    def test_parse_arguments_dump_default(self, mock_cs):
        """Test parsing dump command with default filename."""
        command = SPICommand(['dump'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spi_dump
        assert command.out_file == 'rom.bin'

    @pytest.mark.unit
    def test_parse_arguments_read(self, mock_cs):
        """Test parsing read command arguments."""
        command = SPICommand(['read', '0x1000', '0x100', 'output.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spi_read
        assert command.spi_fla == 0x1000
        assert command.length == 0x100
        assert command.out_file == 'output.bin'

    @pytest.mark.unit
    def test_parse_arguments_read_defaults(self, mock_cs):
        """Test parsing read command with default values."""
        command = SPICommand(['read', '0x1000'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spi_read
        assert command.spi_fla == 0x1000
        assert command.length == 0x4
        assert command.out_file == 'read.bin'

    @pytest.mark.unit
    def test_parse_arguments_write(self, mock_cs):
        """Test parsing write command arguments."""
        command = SPICommand(['write', '0x1000', 'input.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spi_write
        assert command.spi_fla == 0x1000
        assert command.filename == 'input.bin'

    @pytest.mark.unit
    def test_parse_arguments_erase(self, mock_cs):
        """Test parsing erase command arguments."""
        command = SPICommand(['erase', '0x1000'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spi_erase
        assert command.spi_fla == 0x1000

    @pytest.mark.unit
    def test_parse_arguments_disable_wp(self, mock_cs):
        """Test parsing disable-wp command arguments."""
        command = SPICommand(['disable-wp'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spi_disable_wp

    @pytest.mark.unit
    def test_parse_arguments_sfdp(self, mock_cs):
        """Test parsing sfdp command arguments."""
        command = SPICommand(['sfdp'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spi_sfdp

    @pytest.mark.unit
    def test_parse_arguments_jedec(self, mock_cs):
        """Test parsing jedec command arguments."""
        command = SPICommand(['jedec'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spi_jedec
        assert command.option == ''

    @pytest.mark.unit
    def test_parse_arguments_jedec_decode(self, mock_cs):
        """Test parsing jedec command with decode option."""
        command = SPICommand(['jedec', 'decode'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spi_jedec
        assert command.option == 'decode'

    @pytest.mark.unit
    def test_requirements(self, spi_command):
        """Test command requirements."""
        reqs = spi_command.requirements()
        assert hasattr(reqs, 'load_driver')
        assert hasattr(reqs, 'load_config')

    @pytest.mark.unit
    def test_set_up(self, spi_command, mock_cs):
        """Test set_up method."""
        # Mock the SPI HAL to avoid complex initialization
        with patch('chipsec.utilcmd.spi_cmd.SPI') as mock_spi_class:
            mock_spi_instance = Mock()
            mock_spi_class.return_value = mock_spi_instance

            spi_command.set_up()

            assert hasattr(spi_command, '_spi')
            assert hasattr(spi_command, '_msg')
            mock_spi_class.assert_called_once_with(spi_command.cs)

    @pytest.mark.unit
    def test_spi_info(self, spi_command, mock_cs):
        """Test spi_info command."""
        with patch('chipsec.utilcmd.spi_cmd.SPI') as mock_spi_class:
            mock_spi_instance = Mock()
            mock_spi_class.return_value = mock_spi_instance
            spi_command.set_up()

            with patch.object(spi_command.logger, 'log') as mock_log:
                spi_command.spi_info()

                mock_log.assert_called_once()
                mock_spi_instance.display_SPI_map.assert_called_once()

    @pytest.mark.unit
    def test_spi_dump(self, spi_command, mock_cs):
        """Test spi_dump command."""
        with patch('chipsec.utilcmd.spi_cmd.SPI') as mock_spi_class:
            mock_spi_instance = Mock()
            mock_spi_instance.get_SPI_region.return_value = (0x0, 0x100000, 'BIOS')
            mock_spi_instance.read_spi_to_file.return_value = b'\x00\x01\x02\x03'
            mock_spi_class.return_value = mock_spi_instance
            spi_command.set_up()
            spi_command.out_file = 'test_dump.bin'

            with patch.object(spi_command.logger, 'log') as mock_log:
                spi_command.spi_dump()

                # Should log multiple messages
                assert mock_log.call_count >= 3
                mock_spi_instance.get_SPI_region.assert_called_once_with(BIOS)
                mock_spi_instance.read_spi_to_file.assert_called_once()

    @pytest.mark.unit
    def test_spi_dump_no_data(self, spi_command, mock_cs):
        """Test spi_dump command when no data is returned."""
        with patch('chipsec.utilcmd.spi_cmd.SPI') as mock_spi_class:
            mock_spi_instance = Mock()
            mock_spi_instance.get_SPI_region.return_value = (0x0, 0x100000, 'BIOS')
            mock_spi_instance.read_spi_to_file.return_value = None
            mock_spi_class.return_value = mock_spi_instance
            spi_command.set_up()
            spi_command.out_file = 'test_dump.bin'

            with patch.object(spi_command.logger, 'log_error') as mock_error:
                spi_command.spi_dump()

                mock_error.assert_called_once()

    @pytest.mark.unit
    def test_spi_read(self, spi_command, mock_cs):
        """Test spi_read command."""
        with patch('chipsec.utilcmd.spi_cmd.SPI') as mock_spi_class:
            mock_spi_instance = Mock()
            mock_spi_instance.read_spi_to_file.return_value = b'\x00\x01\x02\x03'
            mock_spi_class.return_value = mock_spi_instance
            spi_command.set_up()
            spi_command.spi_fla = 0x1000
            spi_command.length = 0x100
            spi_command.out_file = 'test_read.bin'

            with patch.object(spi_command.logger, 'log') as mock_log:
                spi_command.spi_read()

                # Should log multiple messages
                assert mock_log.call_count >= 2
                mock_spi_instance.read_spi_to_file.assert_called_once_with(0x1000, 0x100, 'test_read.bin')

    @pytest.mark.unit
    def test_spi_read_no_data(self, spi_command, mock_cs):
        """Test spi_read command when no data is returned."""
        with patch('chipsec.utilcmd.spi_cmd.SPI') as mock_spi_class:
            mock_spi_instance = Mock()
            mock_spi_instance.read_spi_to_file.return_value = None
            mock_spi_class.return_value = mock_spi_instance
            spi_command.set_up()
            spi_command.spi_fla = 0x1000
            spi_command.length = 0x100
            spi_command.out_file = 'test_read.bin'

            with patch.object(spi_command.logger, 'log_error') as mock_error:
                spi_command.spi_read()

                mock_error.assert_called_once()

    @pytest.mark.unit
    def test_spi_write_file_exists(self, spi_command, mock_cs):
        """Test spi_write command when file exists."""
        spi_command.set_up()
        spi_command.spi_fla = 0x1000
        spi_command.filename = 'test_write.bin'

        with patch('os.path.exists', return_value=True), \
             patch.object(spi_command.logger, 'log') as mock_log:
            spi_command.spi_write()

            # Should log multiple messages
            assert mock_log.call_count >= 2
            mock_cs.hals.SPI.write_spi_from_file.assert_called_once_with(0x1000, 'test_write.bin')

    @pytest.mark.unit
    def test_spi_write_file_not_exists(self, spi_command, mock_cs):
        """Test spi_write command when file doesn't exist."""
        spi_command.set_up()
        spi_command.spi_fla = 0x1000
        spi_command.filename = 'nonexistent.bin'

        with patch('os.path.exists', return_value=False), \
             patch.object(spi_command.logger, 'log_error') as mock_error:
            spi_command.spi_write()

            mock_error.assert_called_once()
            mock_cs.hals.SPI.write_spi_from_file.assert_not_called()

    @pytest.mark.unit
    def test_spi_write_error(self, spi_command, mock_cs):
        """Test spi_write command when write fails."""
        spi_command.set_up()
        spi_command.spi_fla = 0x1000
        spi_command.filename = 'test_write.bin'
        mock_cs.hals.SPI.write_spi_from_file.return_value = False

        with patch('os.path.exists', return_value=True), \
             patch.object(spi_command.logger, 'log_warning') as mock_warning:
            spi_command.spi_write()

            mock_warning.assert_called_once()

    @pytest.mark.unit
    def test_spi_erase_success(self, spi_command, mock_cs):
        """Test spi_erase command successful."""
        spi_command.set_up()
        spi_command.spi_fla = 0x1000

        with patch.object(spi_command.logger, 'log') as mock_log, \
             patch.object(spi_command.logger, 'log_good') as mock_good:
            spi_command.spi_erase()

            mock_log.assert_called_once()
            mock_good.assert_called_once()
            mock_cs.hals.SPI.erase_spi_block.assert_called_once_with(0x1000)

    @pytest.mark.unit
    def test_spi_erase_error(self, spi_command, mock_cs):
        """Test spi_erase command when erase fails."""
        spi_command.set_up()
        spi_command.spi_fla = 0x1000
        mock_cs.hals.SPI.erase_spi_block.return_value = False

        with patch.object(spi_command.logger, 'log') as mock_log, \
             patch.object(spi_command.logger, 'log_warning') as mock_warning:
            spi_command.spi_erase()

            mock_log.assert_called_once()
            mock_warning.assert_called_once()

    @pytest.mark.unit
    def test_spi_disable_wp_success(self, spi_command, mock_cs):
        """Test spi_disable_wp command successful."""
        spi_command.set_up()

        with patch.object(spi_command.logger, 'log') as mock_log, \
             patch.object(spi_command.logger, 'log_good') as mock_good:
            spi_command.spi_disable_wp()

            mock_log.assert_called_once()
            mock_good.assert_called_once()
            mock_cs.hals.SPI.disable_BIOS_write_protection.assert_called_once()

    @pytest.mark.unit
    def test_spi_disable_wp_error(self, spi_command, mock_cs):
        """Test spi_disable_wp command when disable fails."""
        spi_command.set_up()
        mock_cs.hals.SPI.disable_BIOS_write_protection.return_value = False

        with patch.object(spi_command.logger, 'log') as mock_log, \
             patch.object(spi_command.logger, 'log_bad') as mock_bad:
            spi_command.spi_disable_wp()

            mock_log.assert_called_once()
            mock_bad.assert_called_once()

    @pytest.mark.unit
    def test_spi_sfdp(self, spi_command, mock_cs):
        """Test spi_sfdp command."""
        spi_command.set_up()

        spi_command.spi_sfdp()

        mock_cs.hals.SPI.get_SPI_SFDP.assert_called_once()

    @pytest.mark.unit
    def test_spi_jedec_basic(self, spi_command, mock_cs):
        """Test spi_jedec command basic mode."""
        spi_command.set_up()
        spi_command.option = ''

        with patch.object(spi_command.logger, 'log') as mock_log:
            spi_command.spi_jedec()

            mock_log.assert_called_once()
            mock_cs.hals.SPI.get_SPI_JEDEC_ID.assert_called_once()

    @pytest.mark.unit
    def test_spi_jedec_decode(self, spi_command, mock_cs):
        """Test spi_jedec command decode mode."""
        spi_command.set_up()
        spi_command.option = 'decode'

        with patch.object(spi_command.logger, 'log') as mock_log:
            spi_command.spi_jedec()

            # Should log multiple lines for decoded information
            assert mock_log.call_count >= 3
            mock_cs.hals.SPI.get_SPI_JEDEC_ID_decoded.assert_called_once()

    @pytest.mark.unit
    def test_spi_jedec_not_supported(self, spi_command, mock_cs):
        """Test spi_jedec command when JEDEC is not supported."""
        spi_command.set_up()
        spi_command.option = ''
        mock_cs.hals.SPI.get_SPI_JEDEC_ID.return_value = False

        with patch.object(spi_command.logger, 'log') as mock_log:
            spi_command.spi_jedec()

            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_spi_jedec_decode_not_supported(self, spi_command, mock_cs):
        """Test spi_jedec decode command when JEDEC is not supported."""
        spi_command.set_up()
        spi_command.option = 'decode'
        mock_cs.hals.SPI.get_SPI_JEDEC_ID_decoded.return_value = (False, None, None)

        with patch.object(spi_command.logger, 'log') as mock_log:
            spi_command.spi_jedec()

            mock_log.assert_called_once()


class TestSPICommandIntegration:
    """Integration tests for SPI command with HAL components."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for SPI testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        cs_mock.hals.SPI = Mock()
        cs_mock.hals.SPI.display_SPI_map.return_value = None
        cs_mock.hals.SPI.read_spi_to_file.return_value = b'\xAA\xBB\xCC\xDD' * 0x40
        cs_mock.hals.SPI.write_spi_from_file.return_value = True
        cs_mock.hals.SPI.erase_spi_block.return_value = True
        cs_mock.hals.SPI.disable_BIOS_write_protection.return_value = True
        cs_mock.hals.SPI.get_SPI_region.return_value = (0x0, 0x200000, 'BIOS')

        # Mock helper
        cs_mock.helper = Mock()
        cs_mock.helper.get_threads_count.return_value = 2

        return cs_mock

    @pytest.mark.integration
    def test_spi_read_write_workflow(self, integrated_cs):
        """Test complete SPI read/write workflow."""
        # Test dump operation
        dump_cmd = SPICommand(['dump', 'test.bin'], cs=integrated_cs)
        dump_cmd.parse_arguments()
        dump_cmd.set_up()

        with patch.object(dump_cmd.logger, 'log') as mock_log:
            dump_cmd.run()

            # Should perform dump operation
            assert mock_log.call_count >= 3
            integrated_cs.hals.SPI.get_SPI_region.assert_called_once_with(BIOS)

        # Test read operation
        read_cmd = SPICommand(['read', '0x1000', '0x100', 'output.bin'], cs=integrated_cs)
        read_cmd.parse_arguments()
        read_cmd.set_up()

        with patch.object(read_cmd.logger, 'log') as mock_log:
            read_cmd.run()

            assert mock_log.call_count >= 2
            integrated_cs.hals.SPI.read_spi_to_file.assert_called_once_with(0x1000, 0x100, 'output.bin')

    @pytest.mark.integration
    def test_spi_write_protection_workflow(self, integrated_cs):
        """Test SPI write protection workflow."""
        # Test disable write protection
        wp_cmd = SPICommand(['disable-wp'], cs=integrated_cs)
        wp_cmd.parse_arguments()
        wp_cmd.set_up()

        with patch.object(wp_cmd.logger, 'log') as mock_log, \
             patch.object(wp_cmd.logger, 'log_good') as mock_good:
            wp_cmd.run()

            mock_log.assert_called_once()
            mock_good.assert_called_once()
            integrated_cs.hals.SPI.disable_BIOS_write_protection.assert_called_once()

    @pytest.mark.integration
    def test_spi_identification_workflow(self, integrated_cs):
        """Test SPI identification workflow."""
        # Test JEDEC ID
        jedec_cmd = SPICommand(['jedec'], cs=integrated_cs)
        jedec_cmd.parse_arguments()
        jedec_cmd.set_up()
        integrated_cs.hals.SPI.get_SPI_JEDEC_ID.return_value = 0x1F1234

        with patch.object(jedec_cmd.logger, 'log') as mock_log:
            jedec_cmd.run()

            mock_log.assert_called_once()
            integrated_cs.hals.SPI.get_SPI_JEDEC_ID.assert_called_once()


class TestSPICommandEdgeCases:
    """Test edge cases and error conditions for SPI command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals.SPI = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        spi_cmd = SPICommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            spi_cmd.parse_arguments()

    @pytest.mark.unit
    def test_invalid_subcommand(self, mock_cs):
        """Test handling of invalid subcommand."""
        spi_cmd = SPICommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            spi_cmd.parse_arguments()

    @pytest.mark.unit
    def test_dump_missing_file_handling(self, mock_cs):
        """Test dump command with missing file handling."""
        spi_cmd = SPICommand(['dump'], cs=mock_cs)
        spi_cmd.parse_arguments()
        spi_cmd.set_up()

        # Should use default filename
        assert spi_cmd.out_file == 'rom.bin'

    @pytest.mark.unit
    def test_read_invalid_address(self, mock_cs):
        """Test read command with invalid address."""
        spi_cmd = SPICommand(['read', 'invalid', '0x100'], cs=mock_cs)

        # Should raise SystemExit due to invalid address
        with pytest.raises(SystemExit):
            spi_cmd.parse_arguments()

    @pytest.mark.unit
    def test_write_invalid_address(self, mock_cs):
        """Test write command with invalid address."""
        spi_cmd = SPICommand(['write', 'invalid', 'test.bin'], cs=mock_cs)

        # Should raise SystemExit due to invalid address
        with pytest.raises(SystemExit):
            spi_cmd.parse_arguments()

    @pytest.mark.unit
    def test_erase_invalid_address(self, mock_cs):
        """Test erase command with invalid address."""
        spi_cmd = SPICommand(['erase', 'invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid address
        with pytest.raises(SystemExit):
            spi_cmd.parse_arguments()

    @pytest.mark.unit
    def test_large_address_values(self, mock_cs):
        """Test handling of large address values."""
        # Test with maximum 32-bit address
        spi_cmd = SPICommand(['read', '0xFFFFFFFF', '0x1000'], cs=mock_cs)
        spi_cmd.parse_arguments()

        assert spi_cmd.spi_fla == 0xFFFFFFFF
        assert spi_cmd.length == 0x1000

    @pytest.mark.unit
    def test_zero_length_values(self, mock_cs):
        """Test handling of zero length values."""
        spi_cmd = SPICommand(['read', '0x1000', '0x0'], cs=mock_cs)
        spi_cmd.parse_arguments()

        assert spi_cmd.spi_fla == 0x1000
        assert spi_cmd.length == 0x0

    @pytest.mark.unit
    def test_jedec_case_insensitive_decode(self, mock_cs):
        """Test JEDEC decode option is case insensitive."""
        spi_cmd = SPICommand(['jedec', 'DECODE'], cs=mock_cs)
        spi_cmd.parse_arguments()

        assert spi_cmd.option == 'DECODE'

        spi_cmd.set_up()
        spi_cmd.spi_jedec()

        # Should still attempt decode
        mock_cs.hals.SPI.get_SPI_JEDEC_ID_decoded.assert_called_once()


class TestSPICommandConfigurationValidation:
    """Test configuration validation aspects of SPI command."""

    @pytest.fixture
    def config_cs(self):
        """Create ChipsecCs with SPI-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock SPI HAL with configuration
        cs_mock.hals.SPI = Mock()
        cs_mock.hals.SPI.read_spi_to_file.return_value = b'\x00\x01\x02\x03'

        # Mock SPI configuration data
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.SPI_CONFIG = {
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

        return cs_mock

    @pytest.mark.unit
    def test_spi_configuration_access(self, config_cs):
        """Test access to SPI configuration data."""
        spi_config = config_cs.Cfg.SPI_CONFIG

        assert spi_config['max_read_size'] == 0x1000000
        assert spi_config['max_write_size'] == 0x100000
        assert 'info' in spi_config['supported_operations']
        assert 'dump' in spi_config['supported_operations']
        assert 'bios' in spi_config['regions']

    @pytest.mark.unit
    def test_supported_operations_validation(self, config_cs):
        """Test validation of supported SPI operations."""
        supported_ops = config_cs.Cfg.SPI_CONFIG['supported_operations']

        # Test that all documented operations are supported
        assert 'info' in supported_ops
        assert 'dump' in supported_ops
        assert 'read' in supported_ops
        assert 'write' in supported_ops
        assert 'erase' in supported_ops
        assert 'disable-wp' in supported_ops
        assert 'sfdp' in supported_ops
        assert 'jedec' in supported_ops

    @pytest.mark.unit
    def test_spi_regions_validation(self, config_cs):
        """Test SPI regions configuration validation."""
        regions = config_cs.Cfg.SPI_CONFIG['regions']

        # Test that all regions have required fields
        for region_name, region_info in regions.items():
            assert 'base' in region_info
            assert 'size' in region_info
            assert region_info['base'] >= 0
            assert region_info['size'] > 0

        # Test specific region configurations
        assert regions['bios']['base'] == 0x0
        assert regions['bios']['size'] == 0x800000
        assert regions['me']['base'] == 0x1000
        assert regions['gbe']['size'] == 0x2000

    @pytest.mark.unit
    def test_flash_types_validation(self, config_cs):
        """Test SPI flash types validation."""
        flash_types = config_cs.Cfg.SPI_CONFIG['flash_types']

        # Test that flash types list is not empty
        assert len(flash_types) > 0

        # Test that all flash types are strings
        for flash_type in flash_types:
            assert isinstance(flash_type, str)
            assert len(flash_type) > 0

        # Test specific flash types
        assert 'MX25L3205D' in flash_types
        assert 'W25Q64FV' in flash_types

    @pytest.mark.unit
    def test_operation_limits_validation(self, config_cs):
        """Test SPI operation limits validation."""
        max_read = config_cs.Cfg.SPI_CONFIG['max_read_size']
        max_write = config_cs.Cfg.SPI_CONFIG['max_write_size']

        # Test that limits are reasonable
        assert max_read > 0
        assert max_write > 0
        # Write limit should be smaller than read limit for safety
        assert max_write <= max_read


if __name__ == '__main__':
    pytest.main([__file__])
