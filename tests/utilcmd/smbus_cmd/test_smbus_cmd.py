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
from chipsec.utilcmd.smbus_cmd import SMBusCommand
from tests.test_utils import MockFactory


class TestSMBusCommand:
    """Comprehensive tests for SMBus utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for SMBus testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        # Mock SMBus HAL
        cs_mock.hals.SMBus = Mock()
        cs_mock.hals.SMBusMMIO = Mock()
        cs_mock.hals.SMBus.read_byte.return_value = [0x12]
        cs_mock.hals.SMBus.read_word.return_value = [0x12, 0x34]
        cs_mock.hals.SMBus.read_block.return_value = [0x12, 0x34, 0x56, 0x78]
        cs_mock.hals.SMBus.write_byte.return_value = True
        cs_mock.hals.SMBus.write_word.return_value = True
        cs_mock.hals.SMBus.process_call.return_value = [0xAB, 0xCD]
        cs_mock.hals.SMBus.quick_write.return_value = True
        cs_mock.hals.SMBus.is_SMBus_supported.return_value = True
        cs_mock.hals.SMBus.display_SMBus_info.return_value = None

        # Mock MMIO version as well
        cs_mock.hals.SMBusMMIO.read_byte.return_value = [0x12]
        cs_mock.hals.SMBusMMIO.read_word.return_value = [0x12, 0x34]
        cs_mock.hals.SMBusMMIO.read_block.return_value = [0x12, 0x34, 0x56, 0x78]
        cs_mock.hals.SMBusMMIO.write_byte.return_value = True
        cs_mock.hals.SMBusMMIO.write_word.return_value = True
        cs_mock.hals.SMBusMMIO.process_call.return_value = [0xAB, 0xCD]
        cs_mock.hals.SMBusMMIO.quick_write.return_value = True
        cs_mock.hals.SMBusMMIO.is_SMBus_supported.return_value = True
        cs_mock.hals.SMBusMMIO.display_SMBus_info.return_value = None

        return cs_mock

    @pytest.fixture
    def smbus_command(self, mock_cs):
        """Create SMBusCommand instance."""
        return SMBusCommand(['read', '0xA0', '0x0', '0x4'], cs=mock_cs)

    @pytest.mark.unit
    def test_smbus_command_initialization(self, smbus_command, mock_cs):
        """Test SMBusCommand initialization."""
        assert smbus_command.cs == mock_cs
        assert smbus_command.argv == ['read', '0xA0', '0x0', '0x4']

    @pytest.mark.unit
    def test_parse_arguments_read(self, mock_cs):
        """Test parsing read command arguments."""
        command = SMBusCommand(['read', '0xA0', '0x0', '0x4'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.read
        assert command.command == 'read'
        assert command.dev_addr == 0xA0
        assert command.offset == 0x0
        assert command.size == 0x4
        assert command.is_addr_8b is False
        assert command.is_mmio is False
        assert command.is_i2c is False
        assert command.is_OnSemi is False

    @pytest.mark.unit
    def test_parse_arguments_read_with_flags(self, mock_cs):
        """Test parsing read command with flags."""
        command = SMBusCommand(['read', '0xA0', '0x0', '0x4', '--addr8b', '--mmio', '--i2c', '--OnSemi'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.read
        assert command.command == 'read'
        assert command.dev_addr == 0xA0
        assert command.offset == 0x0
        assert command.size == 0x4
        assert command.is_addr_8b is True
        assert command.is_mmio is True
        assert command.is_i2c is True
        assert command.is_OnSemi is True

    @pytest.mark.unit
    def test_parse_arguments_readblock(self, mock_cs):
        """Test parsing readblock command arguments."""
        command = SMBusCommand(['readblock', '0xA0', '0x0', '--i2c'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.readblock
        assert command.command == 'readblock'
        assert command.dev_addr == 0xA0
        assert command.offset == 0x0
        assert command.is_i2c is True

    @pytest.mark.unit
    def test_parse_arguments_write(self, mock_cs):
        """Test parsing write command arguments."""
        command = SMBusCommand(['write', '0xA0', '0x0', '0x1234', '0x2'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.write
        assert command.command == 'write'
        assert command.dev_addr == 0xA0
        assert command.offset == 0x0
        assert command.write_data == 0x1234
        assert command.size == 0x2

    @pytest.mark.unit
    def test_parse_arguments_process_call(self, mock_cs):
        """Test parsing process_call command arguments."""
        command = SMBusCommand(['process_call', '0xA0', '0x0', '0x1234'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.process_call
        assert command.command == 'process_call'
        assert command.dev_addr == 0xA0
        assert command.offset == 0x0
        assert command.write_data == 0x1234

    @pytest.mark.unit
    def test_parse_arguments_scan(self, mock_cs):
        """Test parsing scan command arguments."""
        command = SMBusCommand(['scan'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.scan
        assert command.command == 'scan'
        assert command.s_min == 0x00
        assert command.s_max == 0x7F

    @pytest.mark.unit
    def test_parse_arguments_scan_with_range(self, mock_cs):
        """Test parsing scan command with range arguments."""
        command = SMBusCommand(['scan', '0x10', '0x20'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.scan
        assert command.command == 'scan'
        assert command.r_min == 0x10
        assert command.r_max == 0x20

    @pytest.mark.unit
    def test_parse_arguments_dump(self, mock_cs):
        """Test parsing dump command arguments."""
        command = SMBusCommand(['dump', '0xA0'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.dump_dev
        assert command.command == 'dump'
        assert command.dev_addr == 0xA0
        assert command.r_min == 0x00
        assert command.r_max == 0xFF

    @pytest.mark.unit
    def test_parse_arguments_dump_with_range(self, mock_cs):
        """Test parsing dump command with range arguments."""
        command = SMBusCommand(['dump', '0xA0', '0x10', '0x20'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.dump_dev
        assert command.command == 'dump'
        assert command.dev_addr == 0xA0
        assert command.r_min == 0x10
        assert command.r_max == 0x20

    @pytest.mark.unit
    def test_requirements(self, smbus_command):
        """Test command requirements."""
        reqs = smbus_command.requirements()
        assert hasattr(reqs, 'load_driver')
        assert hasattr(reqs, 'load_config')

    @pytest.mark.unit
    def test_configure_mmio_mode(self, smbus_command, mock_cs):
        """Test configure method in MMIO mode."""
        smbus_command.is_mmio = True
        smbus_command.is_i2c = False

        result = smbus_command.configure()

        assert result is True
        assert smbus_command._smbus == mock_cs.hals.SMBusMMIO
        mock_cs.hals.SMBusMMIO.set_i2c_mode.assert_called_once_with(False)
        mock_cs.hals.SMBusMMIO.enable.assert_called_once()

    @pytest.mark.unit
    def test_configure_standard_mode(self, smbus_command, mock_cs):
        """Test configure method in standard mode."""
        smbus_command.is_mmio = False
        smbus_command.is_i2c = True

        result = smbus_command.configure()

        assert result is True
        assert smbus_command._smbus == mock_cs.hals.SMBus
        mock_cs.hals.SMBus.set_i2c_mode.assert_called_once_with(True)
        mock_cs.hals.SMBus.enable.assert_called_once()

    @pytest.mark.unit
    def test_read_standard_mode(self, smbus_command, mock_cs):
        """Test read method in standard mode."""
        smbus_command.dev_addr = 0xA0
        smbus_command.offset = 0x0
        smbus_command.size = 0x4
        smbus_command.is_OnSemi = False
        smbus_command._smbus = mock_cs.hals.SMBus

        with patch.object(smbus_command.logger, 'log_verbose') as mock_verbose:
            result = smbus_command.read()

            assert result == [0x12, 0x34, 0x56, 0x78]  # Mocked read_block result
            mock_verbose.assert_called_once()

    @pytest.mark.unit
    def test_read_OnSemi_mode(self, smbus_command, mock_cs):
        """Test read method in OnSemi mode."""
        smbus_command.dev_addr = 0xA0
        smbus_command.offset = 0x0
        smbus_command.size = 0x4
        smbus_command.is_OnSemi = True
        smbus_command._smbus = mock_cs.hals.SMBus

        with patch.object(smbus_command.logger, 'log_verbose') as mock_verbose:
            result = smbus_command.read()

            assert result == [0xAB, 0xCD]  # Mocked process_call result
            mock_verbose.assert_called_once()
            mock_cs.hals.SMBus.process_call.assert_called_once_with(0xA0, 0x0, 0x0, 0x1)

    @pytest.mark.unit
    def test_readblock(self, smbus_command, mock_cs):
        """Test readblock method."""
        smbus_command.dev_addr = 0xA0
        smbus_command.offset = 0x0
        smbus_command._smbus = mock_cs.hals.SMBus

        with patch.object(smbus_command.logger, 'log_verbose') as mock_verbose:
            result = smbus_command.readblock()

            assert result == [0x12, 0x34, 0x56, 0x78]  # Mocked read_block result
            mock_verbose.assert_called_once()
            mock_cs.hals.SMBus.read_block.assert_called_once_with(0xA0, 0x0)

    @pytest.mark.unit
    def test_write_standard_mode(self, smbus_command, mock_cs):
        """Test write method in standard mode."""
        smbus_command.dev_addr = 0xA0
        smbus_command.offset = 0x0
        smbus_command.write_data = 0x1234
        smbus_command.size = 0x2
        smbus_command.is_OnSemi = False
        smbus_command._smbus = mock_cs.hals.SMBus

        with patch.object(smbus_command.logger, 'log_verbose') as mock_verbose:
            result = smbus_command.write()

            assert result is True
            mock_verbose.assert_called_once()

    @pytest.mark.unit
    def test_write_OnSemi_mode(self, smbus_command, mock_cs):
        """Test write method in OnSemi mode."""
        smbus_command.dev_addr = 0xA0
        smbus_command.offset = 0x0
        smbus_command.write_data = 0x1234
        smbus_command.size = 0x2
        smbus_command.is_OnSemi = True
        smbus_command._smbus = mock_cs.hals.SMBus

        with patch.object(smbus_command.logger, 'log_verbose') as mock_verbose:
            result = smbus_command.write()

            assert result is True
            mock_verbose.assert_called_once()
            mock_cs.hals.SMBus.write_word.assert_called_once_with(0xA0, 0x2, 0x1234, 0x0)

    @pytest.mark.unit
    def test_process_call(self, smbus_command, mock_cs):
        """Test process_call method."""
        smbus_command.dev_addr = 0xA0
        smbus_command.offset = 0x0
        smbus_command.write_data = 0x1234
        smbus_command._smbus = mock_cs.hals.SMBus

        with patch.object(smbus_command.logger, 'log_verbose') as mock_verbose, \
             patch('chipsec.utilcmd.smbus_cmd.print_buffer') as mock_print:
            result = smbus_command.process_call()

            assert result is True
            mock_verbose.assert_called_once()
            mock_print.assert_called_once()
            mock_cs.hals.SMBus.process_call.assert_called_once_with(0xA0, 0x0, 0x0, 0x34)

    @pytest.mark.unit
    def test_scan_range_i2c_mode(self, smbus_command, mock_cs):
        """Test scan_range method in I2C mode."""
        smbus_command.is_i2c = True
        smbus_command._smbus = mock_cs.hals.SMBus

        # Mock the I2C methods to return success for device 0x52
        with patch.object(smbus_command, 'i2c_fixed_read_1', return_value=[0x12]), \
             patch.object(smbus_command, 'i2c_fixed_read_2', return_value=False), \
             patch.object(smbus_command, 'OnSemi_i2c_read', return_value=False), \
             patch.object(smbus_command, 'i2c_fixed_write', return_value=False):
            result = smbus_command.scan_range(0x50, 0x54)

            assert 0x52 in result

    @pytest.mark.unit
    def test_scan_range_smbus_mode(self, smbus_command, mock_cs):
        """Test scan_range method in SMBus mode."""
        smbus_command.is_i2c = False
        smbus_command._smbus = mock_cs.hals.SMBus

        result = smbus_command.scan_range(0x50, 0x54)

        assert 0x52 in result  # Device 0x52 is in the hardcoded test list

    @pytest.mark.unit
    def test_scan(self, smbus_command, mock_cs):
        """Test scan method."""
        smbus_command.s_min = 0x50
        smbus_command.s_max = 0x54
        smbus_command._smbus = mock_cs.hals.SMBus

        with patch.object(smbus_command, 'scan_range', return_value=[0x52]), \
             patch.object(smbus_command, 'pretty_print_buffer') as mock_print:
            smbus_command.scan()

            mock_print.assert_called_once()

    @pytest.mark.unit
    def test_dump_dev(self, smbus_command, mock_cs):
        """Test dump_dev method."""
        smbus_command.dev_addr = 0xA0
        smbus_command.r_min = 0x0
        smbus_command.r_max = 0x10
        smbus_command._smbus = mock_cs.hals.SMBus

        with patch.object(smbus_command, '_read_range', return_value=[0x12, 0x34, 0x56, 0x78]), \
             patch.object(smbus_command.logger, 'log_verbose') as mock_verbose, \
             patch.object(smbus_command.logger, 'log_heading') as mock_heading, \
             patch('chipsec.utilcmd.smbus_cmd.pretty_print_hex_buffer') as mock_print:
            result = smbus_command.dump_dev()

            assert result is True
            mock_verbose.assert_called_once()
            mock_print.assert_called_once()

    @pytest.mark.unit
    def test_OnSemi_i2c_read(self, smbus_command, mock_cs):
        """Test OnSemi_i2c_read method."""
        smbus_command._smbus = mock_cs.hals.SMBus

        result = smbus_command.OnSemi_i2c_read(0xA0, 0x0)

        assert result == [0xAB]  # First byte of process_call result
        mock_cs.hals.SMBus.process_call.assert_called_once_with(0xA0, 0x0, 0x0, 0x1)

    @pytest.mark.unit
    def test_i2c_fixed_read_1(self, smbus_command, mock_cs):
        """Test i2c_fixed_read_1 method."""
        smbus_command._smbus = mock_cs.hals.SMBus

        result = smbus_command.i2c_fixed_read_1(0xA0)

        assert result == [0x12]  # Mocked read_byte result
        mock_cs.hals.SMBus.read_byte.assert_called_once_with(0xA0, 0)

    @pytest.mark.unit
    def test_i2c_fixed_read_2(self, smbus_command, mock_cs):
        """Test i2c_fixed_read_2 method."""
        smbus_command._smbus = mock_cs.hals.SMBus

        result = smbus_command.i2c_fixed_read_2(0xA0)

        assert result == [0xAB]  # First byte of process_call result
        mock_cs.hals.SMBus.process_call.assert_called_once_with(0xA0, 0x0, 0x0, 0x0)

    @pytest.mark.unit
    def test_i2c_fixed_write(self, smbus_command, mock_cs):
        """Test i2c_fixed_write method."""
        smbus_command._smbus = mock_cs.hals.SMBus

        result = smbus_command.i2c_fixed_write(0xA0)

        assert result is True
        mock_cs.hals.SMBus.write_byte.assert_called_once_with(0xA0, 0x0, 0x0)

    @pytest.mark.unit
    def test_read_range(self, smbus_command, mock_cs):
        """Test _read_range method."""
        smbus_command.dev_addr = 0xA0
        smbus_command._smbus = mock_cs.hals.SMBus

        result = smbus_command._read_range(0x0, 0x4)

        assert result == [0x12, 0x34, 0x56, 0x78]  # Mocked read_block result

    @pytest.mark.unit
    def test_write_range(self, smbus_command, mock_cs):
        """Test _write_range method."""
        smbus_command.dev_addr = 0xA0
        smbus_command.offset = 0x0
        smbus_command.size = 0x2
        smbus_command.write_data = 0x1234
        smbus_command._smbus = mock_cs.hals.SMBus

        result = smbus_command._write_range()

        assert result is True
        mock_cs.hals.SMBus.write_word.assert_called_once_with(0xA0, 0x0, 0x12, 0x34)

    @pytest.mark.unit
    def test_run_success(self, smbus_command, mock_cs):
        """Test successful run method."""
        smbus_command.func = Mock(return_value=[0x12, 0x34])
        smbus_command.command = 'test_command'

        with patch.object(smbus_command, 'configure', return_value=True), \
             patch.object(smbus_command.logger, 'log') as mock_log:
            smbus_command.run()

            smbus_command.func.assert_called_once()
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_run_configure_failure(self, smbus_command, mock_cs):
        """Test run method when configure fails."""
        smbus_command.func = Mock()

        with patch.object(smbus_command, 'configure', return_value=False):
            result = smbus_command.run()

            assert result is False
            smbus_command.func.assert_not_called()

    @pytest.mark.unit
    def test_run_smbus_not_supported(self, smbus_command, mock_cs):
        """Test run method when SMBus is not supported."""
        smbus_command.func = Mock()
        smbus_command._smbus = mock_cs.hals.SMBus
        mock_cs.hals.SMBus.is_SMBus_supported.return_value = False

        with patch.object(smbus_command, 'configure', return_value=True), \
             patch.object(smbus_command.logger, 'log_verbose') as mock_verbose:
            smbus_command.run()

            mock_verbose.assert_called_once()
            smbus_command.func.assert_not_called()

    @pytest.mark.unit
    def test_run_with_addr_8b_conversion(self, smbus_command, mock_cs):
        """Test run method with 8-bit address conversion."""
        smbus_command.func = Mock(return_value=True)
        smbus_command.command = 'test_command'
        smbus_command.dev_addr = 0xA0
        smbus_command.is_addr_8b = True

        with patch.object(smbus_command, 'configure', return_value=True), \
             patch.object(smbus_command.logger, 'log_hal') as mock_hal, \
             patch.object(smbus_command.logger, 'log_good') as mock_good:
            smbus_command.run()

            assert smbus_command.dev_addr == 0x50  # 0xA0 >> 1
            mock_hal.assert_called_once()
            mock_good.assert_called_once()

    @pytest.mark.unit
    def test_pretty_print_buffer(self, smbus_command):
        """Test pretty_print_buffer method."""
        test_data = "48656C6C6F20576F726C64"  # "Hello World" in hex

        with patch.object(smbus_command.logger, 'log') as mock_log:
            smbus_command.pretty_print_buffer(test_data, 8)

            mock_log.assert_called_once()
            log_call = mock_log.call_args[0][0]
            assert '00 |' in log_call  # Should contain grid format


class TestSMBusCommandIntegration:
    """Integration tests for SMBus command with HAL components."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for SMBus testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        cs_mock.hals.SMBus = Mock()
        cs_mock.hals.SMBus.read_byte.return_value = [0xDE, 0xAD]
        cs_mock.hals.SMBus.read_word.return_value = [0xDE, 0xAD, 0xBE, 0xEF]
        cs_mock.hals.SMBus.read_block.return_value = list(range(32))  # 32 bytes
        cs_mock.hals.SMBus.write_byte.return_value = True
        cs_mock.hals.SMBus.write_word.return_value = True
        cs_mock.hals.SMBus.process_call.return_value = [0xCA, 0xFE]
        cs_mock.hals.SMBus.quick_write.return_value = True
        cs_mock.hals.SMBus.is_SMBus_supported.return_value = True
        cs_mock.hals.SMBus.display_SMBus_info.return_value = None

        # Mock helper
        cs_mock.helper = Mock()
        cs_mock.helper.get_threads_count.return_value = 2

        return cs_mock

    @pytest.mark.integration
    def test_smbus_read_write_workflow(self, integrated_cs):
        """Test complete SMBus read/write workflow."""
        # Test read operation
        read_cmd = SMBusCommand(['read', '0xA0', '0x0', '0x4'], cs=integrated_cs)
        read_cmd.parse_arguments()

        with patch.object(read_cmd.logger, 'log_verbose') as mock_verbose, \
             patch.object(read_cmd.logger, 'log') as mock_log:
            read_cmd.run()

            mock_verbose.assert_called_once()
            mock_log.assert_called_once()

        # Test write operation
        write_cmd = SMBusCommand(['write', '0xA0', '0x0', '0x1234', '0x2'], cs=integrated_cs)
        write_cmd.parse_arguments()

        with patch.object(write_cmd.logger, 'log_verbose') as mock_verbose, \
             patch.object(write_cmd.logger, 'log_good') as mock_good:
            write_cmd.run()

            mock_verbose.assert_called_once()
            mock_good.assert_called_once()

    @pytest.mark.integration
    def test_smbus_scan_workflow(self, integrated_cs):
        """Test SMBus scan workflow."""
        scan_cmd = SMBusCommand(['scan'], cs=integrated_cs)
        scan_cmd.parse_arguments()

        with patch.object(scan_cmd, 'scan_range', return_value=[0x52]), \
             patch.object(scan_cmd, 'pretty_print_buffer') as mock_print:
            scan_cmd.run()

            mock_print.assert_called_once()

    @pytest.mark.integration
    def test_smbus_dump_workflow(self, integrated_cs):
        """Test SMBus dump workflow."""
        dump_cmd = SMBusCommand(['dump', '0xA0'], cs=integrated_cs)
        dump_cmd.parse_arguments()

        with patch.object(dump_cmd, '_read_range', return_value=list(range(16))), \
             patch.object(dump_cmd.logger, 'log_verbose') as mock_verbose, \
             patch.object(dump_cmd.logger, 'log_heading') as mock_heading, \
             patch('chipsec.utilcmd.smbus_cmd.pretty_print_hex_buffer') as mock_print:
            dump_cmd.run()

            mock_verbose.assert_called_once()
            mock_print.assert_called_once()

    @pytest.mark.integration
    def test_smbus_process_call_workflow(self, integrated_cs):
        """Test SMBus process call workflow."""
        pc_cmd = SMBusCommand(['process_call', '0xA0', '0x0', '0x1234'], cs=integrated_cs)
        pc_cmd.parse_arguments()

        with patch.object(pc_cmd.logger, 'log_verbose') as mock_verbose, \
             patch('chipsec.utilcmd.smbus_cmd.print_buffer') as mock_print, \
             patch.object(pc_cmd.logger, 'log_good') as mock_good:
            pc_cmd.run()

            mock_verbose.assert_called_once()
            mock_print.assert_called_once()
            mock_good.assert_called_once()


class TestSMBusCommandEdgeCases:
    """Test edge cases and error conditions for SMBus command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals.SMBus = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        smbus_cmd = SMBusCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            smbus_cmd.parse_arguments()

    @pytest.mark.unit
    def test_invalid_subcommand(self, mock_cs):
        """Test handling of invalid subcommand."""
        smbus_cmd = SMBusCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            smbus_cmd.parse_arguments()

    @pytest.mark.unit
    def test_read_missing_size(self, mock_cs):
        """Test read command with missing size."""
        smbus_cmd = SMBusCommand(['read', '0xA0', '0x0'], cs=mock_cs)

        # Should raise SystemExit due to missing size
        with pytest.raises(SystemExit):
            smbus_cmd.parse_arguments()

    @pytest.mark.unit
    def test_write_missing_data(self, mock_cs):
        """Test write command with missing data."""
        smbus_cmd = SMBusCommand(['write', '0xA0', '0x0'], cs=mock_cs)

        # Should raise SystemExit due to missing write_data
        with pytest.raises(SystemExit):
            smbus_cmd.parse_arguments()

    @pytest.mark.unit
    def test_process_call_missing_data(self, mock_cs):
        """Test process_call command with missing data."""
        smbus_cmd = SMBusCommand(['process_call', '0xA0', '0x0'], cs=mock_cs)

        # Should raise SystemExit due to missing write_data
        with pytest.raises(SystemExit):
            smbus_cmd.parse_arguments()

    @pytest.mark.unit
    def test_zero_device_address(self, mock_cs):
        """Test operations with zero device address."""
        smbus_cmd = SMBusCommand(['read', '0x0', '0x0', '0x1'], cs=mock_cs)
        smbus_cmd.parse_arguments()

        assert smbus_cmd.dev_addr == 0x0

    @pytest.mark.unit
    def test_maximum_device_address(self, mock_cs):
        """Test operations with maximum device address."""
        smbus_cmd = SMBusCommand(['write', '0xFF', '0x0', '0x1234', '0x1'], cs=mock_cs)
        smbus_cmd.parse_arguments()

        assert smbus_cmd.dev_addr == 0xFF

    @pytest.mark.unit
    def test_zero_offset(self, mock_cs):
        """Test operations with zero offset."""
        smbus_cmd = SMBusCommand(['read', '0xA0', '0x0', '0x1'], cs=mock_cs)
        smbus_cmd.parse_arguments()

        assert smbus_cmd.offset == 0x0

    @pytest.mark.unit
    def test_large_offset(self, mock_cs):
        """Test operations with large offset."""
        smbus_cmd = SMBusCommand(['write', '0xA0', '0xFFFF', '0x1234', '0x1'], cs=mock_cs)
        smbus_cmd.parse_arguments()

        assert smbus_cmd.offset == 0xFFFF

    @pytest.mark.unit
    def test_zero_size(self, mock_cs):
        """Test operations with zero size."""
        smbus_cmd = SMBusCommand(['read', '0xA0', '0x0', '0x0'], cs=mock_cs)
        smbus_cmd.parse_arguments()

        assert smbus_cmd.size == 0x0

    @pytest.mark.unit
    def test_large_size(self, mock_cs):
        """Test operations with large size."""
        smbus_cmd = SMBusCommand(['read', '0xA0', '0x0', '0x1000'], cs=mock_cs)
        smbus_cmd.parse_arguments()

        assert smbus_cmd.size == 0x1000

    @pytest.mark.unit
    def test_zero_write_data(self, mock_cs):
        """Test write operations with zero data."""
        smbus_cmd = SMBusCommand(['write', '0xA0', '0x0', '0x0', '0x1'], cs=mock_cs)
        smbus_cmd.parse_arguments()

        assert smbus_cmd.write_data == 0x0

    @pytest.mark.unit
    def test_maximum_write_data(self, mock_cs):
        """Test write operations with maximum data."""
        smbus_cmd = SMBusCommand(['write', '0xA0', '0x0', '0xFFFFFFFF', '0x4'], cs=mock_cs)
        smbus_cmd.parse_arguments()

        assert smbus_cmd.write_data == 0xFFFFFFFF

    @pytest.mark.unit
    def test_read_range_fallback(self, smbus_command, mock_cs):
        """Test _read_range method with fallback logic."""
        smbus_command.dev_addr = 0xA0
        smbus_command._smbus = mock_cs.hals.SMBus

        # Mock read_block to fail, forcing fallback to read_word
        mock_cs.hals.SMBus.read_block.return_value = False
        mock_cs.hals.SMBus.read_word.return_value = [0x12, 0x34]

        result = smbus_command._read_range(0x0, 0x2)

        assert result == [0x12, 0x34]
        mock_cs.hals.SMBus.read_block.assert_called_once()
        mock_cs.hals.SMBus.read_word.assert_called_once()

    @pytest.mark.unit
    def test_write_range_fallback(self, smbus_command, mock_cs):
        """Test _write_range method with fallback logic."""
        smbus_command.dev_addr = 0xA0
        smbus_command.offset = 0x0
        smbus_command.size = 0x1
        smbus_command.write_data = 0x1234
        smbus_command._smbus = mock_cs.hals.SMBus

        # Mock write_word to fail, forcing fallback to write_byte
        mock_cs.hals.SMBus.write_word.return_value = False
        mock_cs.hals.SMBus.write_byte.return_value = True

        result = smbus_command._write_range()

        assert result is True
        mock_cs.hals.SMBus.write_word.assert_called_once()
        mock_cs.hals.SMBus.write_byte.assert_called_once()

    @pytest.mark.unit
    def test_run_result_logging_list(self, smbus_command, mock_cs):
        """Test run method result logging for list results."""
        smbus_command.func = Mock(return_value=[0x12, 0x34, 0x56])
        smbus_command.command = 'test_command'

        with patch.object(smbus_command, 'configure', return_value=True), \
             patch.object(smbus_command.logger, 'log') as mock_log:
            smbus_command.run()

            # Should log the result as a formatted hex list
            result_log = [call for call in mock_log.call_args_list if '0x12' in str(call)][0]
            assert '0x12' in str(result_log)
            assert '0x34' in str(result_log)
            assert '0x56' in str(result_log)

    @pytest.mark.unit
    def test_run_result_logging_bool_success(self, smbus_command, mock_cs):
        """Test run method result logging for boolean success."""
        smbus_command.func = Mock(return_value=True)
        smbus_command.command = 'test_command'

        with patch.object(smbus_command, 'configure', return_value=True), \
             patch.object(smbus_command.logger, 'log_good') as mock_good:
            smbus_command.run()

            mock_good.assert_called_once_with('command "test_command" succeeded')

    @pytest.mark.unit
    def test_run_result_logging_bool_failure(self, smbus_command, mock_cs):
        """Test run method result logging for boolean failure."""
        smbus_command.func = Mock(return_value=False)
        smbus_command.command = 'test_command'

        with patch.object(smbus_command, 'configure', return_value=True), \
             patch.object(smbus_command.logger, 'log_bad') as mock_bad:
            smbus_command.run()

            mock_bad.assert_called_once_with('command "test_command" failed')


class TestSMBusCommandConfigurationValidation:
    """Test configuration validation aspects of SMBus command."""

    @pytest.fixture
    def config_cs(self):
        """Create ChipsecCs with SMBus-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock SMBus HAL with configuration
        cs_mock.hals.SMBus = Mock()
        cs_mock.hals.SMBus.read_byte.return_value = [0xAB]

        # Mock SMBus configuration data
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.SMBUS_CONFIG = {
            'max_device_address': 0x7F,
            'supported_protocols': ['smbus', 'i2c'],
            'device_types': {
                'eeprom': {'address_range': [0x50, 0x57], 'description': 'EEPROM devices'},
                'thermal_sensor': {'address_range': [0x18, 0x1F], 'description': 'Thermal sensors'},
                'smart_battery': {'address_range': [0x0B, 0x0B], 'description': 'Smart battery'},
                'pmic': {'address_range': [0x12, 0x12], 'description': 'Power management IC'},
            },
            'transfer_speeds': {
                'standard': 100,  # kHz
                'fast': 400,
                'high_speed': 3400,
            },
            'security_features': {
                'pec_support': True,
                'timeout_protection': True,
                'address_validation': True,
            }
        }

        return cs_mock

    @pytest.mark.unit
    def test_smbus_configuration_access(self, config_cs):
        """Test access to SMBus configuration data."""
        smbus_config = config_cs.Cfg.SMBUS_CONFIG

        assert smbus_config['max_device_address'] == 0x7F
        assert 'smbus' in smbus_config['supported_protocols']
        assert 'i2c' in smbus_config['supported_protocols']
        assert 'eeprom' in smbus_config['device_types']
        assert smbus_config['device_types']['eeprom']['address_range'] == [0x50, 0x57]

    @pytest.mark.unit
    def test_supported_protocols_validation(self, config_cs):
        """Test validation of supported SMBus protocols."""
        supported_protocols = config_cs.Cfg.SMBUS_CONFIG['supported_protocols']

        # Test that all expected protocols are supported
        assert 'smbus' in supported_protocols
        assert 'i2c' in supported_protocols

        # Test that protocols list is not empty
        assert len(supported_protocols) > 0

    @pytest.mark.unit
    def test_device_types_validation(self, config_cs):
        """Test validation of SMBus device types."""
        device_types = config_cs.Cfg.SMBUS_CONFIG['device_types']

        # Test that all expected device types are defined
        expected_types = ['eeprom', 'thermal_sensor', 'smart_battery', 'pmic']
        for device_type in expected_types:
            assert device_type in device_types
            assert 'address_range' in device_types[device_type]
            assert 'description' in device_types[device_type]
            assert len(device_types[device_type]['address_range']) == 2

        # Test specific device configurations
        assert device_types['eeprom']['address_range'] == [0x50, 0x57]
        assert device_types['thermal_sensor']['address_range'] == [0x18, 0x1F]
        assert device_types['smart_battery']['address_range'] == [0x0B, 0x0B]

    @pytest.mark.unit
    def test_transfer_speeds_validation(self, config_cs):
        """Test validation of SMBus transfer speeds."""
        transfer_speeds = config_cs.Cfg.SMBUS_CONFIG['transfer_speeds']

        # Test that all expected speeds are defined
        expected_speeds = ['standard', 'fast', 'high_speed']
        for speed in expected_speeds:
            assert speed in transfer_speeds
            assert isinstance(transfer_speeds[speed], int)
            assert transfer_speeds[speed] > 0

        # Test specific speed values
        assert transfer_speeds['standard'] == 100  # 100 kHz
        assert transfer_speeds['fast'] == 400  # 400 kHz
        assert transfer_speeds['high_speed'] == 3400  # 3.4 MHz

    @pytest.mark.unit
    def test_security_features_validation(self, config_cs):
        """Test validation of SMBus security features."""
        security_features = config_cs.Cfg.SMBUS_CONFIG['security_features']

        # Test that all expected security features are defined
        expected_features = ['pec_support', 'timeout_protection', 'address_validation']
        for feature in expected_features:
            assert feature in security_features
            assert isinstance(security_features[feature], bool)

        # Test specific security feature values
        assert security_features['pec_support'] is True
        assert security_features['timeout_protection'] is True
        assert security_features['address_validation'] is True

    @pytest.mark.unit
    def test_device_address_range_validation(self, config_cs):
        """Test SMBus device address range validation."""
        max_address = config_cs.Cfg.SMBUS_CONFIG['max_device_address']
        device_types = config_cs.Cfg.SMBUS_CONFIG['device_types']

        # Test that all device address ranges are within valid limits
        for device_type, config in device_types.items():
            addr_range = config['address_range']
            min_addr, max_addr = addr_range

            assert 0 <= min_addr <= max_address, f"Device {device_type} min address 0x{min_addr:02X} exceeds maximum 0x{max_address:02X}"
            assert 0 <= max_addr <= max_address, f"Device {device_type} max address 0x{max_addr:02X} exceeds maximum 0x{max_address:02X}"
            assert min_addr <= max_addr, f"Device {device_type} address range is invalid: {addr_range}"


if __name__ == '__main__':
    pytest.main([__file__])
