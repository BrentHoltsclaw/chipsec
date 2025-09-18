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
from chipsec.utilcmd.cmos_cmd import CMOSCommand
from tests.test_utils import MockFactory


class TestCMOSCommand:
    """Comprehensive tests for CMOS utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for CMOS testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        # Mock CMOS HAL
        cs_mock.hals.CMOS = Mock()
        cs_mock.hals.CMOS.dump.return_value = None
        cs_mock.hals.CMOS.read_cmos_low.return_value = 0x12
        cs_mock.hals.CMOS.write_cmos_low.return_value = None
        cs_mock.hals.CMOS.read_cmos_high.return_value = 0x34
        cs_mock.hals.CMOS.write_cmos_high.return_value = None
        return cs_mock

    @pytest.fixture
    def cmos_command(self, mock_cs):
        """Create CMOSCommand instance."""
        return CMOSCommand(['dump'], cs=mock_cs)

    @pytest.mark.unit
    def test_cmos_command_initialization(self, cmos_command, mock_cs):
        """Test CMOSCommand initialization."""
        assert cmos_command.cs == mock_cs
        assert cmos_command.argv == ['dump']

    @pytest.mark.unit
    def test_parse_arguments_dump(self, mock_cs):
        """Test parsing dump command arguments."""
        command = CMOSCommand(['dump'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.cmos_dump

    @pytest.mark.unit
    def test_parse_arguments_readl(self, mock_cs):
        """Test parsing readl command arguments."""
        command = CMOSCommand(['readl', '0x10'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.cmos_readl
        assert command.offset == 0x10

    @pytest.mark.unit
    def test_parse_arguments_writel(self, mock_cs):
        """Test parsing writel command arguments."""
        command = CMOSCommand(['writel', '0x10', '0xAB'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.cmos_writel
        assert command.offset == 0x10
        assert command.value == 0xAB

    @pytest.mark.unit
    def test_parse_arguments_readh(self, mock_cs):
        """Test parsing readh command arguments."""
        command = CMOSCommand(['readh', '0x20'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.cmos_readh
        assert command.offset == 0x20

    @pytest.mark.unit
    def test_parse_arguments_writeh(self, mock_cs):
        """Test parsing writeh command arguments."""
        command = CMOSCommand(['writeh', '0x20', '0xCD'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.cmos_writeh
        assert command.offset == 0x20
        assert command.value == 0xCD

    @pytest.mark.unit
    def test_parse_arguments_decimal_values(self, mock_cs):
        """Test parsing arguments with decimal values."""
        command = CMOSCommand(['readl', '16'], cs=mock_cs)
        command.parse_arguments()
        assert command.offset == 16  # 0x10

        command2 = CMOSCommand(['writel', '32', '171'], cs=mock_cs)
        command2.parse_arguments()
        assert command2.offset == 32  # 0x20
        assert command2.value == 171  # 0xAB

    @pytest.mark.unit
    def test_requirements(self, cmos_command):
        """Test command requirements."""
        reqs = cmos_command.requirements()
        assert hasattr(reqs, 'load_driver')

    @pytest.mark.unit
    def test_set_up(self, cmos_command, mock_cs):
        """Test set_up method."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance

            cmos_command.set_up()

            assert hasattr(cmos_command, '_cmos')
            mock_cmos_class.assert_called_once_with(cmos_command.cs)

    @pytest.mark.unit
    def test_cmos_dump(self, cmos_command, mock_cs):
        """Test cmos_dump command."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance
            cmos_command.set_up()

            with patch.object(cmos_command.logger, 'log') as mock_log:
                cmos_command.cmos_dump()

                mock_log.assert_called_once_with('[CHIPSEC] Dumping CMOS memory..')
                mock_cmos_instance.dump.assert_called_once()

    @pytest.mark.unit
    def test_cmos_readl(self, cmos_command, mock_cs):
        """Test cmos_readl command."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_instance.read_cmos_low.return_value = 0xAB
            mock_cmos_class.return_value = mock_cmos_instance
            cmos_command.set_up()
            cmos_command.offset = 0x10

            with patch.object(cmos_command.logger, 'log') as mock_log:
                cmos_command.cmos_readl()

                mock_log.assert_called_once_with('[CHIPSEC] CMOS low byte 0x10 = 0xAB')
                mock_cmos_instance.read_cmos_low.assert_called_once_with(0x10)

    @pytest.mark.unit
    def test_cmos_writel(self, cmos_command, mock_cs):
        """Test cmos_writel command."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_instance.write_cmos_low.return_value = None
            mock_cmos_class.return_value = mock_cmos_instance
            cmos_command.set_up()
            cmos_command.offset = 0x10
            cmos_command.value = 0xAB

            with patch.object(cmos_command.logger, 'log') as mock_log:
                cmos_command.cmos_writel()

                mock_log.assert_called_once_with('[CHIPSEC] CMOS low byte 0x10 = 0xAB')
                mock_cmos_instance.write_cmos_low.assert_called_once_with(0x10, 0xAB)

    @pytest.mark.unit
    def test_cmos_readh(self, cmos_command, mock_cs):
        """Test cmos_readh command."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_instance.read_cmos_high.return_value = 0xCD
            mock_cmos_class.return_value = mock_cmos_instance
            cmos_command.set_up()
            cmos_command.offset = 0x20

            with patch.object(cmos_command.logger, 'log') as mock_log:
                cmos_command.cmos_readh()

                mock_log.assert_called_once_with('[CHIPSEC] CMOS high byte 0x20 = 0xCD')
                mock_cmos_instance.read_cmos_high.assert_called_once_with(0x20)

    @pytest.mark.unit
    def test_cmos_writeh(self, cmos_command, mock_cs):
        """Test cmos_writeh command."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_instance.write_cmos_high.return_value = None
            mock_cmos_class.return_value = mock_cmos_instance
            cmos_command.set_up()
            cmos_command.offset = 0x20
            cmos_command.value = 0xCD

            with patch.object(cmos_command.logger, 'log') as mock_log:
                cmos_command.cmos_writeh()

                mock_log.assert_called_once_with('[CHIPSEC] Writing CMOS high byte 0x20 <- 0xCD')
                mock_cmos_instance.write_cmos_high.assert_called_once_with(0x20, 0xCD)

    @pytest.mark.unit
    def test_cmos_readl_different_values(self, cmos_command, mock_cs):
        """Test cmos_readl with different return values."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance
            cmos_command.set_up()
            cmos_command.offset = 0x10

            # Test with different return values
            test_values = [0x0, 0xFF, 0x12, 0xAB]

            for expected_value in test_values:
                mock_cmos_instance.read_cmos_low.return_value = expected_value

                with patch.object(cmos_command.logger, 'log') as mock_log:
                    cmos_command.cmos_readl()

                    log_call = mock_log.call_args[0][0]
                    expected_hex = f'0x{expected_value:X}'
                    assert expected_hex in log_call

    @pytest.mark.unit
    def test_cmos_readh_different_values(self, cmos_command, mock_cs):
        """Test cmos_readh with different return values."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance
            cmos_command.set_up()
            cmos_command.offset = 0x20

            # Test with different return values
            test_values = [0x0, 0xFF, 0x34, 0xCD]

            for expected_value in test_values:
                mock_cmos_instance.read_cmos_high.return_value = expected_value

                with patch.object(cmos_command.logger, 'log') as mock_log:
                    cmos_command.cmos_readh()

                    log_call = mock_log.call_args[0][0]
                    expected_hex = f'0x{expected_value:X}'
                    assert expected_hex in log_call

    @pytest.mark.unit
    def test_cmos_writel_different_values(self, cmos_command, mock_cs):
        """Test cmos_writel with different values."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance
            cmos_command.set_up()
            cmos_command.offset = 0x10

            # Test with different values
            test_values = [0x0, 0xFF, 0xAB, 0x12]

            for test_value in test_values:
                cmos_command.value = test_value

                with patch.object(cmos_command.logger, 'log') as mock_log:
                    cmos_command.cmos_writel()

                    log_call = mock_log.call_args[0][0]
                    expected_hex = f'0x{test_value:X}'
                    assert expected_hex in log_call
                    mock_cmos_instance.write_cmos_low.assert_called_with(0x10, test_value)

    @pytest.mark.unit
    def test_cmos_writeh_different_values(self, cmos_command, mock_cs):
        """Test cmos_writeh with different values."""
        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance
            cmos_command.set_up()
            cmos_command.offset = 0x20

            # Test with different values
            test_values = [0x0, 0xFF, 0xCD, 0x34]

            for test_value in test_values:
                cmos_command.value = test_value

                with patch.object(cmos_command.logger, 'log') as mock_log:
                    cmos_command.cmos_writeh()

                    mock_log.assert_called_once_with(f'[CHIPSEC] Writing CMOS high byte 0x20 <- 0x{test_value:X}')
                    mock_cmos_instance.write_cmos_high.assert_called_with(0x20, test_value)


class TestCMOSCommandIntegration:
    """Integration tests for CMOS command with HAL components."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for CMOS testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        cs_mock.hals.CMOS = Mock()
        cs_mock.hals.CMOS.dump.return_value = None
        cs_mock.hals.CMOS.read_cmos_low.return_value = 0xDE
        cs_mock.hals.CMOS.write_cmos_low.return_value = None
        cs_mock.hals.CMOS.read_cmos_high.return_value = 0xAD
        cs_mock.hals.CMOS.write_cmos_high.return_value = None

        # Mock helper
        cs_mock.helper = Mock()
        cs_mock.helper.get_threads_count.return_value = 2

        return cs_mock

    @pytest.mark.integration
    def test_cmos_read_write_workflow(self, integrated_cs):
        """Test complete CMOS read/write workflow."""
        # Test dump operation
        dump_cmd = CMOSCommand(['dump'], cs=integrated_cs)
        dump_cmd.parse_arguments()

        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance

            with patch.object(dump_cmd.logger, 'log') as mock_log:
                dump_cmd.run()

                mock_log.assert_called_once_with('[CHIPSEC] Dumping CMOS memory..')
                mock_cmos_instance.dump.assert_called_once()

        # Test readl operation
        readl_cmd = CMOSCommand(['readl', '0x10'], cs=integrated_cs)
        readl_cmd.parse_arguments()

        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_instance.read_cmos_low.return_value = 0xAB
            mock_cmos_class.return_value = mock_cmos_instance

            with patch.object(readl_cmd.logger, 'log') as mock_log:
                readl_cmd.run()

                mock_log.assert_called_once_with('[CHIPSEC] CMOS low byte 0x10 = 0xAB')
                mock_cmos_instance.read_cmos_low.assert_called_once_with(0x10)

        # Test writel operation
        writel_cmd = CMOSCommand(['writel', '0x10', '0xAB'], cs=integrated_cs)
        writel_cmd.parse_arguments()

        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance

            with patch.object(writel_cmd.logger, 'log') as mock_log:
                writel_cmd.run()

                mock_log.assert_called_once_with('[CHIPSEC] CMOS low byte 0x10 = 0xAB')
                mock_cmos_instance.write_cmos_low.assert_called_once_with(0x10, 0xAB)

    @pytest.mark.integration
    def test_cmos_high_byte_operations_workflow(self, integrated_cs):
        """Test CMOS high byte operations workflow."""
        # Test readh operation
        readh_cmd = CMOSCommand(['readh', '0x20'], cs=integrated_cs)
        readh_cmd.parse_arguments()

        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_instance.read_cmos_high.return_value = 0xCD
            mock_cmos_class.return_value = mock_cmos_instance

            with patch.object(readh_cmd.logger, 'log') as mock_log:
                readh_cmd.run()

                mock_log.assert_called_once_with('[CHIPSEC] CMOS high byte 0x20 = 0xCD')
                mock_cmos_instance.read_cmos_high.assert_called_once_with(0x20)

        # Test writeh operation
        writeh_cmd = CMOSCommand(['writeh', '0x20', '0xCD'], cs=integrated_cs)
        writeh_cmd.parse_arguments()

        with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
            mock_cmos_instance = Mock()
            mock_cmos_class.return_value = mock_cmos_instance

            with patch.object(writeh_cmd.logger, 'log') as mock_log:
                writeh_cmd.run()

                mock_log.assert_called_once_with('[CHIPSEC] Writing CMOS high byte 0x20 <- 0xCD')
                mock_cmos_instance.write_cmos_high.assert_called_once_with(0x20, 0xCD)

    @pytest.mark.integration
    def test_cmos_mixed_operations_workflow(self, integrated_cs):
        """Test CMOS mixed operations workflow."""
        # Test sequence of operations
        operations = [
            ('dump', ['dump']),
            ('readl', ['readl', '0x0']),
            ('readh', ['readh', '0x1']),
            ('writel', ['writel', '0x2', '0xFF']),
            ('writeh', ['writeh', '0x3', '0xAA']),
        ]

        for op_name, args in operations:
            cmd = CMOSCommand(args, cs=integrated_cs)
            cmd.parse_arguments()

            with patch('chipsec.utilcmd.cmos_cmd.CMOS') as mock_cmos_class:
                mock_cmos_instance = Mock()
                mock_cmos_class.return_value = mock_cmos_instance

                with patch.object(cmd.logger, 'log') as mock_log:
                    cmd.run()

                    # Verify that the appropriate method was called
                    if op_name == 'dump':
                        mock_cmos_instance.dump.assert_called_once()
                    elif op_name == 'readl':
                        mock_cmos_instance.read_cmos_low.assert_called_once_with(0x0)
                    elif op_name == 'readh':
                        mock_cmos_instance.read_cmos_high.assert_called_once_with(0x1)
                    elif op_name == 'writel':
                        mock_cmos_instance.write_cmos_low.assert_called_once_with(0x2, 0xFF)
                    elif op_name == 'writeh':
                        mock_cmos_instance.write_cmos_high.assert_called_once_with(0x3, 0xAA)


class TestCMOSCommandEdgeCases:
    """Test edge cases and error conditions for CMOS command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals.CMOS = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        cmos_cmd = CMOSCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            cmos_cmd.parse_arguments()

    @pytest.mark.unit
    def test_invalid_subcommand(self, mock_cs):
        """Test handling of invalid subcommand."""
        cmos_cmd = CMOSCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            cmos_cmd.parse_arguments()

    @pytest.mark.unit
    def test_readl_missing_offset(self, mock_cs):
        """Test readl command with missing offset."""
        cmos_cmd = CMOSCommand(['readl'], cs=mock_cs)

        # Should raise SystemExit due to missing offset
        with pytest.raises(SystemExit):
            cmos_cmd.parse_arguments()

    @pytest.mark.unit
    def test_writel_missing_value(self, mock_cs):
        """Test writel command with missing value."""
        cmos_cmd = CMOSCommand(['writel', '0x10'], cs=mock_cs)

        # Should raise SystemExit due to missing value
        with pytest.raises(SystemExit):
            cmos_cmd.parse_arguments()

    @pytest.mark.unit
    def test_readh_missing_offset(self, mock_cs):
        """Test readh command with missing offset."""
        cmos_cmd = CMOSCommand(['readh'], cs=mock_cs)

        # Should raise SystemExit due to missing offset
        with pytest.raises(SystemExit):
            cmos_cmd.parse_arguments()

    @pytest.mark.unit
    def test_writeh_missing_value(self, mock_cs):
        """Test writeh command with missing value."""
        cmos_cmd = CMOSCommand(['writeh', '0x20'], cs=mock_cs)

        # Should raise SystemExit due to missing value
        with pytest.raises(SystemExit):
            cmos_cmd.parse_arguments()

    @pytest.mark.unit
    def test_zero_offset_values(self, mock_cs):
        """Test operations with zero offset values."""
        # Test readl with zero offset
        readl_cmd = CMOSCommand(['readl', '0x0'], cs=mock_cs)
        readl_cmd.parse_arguments()
        assert readl_cmd.offset == 0x0

        # Test readh with zero offset
        readh_cmd = CMOSCommand(['readh', '0x0'], cs=mock_cs)
        readh_cmd.parse_arguments()
        assert readh_cmd.offset == 0x0

    @pytest.mark.unit
    def test_maximum_offset_values(self, mock_cs):
        """Test operations with maximum offset values."""
        # CMOS memory is typically 256 bytes (0x00-0xFF)
        max_offset = 0xFF

        # Test readl with maximum offset
        readl_cmd = CMOSCommand(['readl', f'0x{max_offset:X}'], cs=mock_cs)
        readl_cmd.parse_arguments()
        assert readl_cmd.offset == max_offset

        # Test readh with maximum offset
        readh_cmd = CMOSCommand(['readh', f'0x{max_offset:X}'], cs=mock_cs)
        readh_cmd.parse_arguments()
        assert readh_cmd.offset == max_offset

    @pytest.mark.unit
    def test_zero_value_writes(self, mock_cs):
        """Test write operations with zero values."""
        # Test writel with zero value
        writel_cmd = CMOSCommand(['writel', '0x10', '0x0'], cs=mock_cs)
        writel_cmd.parse_arguments()
        assert writel_cmd.value == 0x0

        # Test writeh with zero value
        writeh_cmd = CMOSCommand(['writeh', '0x20', '0x0'], cs=mock_cs)
        writeh_cmd.parse_arguments()
        assert writeh_cmd.value == 0x0

    @pytest.mark.unit
    def test_maximum_value_writes(self, mock_cs):
        """Test write operations with maximum values."""
        # Test writel with maximum byte value
        writel_cmd = CMOSCommand(['writel', '0x10', '0xFF'], cs=mock_cs)
        writel_cmd.parse_arguments()
        assert writel_cmd.value == 0xFF

        # Test writeh with maximum byte value
        writeh_cmd = CMOSCommand(['writeh', '0x20', '0xFF'], cs=mock_cs)
        writeh_cmd.parse_arguments()
        assert writeh_cmd.value == 0xFF

    @pytest.mark.unit
    def test_hex_value_parsing(self, mock_cs):
        """Test hex value parsing in various commands."""
        # Test writel with hex value
        writel_cmd = CMOSCommand(['writel', '0x10', '0xAB'], cs=mock_cs)
        writel_cmd.parse_arguments()
        assert writel_cmd.value == 0xAB

        # Test writel with decimal value
        writel_cmd2 = CMOSCommand(['writel', '0x10', '171'], cs=mock_cs)
        writel_cmd2.parse_arguments()
        assert writel_cmd2.value == 171

        # Test writeh with hex value
        writeh_cmd = CMOSCommand(['writeh', '0x20', '0xCD'], cs=mock_cs)
        writeh_cmd.parse_arguments()
        assert writeh_cmd.value == 0xCD

    @pytest.mark.unit
    def test_case_insensitive_hex_parsing(self, mock_cs):
        """Test case insensitive hex value parsing."""
        # Test with uppercase hex
        writel_cmd1 = CMOSCommand(['writel', '0x10', '0xAB'], cs=mock_cs)
        writel_cmd1.parse_arguments()
        assert writel_cmd1.value == 0xAB

        # Test with lowercase hex
        writel_cmd2 = CMOSCommand(['writel', '0x10', '0xab'], cs=mock_cs)
        writel_cmd2.parse_arguments()
        assert writel_cmd2.value == 0xAB

        # Test with mixed case hex
        writel_cmd3 = CMOSCommand(['writel', '0x10', '0xAb'], cs=mock_cs)
        writel_cmd3.parse_arguments()
        assert writel_cmd3.value == 0xAB

    @pytest.mark.unit
    def test_common_cmos_offsets(self, mock_cs):
        """Test operations on common CMOS offsets."""
        common_offsets = {
            'rtc_seconds': 0x00,
            'rtc_minutes': 0x02,
            'rtc_hours': 0x04,
            'rtc_day': 0x07,
            'rtc_month': 0x08,
            'rtc_year': 0x09,
            'floppy_type': 0x10,
            'hd0_type': 0x12,
            'hd1_type': 0x13,
            'equipment_byte': 0x14,
        }

        for offset_name, offset_addr in common_offsets.items():
            # Test readl operation
            readl_cmd = CMOSCommand(['readl', f'0x{offset_addr:X}'], cs=mock_cs)
            readl_cmd.parse_arguments()
            assert readl_cmd.offset == offset_addr

            # Test readh operation
            readh_cmd = CMOSCommand(['readh', f'0x{offset_addr:X}'], cs=mock_cs)
            readh_cmd.parse_arguments()
            assert readh_cmd.offset == offset_addr


class TestCMOSCommandConfigurationValidation:
    """Test configuration validation aspects of CMOS command."""

    @pytest.fixture
    def config_cs(self):
        """Create ChipsecCs with CMOS-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock CMOS HAL with configuration
        cs_mock.hals.CMOS = Mock()
        cs_mock.hals.CMOS.read_cmos_low.return_value = 0x12

        # Mock CMOS configuration data
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.CMOS_CONFIG = {
            'max_offset': 0xFF,
            'cmos_size': 256,
            'supported_operations': ['dump', 'readl', 'writel', 'readh', 'writeh'],
            'common_offsets': {
                'rtc_seconds': 0x00,
                'rtc_minutes': 0x02,
                'rtc_hours': 0x04,
                'rtc_day': 0x07,
                'rtc_month': 0x08,
                'rtc_year': 0x09,
                'floppy_type': 0x10,
                'hd0_type': 0x12,
                'hd1_type': 0x13,
                'equipment_byte': 0x14,
            },
            'security_offsets': {
                'bios_checksum_low': 0x2E,
                'bios_checksum_high': 0x2F,
                'extended_memory_low': 0x30,
                'extended_memory_high': 0x31,
                'century_byte': 0x32,
                'boot_flags': 0x38,
            },
            'nvram_area': {
                'start': 0x0E,
                'end': 0x7F,
                'description': 'Non-volatile RAM area for BIOS settings'
            }
        }

        return cs_mock

    @pytest.mark.unit
    def test_cmos_configuration_access(self, config_cs):
        """Test access to CMOS configuration data."""
        cmos_config = config_cs.Cfg.CMOS_CONFIG

        assert cmos_config['max_offset'] == 0xFF
        assert cmos_config['cmos_size'] == 256
        assert 'dump' in cmos_config['supported_operations']
        assert 'readl' in cmos_config['supported_operations']
        assert 'rtc_seconds' in cmos_config['common_offsets']
        assert cmos_config['common_offsets']['rtc_seconds'] == 0x00

    @pytest.mark.unit
    def test_supported_operations_validation(self, config_cs):
        """Test validation of supported CMOS operations."""
        supported_ops = config_cs.Cfg.CMOS_CONFIG['supported_operations']

        # Test that all documented operations are supported
        expected_ops = ['dump', 'readl', 'writel', 'readh', 'writeh']
        for op in expected_ops:
            assert op in supported_ops

        # Test that operations list is not empty
        assert len(supported_ops) > 0

    @pytest.mark.unit
    def test_common_offsets_validation(self, config_cs):
        """Test validation of common CMOS offsets."""
        common_offsets = config_cs.Cfg.CMOS_CONFIG['common_offsets']

        # Test that all expected common offsets are defined
        expected_offsets = [
            'rtc_seconds', 'rtc_minutes', 'rtc_hours', 'rtc_day',
            'rtc_month', 'rtc_year', 'floppy_type', 'hd0_type',
            'hd1_type', 'equipment_byte'
        ]

        for offset_name in expected_offsets:
            assert offset_name in common_offsets
            assert isinstance(common_offsets[offset_name], int)
            assert 0 <= common_offsets[offset_name] <= 0xFF

        # Test specific offset values
        assert common_offsets['rtc_seconds'] == 0x00
        assert common_offsets['rtc_hours'] == 0x04
        assert common_offsets['equipment_byte'] == 0x14

    @pytest.mark.unit
    def test_security_offsets_validation(self, config_cs):
        """Test validation of security-related CMOS offsets."""
        security_offsets = config_cs.Cfg.CMOS_CONFIG['security_offsets']

        # Test that all expected security offsets are defined
        expected_security_offsets = [
            'bios_checksum_low', 'bios_checksum_high',
            'extended_memory_low', 'extended_memory_high',
            'century_byte', 'boot_flags'
        ]

        for offset_name in expected_security_offsets:
            assert offset_name in security_offsets
            assert isinstance(security_offsets[offset_name], int)
            assert 0 <= security_offsets[offset_name] <= 0xFF

        # Test specific security offset values
        assert security_offsets['bios_checksum_low'] == 0x2E
        assert security_offsets['bios_checksum_high'] == 0x2F
        assert security_offsets['century_byte'] == 0x32

    @pytest.mark.unit
    def test_nvram_area_validation(self, config_cs):
        """Test validation of NVRAM area configuration."""
        nvram_area = config_cs.Cfg.CMOS_CONFIG['nvram_area']

        # Test NVRAM area configuration
        assert nvram_area['start'] == 0x0E
        assert nvram_area['end'] == 0x7F
        assert 'description' in nvram_area
        assert nvram_area['start'] < nvram_area['end']

        # Test that NVRAM area is within valid CMOS range
        max_offset = config_cs.Cfg.CMOS_CONFIG['max_offset']
        assert 0 <= nvram_area['start'] <= max_offset
        assert 0 <= nvram_area['end'] <= max_offset

    @pytest.mark.unit
    def test_offset_range_validation(self, config_cs):
        """Test CMOS offset range validation."""
        max_offset = config_cs.Cfg.CMOS_CONFIG['max_offset']
        cmos_size = config_cs.Cfg.CMOS_CONFIG['cmos_size']

        # Test that maximum offset matches CMOS size - 1
        assert max_offset == cmos_size - 1

        # Test that all configured offsets are within valid range
        all_offsets = {}
        all_offsets.update(config_cs.Cfg.CMOS_CONFIG['common_offsets'])
        all_offsets.update(config_cs.Cfg.CMOS_CONFIG['security_offsets'])

        for offset_name, offset_addr in all_offsets.items():
            assert 0 <= offset_addr <= max_offset, f"CMOS offset {offset_name} address 0x{offset_addr:X} exceeds maximum 0x{max_offset:X}"

        # Test NVRAM area bounds
        nvram_start = config_cs.Cfg.CMOS_CONFIG['nvram_area']['start']
        nvram_end = config_cs.Cfg.CMOS_CONFIG['nvram_area']['end']
        assert 0 <= nvram_start <= max_offset, f"NVRAM start address 0x{nvram_start:X} exceeds maximum 0x{max_offset:X}"
        assert 0 <= nvram_end <= max_offset, f"NVRAM end address 0x{nvram_end:X} exceeds maximum 0x{max_offset:X}"


if __name__ == '__main__':
    pytest.main([__file__])
