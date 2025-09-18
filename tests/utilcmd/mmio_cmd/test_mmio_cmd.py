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
from chipsec.utilcmd.mmio_cmd import MMIOCommand
from tests.test_utils import MockFactory


class TestMMIOCommand:
    """Comprehensive tests for MMIO utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for MMIO testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock MMIO HAL component
        cs_mock.hals = Mock()
        cs_mock.hals.mmio = Mock()

        return cs_mock

    @pytest.fixture
    def mmio_command(self, mock_cs):
        """Create MMIOCommand instance."""
        return MMIOCommand(['list'], cs=mock_cs)

    @pytest.mark.unit
    def test_mmio_command_initialization(self, mmio_command, mock_cs):
        """Test MMIOCommand initialization."""
        assert mmio_command.cs == mock_cs
        assert mmio_command.argv == ['list']

    @pytest.mark.unit
    def test_requirements(self, mmio_command):
        """Test command requirements."""
        reqs = mmio_command.requirements()
        assert reqs == mmio_command.toLoad.All

    @pytest.mark.unit
    def test_parse_arguments_list(self, mock_cs):
        """Test parsing list command."""
        command = MMIOCommand(['list'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.list_bars

    @pytest.mark.unit
    def test_parse_arguments_dump(self, mock_cs):
        """Test parsing dump command."""
        command = MMIOCommand(['dump', 'MCHBAR', '0x70', '0x10'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.dump_bar
        assert command.bar_name == 'MCHBAR'
        assert command.offset == 0x70
        assert command.length == 0x10

    @pytest.mark.unit
    def test_parse_arguments_dump_defaults(self, mock_cs):
        """Test parsing dump command with defaults."""
        command = MMIOCommand(['dump', 'SPIBAR'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.dump_bar
        assert command.bar_name == 'SPIBAR'
        assert command.offset == 0
        assert command.length is None

    @pytest.mark.unit
    def test_parse_arguments_dump_abs(self, mock_cs):
        """Test parsing dump-abs command."""
        command = MMIOCommand(['dump-abs', '0xFED00000', '0x0', '0x1000'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.dump_bar_abs
        assert command.base == 0xFED00000
        assert command.offset == 0x0
        assert command.length == 0x1000

    @pytest.mark.unit
    def test_parse_arguments_dump_abs_defaults(self, mock_cs):
        """Test parsing dump-abs command with defaults."""
        command = MMIOCommand(['dump-abs', '0xFED00000'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.dump_bar_abs
        assert command.base == 0xFED00000
        assert command.offset == 0
        assert command.length is None

    @pytest.mark.unit
    def test_parse_arguments_read(self, mock_cs):
        """Test parsing read command."""
        command = MMIOCommand(['read', 'SPIBAR', '0x74', '0x4', '0x0'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.read_bar
        assert command.bar_name == 'SPIBAR'
        assert command.offset == 0x74
        assert command.width == 0x4
        assert command.bus == 0x0

    @pytest.mark.unit
    def test_parse_arguments_read_no_bus(self, mock_cs):
        """Test parsing read command without bus."""
        command = MMIOCommand(['read', 'MCHBAR', '0x70', '0x4'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.read_bar
        assert command.bar_name == 'MCHBAR'
        assert command.offset == 0x70
        assert command.width == 0x4
        assert command.bus is None

    @pytest.mark.unit
    def test_parse_arguments_read_abs(self, mock_cs):
        """Test parsing read-abs command."""
        command = MMIOCommand(['read-abs', '0xFED00000', '0x74', '0x4'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.read_abs
        assert command.base == 0xFED00000
        assert command.offset == 0x74
        assert command.width == 0x4

    @pytest.mark.unit
    def test_parse_arguments_write(self, mock_cs):
        """Test parsing write command."""
        command = MMIOCommand(['write', 'SPIBAR', '0x74', '0x4', '0xFFFF0000', '0x0'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.write_bar
        assert command.bar_name == 'SPIBAR'
        assert command.offset == 0x74
        assert command.width == 0x4
        assert command.value == 0xFFFF0000
        assert command.bus == 0x0

    @pytest.mark.unit
    def test_parse_arguments_write_no_bus(self, mock_cs):
        """Test parsing write command without bus."""
        command = MMIOCommand(['write', 'MCHBAR', '0x70', '0x4', '0x12345678'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.write_bar
        assert command.bar_name == 'MCHBAR'
        assert command.offset == 0x70
        assert command.width == 0x4
        assert command.value == 0x12345678
        assert command.bus is None

    @pytest.mark.unit
    def test_parse_arguments_write_abs(self, mock_cs):
        """Test parsing write-abs command."""
        command = MMIOCommand(['write-abs', '0xFED00000', '0x74', '0x4', '0xFFFF0000'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.write_abs
        assert command.base == 0xFED00000
        assert command.offset == 0x74
        assert command.width == 0x4
        assert command.value == 0xFFFF0000

    @pytest.mark.unit
    def test_parse_arguments_invalid_width(self, mock_cs):
        """Test parsing command with invalid width."""
        command = MMIOCommand(['read', 'SPIBAR', '0x74', '0x3'], cs=mock_cs)

        # Should raise SystemExit due to invalid width choice
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_invalid(self, mock_cs):
        """Test parsing invalid command."""
        command = MMIOCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_set_up(self, mmio_command, mock_cs):
        """Test set_up method."""
        mmio_command.set_up()
        # Should create MMIO instance
        assert hasattr(mmio_command, '_mmio')

    @pytest.mark.unit
    def test_list_bars(self, mmio_command, mock_cs):
        """Test list_bars method."""
        mmio_command._mmio = Mock()

        mmio_command.list_bars()

        mmio_command._mmio.list_MMIO_BARs.assert_called_once()

    @pytest.mark.unit
    def test_dump_bar_with_length(self, mmio_command, mock_cs):
        """Test dump_bar method with specified length."""
        mmio_command.bar_name = 'MCHBAR'
        mmio_command.offset = 0x70
        mmio_command.length = 0x10

        mmio_command._mmio = Mock()
        mmio_command._mmio.get_MMIO_BAR_base_address.return_value = (0xFED00000, 0x1000)

        with patch.object(mmio_command.logger, 'log') as mock_log:
            mmio_command.dump_bar()

            mmio_command._mmio.get_MMIO_BAR_base_address.assert_called_once_with('MCHBAR')
            mmio_command._mmio.dump_MMIO.assert_called_once_with(0xFED00070, 0x10)
            mock_log.assert_called_with("[CHIPSEC] Dumping MCHBAR MMIO space..")

    @pytest.mark.unit
    def test_dump_bar_without_length(self, mmio_command, mock_cs):
        """Test dump_bar method without specified length."""
        mmio_command.bar_name = 'SPIBAR'
        mmio_command.offset = 0x0
        mmio_command.length = None

        mmio_command._mmio = Mock()
        mmio_command._mmio.get_MMIO_BAR_base_address.return_value = (0xFED00000, 0x1000)

        with patch.object(mmio_command.logger, 'log') as mock_log:
            mmio_command.dump_bar()

            mmio_command._mmio.get_MMIO_BAR_base_address.assert_called_once_with('SPIBAR')
            mmio_command._mmio.dump_MMIO.assert_called_once_with(0xFED00000, 0x1000)
            mock_log.assert_called_with("[CHIPSEC] Dumping SPIBAR MMIO space..")

    @pytest.mark.unit
    def test_dump_bar_abs_with_length(self, mmio_command, mock_cs):
        """Test dump_bar_abs method with specified length."""
        mmio_command.base = 0xFED00000
        mmio_command.offset = 0x70
        mmio_command.length = 0x10

        mmio_command._mmio = Mock()

        with patch.object(mmio_command.logger, 'log') as mock_log:
            mmio_command.dump_bar_abs()

            mmio_command._mmio.dump_MMIO.assert_called_once_with(0xFED00070, 0x10)
            mock_log.assert_called_with("[CHIPSEC] Dumping MMIO space 0xFED00070 to 0xFED00080")

    @pytest.mark.unit
    def test_dump_bar_abs_without_length(self, mmio_command, mock_cs):
        """Test dump_bar_abs method without specified length."""
        mmio_command.base = 0xFED00000
        mmio_command.offset = 0x0
        mmio_command.length = None

        mmio_command._mmio = Mock()

        with patch.object(mmio_command.logger, 'log') as mock_log:
            mmio_command.dump_bar_abs()

            mmio_command._mmio.dump_MMIO.assert_called_once_with(0xFED00000, 0x1000)
            mock_log.assert_called_with("[CHIPSEC] Dumping MMIO space 0xFED00000 to 0xFED01000")

    @pytest.mark.unit
    def test_read_bar_byte(self, mmio_command, mock_cs):
        """Test read_bar method with byte width."""
        mmio_command.bar_name = 'SPIBAR'
        mmio_command.offset = 0x74
        mmio_command.width = 0x1
        mmio_command.bus = 0x0

        mmio_command._mmio = Mock()
        mmio_command._mmio.read_MMIO_BAR_reg.return_value = 0xAB

        with patch.object(mmio_command.logger, 'log') as mock_log:
            mmio_command.read_bar()

            mmio_command._mmio.read_MMIO_BAR_reg.assert_called_once_with('SPIBAR', 0x74, 0x1, 0x0)
            mock_log.assert_called_with("[CHIPSEC] Read SPIBAR + 0x74: 0x000000AB")

    @pytest.mark.unit
    def test_read_bar_dword(self, mmio_command, mock_cs):
        """Test read_bar method with dword width."""
        mmio_command.bar_name = 'MCHBAR'
        mmio_command.offset = 0x70
        mmio_command.width = 0x4
        mmio_command.bus = None

        mmio_command._mmio = Mock()
        mmio_command._mmio.read_MMIO_BAR_reg.return_value = 0x12345678

        with patch.object(mmio_command.logger, 'log') as mock_log:
            mmio_command.read_bar()

            mmio_command._mmio.read_MMIO_BAR_reg.assert_called_once_with('MCHBAR', 0x70, 0x4, None)
            mock_log.assert_called_with("[CHIPSEC] Read MCHBAR + 0x70: 0x12345678")

    @pytest.mark.unit
    def test_read_abs_byte(self, mmio_command, mock_cs):
        """Test read_abs method with byte width."""
        mmio_command.base = 0xFED00000
        mmio_command.offset = 0x74
        mmio_command.width = 1

        mmio_command._mmio = Mock()
        mmio_command._mmio.read_MMIO_reg_byte.return_value = 0xAB

        with patch.object(mmio_command.logger, 'log') as mock_log:
            mmio_command.read_abs()

            mmio_command._mmio.read_MMIO_reg_byte.assert_called_once_with(0xFED00000, 0x74)
            mock_log.assert_called_with("[CHIPSEC] Read 0xFED00000 + 0x74: 0x000000AB")

    @pytest.mark.unit
    def test_read_abs_word(self, mmio_command, mock_cs):
        """Test read_abs method with word width."""
        mmio_command.base = 0xFED00000
        mmio_command.offset = 0x74
        mmio_command.width = 2

        mmio_command._mmio = Mock()
        mmio_command._mmio.read_MMIO_reg_word.return_value = 0xABCD

        with patch.object(mmio_command.logger, 'log') as mock_log:
            mmio_command.read_abs()

            mmio_command._mmio.read_MMIO_reg_word.assert_called_once_with(0xFED00000, 0x74)
            mock_log.assert_called_with("[CHIPSEC] Read 0xFED00000 + 0x74: 0x0000ABCD")

    @pytest.mark.unit
    def test_read_abs_dword(self, mmio_command, mock_cs):
        """Test read_abs method with dword width."""
        mmio_command.base = 0xFED00000
        mmio_command.offset = 0x74
        mmio_command.width = 4

        mmio_command._mmio = Mock()
        mmio_command._mmio.read_MMIO_reg_dword.return_value = 0x12345678

        with patch.object(mmio_command.logger, 'log') as mock_log:
            mmio_command.read_abs()

            mmio_command._mmio.read_MMIO_reg_dword.assert_called_once_with(0xFED00000, 0x74)
            mock_log.assert_called_with("[CHIPSEC] Read 0xFED00000 + 0x74: 0x12345678")

    @pytest.mark.unit
    def test_read_abs_qword(self, mmio_command, mock_cs):
        """Test read_abs method with qword width."""
        mmio_command.base = 0xFED00000
        mmio_command.offset = 0x74
        mmio_command.width = 8

        mmio_command._mmio = Mock()
        mmio_command._mmio.read_MMIO_reg_dword.side_effect = [0x12345678, 0x9ABCDEF0]

        with patch.object(mmio_command.logger, 'log') as mock_log:
            mmio_command.read_abs()

            # Should read two dwords for qword
            assert mmio_command._mmio.read_MMIO_reg_dword.call_count == 2
            mock_log.assert_called_with("[CHIPSEC] Read 0xFED00000 + 0x74: 0x9ABCDEF012345678")

    @pytest.mark.unit
    def test_write_bar_byte(self, mmio_command, mock_cs):
        """Test write_bar method with byte width."""
        mmio_command.bar_name = 'SPIBAR'
        mmio_command.offset = 0x74
        mmio_command.width = 0x1
        mmio_command.value = 0xAB
        mmio_command.bus = 0x0

        mmio_command._mmio = Mock()

        with patch.object(mmio_command.logger, 'log') as mock_log:
            mmio_command.write_bar()

            mmio_command._mmio.write_MMIO_BAR_reg.assert_called_once_with('SPIBAR', 0x74, 0xAB, 0x1, 0x0)
            mock_log.assert_called_with("[CHIPSEC] Write SPIBAR + 0x74: 0x000000AB")

    @pytest.mark.unit
    def test_write_bar_dword(self, mmio_command, mock_cs):
        """Test write_bar method with dword width."""
        mmio_command.bar_name = 'MCHBAR'
        mmio_command.offset = 0x70
        mmio_command.width = 0x4
        mmio_command.value = 0x12345678
        mmio_command.bus = None

        mmio_command._mmio = Mock()

        with patch.object(mmio_command.logger, 'log') as mock_log:
            mmio_command.write_bar()

            mmio_command._mmio.write_MMIO_BAR_reg.assert_called_once_with('MCHBAR', 0x70, 0x12345678, 0x4, None)
            mock_log.assert_called_with("[CHIPSEC] Write MCHBAR + 0x70: 0x12345678")

    @pytest.mark.unit
    def test_write_abs_byte(self, mmio_command, mock_cs):
        """Test write_abs method with byte width."""
        mmio_command.base = 0xFED00000
        mmio_command.offset = 0x74
        mmio_command.width = 1
        mmio_command.value = 0xAB

        mmio_command._mmio = Mock()

        with patch.object(mmio_command.logger, 'log') as mock_log:
            mmio_command.write_abs()

            mmio_command._mmio.write_MMIO_reg_byte.assert_called_once_with(0xFED00000, 0x74, 0xAB)
            mock_log.assert_called_with("[CHIPSEC] Write 0xFED00000 + 0x74: 0x000000AB")

    @pytest.mark.unit
    def test_write_abs_word(self, mmio_command, mock_cs):
        """Test write_abs method with word width."""
        mmio_command.base = 0xFED00000
        mmio_command.offset = 0x74
        mmio_command.width = 2
        mmio_command.value = 0xABCD

        mmio_command._mmio = Mock()

        with patch.object(mmio_command.logger, 'log') as mock_log:
            mmio_command.write_abs()

            mmio_command._mmio.write_MMIO_reg_word.assert_called_once_with(0xFED00000, 0x74, 0xABCD)
            mock_log.assert_called_with("[CHIPSEC] Write 0xFED00000 + 0x74: 0x0000ABCD")

    @pytest.mark.unit
    def test_write_abs_dword(self, mmio_command, mock_cs):
        """Test write_abs method with dword width."""
        mmio_command.base = 0xFED00000
        mmio_command.offset = 0x74
        mmio_command.width = 4
        mmio_command.value = 0x12345678

        mmio_command._mmio = Mock()

        with patch.object(mmio_command.logger, 'log') as mock_log:
            mmio_command.write_abs()

            mmio_command._mmio.write_MMIO_reg_dword.assert_called_once_with(0xFED00000, 0x74, 0x12345678)
            mock_log.assert_called_with("[CHIPSEC] Write 0xFED00000 + 0x74: 0x12345678")

    @pytest.mark.unit
    def test_write_abs_qword(self, mmio_command, mock_cs):
        """Test write_abs method with qword width."""
        mmio_command.base = 0xFED00000
        mmio_command.offset = 0x74
        mmio_command.width = 8
        mmio_command.value = 0x123456789ABCDEF0

        mmio_command._mmio = Mock()

        with patch.object(mmio_command.logger, 'log') as mock_log:
            mmio_command.write_abs()

            # Should write two dwords for qword
            assert mmio_command._mmio.write_MMIO_reg_dword.call_count == 2
            mmio_command._mmio.write_MMIO_reg_dword.assert_any_call(0xFED00000, 0x74, 0x9ABCDEF0)
            mmio_command._mmio.write_MMIO_reg_dword.assert_any_call(0xFED00000, 0x78, 0x12345678)
            mock_log.assert_called_with("[CHIPSEC] Write 0xFED00000 + 0x74: 0x123456789ABCDEF0")

    @pytest.mark.unit
    def test_run(self, mmio_command, mock_cs):
        """Test run method."""
        mmio_command.func = Mock()

        mmio_command.run()

        mmio_command.func.assert_called_once()


class TestMMIOCommandIntegration:
    """Integration tests for MMIO command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for MMIO testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock MMIO components with realistic data
        cs_mock.hals = Mock()
        cs_mock.hals.mmio = Mock()

        return cs_mock

    @pytest.mark.integration
    def test_mmio_list_integration(self, integrated_cs):
        """Test complete mmio_list workflow."""
        mmio_cmd = MMIOCommand(['list'], cs=integrated_cs)
        mmio_cmd.set_up()

        mmio_cmd.run()

        mmio_cmd._mmio.list_MMIO_BARs.assert_called_once()

    @pytest.mark.integration
    def test_mmio_dump_integration(self, integrated_cs):
        """Test complete mmio_dump workflow."""
        mmio_cmd = MMIOCommand(['dump', 'MCHBAR', '0x70', '0x10'], cs=integrated_cs)
        mmio_cmd.set_up()

        mmio_cmd._mmio.get_MMIO_BAR_base_address.return_value = (0xFED00000, 0x1000)

        with patch.object(mmio_cmd.logger, 'log'):
            mmio_cmd.run()

            mmio_cmd._mmio.get_MMIO_BAR_base_address.assert_called_once_with('MCHBAR')
            mmio_cmd._mmio.dump_MMIO.assert_called_once_with(0xFED00070, 0x10)

    @pytest.mark.integration
    def test_mmio_read_write_integration(self, integrated_cs):
        """Test complete read-write workflow."""
        # Test write operation
        write_cmd = MMIOCommand(['write', 'SPIBAR', '0x74', '0x4', '0xFFFF0000'], cs=integrated_cs)
        write_cmd.set_up()

        with patch.object(write_cmd.logger, 'log'):
            write_cmd.run()

            write_cmd._mmio.write_MMIO_BAR_reg.assert_called_once_with('SPIBAR', 0x74, 0xFFFF0000, 0x4, None)

        # Test read operation
        read_cmd = MMIOCommand(['read', 'SPIBAR', '0x74', '0x4'], cs=integrated_cs)
        read_cmd.set_up()

        read_cmd._mmio.read_MMIO_BAR_reg.return_value = 0xFFFF0000

        with patch.object(read_cmd.logger, 'log'):
            read_cmd.run()

            read_cmd._mmio.read_MMIO_BAR_reg.assert_called_once_with('SPIBAR', 0x74, 0x4, None)

    @pytest.mark.integration
    def test_mmio_abs_operations_integration(self, integrated_cs):
        """Test complete absolute address operations workflow."""
        # Test write-abs operation
        write_abs_cmd = MMIOCommand(['write-abs', '0xFED00000', '0x74', '0x4', '0x12345678'], cs=integrated_cs)
        write_abs_cmd.set_up()

        with patch.object(write_abs_cmd.logger, 'log'):
            write_abs_cmd.run()

            write_abs_cmd._mmio.write_MMIO_reg_dword.assert_called_once_with(0xFED00000, 0x74, 0x12345678)

        # Test read-abs operation
        read_abs_cmd = MMIOCommand(['read-abs', '0xFED00000', '0x74', '0x4'], cs=integrated_cs)
        read_abs_cmd.set_up()

        read_abs_cmd._mmio.read_MMIO_reg_dword.return_value = 0x12345678

        with patch.object(read_abs_cmd.logger, 'log'):
            read_abs_cmd.run()

            read_abs_cmd._mmio.read_MMIO_reg_dword.assert_called_once_with(0xFED00000, 0x74)


class TestMMIOCommandEdgeCases:
    """Test edge cases and error conditions for MMIO command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        cs_mock.hals.mmio = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        command = MMIOCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_dump_bar_zero_offset(self, mock_cs):
        """Test dump_bar with zero offset."""
        command = MMIOCommand(['dump', 'SPIBAR', '0x0', '0x100'], cs=mock_cs)
        command.set_up()

        command._mmio.get_MMIO_BAR_base_address.return_value = (0xFED00000, 0x1000)

        with patch.object(command.logger, 'log'):
            command.run()

            command._mmio.dump_MMIO.assert_called_once_with(0xFED00000, 0x100)

    @pytest.mark.unit
    def test_dump_bar_full_bar_size(self, mock_cs):
        """Test dump_bar with full BAR size."""
        command = MMIOCommand(['dump', 'MCHBAR'], cs=mock_cs)
        command.set_up()

        command._mmio.get_MMIO_BAR_base_address.return_value = (0xFED00000, 0x1000)

        with patch.object(command.logger, 'log'):
            command.run()

            command._mmio.dump_MMIO.assert_called_once_with(0xFED00000, 0x1000)

    @pytest.mark.unit
    def test_read_bar_different_widths(self, mock_cs):
        """Test read_bar with different data widths."""
        test_cases = [
            (1, 'read_MMIO_BAR_reg'),
            (2, 'read_MMIO_BAR_reg'),
            (4, 'read_MMIO_BAR_reg'),
            (8, 'read_MMIO_BAR_reg')
        ]

        for width, expected_method in test_cases:
            command = MMIOCommand(['read', 'SPIBAR', '0x74', f'0x{width}'], cs=mock_cs)
            command.set_up()

            with patch.object(command.logger, 'log'):
                command.run()

                getattr(command._mmio, expected_method).assert_called_with('SPIBAR', 0x74, width, None)

    @pytest.mark.unit
    def test_write_bar_different_widths(self, mock_cs):
        """Test write_bar with different data widths."""
        test_cases = [
            (1, 'write_MMIO_BAR_reg'),
            (2, 'write_MMIO_BAR_reg'),
            (4, 'write_MMIO_BAR_reg'),
            (8, 'write_MMIO_BAR_reg')
        ]

        for width, expected_method in test_cases:
            command = MMIOCommand(['write', 'SPIBAR', '0x74', f'0x{width}', '0x12345678'], cs=mock_cs)
            command.set_up()

            with patch.object(command.logger, 'log'):
                command.run()

                getattr(command._mmio, expected_method).assert_called_with('SPIBAR', 0x74, 0x12345678, width, None)

    @pytest.mark.unit
    def test_read_abs_different_widths(self, mock_cs):
        """Test read_abs with different data widths."""
        test_cases = [
            (1, 'read_MMIO_reg_byte'),
            (2, 'read_MMIO_reg_word'),
            (4, 'read_MMIO_reg_dword'),
            (8, 'read_MMIO_reg_dword')  # Qword uses two dwords
        ]

        for width, expected_method in test_cases:
            command = MMIOCommand(['read-abs', '0xFED00000', '0x74', f'0x{width}'], cs=mock_cs)
            command.set_up()

            if width == 8:
                command._mmio.read_MMIO_reg_dword.side_effect = [0x12345678, 0x9ABCDEF0]

            with patch.object(command.logger, 'log'):
                command.run()

                if width == 8:
                    assert command._mmio.read_MMIO_reg_dword.call_count == 2
                else:
                    getattr(command._mmio, expected_method).assert_called_with(0xFED00000, 0x74)

    @pytest.mark.unit
    def test_write_abs_different_widths(self, mock_cs):
        """Test write_abs with different data widths."""
        test_cases = [
            (1, 'write_MMIO_reg_byte', 0xAB),
            (2, 'write_MMIO_reg_word', 0xABCD),
            (4, 'write_MMIO_reg_dword', 0x12345678),
            (8, 'write_MMIO_reg_dword', 0x123456789ABCDEF0)  # Qword uses two dwords
        ]

        for width, expected_method, value in test_cases:
            command = MMIOCommand(['write-abs', '0xFED00000', '0x74', f'0x{width}', f'0x{value:X}'], cs=mock_cs)
            command.set_up()

            with patch.object(command.logger, 'log'):
                command.run()

                if width == 8:
                    assert command._mmio.write_MMIO_reg_dword.call_count == 2
                else:
                    getattr(command._mmio, expected_method).assert_called_with(0xFED00000, 0x74, value & ((1 << (width * 8)) - 1))

    @pytest.mark.unit
    def test_dump_bar_abs_large_region(self, mock_cs):
        """Test dump_bar_abs with large memory region."""
        command = MMIOCommand(['dump-abs', '0xFED00000', '0x0', '0x100000'], cs=mock_cs)
        command.set_up()

        with patch.object(command.logger, 'log'):
            command.run()

            command._mmio.dump_MMIO.assert_called_once_with(0xFED00000, 0x100000)

    @pytest.mark.unit
    def test_read_bar_with_bus_parameter(self, mock_cs):
        """Test read_bar with bus parameter specified."""
        command = MMIOCommand(['read', 'SPIBAR', '0x74', '0x4', '0x1'], cs=mock_cs)
        command.set_up()

        command._mmio.read_MMIO_BAR_reg.return_value = 0x12345678

        with patch.object(command.logger, 'log'):
            command.run()

            command._mmio.read_MMIO_BAR_reg.assert_called_once_with('SPIBAR', 0x74, 0x4, 0x1)

    @pytest.mark.unit
    def test_write_bar_with_bus_parameter(self, mock_cs):
        """Test write_bar with bus parameter specified."""
        command = MMIOCommand(['write', 'SPIBAR', '0x74', '0x4', '0x12345678', '0x1'], cs=mock_cs)
        command.set_up()

        with patch.object(command.logger, 'log'):
            command.run()

            command._mmio.write_MMIO_BAR_reg.assert_called_once_with('SPIBAR', 0x74, 0x12345678, 0x4, 0x1)


class TestMMIOCommandConfigurationValidation:
    """Test configuration validation aspects of MMIO command."""

    @pytest.fixture
    def mmio_cs(self):
        """Create ChipsecCs with MMIO-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock MMIO configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.MMIO = {
            'MCHBAR_BASE': 0xFED00000,
            'MCHBAR_SIZE': 0x1000,
            'SPIBAR_BASE': 0xFED10000,
            'SPIBAR_SIZE': 0x1000
        }

        cs_mock.hals = Mock()
        cs_mock.hals.mmio = Mock()

        return cs_mock

    @pytest.mark.unit
    def test_mmio_configuration_structure(self, mmio_cs):
        """Test MMIO configuration structure."""
        mmio_config = mmio_cs.Cfg.MMIO

        # Test that required MMIO configuration exists
        assert 'MCHBAR_BASE' in mmio_config
        assert 'MCHBAR_SIZE' in mmio_config

        # Test configuration values are reasonable
        assert mmio_config['MCHBAR_BASE'] > 0
        assert mmio_config['MCHBAR_SIZE'] > 0

    @pytest.mark.unit
    def test_mmio_bar_address_validation(self, mmio_cs):
        """Test MMIO BAR address validation."""
        command = MMIOCommand(['read', 'MCHBAR', '0x70', '0x4'], cs=mmio_cs)
        command.parse_arguments()
        command.set_up()

        # Test that BAR name is properly parsed
        assert command.bar_name == 'MCHBAR'
        assert isinstance(command.offset, int)
        assert command.offset == 0x70
        assert isinstance(command.width, int)
        assert command.width == 0x4

    @pytest.mark.unit
    def test_mmio_absolute_address_validation(self, mmio_cs):
        """Test MMIO absolute address validation."""
        command = MMIOCommand(['read-abs', '0xFED00000', '0x74', '0x4'], cs=mmio_cs)
        command.parse_arguments()
        command.set_up()

        # Test that absolute address is properly parsed
        assert command.base == 0xFED00000
        assert isinstance(command.offset, int)
        assert command.offset == 0x74
        assert isinstance(command.width, int)
        assert command.width == 0x4

    @pytest.mark.unit
    def test_mmio_width_validation(self, mmio_cs):
        """Test MMIO data width validation."""
        valid_widths = [1, 2, 4, 8]

        for width in valid_widths:
            command = MMIOCommand(['read-abs', '0xFED00000', '0x74', f'0x{width}'], cs=mmio_cs)
            command.parse_arguments()  # Should not raise exception

            assert command.width == width

    @pytest.mark.unit
    def test_mmio_offset_validation(self, mmio_cs):
        """Test MMIO offset validation."""
        # Test various offset formats
        test_cases = [
            ('0x70', 0x70),
            ('0x0', 0x0),
            ('0x100', 0x100),
            ('0', 0)
        ]

        for offset_str, expected_offset in test_cases:
            command = MMIOCommand(['read', 'SPIBAR', offset_str, '0x4'], cs=mmio_cs)
            command.parse_arguments()

            assert command.offset == expected_offset

    @pytest.mark.unit
    def test_mmio_length_validation(self, mmio_cs):
        """Test MMIO length validation."""
        # Test various length formats
        test_cases = [
            ('0x10', 0x10),
            ('0x100', 0x100),
            ('0x1000', 0x1000),
            ('0', 0)
        ]

        for length_str, expected_length in test_cases:
            command = MMIOCommand(['dump', 'MCHBAR', '0x0', length_str], cs=mmio_cs)
            command.parse_arguments()

            assert command.length == expected_length


if __name__ == '__main__':
    pytest.main([__file__])
