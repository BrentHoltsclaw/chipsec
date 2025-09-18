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
from chipsec.utilcmd.msgbus_cmd import MsgBusCommand
from tests.test_utils import MockFactory


class TestMsgBusCommand:
    """Comprehensive tests for Message Bus command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for Message Bus testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock MsgBus HAL component
        cs_mock.hals = Mock()
        cs_mock.hals.MsgBus = Mock()

        return cs_mock

    @pytest.fixture
    def msgbus_command(self, mock_cs):
        """Create MsgBusCommand instance."""
        return MsgBusCommand(['read', '0x3', '0x2E'], cs=mock_cs)

    @pytest.mark.unit
    def test_msgbus_command_initialization(self, msgbus_command, mock_cs):
        """Test MsgBusCommand initialization."""
        assert msgbus_command.cs == mock_cs
        assert msgbus_command.argv == ['read', '0x3', '0x2E']

    @pytest.mark.unit
    def test_requirements(self, msgbus_command):
        """Test command requirements."""
        reqs = msgbus_command.requirements()
        assert reqs == msgbus_command.toLoad.All

    @pytest.mark.unit
    def test_parse_arguments_read(self, mock_cs):
        """Test parsing arguments for read subcommand."""
        command = MsgBusCommand(['read', '0x3', '0x2E'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.msgbus_read
        assert command.port == 0x3
        assert command.reg == 0x2E

    @pytest.mark.unit
    def test_parse_arguments_write(self, mock_cs):
        """Test parsing arguments for write subcommand."""
        command = MsgBusCommand(['write', '0x3', '0x27', '0xE0000001'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.msgbus_write
        assert command.port == 0x3
        assert command.reg == 0x27
        assert command.val == 0xE0000001

    @pytest.mark.unit
    def test_parse_arguments_message_with_value(self, mock_cs):
        """Test parsing arguments for message subcommand with value."""
        command = MsgBusCommand(['message', '0x3', '0x2E', '0x10', '0x12345678'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.msgbus_message
        assert command.port == 0x3
        assert command.reg == 0x2E
        assert command.opcode == 0x10
        assert command.val == 0x12345678

    @pytest.mark.unit
    def test_parse_arguments_message_without_value(self, mock_cs):
        """Test parsing arguments for message subcommand without value."""
        command = MsgBusCommand(['message', '0x3', '0x2E', '0x10'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.msgbus_message
        assert command.port == 0x3
        assert command.reg == 0x2E
        assert command.opcode == 0x10
        assert command.val is None

    @pytest.mark.unit
    def test_parse_arguments_no_subcommand(self, mock_cs):
        """Test parsing arguments with no subcommand."""
        command = MsgBusCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_invalid_subcommand(self, mock_cs):
        """Test parsing arguments with invalid subcommand."""
        command = MsgBusCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_read_missing_args(self, mock_cs):
        """Test parsing arguments for read subcommand with missing arguments."""
        command = MsgBusCommand(['read'], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_write_missing_args(self, mock_cs):
        """Test parsing arguments for write subcommand with missing arguments."""
        command = MsgBusCommand(['write', '0x3'], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_message_missing_args(self, mock_cs):
        """Test parsing arguments for message subcommand with missing arguments."""
        command = MsgBusCommand(['message', '0x3'], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_invalid_hex_port(self, mock_cs):
        """Test parsing arguments with invalid hex port."""
        command = MsgBusCommand(['read', 'invalid', '0x2E'], cs=mock_cs)

        # Should raise SystemExit due to invalid hex conversion
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_invalid_hex_reg(self, mock_cs):
        """Test parsing arguments with invalid hex register."""
        command = MsgBusCommand(['read', '0x3', 'invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid hex conversion
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_invalid_hex_val(self, mock_cs):
        """Test parsing arguments with invalid hex value."""
        command = MsgBusCommand(['write', '0x3', '0x27', 'invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid hex conversion
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_invalid_hex_opcode(self, mock_cs):
        """Test parsing arguments with invalid hex opcode."""
        command = MsgBusCommand(['message', '0x3', '0x2E', 'invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid hex conversion
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_msgbus_read_success(self, msgbus_command, mock_cs):
        """Test msgbus_read method with successful read."""
        msgbus_command.port = 0x3
        msgbus_command.reg = 0x2E
        msgbus_command._msgbus = mock_cs.hals.MsgBus
        mock_cs.hals.MsgBus.msgbus_reg_read.return_value = 0xDEADBEEF

        with patch.object(msgbus_command.logger, 'log') as mock_log:
            result = msgbus_command.msgbus_read()

            assert result == 0xDEADBEEF
            mock_cs.hals.MsgBus.msgbus_reg_read.assert_called_once_with(0x3, 0x2E)
            mock_log.assert_called_with('[CHIPSEC] msgbus read: port 0x03 + 0x0000002E')

    @pytest.mark.unit
    def test_msgbus_read_none_result(self, msgbus_command, mock_cs):
        """Test msgbus_read method with None result."""
        msgbus_command.port = 0x3
        msgbus_command.reg = 0x2E
        msgbus_command._msgbus = mock_cs.hals.MsgBus
        mock_cs.hals.MsgBus.msgbus_reg_read.return_value = None

        with patch.object(msgbus_command.logger, 'log') as mock_log:
            result = msgbus_command.msgbus_read()

            assert result is None
            mock_cs.hals.MsgBus.msgbus_reg_read.assert_called_once_with(0x3, 0x2E)
            mock_log.assert_called_with('[CHIPSEC] msgbus read: port 0x03 + 0x0000002E')

    @pytest.mark.unit
    def test_msgbus_write_success(self, msgbus_command, mock_cs):
        """Test msgbus_write method with successful write."""
        msgbus_command.port = 0x3
        msgbus_command.reg = 0x27
        msgbus_command.val = 0xE0000001
        msgbus_command._msgbus = mock_cs.hals.MsgBus
        mock_cs.hals.MsgBus.msgbus_reg_write.return_value = 0x1

        with patch.object(msgbus_command.logger, 'log') as mock_log:
            result = msgbus_command.msgbus_write()

            assert result == 0x1
            mock_cs.hals.MsgBus.msgbus_reg_write.assert_called_once_with(0x3, 0x27, 0xE0000001)
            mock_log.assert_called_with('[CHIPSEC] msgbus write: port 0x03 + 0x00000027 < 0xE0000001')

    @pytest.mark.unit
    def test_msgbus_write_none_result(self, msgbus_command, mock_cs):
        """Test msgbus_write method with None result."""
        msgbus_command.port = 0x3
        msgbus_command.reg = 0x27
        msgbus_command.val = 0xE0000001
        msgbus_command._msgbus = mock_cs.hals.MsgBus
        mock_cs.hals.MsgBus.msgbus_reg_write.return_value = None

        with patch.object(msgbus_command.logger, 'log') as mock_log:
            result = msgbus_command.msgbus_write()

            assert result is None
            mock_cs.hals.MsgBus.msgbus_reg_write.assert_called_once_with(0x3, 0x27, 0xE0000001)
            mock_log.assert_called_with('[CHIPSEC] msgbus write: port 0x03 + 0x00000027 < 0xE0000001')

    @pytest.mark.unit
    def test_msgbus_message_with_value(self, msgbus_command, mock_cs):
        """Test msgbus_message method with value."""
        msgbus_command.port = 0x3
        msgbus_command.reg = 0x2E
        msgbus_command.opcode = 0x10
        msgbus_command.val = 0x12345678
        msgbus_command._msgbus = mock_cs.hals.MsgBus
        mock_cs.hals.MsgBus.msgbus_send_message.return_value = 0xDEADBEEF

        with patch.object(msgbus_command.logger, 'log') as mock_log:
            result = msgbus_command.msgbus_message()

            assert result == 0xDEADBEEF
            mock_cs.hals.MsgBus.msgbus_send_message.assert_called_once_with(0x3, 0x2E, 0x10, 0x12345678)
            mock_log.assert_any_call('[CHIPSEC] msgbus message: port 0x03 + 0x0000002E, opcode: 0x10')
            mock_log.assert_any_call('[CHIPSEC]                 Data: 0x12345678')

    @pytest.mark.unit
    def test_msgbus_message_without_value(self, msgbus_command, mock_cs):
        """Test msgbus_message method without value."""
        msgbus_command.port = 0x3
        msgbus_command.reg = 0x2E
        msgbus_command.opcode = 0x10
        msgbus_command.val = None
        msgbus_command._msgbus = mock_cs.hals.MsgBus
        mock_cs.hals.MsgBus.msgbus_send_message.return_value = 0xDEADBEEF

        with patch.object(msgbus_command.logger, 'log') as mock_log:
            result = msgbus_command.msgbus_message()

            assert result == 0xDEADBEEF
            mock_cs.hals.MsgBus.msgbus_send_message.assert_called_once_with(0x3, 0x2E, 0x10, None)
            mock_log.assert_any_call('[CHIPSEC] msgbus message: port 0x03 + 0x0000002E, opcode: 0x10')
            # Should not log data when val is None
            data_logs = [call for call in mock_log.call_args_list if 'Data:' in str(call)]
            assert len(data_logs) == 0

    @pytest.mark.unit
    def test_msgbus_message_none_result(self, msgbus_command, mock_cs):
        """Test msgbus_message method with None result."""
        msgbus_command.port = 0x3
        msgbus_command.reg = 0x2E
        msgbus_command.opcode = 0x10
        msgbus_command.val = 0x12345678
        msgbus_command._msgbus = mock_cs.hals.MsgBus
        mock_cs.hals.MsgBus.msgbus_send_message.return_value = None

        with patch.object(msgbus_command.logger, 'log') as mock_log:
            result = msgbus_command.msgbus_message()

            assert result is None
            mock_cs.hals.MsgBus.msgbus_send_message.assert_called_once_with(0x3, 0x2E, 0x10, 0x12345678)
            mock_log.assert_any_call('[CHIPSEC] msgbus message: port 0x03 + 0x0000002E, opcode: 0x10')
            mock_log.assert_any_call('[CHIPSEC]                 Data: 0x12345678')

    @pytest.mark.unit
    def test_run_with_result(self, msgbus_command, mock_cs):
        """Test run method with result returned."""
        msgbus_command.func = Mock(return_value=0xDEADBEEF)
        msgbus_command._msgbus = mock_cs.hals.MsgBus

        with patch.object(msgbus_command.logger, 'log') as mock_log:
            msgbus_command.run()

            mock_log.assert_called_with('[CHIPSEC] Result: 0xdeadbeef')

    @pytest.mark.unit
    def test_run_with_none_result(self, msgbus_command, mock_cs):
        """Test run method with None result."""
        msgbus_command.func = Mock(return_value=None)
        msgbus_command._msgbus = mock_cs.hals.MsgBus

        with patch.object(msgbus_command.logger, 'log') as mock_log:
            msgbus_command.run()

            # Should not log result when None
            result_logs = [call for call in mock_log.call_args_list if 'Result:' in str(call)]
            assert len(result_logs) == 0

    @pytest.mark.unit
    def test_run_msgbus_read_error(self, msgbus_command, mock_cs):
        """Test run method with msgbus read error."""
        msgbus_command.func = Mock(side_effect=Exception("MsgBus read failed"))

        with patch.object(msgbus_command.logger, 'log'):
            # Should handle exception gracefully
            with pytest.raises(Exception):
                msgbus_command.run()

    @pytest.mark.unit
    def test_run_msgbus_write_error(self, msgbus_command, mock_cs):
        """Test run method with msgbus write error."""
        msgbus_command.func = Mock(side_effect=Exception("MsgBus write failed"))

        with patch.object(msgbus_command.logger, 'log'):
            # Should handle exception gracefully
            with pytest.raises(Exception):
                msgbus_command.run()

    @pytest.mark.unit
    def test_run_msgbus_message_error(self, msgbus_command, mock_cs):
        """Test run method with msgbus message error."""
        msgbus_command.func = Mock(side_effect=Exception("MsgBus message failed"))

        with patch.object(msgbus_command.logger, 'log'):
            # Should handle exception gracefully
            with pytest.raises(Exception):
                msgbus_command.run()


class TestMsgBusCommandIntegration:
    """Integration tests for Message Bus command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for Message Bus testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock MsgBus with realistic behavior
        cs_mock.hals = Mock()
        cs_mock.hals.MsgBus = Mock()
        cs_mock.hals.MsgBus.msgbus_reg_read.return_value = 0xDEADBEEF
        cs_mock.hals.MsgBus.msgbus_reg_write.return_value = 0x1
        cs_mock.hals.MsgBus.msgbus_send_message.return_value = 0x12345678

        return cs_mock

    @pytest.mark.integration
    def test_msgbus_read_integration(self, integrated_cs):
        """Test complete Message Bus read workflow."""
        msgbus_cmd = MsgBusCommand(['read', '0x3', '0x2E'], cs=integrated_cs)

        with patch.object(msgbus_cmd.logger, 'log'):
            msgbus_cmd.run()

            integrated_cs.hals.MsgBus.msgbus_reg_read.assert_called_with(0x3, 0x2E)

    @pytest.mark.integration
    def test_msgbus_write_integration(self, integrated_cs):
        """Test complete Message Bus write workflow."""
        msgbus_cmd = MsgBusCommand(['write', '0x3', '0x27', '0xE0000001'], cs=integrated_cs)

        with patch.object(msgbus_cmd.logger, 'log'):
            msgbus_cmd.run()

            integrated_cs.hals.MsgBus.msgbus_reg_write.assert_called_with(0x3, 0x27, 0xE0000001)

    @pytest.mark.integration
    def test_msgbus_message_integration(self, integrated_cs):
        """Test complete Message Bus message workflow."""
        msgbus_cmd = MsgBusCommand(['message', '0x3', '0x2E', '0x10', '0x12345678'], cs=integrated_cs)

        with patch.object(msgbus_cmd.logger, 'log'):
            msgbus_cmd.run()

            integrated_cs.hals.MsgBus.msgbus_send_message.assert_called_with(0x3, 0x2E, 0x10, 0x12345678)

    @pytest.mark.integration
    def test_msgbus_read_write_sequence(self, integrated_cs):
        """Test Message Bus read-write sequence."""
        # Test read
        read_cmd = MsgBusCommand(['read', '0x3', '0x2E'], cs=integrated_cs)
        with patch.object(read_cmd.logger, 'log'):
            read_cmd.run()
            assert integrated_cs.hals.MsgBus.msgbus_reg_read.called

        # Test write
        write_cmd = MsgBusCommand(['write', '0x3', '0x2E', '0xDEADBEEF'], cs=integrated_cs)
        with patch.object(write_cmd.logger, 'log'):
            write_cmd.run()
            assert integrated_cs.hals.MsgBus.msgbus_reg_write.called

        # Test message
        message_cmd = MsgBusCommand(['message', '0x3', '0x2E', '0x10'], cs=integrated_cs)
        with patch.object(message_cmd.logger, 'log'):
            message_cmd.run()
            assert integrated_cs.hals.MsgBus.msgbus_send_message.called


class TestMsgBusCommandEdgeCases:
    """Test edge cases and error conditions for Message Bus command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        cs_mock.hals.MsgBus = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_parse_arguments_hex_conversion_edge_cases(self, mock_cs):
        """Test hex conversion edge cases."""
        test_cases = [
            (['read', '0x0', '0x0'], 0x0, 0x0),
            (['read', '0xFF', '0xFFFFFFFF'], 0xFF, 0xFFFFFFFF),
            (['write', '0x1', '0x2', '0x3'], 0x1, 0x2, 0x3),
            (['message', '0x7F', '0x80000000', '0xFF', '0xFFFFFFFFFFFFFFFF'], 0x7F, 0x80000000, 0xFF, 0xFFFFFFFFFFFFFFFF),
        ]

        for args, expected_port, expected_reg, *expected_val in test_cases:
            command = MsgBusCommand(args, cs=mock_cs)
            command.parse_arguments()

            assert command.port == expected_port
            assert command.reg == expected_reg
            if expected_val:
                if len(expected_val) == 1:
                    assert command.val == expected_val[0]
                elif len(expected_val) == 2:
                    assert command.opcode == expected_val[0]
                    assert command.val == expected_val[1]

    @pytest.mark.unit
    def test_msgbus_operations_with_different_ports_registers(self, mock_cs):
        """Test msgbus operations with different port and register combinations."""
        test_cases = [
            (0x0, 0x0),
            (0xFF, 0xFFFFFFFF),
            (0x10, 0x1000),
            (0x7F, 0x80000000),
        ]

        for port, reg in test_cases:
            command = MsgBusCommand(['read', '0x0', '0x0'], cs=mock_cs)
            command.port = port
            command.reg = reg
            command._msgbus = mock_cs.hals.MsgBus

            mock_cs.hals.MsgBus.msgbus_reg_read.return_value = 0x12345678

            with patch.object(command.logger, 'log'):
                result = command.msgbus_read()

                assert result == 0x12345678
                mock_cs.hals.MsgBus.msgbus_reg_read.assert_called_with(port, reg)

    @pytest.mark.unit
    def test_msgbus_write_with_different_values(self, mock_cs):
        """Test msgbus write with different values."""
        test_cases = [
            (0x0, 0x0, 0x0),
            (0xFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
            (0x10, 0x1000, 0xDEADBEEF),
        ]

        for port, reg, val in test_cases:
            command = MsgBusCommand(['write', '0x0', '0x0', '0x0'], cs=mock_cs)
            command.port = port
            command.reg = reg
            command.val = val
            command._msgbus = mock_cs.hals.MsgBus

            mock_cs.hals.MsgBus.msgbus_reg_write.return_value = 0x1

            with patch.object(command.logger, 'log'):
                result = command.msgbus_write()

                assert result == 0x1
                mock_cs.hals.MsgBus.msgbus_reg_write.assert_called_with(port, reg, val)

    @pytest.mark.unit
    def test_msgbus_message_with_different_opcodes(self, mock_cs):
        """Test msgbus message with different opcodes."""
        test_cases = [
            (0x0, 0x0, 0x0, None),
            (0xFF, 0xFFFFFFFF, 0xFF, 0xFFFFFFFFFFFFFFFF),
            (0x10, 0x1000, 0x10, 0xDEADBEEF),
        ]

        for port, reg, opcode, val in test_cases:
            command = MsgBusCommand(['message', '0x0', '0x0', '0x0'], cs=mock_cs)
            command.port = port
            command.reg = reg
            command.opcode = opcode
            command.val = val
            command._msgbus = mock_cs.hals.MsgBus

            mock_cs.hals.MsgBus.msgbus_send_message.return_value = 0x12345678

            with patch.object(command.logger, 'log'):
                result = command.msgbus_message()

                assert result == 0x12345678
                mock_cs.hals.MsgBus.msgbus_send_message.assert_called_with(port, reg, opcode, val)

    @pytest.mark.unit
    def test_msgbus_error_handling(self, mock_cs):
        """Test Message Bus error handling."""
        # Test read error
        read_command = MsgBusCommand(['read', '0x3', '0x2E'], cs=mock_cs)
        read_command._msgbus = mock_cs.hals.MsgBus
        mock_cs.hals.MsgBus.msgbus_reg_read.side_effect = Exception("MsgBus read error")

        with pytest.raises(Exception):
            read_command.msgbus_read()

        # Test write error
        write_command = MsgBusCommand(['write', '0x3', '0x27', '0x1'], cs=mock_cs)
        write_command._msgbus = mock_cs.hals.MsgBus
        mock_cs.hals.MsgBus.msgbus_reg_write.side_effect = Exception("MsgBus write error")

        with pytest.raises(Exception):
            write_command.msgbus_write()

        # Test message error
        message_command = MsgBusCommand(['message', '0x3', '0x2E', '0x10'], cs=mock_cs)
        message_command._msgbus = mock_cs.hals.MsgBus
        mock_cs.hals.MsgBus.msgbus_send_message.side_effect = Exception("MsgBus message error")

        with pytest.raises(Exception):
            message_command.msgbus_message()

    @pytest.mark.unit
    def test_run_with_different_result_values(self, mock_cs):
        """Test run method with different result values."""
        test_cases = [
            (0, '[CHIPSEC] Result: 0x0'),
            (1, '[CHIPSEC] Result: 0x1'),
            (-1, '[CHIPSEC] Result: 0xffffffffffffffff'),  # Python handles negative as unsigned
            (0x80000000, '[CHIPSEC] Result: 0x80000000'),
            (0xFFFFFFFFFFFFFFFF, '[CHIPSEC] Result: 0xffffffffffffffff'),
        ]

        for value, expected_log in test_cases:
            command = MsgBusCommand(['read', '0x0', '0x0'], cs=mock_cs)
            command.func = Mock(return_value=value)

            with patch.object(command.logger, 'log') as mock_log:
                command.run()

                mock_log.assert_any_call(expected_log)

    @pytest.mark.unit
    def test_parse_arguments_case_insensitive_hex(self, mock_cs):
        """Test parsing arguments with case-insensitive hex values."""
        test_cases = [
            (['read', '0x3', '0x2e'], 0x3, 0x2E),
            (['read', '0X3', '0X2E'], 0x3, 0x2E),
            (['write', '0x3', '0x27', '0xe0000001'], 0x3, 0x27, 0xE0000001),
            (['message', '0x3', '0x2e', '0x10', '0x12345678'], 0x3, 0x2E, 0x10, 0x12345678),
        ]

        for args, expected_port, expected_reg, *expected_val in test_cases:
            command = MsgBusCommand(args, cs=mock_cs)
            command.parse_arguments()

            assert command.port == expected_port
            assert command.reg == expected_reg
            if expected_val:
                if len(expected_val) == 1:
                    assert command.val == expected_val[0]
                elif len(expected_val) == 2:
                    assert command.opcode == expected_val[0]
                    assert command.val == expected_val[1]

    @pytest.mark.unit
    def test_msgbus_command_reuse(self, mock_cs):
        """Test reusing Message Bus command instance."""
        command = MsgBusCommand(['read', '0x3', '0x2E'], cs=mock_cs)
        command._msgbus = mock_cs.hals.MsgBus

        # First read
        mock_cs.hals.MsgBus.msgbus_reg_read.return_value = 0x11111111
        with patch.object(command.logger, 'log'):
            result1 = command.msgbus_read()
            assert result1 == 0x11111111

        # Second read with different result
        mock_cs.hals.MsgBus.msgbus_reg_read.return_value = 0x22222222
        with patch.object(command.logger, 'log'):
            result2 = command.msgbus_read()
            assert result2 == 0x22222222

        # Verify both calls were made
        assert mock_cs.hals.MsgBus.msgbus_reg_read.call_count == 2


class TestMsgBusCommandConfigurationValidation:
    """Test configuration validation aspects of Message Bus command."""

    @pytest.fixture
    def msgbus_cs(self):
        """Create ChipsecCs with Message Bus-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock Message Bus configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.MSGBUS = {
            'ENABLED_PORTS': [0x0, 0x1, 0x2, 0x3, 0x4],
            'MAX_PORT': 0xFF,
            'TIMEOUT_MS': 1000,
            'RETRY_COUNT': 3,
            'SUPPORTED_OPCODES': [0x10, 0x11, 0x12, 0x13]
        }

        cs_mock.hals = Mock()
        cs_mock.hals.MsgBus = Mock()
        cs_mock.hals.MsgBus.msgbus_reg_read.return_value = 0xDEADBEEF
        cs_mock.hals.MsgBus.msgbus_reg_write.return_value = 0x1
        cs_mock.hals.MsgBus.msgbus_send_message.return_value = 0x12345678

        return cs_mock

    @pytest.mark.unit
    def test_msgbus_configuration_structure(self, msgbus_cs):
        """Test Message Bus configuration structure."""
        msgbus_config = msgbus_cs.Cfg.MSGBUS

        # Test that required MSGBUS configuration exists
        assert 'ENABLED_PORTS' in msgbus_config
        assert 'MAX_PORT' in msgbus_config
        assert 'TIMEOUT_MS' in msgbus_config
        assert 'RETRY_COUNT' in msgbus_config
        assert 'SUPPORTED_OPCODES' in msgbus_config

        # Test configuration values are reasonable
        assert isinstance(msgbus_config['ENABLED_PORTS'], list)
        assert msgbus_config['MAX_PORT'] > 0
        assert msgbus_config['TIMEOUT_MS'] > 0
        assert msgbus_config['RETRY_COUNT'] >= 0
        assert isinstance(msgbus_config['SUPPORTED_OPCODES'], list)

    @pytest.mark.unit
    def test_enabled_ports_validation(self, msgbus_cs):
        """Test enabled ports validation."""
        enabled_ports = msgbus_cs.Cfg.MSGBUS['ENABLED_PORTS']
        max_port = msgbus_cs.Cfg.MSGBUS['MAX_PORT']

        # All enabled ports should be within valid range
        for port in enabled_ports:
            assert 0 <= port <= max_port

    @pytest.mark.unit
    def test_supported_opcodes_validation(self, msgbus_cs):
        """Test supported opcodes validation."""
        supported_opcodes = msgbus_cs.Cfg.MSGBUS['SUPPORTED_OPCODES']

        # All supported opcodes should be valid hex values
        for opcode in supported_opcodes:
            assert isinstance(opcode, int)
            assert 0 <= opcode <= 0xFF  # Valid opcode range

    @pytest.mark.unit
    def test_msgbus_port_range_validation(self, msgbus_cs):
        """Test Message Bus port range validation."""
        max_port = msgbus_cs.Cfg.MSGBUS['MAX_PORT']

        # Test valid ports
        valid_ports = [0, 1, 0x10, 0x7F, max_port]
        for port in valid_ports:
            assert 0 <= port <= max_port

        # Test invalid ports
        invalid_ports = [-1, max_port + 1, 0x100]
        for port in invalid_ports:
            assert not (0 <= port <= max_port)

    @pytest.mark.unit
    def test_msgbus_timeout_configuration(self, msgbus_cs):
        """Test Message Bus timeout configuration."""
        timeout = msgbus_cs.Cfg.MSGBUS['TIMEOUT_MS']

        # Timeout should be reasonable (between 100ms and 10 seconds)
        assert 100 <= timeout <= 10000

    @pytest.mark.unit
    def test_msgbus_retry_configuration(self, msgbus_cs):
        """Test Message Bus retry configuration."""
        retry_count = msgbus_cs.Cfg.MSGBUS['RETRY_COUNT']

        # Retry count should be reasonable (0-10)
        assert 0 <= retry_count <= 10

    @pytest.mark.unit
    def test_msgbus_command_with_config(self, msgbus_cs):
        """Test Message Bus command with configuration."""
        command = MsgBusCommand(['read', '0x3', '0x2E'], cs=msgbus_cs)

        with patch.object(command.logger, 'log'):
            command.run()

            msgbus_cs.hals.MsgBus.msgbus_reg_read.assert_called_with(0x3, 0x2E)

    @pytest.mark.unit
    def test_msgbus_enabled_ports_check(self, msgbus_cs):
        """Test Message Bus enabled ports check."""
        enabled_ports = msgbus_cs.Cfg.MSGBUS['ENABLED_PORTS']

        # Test that common Message Bus ports are enabled
        common_ports = [0x0, 0x1, 0x2, 0x3]
        for port in common_ports:
            assert port in enabled_ports

    @pytest.mark.unit
    def test_msgbus_supported_opcodes_check(self, msgbus_cs):
        """Test Message Bus supported opcodes check."""
        supported_opcodes = msgbus_cs.Cfg.MSGBUS['SUPPORTED_OPCODES']

        # Test that common opcodes are supported
        common_opcodes = [0x10, 0x11]
        for opcode in common_opcodes:
            assert opcode in supported_opcodes

    @pytest.mark.unit
    def test_msgbus_configuration_consistency(self, msgbus_cs):
        """Test Message Bus configuration consistency."""
        enabled_ports = set(msgbus_cs.Cfg.MSGBUS['ENABLED_PORTS'])
        max_port = msgbus_cs.Cfg.MSGBUS['MAX_PORT']

        # All enabled ports should be <= max_port
        for port in enabled_ports:
            assert port <= max_port

    @pytest.mark.unit
    def test_msgbus_error_handling_with_config(self, msgbus_cs):
        """Test Message Bus error handling with configuration."""
        command = MsgBusCommand(['read', '0x3', '0x2E'], cs=msgbus_cs)

        # Test read error with config
        msgbus_cs.hals.MsgBus.msgbus_reg_read.side_effect = Exception("Configured read error")

        with pytest.raises(Exception):
            command.run()

        # Test write error with config
        write_command = MsgBusCommand(['write', '0x3', '0x27', '0x1'], cs=msgbus_cs)
        msgbus_cs.hals.MsgBus.msgbus_reg_write.side_effect = Exception("Configured write error")

        with pytest.raises(Exception):
            write_command.run()

        # Test message error with config
        message_command = MsgBusCommand(['message', '0x3', '0x2E', '0x10'], cs=msgbus_cs)
        msgbus_cs.hals.MsgBus.msgbus_send_message.side_effect = Exception("Configured message error")

        with pytest.raises(Exception):
            message_command.run()

    @pytest.mark.unit
    def test_msgbus_command_logging_with_config(self, msgbus_cs):
        """Test Message Bus command logging with configuration."""
        command = MsgBusCommand(['read', '0x3', '0x2E'], cs=msgbus_cs)

        with patch.object(command.logger, 'log') as mock_log:
            command.run()

            # Verify logging still works with configuration
            assert mock_log.call_count >= 2  # Operation log + result log


if __name__ == '__main__':
    pytest.main([__file__])
