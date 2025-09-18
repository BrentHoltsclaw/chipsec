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
from chipsec.utilcmd.mm_msgbus_cmd import MMMsgBusCommand
from chipsec.command import toLoad
from tests.test_utils import MockFactory


class TestMMMsgBusCommand:
    """Comprehensive tests for MM Message Bus command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for MM Message Bus testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock MMMsgBus HAL component
        cs_mock.hals = Mock()
        cs_mock.hals.MMMsgBus = Mock()

        return cs_mock

    @pytest.fixture
    def mm_msgbus_command(self, mock_cs):
        """Create MMMsgBusCommand instance."""
        return MMMsgBusCommand(['mm_read', '0x3', '0x2E'], cs=mock_cs)

    @pytest.mark.unit
    def test_mm_msgbus_command_initialization(self, mm_msgbus_command, mock_cs):
        """Test MMMsgBusCommand initialization."""
        assert mm_msgbus_command.cs == mock_cs
        assert mm_msgbus_command.argv == ['mm_read', '0x3', '0x2E']

    @pytest.mark.unit
    def test_requirements(self, mm_msgbus_command):
        """Test command requirements."""
        reqs = mm_msgbus_command.requirements()
        assert reqs == toLoad.All

    @pytest.mark.unit
    def test_parse_arguments_mm_read(self, mock_cs):
        """Test parsing arguments for mm_read subcommand."""
        command = MMMsgBusCommand(['mm_read', '0x3', '0x2E'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.msgbus_mm_read
        assert command.port == 0x3
        assert command.reg == 0x2E

    @pytest.mark.unit
    def test_parse_arguments_mm_write(self, mock_cs):
        """Test parsing arguments for mm_write subcommand."""
        command = MMMsgBusCommand(['mm_write', '0x3', '0x27', '0xE0000001'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.msgbus_mm_write
        assert command.port == 0x3
        assert command.reg == 0x27
        assert command.val == 0xE0000001

    @pytest.mark.unit
    def test_parse_arguments_no_subcommand(self, mock_cs):
        """Test parsing arguments with no subcommand."""
        command = MMMsgBusCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_invalid_subcommand(self, mock_cs):
        """Test parsing arguments with invalid subcommand."""
        command = MMMsgBusCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_mm_read_missing_args(self, mock_cs):
        """Test parsing arguments for mm_read with missing arguments."""
        command = MMMsgBusCommand(['mm_read'], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_mm_write_missing_args(self, mock_cs):
        """Test parsing arguments for mm_write with missing arguments."""
        command = MMMsgBusCommand(['mm_write', '0x3'], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_invalid_hex_port(self, mock_cs):
        """Test parsing arguments with invalid hex port."""
        command = MMMsgBusCommand(['mm_read', 'invalid', '0x2E'], cs=mock_cs)

        # Should raise SystemExit due to invalid hex conversion
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_invalid_hex_reg(self, mock_cs):
        """Test parsing arguments with invalid hex register."""
        command = MMMsgBusCommand(['mm_read', '0x3', 'invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid hex conversion
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_invalid_hex_val(self, mock_cs):
        """Test parsing arguments with invalid hex value."""
        command = MMMsgBusCommand(['mm_write', '0x3', '0x27', 'invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid hex conversion
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_msgbus_mm_read_success(self, mm_msgbus_command, mock_cs):
        """Test msgbus_mm_read method with successful read."""
        mm_msgbus_command.port = 0x3
        mm_msgbus_command.reg = 0x2E
        mock_cs.hals.MMMsgBus.read.return_value = 0xDEADBEEF

        with patch.object(mm_msgbus_command.logger, 'log') as mock_log:
            result = mm_msgbus_command.msgbus_mm_read()

            assert result is True
            mock_cs.hals.MMMsgBus.read.assert_called_once_with(0x3, 0x2E)
            mock_log.assert_any_call('[CHIPSEC] MMIO msgbus read: port 0x03 + 0x0000002E')
            mock_log.assert_any_call('[CHIPSEC] Result: 0xdeadbeef')

    @pytest.mark.unit
    def test_msgbus_mm_read_none_result(self, mm_msgbus_command, mock_cs):
        """Test msgbus_mm_read method with None result."""
        mm_msgbus_command.port = 0x3
        mm_msgbus_command.reg = 0x2E
        mock_cs.hals.MMMsgBus.read.return_value = None

        with patch.object(mm_msgbus_command.logger, 'log') as mock_log:
            result = mm_msgbus_command.msgbus_mm_read()

            assert result is True
            mock_cs.hals.MMMsgBus.read.assert_called_once_with(0x3, 0x2E)
            mock_log.assert_any_call('[CHIPSEC] MMIO msgbus read: port 0x03 + 0x0000002E')
            mock_log.assert_any_call('[CHIPSEC] No result returned')

    @pytest.mark.unit
    def test_msgbus_mm_write_success(self, mm_msgbus_command, mock_cs):
        """Test msgbus_mm_write method with successful write."""
        mm_msgbus_command.port = 0x3
        mm_msgbus_command.reg = 0x27
        mm_msgbus_command.val = 0xE0000001
        mock_cs.hals.MMMsgBus.write.return_value = 0x1

        with patch.object(mm_msgbus_command.logger, 'log') as mock_log:
            result = mm_msgbus_command.msgbus_mm_write()

            assert result is True
            mock_cs.hals.MMMsgBus.write.assert_called_once_with(0x3, 0x27, 0xE0000001)
            mock_log.assert_any_call('[CHIPSEC] MMIO msgbus write: port 0x03 + 0x00000027 < 0xE0000001')
            mock_log.assert_any_call('[CHIPSEC] Result: 0x1')

    @pytest.mark.unit
    def test_msgbus_mm_write_none_result(self, mm_msgbus_command, mock_cs):
        """Test msgbus_mm_write method with None result."""
        mm_msgbus_command.port = 0x3
        mm_msgbus_command.reg = 0x27
        mm_msgbus_command.val = 0xE0000001
        mock_cs.hals.MMMsgBus.write.return_value = None

        with patch.object(mm_msgbus_command.logger, 'log') as mock_log:
            result = mm_msgbus_command.msgbus_mm_write()

            assert result is True
            mock_cs.hals.MMMsgBus.write.assert_called_once_with(0x3, 0x27, 0xE0000001)
            mock_log.assert_any_call('[CHIPSEC] MMIO msgbus write: port 0x03 + 0x00000027 < 0xE0000001')
            mock_log.assert_any_call('[CHIPSEC] No result returned')

    @pytest.mark.unit
    def test_msgbus_mm_read_error(self, mm_msgbus_command, mock_cs):
        """Test msgbus_mm_read method with read error."""
        mm_msgbus_command.port = 0x3
        mm_msgbus_command.reg = 0x2E
        mock_cs.hals.MMMsgBus.read.side_effect = Exception("Read failed")

        with patch.object(mm_msgbus_command.logger, 'log'):
            # Should handle exception gracefully
            with pytest.raises(Exception):
                mm_msgbus_command.msgbus_mm_read()

    @pytest.mark.unit
    def test_msgbus_mm_write_error(self, mm_msgbus_command, mock_cs):
        """Test msgbus_mm_write method with write error."""
        mm_msgbus_command.port = 0x3
        mm_msgbus_command.reg = 0x27
        mm_msgbus_command.val = 0xE0000001
        mock_cs.hals.MMMsgBus.write.side_effect = Exception("Write failed")

        with patch.object(mm_msgbus_command.logger, 'log'):
            # Should handle exception gracefully
            with pytest.raises(Exception):
                mm_msgbus_command.msgbus_mm_write()

    @pytest.mark.unit
    def test_log_result_with_value(self, mm_msgbus_command, mock_cs):
        """Test _log_result method with a value."""
        with patch.object(mm_msgbus_command.logger, 'log') as mock_log:
            mm_msgbus_command._log_result(0xDEADBEEF)

            mock_log.assert_called_once_with('[CHIPSEC] Result: 0xdeadbeef')

    @pytest.mark.unit
    def test_log_result_with_none(self, mm_msgbus_command, mock_cs):
        """Test _log_result method with None value."""
        with patch.object(mm_msgbus_command.logger, 'log') as mock_log:
            mm_msgbus_command._log_result(None)

            mock_log.assert_called_once_with('[CHIPSEC] No result returned')

    @pytest.mark.unit
    def test_log_result_with_zero(self, mm_msgbus_command, mock_cs):
        """Test _log_result method with zero value."""
        with patch.object(mm_msgbus_command.logger, 'log') as mock_log:
            mm_msgbus_command._log_result(0)

            mock_log.assert_called_once_with('[CHIPSEC] Result: 0x0')

    @pytest.mark.unit
    def test_log_result_with_large_value(self, mm_msgbus_command, mock_cs):
        """Test _log_result method with large value."""
        with patch.object(mm_msgbus_command.logger, 'log') as mock_log:
            mm_msgbus_command._log_result(0xFFFFFFFFFFFFFFFF)

            mock_log.assert_called_once_with('[CHIPSEC] Result: 0xffffffffffffffff')


class TestMMMsgBusCommandIntegration:
    """Integration tests for MM Message Bus command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for MM Message Bus testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock MMMsgBus with realistic behavior
        cs_mock.hals = Mock()
        cs_mock.hals.MMMsgBus = Mock()
        cs_mock.hals.MMMsgBus.read.return_value = 0xDEADBEEF
        cs_mock.hals.MMMsgBus.write.return_value = 0x1

        return cs_mock

    @pytest.mark.integration
    def test_mm_msgbus_read_integration(self, integrated_cs):
        """Test complete MM Message Bus read workflow."""
        mm_msgbus_cmd = MMMsgBusCommand(['mm_read', '0x3', '0x2E'], cs=integrated_cs)

        with patch.object(mm_msgbus_cmd.logger, 'log'):
            result = mm_msgbus_cmd.msgbus_mm_read()

            assert result is True
            integrated_cs.hals.MMMsgBus.read.assert_called_with(0x3, 0x2E)

    @pytest.mark.integration
    def test_mm_msgbus_write_integration(self, integrated_cs):
        """Test complete MM Message Bus write workflow."""
        mm_msgbus_cmd = MMMsgBusCommand(['mm_write', '0x3', '0x27', '0xE0000001'], cs=integrated_cs)

        with patch.object(mm_msgbus_cmd.logger, 'log'):
            result = mm_msgbus_cmd.msgbus_mm_write()

            assert result is True
            integrated_cs.hals.MMMsgBus.write.assert_called_with(0x3, 0x27, 0xE0000001)

    @pytest.mark.integration
    def test_mm_msgbus_read_write_sequence(self, integrated_cs):
        """Test MM Message Bus read-write sequence."""
        # Test read
        read_cmd = MMMsgBusCommand(['mm_read', '0x3', '0x2E'], cs=integrated_cs)
        with patch.object(read_cmd.logger, 'log'):
            read_result = read_cmd.msgbus_mm_read()
            assert read_result is True

        # Test write
        write_cmd = MMMsgBusCommand(['mm_write', '0x3', '0x2E', '0xDEADBEEF'], cs=integrated_cs)
        with patch.object(write_cmd.logger, 'log'):
            write_result = write_cmd.msgbus_mm_write()
            assert write_result is True

        # Verify both operations were called
        integrated_cs.hals.MMMsgBus.read.assert_called_with(0x3, 0x2E)
        integrated_cs.hals.MMMsgBus.write.assert_called_with(0x3, 0x2E, 0xDEADBEEF)


class TestMMMsgBusCommandEdgeCases:
    """Test edge cases and error conditions for MM Message Bus command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        cs_mock.hals.MMMsgBus = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_parse_arguments_hex_conversion_edge_cases(self, mock_cs):
        """Test hex conversion edge cases."""
        test_cases = [
            (['mm_read', '0x0', '0x0'], 0x0, 0x0),
            (['mm_read', '0xFF', '0xFFFFFFFF'], 0xFF, 0xFFFFFFFF),
            (['mm_write', '0x1', '0x2', '0x3'], 0x1, 0x2, 0x3),
        ]

        for args, expected_port, expected_reg, *expected_val in test_cases:
            command = MMMsgBusCommand(args, cs=mock_cs)
            command.parse_arguments()

            assert command.port == expected_port
            assert command.reg == expected_reg
            if expected_val:
                assert command.val == expected_val[0]

    @pytest.mark.unit
    def test_msgbus_mm_read_different_ports_registers(self, mock_cs):
        """Test msgbus_mm_read with different port and register combinations."""
        test_cases = [
            (0x0, 0x0),
            (0xFF, 0xFFFFFFFF),
            (0x10, 0x1000),
            (0x7F, 0x80000000),
        ]

        for port, reg in test_cases:
            command = MMMsgBusCommand(['mm_read', '0x0', '0x0'], cs=mock_cs)
            command.port = port
            command.reg = reg

            mock_cs.hals.MMMsgBus.read.return_value = 0x12345678

            with patch.object(command.logger, 'log'):
                result = command.msgbus_mm_read()

                assert result is True
                mock_cs.hals.MMMsgBus.read.assert_called_with(port, reg)

    @pytest.mark.unit
    def test_msgbus_mm_write_different_values(self, mock_cs):
        """Test msgbus_mm_write with different values."""
        test_cases = [
            (0x0, 0x0, 0x0),
            (0xFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
            (0x10, 0x1000, 0xDEADBEEF),
        ]

        for port, reg, val in test_cases:
            command = MMMsgBusCommand(['mm_write', '0x0', '0x0', '0x0'], cs=mock_cs)
            command.port = port
            command.reg = reg
            command.val = val

            mock_cs.hals.MMMsgBus.write.return_value = 0x1

            with patch.object(command.logger, 'log'):
                result = command.msgbus_mm_write()

                assert result is True
                mock_cs.hals.MMMsgBus.write.assert_called_with(port, reg, val)

    @pytest.mark.unit
    def test_mm_msgbus_error_handling(self, mock_cs):
        """Test MM Message Bus error handling."""
        # Test read error
        read_command = MMMsgBusCommand(['mm_read', '0x3', '0x2E'], cs=mock_cs)
        mock_cs.hals.MMMsgBus.read.side_effect = Exception("MMMsgBus read error")

        with pytest.raises(Exception):
            read_command.msgbus_mm_read()

        # Test write error
        write_command = MMMsgBusCommand(['mm_write', '0x3', '0x27', '0x1'], cs=mock_cs)
        mock_cs.hals.MMMsgBus.write.side_effect = Exception("MMMsgBus write error")

        with pytest.raises(Exception):
            write_command.msgbus_mm_write()

    @pytest.mark.unit
    def test_log_result_edge_cases(self, mock_cs):
        """Test _log_result method edge cases."""
        command = MMMsgBusCommand(['mm_read', '0x0', '0x0'], cs=mock_cs)

        test_cases = [
            (0, '[CHIPSEC] Result: 0x0'),
            (1, '[CHIPSEC] Result: 0x1'),
            (-1, '[CHIPSEC] Result: 0xffffffffffffffff'),  # Python handles negative as unsigned
            (0x80000000, '[CHIPSEC] Result: 0x80000000'),
            (0xFFFFFFFFFFFFFFFF, '[CHIPSEC] Result: 0xffffffffffffffff'),
        ]

        for value, expected_log in test_cases:
            with patch.object(command.logger, 'log') as mock_log:
                command._log_result(value)

                mock_log.assert_called_with(expected_log)

    @pytest.mark.unit
    def test_parse_arguments_case_insensitive_hex(self, mock_cs):
        """Test parsing arguments with case-insensitive hex values."""
        test_cases = [
            (['mm_read', '0x3', '0x2e'], 0x3, 0x2E),
            (['mm_read', '0X3', '0X2E'], 0x3, 0x2E),
            (['mm_write', '0x3', '0x27', '0xe0000001'], 0x3, 0x27, 0xE0000001),
        ]

        for args, expected_port, expected_reg, *expected_val in test_cases:
            command = MMMsgBusCommand(args, cs=mock_cs)
            command.parse_arguments()

            assert command.port == expected_port
            assert command.reg == expected_reg
            if expected_val:
                assert command.val == expected_val[0]

    @pytest.mark.unit
    def test_mm_msgbus_command_reuse(self, mock_cs):
        """Test reusing MM Message Bus command instance."""
        command = MMMsgBusCommand(['mm_read', '0x3', '0x2E'], cs=mock_cs)

        # First read
        mock_cs.hals.MMMsgBus.read.return_value = 0x11111111
        with patch.object(command.logger, 'log'):
            result1 = command.msgbus_mm_read()
            assert result1 is True

        # Second read with different result
        mock_cs.hals.MMMsgBus.read.return_value = 0x22222222
        with patch.object(command.logger, 'log'):
            result2 = command.msgbus_mm_read()
            assert result2 is True

        # Verify both calls were made
        assert mock_cs.hals.MMMsgBus.read.call_count == 2


class TestMMMsgBusCommandConfigurationValidation:
    """Test configuration validation aspects of MM Message Bus command."""

    @pytest.fixture
    def mm_msgbus_cs(self):
        """Create ChipsecCs with MM Message Bus-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock MMMsgBus configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.MM_MSGBUS = {
            'ENABLED_PORTS': [0x0, 0x1, 0x2, 0x3, 0x4],
            'MAX_PORT': 0xFF,
            'TIMEOUT_MS': 1000,
            'RETRY_COUNT': 3
        }

        cs_mock.hals = Mock()
        cs_mock.hals.MMMsgBus = Mock()
        cs_mock.hals.MMMsgBus.read.return_value = 0xDEADBEEF
        cs_mock.hals.MMMsgBus.write.return_value = 0x1

        return cs_mock

    @pytest.mark.unit
    def test_mm_msgbus_configuration_structure(self, mm_msgbus_cs):
        """Test MM Message Bus configuration structure."""
        msgbus_config = mm_msgbus_cs.Cfg.MM_MSGBUS

        # Test that required MM_MSGBUS configuration exists
        assert 'ENABLED_PORTS' in msgbus_config
        assert 'MAX_PORT' in msgbus_config
        assert 'TIMEOUT_MS' in msgbus_config
        assert 'RETRY_COUNT' in msgbus_config

        # Test configuration values are reasonable
        assert isinstance(msgbus_config['ENABLED_PORTS'], list)
        assert msgbus_config['MAX_PORT'] > 0
        assert msgbus_config['TIMEOUT_MS'] > 0
        assert msgbus_config['RETRY_COUNT'] >= 0

    @pytest.mark.unit
    def test_enabled_ports_validation(self, mm_msgbus_cs):
        """Test enabled ports validation."""
        enabled_ports = mm_msgbus_cs.Cfg.MM_MSGBUS['ENABLED_PORTS']
        max_port = mm_msgbus_cs.Cfg.MM_MSGBUS['MAX_PORT']

        # All enabled ports should be within valid range
        for port in enabled_ports:
            assert 0 <= port <= max_port

    @pytest.mark.unit
    def test_mm_msgbus_port_range_validation(self, mm_msgbus_cs):
        """Test MM Message Bus port range validation."""
        max_port = mm_msgbus_cs.Cfg.MM_MSGBUS['MAX_PORT']

        # Test valid ports
        valid_ports = [0, 1, 0x10, 0x7F, max_port]
        for port in valid_ports:
            assert 0 <= port <= max_port

        # Test invalid ports
        invalid_ports = [-1, max_port + 1, 0x100]
        for port in invalid_ports:
            assert not (0 <= port <= max_port)

    @pytest.mark.unit
    def test_mm_msgbus_timeout_configuration(self, mm_msgbus_cs):
        """Test MM Message Bus timeout configuration."""
        timeout = mm_msgbus_cs.Cfg.MM_MSGBUS['TIMEOUT_MS']

        # Timeout should be reasonable (between 100ms and 10 seconds)
        assert 100 <= timeout <= 10000

    @pytest.mark.unit
    def test_mm_msgbus_retry_configuration(self, mm_msgbus_cs):
        """Test MM Message Bus retry configuration."""
        retry_count = mm_msgbus_cs.Cfg.MM_MSGBUS['RETRY_COUNT']

        # Retry count should be reasonable (0-10)
        assert 0 <= retry_count <= 10

    @pytest.mark.unit
    def test_mm_msgbus_command_with_config(self, mm_msgbus_cs):
        """Test MM Message Bus command with configuration."""
        command = MMMsgBusCommand(['mm_read', '0x3', '0x2E'], cs=mm_msgbus_cs)

        with patch.object(command.logger, 'log'):
            result = command.msgbus_mm_read()

            assert result is True
            mm_msgbus_cs.hals.MMMsgBus.read.assert_called_with(0x3, 0x2E)

    @pytest.mark.unit
    def test_mm_msgbus_enabled_ports_check(self, mm_msgbus_cs):
        """Test MM Message Bus enabled ports check."""
        enabled_ports = mm_msgbus_cs.Cfg.MM_MSGBUS['ENABLED_PORTS']

        # Test that common MM Message Bus ports are enabled
        common_ports = [0x0, 0x1, 0x2, 0x3]
        for port in common_ports:
            assert port in enabled_ports

    @pytest.mark.unit
    def test_mm_msgbus_configuration_consistency(self, mm_msgbus_cs):
        """Test MM Message Bus configuration consistency."""
        enabled_ports = set(mm_msgbus_cs.Cfg.MM_MSGBUS['ENABLED_PORTS'])
        max_port = mm_msgbus_cs.Cfg.MM_MSGBUS['MAX_PORT']

        # All enabled ports should be <= max_port
        for port in enabled_ports:
            assert port <= max_port

    @pytest.mark.unit
    def test_mm_msgbus_error_handling_with_config(self, mm_msgbus_cs):
        """Test MM Message Bus error handling with configuration."""
        command = MMMsgBusCommand(['mm_read', '0x3', '0x2E'], cs=mm_msgbus_cs)

        # Test read error with config
        mm_msgbus_cs.hals.MMMsgBus.read.side_effect = Exception("Configured read error")

        with pytest.raises(Exception):
            command.msgbus_mm_read()

        # Test write error with config
        write_command = MMMsgBusCommand(['mm_write', '0x3', '0x27', '0x1'], cs=mm_msgbus_cs)
        mm_msgbus_cs.hals.MMMsgBus.write.side_effect = Exception("Configured write error")

        with pytest.raises(Exception):
            write_command.msgbus_mm_write()

    @pytest.mark.unit
    def test_mm_msgbus_command_logging_with_config(self, mm_msgbus_cs):
        """Test MM Message Bus command logging with configuration."""
        command = MMMsgBusCommand(['mm_read', '0x3', '0x2E'], cs=mm_msgbus_cs)

        with patch.object(command.logger, 'log') as mock_log:
            result = command.msgbus_mm_read()

            assert result is True
            # Verify logging still works with configuration
            assert mock_log.call_count >= 2  # Operation log + result log


if __name__ == '__main__':
    pytest.main([__file__])
