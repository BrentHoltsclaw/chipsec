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
from chipsec.utilcmd.lock_check_cmd import LOCKCHECKCommand
from chipsec.hal.common.locks import LockResult
from tests.test_utils import MockFactory


class TestLOCKCHECKCommand:
    """Comprehensive tests for LOCKCHECK (Lock Check) command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for LOCKCHECK testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock Locks HAL component
        cs_mock.hals = Mock()
        cs_mock.hals.Locks = Mock()

        # Mock lock configuration
        cs_mock.lock = Mock()
        cs_mock.lock.get.return_value = Mock()

        return cs_mock

    @pytest.fixture
    def lock_check_command(self, mock_cs):
        """Create LOCKCHECKCommand instance."""
        return LOCKCHECKCommand(['list'], cs=mock_cs)

    @pytest.mark.unit
    def test_lock_check_command_initialization(self, lock_check_command, mock_cs):
        """Test LOCKCHECKCommand initialization."""
        assert lock_check_command.cs == mock_cs
        assert lock_check_command.argv == ['list']
        assert lock_check_command.version == "0.8"

    @pytest.mark.unit
    def test_requirements(self, lock_check_command):
        """Test command requirements."""
        reqs = lock_check_command.requirements()
        assert reqs == lock_check_command.toLoad.All

    @pytest.mark.unit
    def test_parse_arguments_list(self, mock_cs):
        """Test parsing arguments for list subcommand."""
        command = LOCKCHECKCommand(['list'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.list_locks

    @pytest.mark.unit
    def test_parse_arguments_all(self, mock_cs):
        """Test parsing arguments for all subcommand."""
        command = LOCKCHECKCommand(['all'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.checkall_locks

    @pytest.mark.unit
    def test_parse_arguments_lock_single(self, mock_cs):
        """Test parsing arguments for lock subcommand with single lock."""
        command = LOCKCHECKCommand(['lock', 'DebugLock'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.check_lock
        assert command.lockname == ['DebugLock']

    @pytest.mark.unit
    def test_parse_arguments_lock_multiple(self, mock_cs):
        """Test parsing arguments for lock subcommand with multiple locks."""
        command = LOCKCHECKCommand(['lock', 'DebugLock', 'BiosLock', 'SpiLock'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.check_lock
        assert command.lockname == ['DebugLock', 'BiosLock', 'SpiLock']

    @pytest.mark.unit
    def test_parse_arguments_no_subcommand(self, mock_cs):
        """Test parsing arguments with no subcommand."""
        command = LOCKCHECKCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_invalid_subcommand(self, mock_cs):
        """Test parsing arguments with invalid subcommand."""
        command = LOCKCHECKCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_list_locks(self, lock_check_command, mock_cs):
        """Test list_locks method."""
        mock_cs.hals.Locks.get_locks.return_value = ['DebugLock', 'BiosLock', 'SpiLock']

        with patch.object(lock_check_command.logger, 'log') as mock_log:
            lock_check_command.list_locks()

            mock_log.assert_any_call('Locks identified within the configuration:')
            mock_log.assert_any_call('DebugLock')
            mock_log.assert_any_call('BiosLock')
            mock_log.assert_any_call('SpiLock')
            mock_log.assert_any_call('')

    @pytest.mark.unit
    def test_list_locks_empty(self, lock_check_command, mock_cs):
        """Test list_locks method with no locks."""
        mock_cs.hals.Locks.get_locks.return_value = []

        with patch.object(lock_check_command.logger, 'log') as mock_log:
            lock_check_command.list_locks()

            mock_log.assert_any_call('Locks identified within the configuration:')
            # Should not log any locks
            assert mock_log.call_count == 2  # Header + empty line

    @pytest.mark.unit
    def test_checkall_locks_with_locks(self, lock_check_command, mock_cs):
        """Test checkall_locks method with locks present."""
        mock_cs.hals.Locks.get_locks.return_value = ['DebugLock', 'BiosLock']
        mock_cs.hals.Locks.is_locked.side_effect = [
            LockResult.LOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ,
            LockResult.UNLOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ
        ]

        mock_lock_obj = Mock()
        mock_lock_obj.is_access_type.return_value = False
        mock_cs.lock.get.return_value = mock_lock_obj

        with patch.object(lock_check_command.logger, 'log') as mock_log, \
             patch.object(lock_check_command.logger, 'VERBOSE', False), \
             patch.object(lock_check_command.logger, 'HAL', False):
            lock_check_command.checkall_locks()

            # Should call is_locked for each lock
            assert mock_cs.hals.Locks.is_locked.call_count == 2
            # Should log header and results
            assert mock_log.call_count >= 3  # Header + 2 results + final log

    @pytest.mark.unit
    def test_checkall_locks_no_locks(self, lock_check_command, mock_cs):
        """Test checkall_locks method with no locks."""
        mock_cs.hals.Locks.get_locks.return_value = []

        with patch.object(lock_check_command.logger, 'log') as mock_log:
            lock_check_command.checkall_locks()

            mock_log.assert_called_with('Did not find any locks')

    @pytest.mark.unit
    def test_check_lock_single(self, lock_check_command, mock_cs):
        """Test check_lock method with single lock."""
        lock_check_command.lockname = ['DebugLock']
        mock_cs.hals.Locks.is_locked.return_value = LockResult.LOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ

        mock_lock_obj = Mock()
        mock_lock_obj.is_access_type.return_value = False
        mock_cs.lock.get.return_value = mock_lock_obj

        with patch.object(lock_check_command.logger, 'log') as mock_log, \
             patch.object(lock_check_command.logger, 'VERBOSE', False), \
             patch.object(lock_check_command.logger, 'HAL', False):
            lock_check_command.check_lock()

            mock_cs.hals.Locks.is_locked.assert_called_with('DebugLock')
            assert mock_log.call_count >= 2  # Header + result

    @pytest.mark.unit
    def test_check_lock_multiple(self, lock_check_command, mock_cs):
        """Test check_lock method with multiple locks."""
        lock_check_command.lockname = ['DebugLock', 'BiosLock']
        mock_cs.hals.Locks.is_locked.side_effect = [
            LockResult.LOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ,
            LockResult.UNLOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ
        ]

        mock_lock_obj = Mock()
        mock_lock_obj.is_access_type.return_value = False
        mock_cs.lock.get.return_value = mock_lock_obj

        with patch.object(lock_check_command.logger, 'log') as mock_log, \
             patch.object(lock_check_command.logger, 'VERBOSE', False), \
             patch.object(lock_check_command.logger, 'HAL', False):
            lock_check_command.check_lock()

            assert mock_cs.hals.Locks.is_locked.call_count == 2
            assert mock_log.call_count >= 3  # Header + 2 results

    @pytest.mark.unit
    def test_check_log_locked_state(self, lock_check_command, mock_cs):
        """Test check_log method with locked state."""
        mock_lock_obj = Mock()
        mock_lock_obj.is_access_type.return_value = False
        mock_cs.lock.get.return_value = mock_lock_obj

        with patch.object(lock_check_command.logger, 'log') as mock_log, \
             patch.object(lock_check_command.logger, 'HAL', False):
            result = lock_check_command.check_log('DebugLock', LockResult.LOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ)

            assert 'Locked' in result
            assert 'Yes' in result  # Consistent
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_check_log_unlocked_state(self, lock_check_command, mock_cs):
        """Test check_log method with unlocked state."""
        mock_lock_obj = Mock()
        mock_lock_obj.is_access_type.return_value = False
        mock_cs.lock.get.return_value = mock_lock_obj

        with patch.object(lock_check_command.logger, 'log') as mock_log, \
             patch.object(lock_check_command.logger, 'HAL', False):
            result = lock_check_command.check_log('BiosLock', LockResult.UNLOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ)

            assert 'UnLocked' in result
            assert 'Yes' in result  # Consistent
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_check_log_rwo_state(self, lock_check_command, mock_cs):
        """Test check_log method with RW/O state."""
        mock_lock_obj = Mock()
        mock_lock_obj.is_access_type.return_value = True
        mock_cs.lock.get.return_value = mock_lock_obj

        with patch.object(lock_check_command.logger, 'log') as mock_log, \
             patch.object(lock_check_command.logger, 'HAL', False):
            result = lock_check_command.check_log('SpiLock', LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ)

            assert 'RW/O' in result
            assert 'Yes' in result  # Consistent
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_check_log_undefined_state(self, lock_check_command, mock_cs):
        """Test check_log method with undefined state."""
        with patch.object(lock_check_command.logger, 'log') as mock_log, \
             patch.object(lock_check_command.logger, 'HAL', False):
            result = lock_check_command.check_log('UnknownLock', 0)  # No flags set

            assert 'Undefined' in result
            assert 'N/A' in result  # Not applicable for consistency
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_check_log_undoc_state(self, lock_check_command, mock_cs):
        """Test check_log method with undocumented state."""
        with patch.object(lock_check_command.logger, 'log') as mock_log, \
             patch.object(lock_check_command.logger, 'HAL', False):
            result = lock_check_command.check_log('UndocLock', LockResult.DEFINED)  # Only defined, no config

            assert 'Undoc' in result
            assert 'N/A' in result  # Not applicable for consistency
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_check_log_hidden_state(self, lock_check_command, mock_cs):
        """Test check_log method with hidden state."""
        with patch.object(lock_check_command.logger, 'log') as mock_log, \
             patch.object(lock_check_command.logger, 'HAL', False):
            result = lock_check_command.check_log('HiddenLock', LockResult.DEFINED | LockResult.HAS_CONFIG)  # Can't read

            assert 'Hidden' in result
            assert 'N/A' in result  # Not applicable for consistency
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_check_log_inconsistent_state(self, lock_check_command, mock_cs):
        """Test check_log method with inconsistent state."""
        mock_lock_obj = Mock()
        mock_lock_obj.is_access_type.return_value = False
        mock_cs.lock.get.return_value = mock_lock_obj

        with patch.object(lock_check_command.logger, 'log') as mock_log, \
             patch.object(lock_check_command.logger, 'HAL', False):
            result = lock_check_command.check_log('InconsistentLock',
                                                  LockResult.LOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ | LockResult.INCONSISTENT)

            assert 'Locked' in result
            assert 'No' in result  # Inconsistent
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_log_header(self, lock_check_command, mock_cs):
        """Test log_header method."""
        with patch.object(lock_check_command.logger, 'log') as mock_log, \
             patch.object(lock_check_command.logger, 'HAL', False):
            result = lock_check_command.log_header()

            assert 'Lock Name' in result
            assert 'State' in result
            assert 'Consistent' in result
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_log_header_hal_mode(self, lock_check_command, mock_cs):
        """Test log_header method in HAL mode."""
        with patch.object(lock_check_command.logger, 'log') as mock_log, \
             patch.object(lock_check_command.logger, 'HAL', True):
            result = lock_check_command.log_header()

            assert 'Lock Name' in result
            assert 'State' in result
            assert 'Consistent' in result
            mock_log.assert_not_called()  # Should not log in HAL mode

    @pytest.mark.unit
    def test_log_key(self, lock_check_command, mock_cs):
        """Test log_key method."""
        with patch.object(lock_check_command.logger, 'log') as mock_log:
            lock_check_command.log_key()

            mock_log.assert_called_once()
            call_args = mock_log.call_args[0][0]
            assert 'KEY:' in call_args
            assert 'Undefined' in call_args
            assert 'Locked' in call_args
            assert 'RW/O' in call_args


class TestLOCKCHECKCommandIntegration:
    """Integration tests for LOCKCHECK command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for LOCKCHECK testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock comprehensive Locks HAL
        cs_mock.hals = Mock()
        cs_mock.hals.Locks = Mock()
        cs_mock.hals.Locks.get_locks.return_value = ['DebugLock', 'BiosLock', 'SpiLock', 'TpmLock']
        cs_mock.hals.Locks.is_locked.side_effect = [
            LockResult.LOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ,
            LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ,
            LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ,  # RW/O case
            LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ | LockResult.INCONSISTENT
        ]

        # Mock lock configuration
        cs_mock.lock = Mock()
        mock_lock_obj = Mock()
        mock_lock_obj.is_access_type.side_effect = [False, False, True, False]  # Third is RW/O
        cs_mock.lock.get.return_value = mock_lock_obj

        return cs_mock

    @pytest.mark.integration
    def test_lock_check_list_integration(self, integrated_cs):
        """Test complete LOCKCHECK list workflow."""
        lock_cmd = LOCKCHECKCommand(['list'], cs=integrated_cs)

        with patch.object(lock_cmd.logger, 'log'):
            lock_cmd.list_locks()

            integrated_cs.hals.Locks.get_locks.assert_called_once()

    @pytest.mark.integration
    def test_lock_check_all_integration(self, integrated_cs):
        """Test complete LOCKCHECK all workflow."""
        lock_cmd = LOCKCHECKCommand(['all'], cs=integrated_cs)

        with patch.object(lock_cmd.logger, 'log'), \
             patch.object(lock_cmd.logger, 'VERBOSE', False), \
             patch.object(lock_cmd.logger, 'HAL', False):
            lock_cmd.checkall_locks()

            assert integrated_cs.hals.Locks.is_locked.call_count == 4  # All locks

    @pytest.mark.integration
    def test_lock_check_specific_integration(self, integrated_cs):
        """Test complete LOCKCHECK specific lock workflow."""
        lock_cmd = LOCKCHECKCommand(['lock', 'DebugLock'], cs=integrated_cs)

        with patch.object(lock_cmd.logger, 'log'), \
             patch.object(lock_cmd.logger, 'VERBOSE', False), \
             patch.object(lock_cmd.logger, 'HAL', False):
            lock_cmd.check_lock()

            integrated_cs.hals.Locks.is_locked.assert_called_with('DebugLock')


class TestLOCKCHECKCommandEdgeCases:
    """Test edge cases and error conditions for LOCKCHECK command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        cs_mock.hals.Locks = Mock()
        cs_mock.lock = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_check_log_long_lock_name(self, mock_cs):
        """Test check_log method with long lock name."""
        command = LOCKCHECKCommand(['list'], cs=mock_cs)

        long_lock_name = 'VeryLongLockNameThatExceedsNormalLength'
        mock_lock_obj = Mock()
        mock_lock_obj.is_access_type.return_value = False
        mock_cs.lock.get.return_value = mock_lock_obj

        with patch.object(command.logger, 'log'), \
             patch.object(command.logger, 'HAL', False):
            result = command.check_log(long_lock_name, LockResult.LOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ)

            # Should truncate long names appropriately
            assert len(result.split('|')[0].strip()) <= 26  # Max length in format

    @pytest.mark.unit
    def test_check_lock_empty_lockname_list(self, mock_cs):
        """Test check_lock method with empty lockname list."""
        command = LOCKCHECKCommand(['lock'], cs=mock_cs)
        command.lockname = []

        with patch.object(command.logger, 'log'), \
             patch.object(command.logger, 'VERBOSE', False), \
             patch.object(command.logger, 'HAL', False):
            command.check_lock()

            # Should not call is_locked if no locknames
            mock_cs.hals.Locks.is_locked.assert_not_called()

    @pytest.mark.unit
    def test_checkall_locks_verbose_mode(self, mock_cs):
        """Test checkall_locks method in verbose mode."""
        command = LOCKCHECKCommand(['all'], cs=mock_cs)
        mock_cs.hals.Locks.get_locks.return_value = ['DebugLock']

        mock_lock_obj = Mock()
        mock_lock_obj.is_access_type.return_value = False
        mock_cs.lock.get.return_value = mock_lock_obj

        with patch.object(command.logger, 'log') as mock_log, \
             patch.object(command.logger, 'VERBOSE', True), \
             patch.object(command.logger, 'HAL', False):
            command.checkall_locks()

            # Should call log_key in verbose mode
            assert any('KEY:' in str(call) for call in mock_log.call_args_list)

    @pytest.mark.unit
    def test_check_lock_verbose_mode(self, mock_cs):
        """Test check_lock method in verbose mode."""
        command = LOCKCHECKCommand(['lock', 'DebugLock'], cs=mock_cs)
        command.lockname = ['DebugLock']

        mock_lock_obj = Mock()
        mock_lock_obj.is_access_type.return_value = False
        mock_cs.lock.get.return_value = mock_lock_obj

        with patch.object(command.logger, 'log') as mock_log, \
             patch.object(command.logger, 'VERBOSE', True), \
             patch.object(command.logger, 'HAL', False):
            command.check_lock()

            # Should call log_key in verbose mode
            assert any('KEY:' in str(call) for call in mock_log.call_args_list)

    @pytest.mark.unit
    def test_check_log_unknown_state(self, mock_cs):
        """Test check_log method with unknown state combination."""
        command = LOCKCHECKCommand(['list'], cs=mock_cs)

        # Create an unusual combination that doesn't match any expected state
        unusual_state = LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ | 0x1000  # Unknown flag

        with patch.object(command.logger, 'log'), \
             patch.object(command.logger, 'HAL', False):
            result = command.check_log('UnknownLock', unusual_state)

            assert 'Unknown' in result

    @pytest.mark.unit
    def test_list_locks_large_number(self, mock_cs):
        """Test list_locks method with large number of locks."""
        large_locks_list = [f'Lock{i}' for i in range(100)]
        mock_cs.hals.Locks.get_locks.return_value = large_locks_list

        command = LOCKCHECKCommand(['list'], cs=mock_cs)

        with patch.object(command.logger, 'log') as mock_log:
            command.list_locks()

            # Should log header
            mock_log.assert_any_call('Locks identified within the configuration:')
            # Should log all locks
            for lock in large_locks_list:
                mock_log.assert_any_call(lock)

    @pytest.mark.unit
    def test_check_log_special_characters_in_name(self, mock_cs):
        """Test check_log method with special characters in lock name."""
        command = LOCKCHECKCommand(['list'], cs=mock_cs)

        special_lock_name = 'Lock_With_Special-Chars.123'
        mock_lock_obj = Mock()
        mock_lock_obj.is_access_type.return_value = False
        mock_cs.lock.get.return_value = mock_lock_obj

        with patch.object(command.logger, 'log'), \
             patch.object(command.logger, 'HAL', False):
            result = command.check_log(special_lock_name, LockResult.LOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ)

            assert special_lock_name[:26] in result  # Should handle special chars

    @pytest.mark.unit
    def test_parse_arguments_lock_empty_string(self, mock_cs):
        """Test parsing arguments with empty string lock name."""
        command = LOCKCHECKCommand(['lock', ''], cs=mock_cs)
        command.parse_arguments()
        assert command.lockname == ['']


class TestLOCKCHECKCommandConfigurationValidation:
    """Test configuration validation aspects of LOCKCHECK command."""

    @pytest.fixture
    def lock_cs(self):
        """Create ChipsecCs with LOCKCHECK-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock Locks HAL with configuration
        cs_mock.hals = Mock()
        cs_mock.hals.Locks = Mock()
        cs_mock.hals.Locks.get_locks.return_value = ['DebugLock', 'BiosLock']
        cs_mock.hals.Locks.is_locked.return_value = LockResult.LOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ

        # Mock lock configuration
        cs_mock.lock = Mock()
        mock_lock_obj = Mock()
        mock_lock_obj.is_access_type.return_value = False
        cs_mock.lock.get.return_value = mock_lock_obj

        # Mock configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.LOCKS = {
            'ENABLED_CHECKS': ['DebugLock', 'BiosLock'],
            'DISABLED_CHECKS': ['TestLock'],
            'LOCK_TIMEOUT': 10
        }

        return cs_mock

    @pytest.mark.unit
    def test_lock_configuration_structure(self, lock_cs):
        """Test LOCKS configuration structure."""
        locks_config = lock_cs.Cfg.LOCKS

        # Test that required LOCKS configuration exists
        assert 'ENABLED_CHECKS' in locks_config
        assert 'DISABLED_CHECKS' in locks_config
        assert 'LOCK_TIMEOUT' in locks_config

        # Test configuration values are reasonable
        assert isinstance(locks_config['ENABLED_CHECKS'], list)
        assert isinstance(locks_config['DISABLED_CHECKS'], list)
        assert locks_config['LOCK_TIMEOUT'] > 0

    @pytest.mark.unit
    def test_enabled_locks_validation(self, lock_cs):
        """Test enabled locks validation."""
        enabled_checks = lock_cs.Cfg.LOCKS['ENABLED_CHECKS']
        available_locks = lock_cs.hals.Locks.get_locks()

        # All enabled checks should be in available locks
        for check in enabled_checks:
            assert check in available_locks

    @pytest.mark.unit
    def test_disabled_locks_exclusion(self, lock_cs):
        """Test disabled locks exclusion."""
        disabled_checks = lock_cs.Cfg.LOCKS['DISABLED_CHECKS']
        available_locks = lock_cs.hals.Locks.get_locks()

        # Disabled checks should not be in available locks
        for check in disabled_checks:
            assert check not in available_locks

    @pytest.mark.unit
    def test_lock_timeout_configuration(self, lock_cs):
        """Test lock timeout configuration."""
        timeout = lock_cs.Cfg.LOCKS['LOCK_TIMEOUT']

        # Timeout should be reasonable (between 1 and 300 seconds)
        assert 1 <= timeout <= 300

    @pytest.mark.unit
    def test_lock_command_with_config(self, lock_cs):
        """Test LOCKCHECK command with configuration."""
        command = LOCKCHECKCommand(['all'], cs=lock_cs)

        with patch.object(command.logger, 'log'), \
             patch.object(command.logger, 'VERBOSE', False), \
             patch.object(command.logger, 'HAL', False):
            command.checkall_locks()

            # Should work with configuration present
            assert lock_cs.hals.Locks.is_locked.called

    @pytest.mark.unit
    def test_lock_configuration_consistency(self, lock_cs):
        """Test lock configuration consistency."""
        enabled_checks = set(lock_cs.Cfg.LOCKS['ENABLED_CHECKS'])
        disabled_checks = set(lock_cs.Cfg.LOCKS['DISABLED_CHECKS'])

        # Enabled and disabled checks should not overlap
        assert len(enabled_checks & disabled_checks) == 0

    @pytest.mark.unit
    def test_lock_state_mapping(self, lock_cs):
        """Test lock state mapping."""
        # Test various lock result combinations
        test_cases = [
            (LockResult.LOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ, 'Locked'),
            (LockResult.UNLOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ, 'UnLocked'),
            (LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ, 'RW/O'),  # When is_access_type returns True
            (LockResult.DEFINED | LockResult.HAS_CONFIG, 'Hidden'),
            (LockResult.DEFINED, 'Undoc'),
            (0, 'Undefined')
        ]

        command = LOCKCHECKCommand(['list'], cs=lock_cs)

        for lock_result, expected_state in test_cases:
            mock_lock_obj = Mock()
            if expected_state == 'RW/O':
                mock_lock_obj.is_access_type.return_value = True
            else:
                mock_lock_obj.is_access_type.return_value = False
            lock_cs.lock.get.return_value = mock_lock_obj

            with patch.object(command.logger, 'log'), \
                 patch.object(command.logger, 'HAL', False):
                result = command.check_log('TestLock', lock_result)

                assert expected_state in result

    @pytest.mark.unit
    def test_lock_consistency_calculation(self, lock_cs):
        """Test lock consistency calculation."""
        command = LOCKCHECKCommand(['list'], cs=lock_cs)

        # Test consistent cases
        consistent_cases = [
            LockResult.LOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ,
            LockResult.UNLOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ
        ]

        for lock_result in consistent_cases:
            mock_lock_obj = Mock()
            mock_lock_obj.is_access_type.return_value = False
            lock_cs.lock.get.return_value = mock_lock_obj

            with patch.object(command.logger, 'log'), \
                 patch.object(command.logger, 'HAL', False):
                result = command.check_log('TestLock', lock_result)

                assert 'Yes' in result

        # Test inconsistent cases
        inconsistent_cases = [
            LockResult.LOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ | LockResult.INCONSISTENT,
            LockResult.UNLOCKED | LockResult.DEFINED | LockResult.HAS_CONFIG | LockResult.CAN_READ | LockResult.INCONSISTENT
        ]

        for lock_result in inconsistent_cases:
            mock_lock_obj = Mock()
            mock_lock_obj.is_access_type.return_value = False
            lock_cs.lock.get.return_value = mock_lock_obj

            with patch.object(command.logger, 'log'), \
                 patch.object(command.logger, 'HAL', False):
                result = command.check_log('TestLock', lock_result)

                assert 'No' in result


if __name__ == '__main__':
    pytest.main([__file__])
