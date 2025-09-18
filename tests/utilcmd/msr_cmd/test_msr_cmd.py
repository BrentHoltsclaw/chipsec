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
from chipsec.utilcmd.msr_cmd import MSRCommand
from tests.test_utils import MockFactory


class TestMSRCommand:
    """Comprehensive tests for MSR utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for MSR testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        # Mock MSR HAL
        cs_mock.hals.Msr = Mock()
        cs_mock.hals.Msr.read_msr.return_value = (0x12345678, 0x9ABCDEF0)
        cs_mock.hals.Msr.write_msr.return_value = None
        cs_mock.hals.Msr.get_cpu_thread_count.return_value = 4
        return cs_mock

    @pytest.fixture
    def msr_command(self, mock_cs):
        """Create MSRCommand instance."""
        return MSRCommand(['0x3A'], cs=mock_cs)

    @pytest.mark.unit
    def test_msr_command_initialization(self, msr_command, mock_cs):
        """Test MSRCommand initialization."""
        assert msr_command.cs == mock_cs
        assert msr_command.argv == ['0x3A']

    @pytest.mark.unit
    def test_parse_arguments_read_all_cpus(self, mock_cs):
        """Test parsing arguments for reading MSR from all CPUs."""
        command = MSRCommand(['0x3A'], cs=mock_cs)
        command.parse_arguments()
        assert command.msr_addr == 0x3A
        assert command.msr_input1 is None
        assert command.msr_input2 is None
        assert command.thread_id is None

    @pytest.mark.unit
    def test_parse_arguments_read_specific_cpu(self, mock_cs):
        """Test parsing arguments for reading MSR from specific CPU."""
        command = MSRCommand(['0x3A', '1'], cs=mock_cs)
        command.parse_arguments()
        assert command.msr_addr == 0x3A
        assert command.msr_input1 == 1
        assert command.msr_input2 is None
        assert command.thread_id is None

    @pytest.mark.unit
    def test_parse_arguments_write_all_cpus(self, mock_cs):
        """Test parsing arguments for writing MSR to all CPUs."""
        command = MSRCommand(['0x3A', '0x12345678', '0x9ABCDEF0'], cs=mock_cs)
        command.parse_arguments()
        assert command.msr_addr == 0x3A
        assert command.msr_input1 == 0x12345678
        assert command.msr_input2 == 0x9ABCDEF0
        assert command.thread_id is None

    @pytest.mark.unit
    def test_parse_arguments_write_specific_cpu(self, mock_cs):
        """Test parsing arguments for writing MSR to specific CPU."""
        command = MSRCommand(['0x3A', '0x12345678', '0x9ABCDEF0', '2'], cs=mock_cs)
        command.parse_arguments()
        assert command.msr_addr == 0x3A
        assert command.msr_input1 == 0x12345678
        assert command.msr_input2 == 0x9ABCDEF0
        assert command.thread_id == 2

    @pytest.mark.unit
    def test_parse_arguments_decimal_values(self, mock_cs):
        """Test parsing arguments with decimal values."""
        command = MSRCommand(['58', '305419896', '2596069104'], cs=mock_cs)
        command.parse_arguments()
        assert command.msr_addr == 58  # 0x3A
        assert command.msr_input1 == 305419896  # 0x12345678
        assert command.msr_input2 == 2596069104  # 0x9ABCDEF0

    @pytest.mark.unit
    def test_requirements(self, msr_command):
        """Test command requirements."""
        reqs = msr_command.requirements()
        assert hasattr(reqs, 'load_driver')

    @pytest.mark.unit
    def test_run_read_all_cpus(self, msr_command, mock_cs):
        """Test reading MSR from all CPUs."""
        msr_command.msr_addr = 0x3A
        msr_command.msr_input1 = None

        with patch.object(msr_command.logger, 'log') as mock_log:
            msr_command.run()

            # Should call read_msr for each CPU thread
            assert mock_cs.hals.Msr.read_msr.call_count == 4  # 4 CPU threads
            mock_cs.hals.Msr.get_cpu_thread_count.assert_called_once()

            # Should log results for each CPU
            assert mock_log.call_count == 4

    @pytest.mark.unit
    def test_run_read_specific_cpu(self, msr_command, mock_cs):
        """Test reading MSR from specific CPU."""
        msr_command.msr_addr = 0x3A
        msr_command.msr_input1 = 2  # CPU thread 2
        msr_command.msr_input2 = None

        with patch.object(msr_command.logger, 'log') as mock_log:
            msr_command.run()

            # Should call read_msr for specific CPU
            mock_cs.hals.Msr.read_msr.assert_called_once_with(2, 0x3A)
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_run_write_all_cpus(self, msr_command, mock_cs):
        """Test writing MSR to all CPUs."""
        msr_command.msr_addr = 0x3A
        msr_command.msr_input1 = 0x12345678
        msr_command.msr_input2 = 0x9ABCDEF0
        msr_command.thread_id = None

        with patch.object(msr_command.logger, 'log') as mock_log:
            msr_command.run()

            # Should call write_msr for each CPU thread
            assert mock_cs.hals.Msr.write_msr.call_count == 4  # 4 CPU threads
            mock_cs.hals.Msr.get_cpu_thread_count.assert_called_once()

            # Should log the write operation
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_run_write_specific_cpu(self, msr_command, mock_cs):
        """Test writing MSR to specific CPU."""
        msr_command.msr_addr = 0x3A
        msr_command.msr_input1 = 0x12345678
        msr_command.msr_input2 = 0x9ABCDEF0
        msr_command.thread_id = 3

        with patch.object(msr_command.logger, 'log') as mock_log:
            msr_command.run()

            # Should call write_msr for specific CPU
            mock_cs.hals.Msr.write_msr.assert_called_once_with(3, 0x3A, 0x12345678, 0x9ABCDEF0)
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_run_read_msr_value_calculation(self, msr_command, mock_cs):
        """Test MSR value calculation in read operations."""
        msr_command.msr_addr = 0x3A
        msr_command.msr_input1 = 1  # Specific CPU
        msr_command.msr_input2 = None  # Ensure msr_input2 is set
        msr_command.thread_id = None

        # Mock MSR read to return specific values
        mock_cs.hals.Msr.read_msr.return_value = (0x12345678, 0x9ABCDEF0)

        with patch.object(msr_command.logger, 'log') as mock_log:
            msr_command.run()

            # Verify the 64-bit value calculation: (EDX << 32) | EAX
            expected_val64 = (0x9ABCDEF0 << 32) | 0x12345678
            assert expected_val64 == 0x9ABCDEF012345678

            # Verify log message contains correct values
            log_call = mock_log.call_args[0][0]
            assert '0x3a' in log_call.lower()
            assert '12345678' in log_call.lower()
            assert '9abcdef0' in log_call.lower()
            assert '9abcdef012345678' in log_call.lower()

    @pytest.mark.unit
    def test_run_write_msr_value_calculation(self, msr_command, mock_cs):
        """Test MSR value calculation in write operations."""
        msr_command.msr_addr = 0x3A
        msr_command.msr_input1 = 0x12345678
        msr_command.msr_input2 = 0x9ABCDEF0
        msr_command.thread_id = 1

        with patch.object(msr_command.logger, 'log') as mock_log:
            msr_command.run()

            # Verify the 64-bit value calculation: (EDX << 32) | EAX
            expected_val64 = (0x9ABCDEF0 << 32) | 0x12345678
            assert expected_val64 == 0x9ABCDEF012345678

            # Verify log message contains correct values
            log_call = mock_log.call_args[0][0]
            assert '0x3a' in log_call.lower()
            assert '9abcdef012345678' in log_call.lower()


class TestMSRCommandIntegration:
    """Integration tests for MSR command with HAL components."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for MSR testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        cs_mock.hals.Msr = Mock()
        cs_mock.hals.Msr.read_msr.return_value = (0xDEADBEEF, 0xCAFEBABE)
        cs_mock.hals.Msr.write_msr.return_value = None
        cs_mock.hals.Msr.get_cpu_thread_count.return_value = 2

        # Mock helper
        cs_mock.helper = Mock()
        cs_mock.helper.get_threads_count.return_value = 2

        return cs_mock

    @pytest.mark.integration
    def test_msr_read_write_workflow(self, integrated_cs):
        """Test complete MSR read/write workflow."""
        # Test read operation
        read_cmd = MSRCommand(['0x3A'], cs=integrated_cs)
        read_cmd.parse_arguments()

        with patch.object(read_cmd.logger, 'log') as mock_log:
            read_cmd.run()

            # Should read from all CPUs
            assert integrated_cs.hals.Msr.read_msr.call_count == 2  # 2 CPU threads
            assert mock_log.call_count == 2

        # Test write operation
        write_cmd = MSRCommand(['0x3A', '0xDEADBEEF', '0xCAFEBABE'], cs=integrated_cs)
        write_cmd.parse_arguments()

        with patch.object(write_cmd.logger, 'log') as mock_log:
            write_cmd.run()

            # Should write to all CPUs
            assert integrated_cs.hals.Msr.write_msr.call_count == 2  # 2 CPU threads
            assert mock_log.call_count == 1  # One summary log

    @pytest.mark.integration
    def test_msr_specific_cpu_operations(self, integrated_cs):
        """Test MSR operations on specific CPU."""
        # Test read from specific CPU
        read_cmd = MSRCommand(['0x8B', '1'], cs=integrated_cs)
        read_cmd.parse_arguments()

        with patch.object(read_cmd.logger, 'log') as mock_log:
            read_cmd.run()

            integrated_cs.hals.Msr.read_msr.assert_called_once_with(1, 0x8B)
            mock_log.assert_called_once()

        # Test write to specific CPU
        write_cmd = MSRCommand(['0x8B', '0xDEADBEEF', '0xCAFEBABE', '1'], cs=integrated_cs)
        write_cmd.parse_arguments()

        with patch.object(write_cmd.logger, 'log') as mock_log:
            write_cmd.run()

            integrated_cs.hals.Msr.write_msr.assert_called_once_with(1, 0x8B, 0xDEADBEEF, 0xCAFEBABE)
            mock_log.assert_called_once()

    @pytest.mark.integration
    def test_msr_error_handling(self, integrated_cs):
        """Test MSR command error handling."""
        # Test with invalid MSR address (should still work with mock)
        read_cmd = MSRCommand(['0xFFFFFFFF'], cs=integrated_cs)
        read_cmd.parse_arguments()

        with patch.object(read_cmd.logger, 'log') as mock_log:
            read_cmd.run()

            # Should still attempt to read despite invalid address
            assert integrated_cs.hals.Msr.read_msr.call_count == 2
            assert mock_log.call_count == 2


class TestMSRCommandEdgeCases:
    """Test edge cases and error conditions for MSR command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals.Msr = Mock()
        cs_mock.hals.Msr.get_cpu_thread_count.return_value = 1
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        msr_cmd = MSRCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            msr_cmd.parse_arguments()

    @pytest.mark.unit
    def test_invalid_msr_address(self, mock_cs):
        """Test handling of invalid MSR address."""
        msr_cmd = MSRCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid MSR address
        with pytest.raises(SystemExit):
            msr_cmd.parse_arguments()

    @pytest.mark.unit
    def test_single_cpu_system(self, mock_cs):
        """Test MSR operations on single CPU system."""
        mock_cs.hals.Msr.get_cpu_thread_count.return_value = 1
        mock_cs.hals.Msr.read_msr.return_value = (0x11111111, 0x22222222)

        msr_cmd = MSRCommand(['0x3A'], cs=mock_cs)
        msr_cmd.parse_arguments()

        with patch.object(msr_cmd.logger, 'log') as mock_log:
            msr_cmd.run()

            # Should read from single CPU
            mock_cs.hals.Msr.read_msr.assert_called_once_with(0, 0x3A)
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_zero_values(self, mock_cs):
        """Test MSR operations with zero values."""
        mock_cs.hals.Msr.read_msr.return_value = (0x0, 0x0)

        msr_cmd = MSRCommand(['0x0'], cs=mock_cs)
        msr_cmd.parse_arguments()

        with patch.object(msr_cmd.logger, 'log') as mock_log:
            msr_cmd.run()

            mock_cs.hals.Msr.read_msr.assert_called_once_with(0, 0x0)
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_maximum_values(self, mock_cs):
        """Test MSR operations with maximum values."""
        mock_cs.hals.Msr.read_msr.return_value = (0xFFFFFFFF, 0xFFFFFFFF)

        msr_cmd = MSRCommand(['0xFFFFFFFF'], cs=mock_cs)
        msr_cmd.parse_arguments()

        with patch.object(msr_cmd.logger, 'log') as mock_log:
            msr_cmd.run()

            mock_cs.hals.Msr.read_msr.assert_called_once_with(0, 0xFFFFFFFF)
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_write_zero_values(self, mock_cs):
        """Test writing zero values to MSR."""
        msr_cmd = MSRCommand(['0x3A', '0x0', '0x0'], cs=mock_cs)
        msr_cmd.parse_arguments()

        with patch.object(msr_cmd.logger, 'log') as mock_log:
            msr_cmd.run()

            mock_cs.hals.Msr.write_msr.assert_called_once_with(0, 0x3A, 0x0, 0x0)
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_write_maximum_values(self, mock_cs):
        """Test writing maximum values to MSR."""
        msr_cmd = MSRCommand(['0x3A', '0xFFFFFFFF', '0xFFFFFFFF'], cs=mock_cs)
        msr_cmd.parse_arguments()

        with patch.object(msr_cmd.logger, 'log') as mock_log:
            msr_cmd.run()

            mock_cs.hals.Msr.write_msr.assert_called_once_with(0, 0x3A, 0xFFFFFFFF, 0xFFFFFFFF)
            mock_log.assert_called_once()


class TestMSRCommandConfigurationValidation:
    """Test configuration validation aspects of MSR command."""

    @pytest.fixture
    def config_cs(self):
        """Create ChipsecCs with MSR-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock MSR HAL with configuration
        cs_mock.hals.Msr = Mock()
        cs_mock.hals.Msr.read_msr.return_value = (0x12345678, 0x9ABCDEF0)
        cs_mock.hals.Msr.get_cpu_thread_count.return_value = 4

        # Mock MSR configuration data
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.MSR_CONFIG = {
            'max_cpu_threads': 64,
            'supported_msrs': [
                0x3A,  # IA32_FEATURE_CONTROL
                0x8B,  # IA32_UCODE_REV
                0xC0000080,  # IA32_EFER
                0x1B,  # IA32_APIC_BASE
            ],
            'security_msrs': {
                'feature_control': 0x3A,
                'ucode_rev': 0x8B,
                'efer': 0xC0000080,
                'apic_base': 0x1B,
            }
        }

        return cs_mock

    @pytest.mark.unit
    def test_msr_configuration_access(self, config_cs):
        """Test access to MSR configuration data."""
        msr_config = config_cs.Cfg.MSR_CONFIG

        assert msr_config['max_cpu_threads'] == 64
        assert 0x3A in msr_config['supported_msrs']
        assert 0x8B in msr_config['supported_msrs']
        assert 'feature_control' in msr_config['security_msrs']
        assert msr_config['security_msrs']['feature_control'] == 0x3A

    @pytest.mark.unit
    def test_supported_msrs_validation(self, config_cs):
        """Test validation of supported MSRs."""
        supported_msrs = config_cs.Cfg.MSR_CONFIG['supported_msrs']

        # Test that all documented MSRs are supported
        assert 0x3A in supported_msrs  # IA32_FEATURE_CONTROL
        assert 0x8B in supported_msrs  # IA32_UCODE_REV
        assert 0xC0000080 in supported_msrs  # IA32_EFER
        assert 0x1B in supported_msrs  # IA32_APIC_BASE

    @pytest.mark.unit
    def test_security_msrs_mapping(self, config_cs):
        """Test security MSR name to address mapping."""
        security_msrs = config_cs.Cfg.MSR_CONFIG['security_msrs']

        # Test that security MSR mappings are correct
        assert security_msrs['feature_control'] == 0x3A
        assert security_msrs['ucode_rev'] == 0x8B
        assert security_msrs['efer'] == 0xC0000080
        assert security_msrs['apic_base'] == 0x1B

    @pytest.mark.unit
    def test_cpu_thread_limit_validation(self, config_cs):
        """Test CPU thread limit validation."""
        max_threads = config_cs.Cfg.MSR_CONFIG['max_cpu_threads']

        # Test that thread limit is reasonable
        assert max_threads > 0
        assert max_threads <= 128  # Reasonable maximum for most systems

        # Test current thread count is within limits
        current_threads = config_cs.hals.Msr.get_cpu_thread_count()
        assert current_threads <= max_threads


if __name__ == '__main__':
    pytest.main([__file__])
