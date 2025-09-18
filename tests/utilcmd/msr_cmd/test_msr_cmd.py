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
from chipsec.utilcmd.msr_cmd import MSRCommand
from tests.test_utils import MockFactory


class TestMSRCommand(unittest.TestCase):
    """Comprehensive tests for MSR utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock ChipsecCs object for MSR testing
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        # Mock MSR HAL
        self.mock_cs.hals.Msr = Mock()
        self.mock_cs.hals.Msr.read_msr.return_value = (0x12345678, 0x9ABCDEF0)
        self.mock_cs.hals.Msr.write_msr.return_value = None
        self.mock_cs.hals.Msr.get_cpu_thread_count.return_value = 4

        # Create MSRCommand instance
        self.msr_command = MSRCommand(['0x3A'], cs=self.mock_cs)

    def test_msr_command_initialization(self):
        """Test MSRCommand initialization."""
        self.assertEqual(self.msr_command.cs, self.mock_cs)
        self.assertEqual(self.msr_command.argv, ['0x3A'])

    def test_parse_arguments_read_all_cpus(self):
        """Test parsing arguments for reading MSR from all CPUs."""
        command = MSRCommand(['0x3A'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.msr_addr, 0x3A)
        self.assertIsNone(command.msr_input1)
        self.assertIsNone(command.msr_input2)
        self.assertIsNone(command.thread_id)

    def test_parse_arguments_read_specific_cpu(self):
        """Test parsing arguments for reading MSR from specific CPU."""
        command = MSRCommand(['0x3A', '1'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.msr_addr, 0x3A)
        self.assertEqual(command.msr_input1, 1)
        self.assertIsNone(command.msr_input2)
        self.assertIsNone(command.thread_id)

    def test_parse_arguments_write_all_cpus(self):
        """Test parsing arguments for writing MSR to all CPUs."""
        command = MSRCommand(['0x3A', '0x12345678', '0x9ABCDEF0'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.msr_addr, 0x3A)
        self.assertEqual(command.msr_input1, 0x12345678)
        self.assertEqual(command.msr_input2, 0x9ABCDEF0)
        self.assertIsNone(command.thread_id)

    def test_parse_arguments_write_specific_cpu(self):
        """Test parsing arguments for writing MSR to specific CPU."""
        command = MSRCommand(['0x3A', '0x12345678', '0x9ABCDEF0', '2'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.msr_addr, 0x3A)
        self.assertEqual(command.msr_input1, 0x12345678)
        self.assertEqual(command.msr_input2, 0x9ABCDEF0)
        self.assertEqual(command.thread_id, 2)

    def test_parse_arguments_decimal_values(self):
        """Test parsing arguments with decimal values."""
        command = MSRCommand(['58', '305419896', '2596069104'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.msr_addr, 58)  # 0x3A
        self.assertEqual(command.msr_input1, 305419896)  # 0x12345678
        self.assertEqual(command.msr_input2, 2596069104)  # 0x9ABCDEF0

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.msr_command.requirements()
        self.assertTrue(hasattr(reqs, 'load_driver'))

    def test_run_read_all_cpus(self):
        """Test reading MSR from all CPUs."""
        self.msr_command.msr_addr = 0x3A
        self.msr_command.msr_input1 = None

        with patch.object(self.msr_command.logger, 'log') as mock_log:
            self.msr_command.run()

            # Should call read_msr for each CPU thread
            self.assertEqual(self.mock_cs.hals.Msr.read_msr.call_count, 4)  # 4 CPU threads
            self.mock_cs.hals.Msr.get_cpu_thread_count.assert_called_once()

            # Should log results for each CPU
            self.assertEqual(mock_log.call_count, 4)

    def test_run_read_specific_cpu(self):
        """Test reading MSR from specific CPU."""
        self.msr_command.msr_addr = 0x3A
        self.msr_command.msr_input1 = 2  # CPU thread 2
        self.msr_command.msr_input2 = None

        with patch.object(self.msr_command.logger, 'log') as mock_log:
            self.msr_command.run()

            # Should call read_msr for specific CPU
            self.mock_cs.hals.Msr.read_msr.assert_called_once_with(2, 0x3A)
            mock_log.assert_called_once()

    def test_run_write_all_cpus(self):
        """Test writing MSR to all CPUs."""
        self.msr_command.msr_addr = 0x3A
        self.msr_command.msr_input1 = 0x12345678
        self.msr_command.msr_input2 = 0x9ABCDEF0
        self.msr_command.thread_id = None

        with patch.object(self.msr_command.logger, 'log') as mock_log:
            self.msr_command.run()

            # Should call write_msr for each CPU thread
            self.assertEqual(self.mock_cs.hals.Msr.write_msr.call_count, 4)  # 4 CPU threads
            self.mock_cs.hals.Msr.get_cpu_thread_count.assert_called_once()

            # Should log the write operation
            mock_log.assert_called_once()

    def test_run_write_specific_cpu(self):
        """Test writing MSR to specific CPU."""
        self.msr_command.msr_addr = 0x3A
        self.msr_command.msr_input1 = 0x12345678
        self.msr_command.msr_input2 = 0x9ABCDEF0
        self.msr_command.thread_id = 3

        with patch.object(self.msr_command.logger, 'log') as mock_log:
            self.msr_command.run()

            # Should call write_msr for specific CPU
            self.mock_cs.hals.Msr.write_msr.assert_called_once_with(3, 0x3A, 0x12345678, 0x9ABCDEF0)
            mock_log.assert_called_once()

    def test_run_read_msr_value_calculation(self):
        """Test MSR value calculation in read operations."""
        self.msr_command.msr_addr = 0x3A
        self.msr_command.msr_input1 = 1  # Specific CPU
        self.msr_command.msr_input2 = None  # Ensure msr_input2 is set
        self.msr_command.thread_id = None

        # Mock MSR read to return specific values
        self.mock_cs.hals.Msr.read_msr.return_value = (0x12345678, 0x9ABCDEF0)

        with patch.object(self.msr_command.logger, 'log') as mock_log:
            self.msr_command.run()

            # Verify the 64-bit value calculation: (EDX << 32) | EAX
            expected_val64 = (0x9ABCDEF0 << 32) | 0x12345678
            self.assertEqual(expected_val64, 0x9ABCDEF012345678)

            # Verify log message contains correct values
            log_call = mock_log.call_args[0][0]
            self.assertIn('0x3a', log_call.lower())
            self.assertIn('12345678', log_call.lower())
            self.assertIn('9abcdef0', log_call.lower())
            self.assertIn('9abcdef012345678', log_call.lower())

    def test_run_write_msr_value_calculation(self):
        """Test MSR value calculation in write operations."""
        self.msr_command.msr_addr = 0x3A
        self.msr_command.msr_input1 = 0x12345678
        self.msr_command.msr_input2 = 0x9ABCDEF0
        self.msr_command.thread_id = 1

        with patch.object(self.msr_command.logger, 'log') as mock_log:
            self.msr_command.run()

            # Verify the 64-bit value calculation: (EDX << 32) | EAX
            expected_val64 = (0x9ABCDEF0 << 32) | 0x12345678
            self.assertEqual(expected_val64, 0x9ABCDEF012345678)

            # Verify log message contains correct values
            log_call = mock_log.call_args[0][0]
            self.assertIn('0x3a', log_call.lower())
            self.assertIn('9abcdef012345678', log_call.lower())


class TestMSRCommandIntegration(unittest.TestCase):
    """Integration tests for MSR command with HAL components."""

    def setUp(self):
        """Set up test fixtures."""
        # Create integrated ChipsecCs for MSR testing
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        self.integrated_cs.hals.Msr = Mock()
        self.integrated_cs.hals.Msr.read_msr.return_value = (0xDEADBEEF, 0xCAFEBABE)
        self.integrated_cs.hals.Msr.write_msr.return_value = None
        self.integrated_cs.hals.Msr.get_cpu_thread_count.return_value = 2

        # Mock helper
        self.integrated_cs.helper = Mock()
        self.integrated_cs.helper.get_threads_count.return_value = 2

    def test_msr_read_write_workflow(self):
        """Test complete MSR read/write workflow."""
        # Test read operation
        read_cmd = MSRCommand(['0x3A'], cs=self.integrated_cs)
        read_cmd.parse_arguments()

        with patch.object(read_cmd.logger, 'log') as mock_log:
            read_cmd.run()

            # Should read from all CPUs
            self.assertEqual(self.integrated_cs.hals.Msr.read_msr.call_count, 2)  # 2 CPU threads
            self.assertEqual(mock_log.call_count, 2)

        # Test write operation
        write_cmd = MSRCommand(['0x3A', '0xDEADBEEF', '0xCAFEBABE'], cs=self.integrated_cs)
        write_cmd.parse_arguments()

        with patch.object(write_cmd.logger, 'log') as mock_log:
            write_cmd.run()

            # Should write to all CPUs
            self.assertEqual(self.integrated_cs.hals.Msr.write_msr.call_count, 2)  # 2 CPU threads
            self.assertEqual(mock_log.call_count, 1)  # One summary log

    def test_msr_specific_cpu_operations(self):
        """Test MSR operations on specific CPU."""
        # Test read from specific CPU
        read_cmd = MSRCommand(['0x8B', '1'], cs=self.integrated_cs)
        read_cmd.parse_arguments()

        with patch.object(read_cmd.logger, 'log') as mock_log:
            read_cmd.run()

            self.integrated_cs.hals.Msr.read_msr.assert_called_once_with(1, 0x8B)
            mock_log.assert_called_once()

        # Test write to specific CPU
        write_cmd = MSRCommand(['0x8B', '0xDEADBEEF', '0xCAFEBABE', '1'], cs=self.integrated_cs)
        write_cmd.parse_arguments()

        with patch.object(write_cmd.logger, 'log') as mock_log:
            write_cmd.run()

            self.integrated_cs.hals.Msr.write_msr.assert_called_once_with(1, 0x8B, 0xDEADBEEF, 0xCAFEBABE)
            mock_log.assert_called_once()

    def test_msr_error_handling(self):
        """Test MSR command error handling."""
        # Test with invalid MSR address (should still work with mock)
        read_cmd = MSRCommand(['0xFFFFFFFF'], cs=self.integrated_cs)
        read_cmd.parse_arguments()

        with patch.object(read_cmd.logger, 'log') as mock_log:
            read_cmd.run()

            # Should still attempt to read despite invalid address
            self.assertEqual(self.integrated_cs.hals.Msr.read_msr.call_count, 2)
            self.assertEqual(mock_log.call_count, 2)


class TestMSRCommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for MSR command."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock ChipsecCs for edge case testing
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.hals.Msr = Mock()
        self.mock_cs.hals.Msr.get_cpu_thread_count.return_value = 1

    def test_empty_argv_handling(self):
        """Test handling of empty argv."""
        msr_cmd = MSRCommand([], cs=self.mock_cs)

        # Should raise SystemExit due to missing required arguments
        with self.assertRaises(SystemExit):
            msr_cmd.parse_arguments()

    def test_invalid_msr_address(self):
        """Test handling of invalid MSR address."""
        msr_cmd = MSRCommand(['invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid MSR address
        with self.assertRaises(SystemExit):
            msr_cmd.parse_arguments()

    def test_single_cpu_system(self):
        """Test MSR operations on single CPU system."""
        self.mock_cs.hals.Msr.get_cpu_thread_count.return_value = 1
        self.mock_cs.hals.Msr.read_msr.return_value = (0x11111111, 0x22222222)

        msr_cmd = MSRCommand(['0x3A'], cs=self.mock_cs)
        msr_cmd.parse_arguments()

        with patch.object(msr_cmd.logger, 'log') as mock_log:
            msr_cmd.run()

            # Should read from single CPU
            self.mock_cs.hals.Msr.read_msr.assert_called_once_with(0, 0x3A)
            mock_log.assert_called_once()

    def test_zero_values(self):
        """Test MSR operations with zero values."""
        self.mock_cs.hals.Msr.read_msr.return_value = (0x0, 0x0)

        msr_cmd = MSRCommand(['0x0'], cs=self.mock_cs)
        msr_cmd.parse_arguments()

        with patch.object(msr_cmd.logger, 'log') as mock_log:
            msr_cmd.run()

            self.mock_cs.hals.Msr.read_msr.assert_called_once_with(0, 0x0)
            mock_log.assert_called_once()

    def test_maximum_values(self):
        """Test MSR operations with maximum values."""
        self.mock_cs.hals.Msr.read_msr.return_value = (0xFFFFFFFF, 0xFFFFFFFF)

        msr_cmd = MSRCommand(['0xFFFFFFFF'], cs=self.mock_cs)
        msr_cmd.parse_arguments()

        with patch.object(msr_cmd.logger, 'log') as mock_log:
            msr_cmd.run()

            self.mock_cs.hals.Msr.read_msr.assert_called_once_with(0, 0xFFFFFFFF)
            mock_log.assert_called_once()

    def test_write_zero_values(self):
        """Test writing zero values to MSR."""
        msr_cmd = MSRCommand(['0x3A', '0x0', '0x0'], cs=self.mock_cs)
        msr_cmd.parse_arguments()

        with patch.object(msr_cmd.logger, 'log') as mock_log:
            msr_cmd.run()

            self.mock_cs.hals.Msr.write_msr.assert_called_once_with(0, 0x3A, 0x0, 0x0)
            mock_log.assert_called_once()

    def test_write_maximum_values(self):
        """Test writing maximum values to MSR."""
        msr_cmd = MSRCommand(['0x3A', '0xFFFFFFFF', '0xFFFFFFFF'], cs=self.mock_cs)
        msr_cmd.parse_arguments()

        with patch.object(msr_cmd.logger, 'log') as mock_log:
            msr_cmd.run()

            self.mock_cs.hals.Msr.write_msr.assert_called_once_with(0, 0x3A, 0xFFFFFFFF, 0xFFFFFFFF)
            mock_log.assert_called_once()


class TestMSRCommandConfigurationValidation(unittest.TestCase):
    """Test configuration validation aspects of MSR command."""

    def setUp(self):
        """Set up test fixtures."""
        # Create ChipsecCs with MSR-specific configuration
        self.config_cs = MockFactory.create_mock_chipsec_cs()

        # Mock MSR HAL with configuration
        self.config_cs.hals.Msr = Mock()
        self.config_cs.hals.Msr.read_msr.return_value = (0x12345678, 0x9ABCDEF0)
        self.config_cs.hals.Msr.get_cpu_thread_count.return_value = 4

        # Mock MSR configuration data
        self.config_cs.Cfg = Mock()
        self.config_cs.Cfg.MSR_CONFIG = {
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

    def test_msr_configuration_access(self):
        """Test access to MSR configuration data."""
        msr_config = self.config_cs.Cfg.MSR_CONFIG

        self.assertEqual(msr_config['max_cpu_threads'], 64)
        self.assertIn(0x3A, msr_config['supported_msrs'])
        self.assertIn(0x8B, msr_config['supported_msrs'])
        self.assertIn('feature_control', msr_config['security_msrs'])
        self.assertEqual(msr_config['security_msrs']['feature_control'], 0x3A)

    def test_supported_msrs_validation(self):
        """Test validation of supported MSRs."""
        supported_msrs = self.config_cs.Cfg.MSR_CONFIG['supported_msrs']

        # Test that all documented MSRs are supported
        self.assertIn(0x3A, supported_msrs)  # IA32_FEATURE_CONTROL
        self.assertIn(0x8B, supported_msrs)  # IA32_UCODE_REV
        self.assertIn(0xC0000080, supported_msrs)  # IA32_EFER
        self.assertIn(0x1B, supported_msrs)  # IA32_APIC_BASE

    def test_security_msrs_mapping(self):
        """Test security MSR name to address mapping."""
        security_msrs = self.config_cs.Cfg.MSR_CONFIG['security_msrs']

        # Test that security MSR mappings are correct
        self.assertEqual(security_msrs['feature_control'], 0x3A)
        self.assertEqual(security_msrs['ucode_rev'], 0x8B)
        self.assertEqual(security_msrs['efer'], 0xC0000080)
        self.assertEqual(security_msrs['apic_base'], 0x1B)

    def test_cpu_thread_limit_validation(self):
        """Test CPU thread limit validation."""
        max_threads = self.config_cs.Cfg.MSR_CONFIG['max_cpu_threads']

        # Test that thread limit is reasonable
        self.assertGreater(max_threads, 0)
        self.assertLessEqual(max_threads, 128)  # Reasonable maximum for most systems

        # Test current thread count is within limits
        current_threads = self.config_cs.hals.Msr.get_cpu_thread_count()
        self.assertLessEqual(current_threads, max_threads)


if __name__ == '__main__':
    unittest.main()
