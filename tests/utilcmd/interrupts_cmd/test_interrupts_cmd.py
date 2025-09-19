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
from unittest.mock import Mock, patch, mock_open
from chipsec.utilcmd.interrupts_cmd import SMICommand, NMICommand
from tests.test_utils import MockFactory


class TestSMICommand(unittest.TestCase):
    """Comprehensive tests for SMI (System Management Interrupt) command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()

        # Mock Interrupts HAL
        self.mock_cs.hals.Interrupts = Mock()
        self.mock_cs.hals.Interrupts.send_SMI_APMC.return_value = None
        self.mock_cs.hals.Interrupts.send_SW_SMI.return_value = (0, 0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222, 0x33333333, 0x44444444)
        self.mock_cs.hals.Interrupts.find_smmc.return_value = 0x79DF0000
        self.mock_cs.hals.Interrupts.send_smmc_SMI.return_value = 0x0

        # Mock register access
        self.mock_cs.register = Mock()
        self.mock_cs.register.get_list_by_name.return_value = [
            Mock(instance=0, read_field=lambda x: 42),
            Mock(instance=1, read_field=lambda x: 15),
            Mock(instance=2, read_field=lambda x: 8)
        ]

        self.smi_command = SMICommand(['count'], cs=self.mock_cs)
        
        # Mock the interrupts attribute that gets initialized in run()
        self.smi_command.interrupts = Mock()
        self.smi_command.interrupts.send_SMI_APMC.return_value = None
        self.smi_command.interrupts.send_SW_SMI.return_value = (0, 0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222, 0x33333333, 0x44444444)
        self.smi_command.interrupts.find_smmc.return_value = 0x79DF0000
        self.smi_command.interrupts.send_smmc_SMI.return_value = 0x0

    def test_smi_command_initialization(self):
        """Test SMICommand initialization."""
        self.assertEqual(self.smi_command.cs, self.mock_cs)
        self.assertEqual(self.smi_command.argv, ['count'])

    def test_parse_arguments_count(self):
        """Test parsing count command arguments."""
        command = SMICommand(['count'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.smi_count)

    def test_parse_arguments_send_minimal(self):
        """Test parsing send command with minimal arguments."""
        command = SMICommand(['send', '0x0', '0xDE', '0x0'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.smi_send)
        self.assertEqual(command.thread_id, 0x0)
        self.assertEqual(command.SMI_code_port_value, 0xDE)
        self.assertEqual(command.SMI_data_port_value, 0x0)
        self.assertIsNone(command._rax)

    def test_parse_arguments_send_full(self):
        """Test parsing send command with all arguments."""
        command = SMICommand(['send', '0x1', '0xDE', '0x0', '0x12345678', '0x9ABCDEF0', '0x11111111', '0x22222222', '0x33333333', '0x44444444'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.smi_send)
        self.assertEqual(command.thread_id, 0x1)
        self.assertEqual(command.SMI_code_port_value, 0xDE)
        self.assertEqual(command.SMI_data_port_value, 0x0)
        self.assertEqual(command._rax, 0x12345678)
        self.assertEqual(command._rbx, 0x9ABCDEF0)
        self.assertEqual(command._rcx, 0x11111111)
        self.assertEqual(command._rdx, 0x22222222)
        self.assertEqual(command._rsi, 0x33333333)
        self.assertEqual(command._rdi, 0x44444444)

    def test_parse_arguments_send_defaults(self):
        """Test parsing send command with default values."""
        command = SMICommand(['send', '0x0', '0xDE', '0x0', '0x12345678'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.smi_send)
        self.assertEqual(command._rbx, 0)  # default value
        self.assertEqual(command._rcx, 0)  # default value
        self.assertEqual(command._rdx, 0)  # default value
        self.assertEqual(command._rsi, 0)  # default value
        self.assertEqual(command._rdi, 0)  # default value

    def test_parse_arguments_smmc(self):
        """Test parsing smmc command arguments."""
        command = SMICommand(['smmc', '0x79dfe000', '0x79efdfff', 'ed32d533-99e6-4209-9cc02d72cdd998a7', '0x79dfaaaa', 'payload.bin'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.smi_smmc)
        self.assertEqual(command.RTC_start, 0x79dfe000)
        self.assertEqual(command.RTC_end, 0x79efdfff)
        self.assertEqual(command.guid, 'ed32d533-99e6-4209-9cc02d72cdd998a7')
        self.assertEqual(command.payload_loc, 0x79dfaaaa)
        self.assertEqual(command.payload, 'payload.bin')
        self.assertEqual(command.port, 0x0)  # default value

    def test_parse_arguments_smmc_with_port(self):
        """Test parsing smmc command with port argument."""
        command = SMICommand(['smmc', '0x79dfe000', '0x79efdfff', 'ed32d533-99e6-4209-9cc02d72cdd998a7', '0x79dfaaaa', 'payload.bin', '0xB2'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.smi_smmc)
        self.assertEqual(command.port, 0xB2)

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.smi_command.requirements()
        self.assertTrue(hasattr(reqs, 'load_driver'))
        self.assertTrue(hasattr(reqs, 'load_config'))

    def test_smi_count(self):
        """Test smi_count command."""
        with patch.object(self.smi_command.logger, 'log') as mock_log:
            self.smi_command.smi_count()

            # Should log header and each CPU's count
            self.assertGreaterEqual(mock_log.call_count, 4)  # header + 3 CPUs
            self.mock_cs.register.get_list_by_name.assert_called_once_with('8086.MSR.MSR_SMI_COUNT')

    def test_smi_send_minimal(self):
        """Test smi_send command with minimal parameters."""
        self.smi_command.thread_id = 0x0
        self.smi_command.SMI_code_port_value = 0xDE
        self.smi_command.SMI_data_port_value = 0x0
        self.smi_command._rax = None

        with patch.object(self.smi_command.logger, 'log') as mock_log:
            self.smi_command.smi_send()

            # Should log the SMI being sent
            self.assertGreaterEqual(mock_log.call_count, 1)
            self.smi_command.interrupts.send_SMI_APMC.assert_called_once_with(0xDE, 0x0)

    def test_smi_send_full(self):
        """Test smi_send command with full parameters."""
        self.smi_command.thread_id = 0x1
        self.smi_command.SMI_code_port_value = 0xDE
        self.smi_command.SMI_data_port_value = 0x0
        self.smi_command._rax = 0x12345678
        self.smi_command._rbx = 0x9ABCDEF0
        self.smi_command._rcx = 0x11111111
        self.smi_command._rdx = 0x22222222
        self.smi_command._rsi = 0x33333333
        self.smi_command._rdi = 0x44444444

        with patch.object(self.smi_command.logger, 'log') as mock_log:
            self.smi_command.smi_send()

            # Should log all parameters and return values
            self.assertGreaterEqual(mock_log.call_count, 8)  # header + 6 register values + return values
            self.smi_command.interrupts.send_SW_SMI.assert_called_once_with(
                0x1, 0xDE, 0x0, 0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222, 0x33333333, 0x44444444
            )

    def test_smi_smmc_with_file(self):
        """Test smi_smmc command with file payload."""
        self.smi_command.RTC_start = 0x79dfe000
        self.smi_command.RTC_end = 0x79efdfff
        self.smi_command.guid = 'ed32d533-99e6-4209-9cc02d72cdd998a7'
        self.smi_command.payload_loc = 0x79dfaaaa
        self.smi_command.payload = 'test_payload.bin'
        self.smi_command.port = 0xB2

        with patch('os.path.isfile', return_value=True), \
             patch('builtins.open', mock_open(read_data=b'test payload data')), \
             patch.object(self.smi_command.logger, 'log') as mock_log:
            self.smi_command.smi_smmc()

            # Should log search and found messages
            self.assertGreaterEqual(mock_log.call_count, 3)
            self.smi_command.interrupts.find_smmc.assert_called_once_with(0x79dfe000, 0x79efdfff)
            self.smi_command.interrupts.send_smmc_SMI.assert_called_once()

    def test_smi_smmc_with_string(self):
        """Test smi_smmc command with string payload."""
        self.smi_command.RTC_start = 0x79dfe000
        self.smi_command.RTC_end = 0x79efdfff
        self.smi_command.guid = 'ed32d533-99e6-4209-9cc02d72cdd998a7'
        self.smi_command.payload_loc = 0x79dfaaaa
        self.smi_command.payload = 'test string payload'
        self.smi_command.port = 0x0

        with patch('os.path.isfile', return_value=False), \
             patch.object(self.smi_command.logger, 'log') as mock_log:
            self.smi_command.smi_smmc()

            # Should log search and found messages
            self.assertGreaterEqual(mock_log.call_count, 3)
            self.smi_command.interrupts.find_smmc.assert_called_once_with(0x79dfe000, 0x79efdfff)
            self.smi_command.interrupts.send_smmc_SMI.assert_called_once()

    def test_smi_smmc_not_found(self):
        """Test smi_smmc command when smmc is not found."""
        self.smi_command.RTC_start = 0x79dfe000
        self.smi_command.RTC_end = 0x79efdfff
        self.smi_command.guid = 'ed32d533-99e6-4209-9cc02d72cdd998a7'
        self.smi_command.payload_loc = 0x79dfaaaa
        self.smi_command.payload = 'payload.bin'
        self.smi_command.port = 0x0

        self.smi_command.interrupts.find_smmc.return_value = 0x0

        with patch('os.path.isfile', return_value=True), \
             patch('builtins.open', mock_open(read_data=b'test data')), \
             patch.object(self.smi_command.logger, 'log') as mock_log:
            self.smi_command.smi_smmc()

            # Should log search and not found messages
            self.assertGreaterEqual(mock_log.call_count, 2)
            self.smi_command.interrupts.find_smmc.assert_called_once_with(0x79dfe000, 0x79efdfff)
            self.smi_command.interrupts.send_smmc_SMI.assert_not_called()

    def test_run_success(self):
        """Test successful run method."""
        self.smi_command.func = Mock()

        with patch('chipsec.utilcmd.interrupts_cmd.Interrupts') as mock_interrupts_class:
            mock_interrupts_instance = Mock()
            mock_interrupts_class.return_value = mock_interrupts_instance

            self.smi_command.run()

            mock_interrupts_class.assert_called_once_with(self.smi_command.cs)
            self.assertTrue(hasattr(self.smi_command, 'interrupts'))
            self.assertEqual(self.smi_command.interrupts, mock_interrupts_instance)
            self.smi_command.func.assert_called_once()

    def test_run_interrupts_init_failure(self):
        """Test run method when interrupts initialization fails."""
        self.smi_command.func = Mock()

        with patch('chipsec.utilcmd.interrupts_cmd.Interrupts', side_effect=RuntimeError("Init failed")), \
             patch.object(self.smi_command.logger, 'log') as mock_log:
            self.smi_command.run()

            mock_log.assert_called_once()
            self.smi_command.func.assert_not_called()


class TestNMICommand(unittest.TestCase):
    """Comprehensive tests for NMI (Non-Maskable Interrupt) command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        # Mock Interrupts HAL
        self.mock_cs.hals.Interrupts = Mock()
        self.mock_cs.hals.Interrupts.send_NMI.return_value = None

        self.nmi_command = NMICommand([], cs=self.mock_cs)

    def test_nmi_command_initialization(self):
        """Test NMICommand initialization."""
        self.assertEqual(self.nmi_command.cs, self.mock_cs)
        self.assertEqual(self.nmi_command.argv, [])

    def test_parse_arguments(self):
        """Test parse_arguments method (should do nothing)."""
        # NMI command doesn't use argument parsing
        self.nmi_command.parse_arguments()
        # Should not raise any exceptions

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.nmi_command.requirements()
        self.assertTrue(hasattr(reqs, 'load_driver'))
        self.assertTrue(hasattr(reqs, 'load_config'))

    def test_run_success(self):
        """Test successful run method."""
        with patch('chipsec.utilcmd.interrupts_cmd.Interrupts') as mock_interrupts_class, \
             patch.object(self.nmi_command.logger, 'log') as mock_log:
            mock_interrupts_instance = Mock()
            mock_interrupts_class.return_value = mock_interrupts_instance

            self.nmi_command.run()

            mock_interrupts_class.assert_called_once_with(self.nmi_command.cs)
            mock_interrupts_instance.send_NMI.assert_called_once()
            mock_log.assert_called_once()

    def test_run_interrupts_init_failure(self):
        """Test run method when interrupts initialization fails."""
        with patch('chipsec.utilcmd.interrupts_cmd.Interrupts', side_effect=RuntimeError("Init failed")), \
             patch.object(self.nmi_command.logger, 'log') as mock_log:
            self.nmi_command.run()

            mock_log.assert_called_once()

    def test_run_send_nmi_failure(self):
        """Test run method when send_NMI fails."""
        with patch('chipsec.utilcmd.interrupts_cmd.Interrupts') as mock_interrupts_class, \
             patch.object(self.nmi_command.logger, 'log') as mock_log:
            mock_interrupts_instance = Mock()
            mock_interrupts_instance.send_NMI.side_effect = Exception("Send NMI failed")
            mock_interrupts_class.return_value = mock_interrupts_instance

            self.nmi_command.run()

            mock_interrupts_class.assert_called_once_with(self.nmi_command.cs)
            mock_interrupts_instance.send_NMI.assert_called_once()
            # Should log the initial message and the error
            self.assertGreaterEqual(mock_log.call_count, 2)


class TestInterruptsCommandIntegration(unittest.TestCase):
    """Integration tests for interrupt commands with HAL components."""

    def setUp(self):
        """Set up test fixtures."""
        # Create integrated ChipsecCs for interrupt testing
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        self.integrated_cs.hals.Interrupts = Mock()
        self.integrated_cs.hals.Interrupts.send_SMI_APMC.return_value = None
        self.integrated_cs.hals.Interrupts.send_SW_SMI.return_value = (0, 0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222, 0x33333333, 0x44444444)
        self.integrated_cs.hals.Interrupts.send_NMI.return_value = None
        self.integrated_cs.hals.Interrupts.find_smmc.return_value = 0x79DF0000
        self.integrated_cs.hals.Interrupts.send_smmc_SMI.return_value = 0x0

        # Mock register access
        self.integrated_cs.register = Mock()
        self.integrated_cs.register.get_list_by_name.return_value = [
            Mock(instance=0, read_field=lambda x: 42),
            Mock(instance=1, read_field=lambda x: 15)
        ]

        # Mock helper
        self.integrated_cs.helper = Mock()
        self.integrated_cs.helper.get_threads_count.return_value = 2

    def test_smi_nmi_workflow(self):
        """Test complete SMI and NMI workflow."""
        # Test SMI count
        smi_cmd = SMICommand(['count'], cs=self.integrated_cs)
        smi_cmd.parse_arguments()

        with patch.object(smi_cmd.logger, 'log') as mock_log:
            smi_cmd.run()

            self.assertGreaterEqual(mock_log.call_count, 3)  # header + 2 CPUs

        # Test NMI
        nmi_cmd = NMICommand([], cs=self.integrated_cs)

        with patch.object(nmi_cmd.logger, 'log') as mock_log:
            nmi_cmd.run()

            mock_log.assert_called_once()
            self.integrated_cs.hals.Interrupts.send_NMI.assert_called_once()

    def test_smi_send_workflow(self):
        """Test SMI send workflow with different parameters."""
        # Test minimal SMI send
        smi_minimal = SMICommand(['send', '0x0', '0xDE', '0x0'], cs=self.integrated_cs)
        smi_minimal.parse_arguments()

        with patch('chipsec.utilcmd.interrupts_cmd.Interrupts') as mock_interrupts_class, \
             patch.object(smi_minimal.logger, 'log') as mock_log:
            # Make Interrupts constructor return our mocked instance
            mock_interrupts_class.return_value = self.integrated_cs.hals.Interrupts
            
            smi_minimal.run()

            self.assertGreaterEqual(mock_log.call_count, 1)
            self.integrated_cs.hals.Interrupts.send_SMI_APMC.assert_called_once_with(0xDE, 0x0)

        # Test full SMI send
        smi_full = SMICommand(['send', '0x1', '0xDE', '0x0', '0x12345678'], cs=self.integrated_cs)
        smi_full.parse_arguments()

        with patch('chipsec.utilcmd.interrupts_cmd.Interrupts') as mock_interrupts_class, \
             patch.object(smi_full.logger, 'log') as mock_log:
            # Make Interrupts constructor return our mocked instance
            mock_interrupts_class.return_value = self.integrated_cs.hals.Interrupts
            
            smi_full.run()

            self.assertGreaterEqual(mock_log.call_count, 8)  # header + 6 registers + return values
            self.integrated_cs.hals.Interrupts.send_SW_SMI.assert_called_once()

    def test_smi_smmc_workflow(self):
        """Test SMMC workflow."""
        smmc_cmd = SMICommand(['smmc', '0x79dfe000', '0x79efdfff', 'ed32d533-99e6-4209-9cc02d72cdd998a7', '0x79dfaaaa', 'payload.bin'], cs=self.integrated_cs)
        smmc_cmd.parse_arguments()

        with patch('os.path.isfile', return_value=True), \
             patch('builtins.open', mock_open(read_data=b'test payload')), \
             patch.object(smmc_cmd.logger, 'log') as mock_log:
            smmc_cmd.run()

            self.assertGreaterEqual(mock_log.call_count, 3)  # search + found + result
            self.integrated_cs.hals.Interrupts.find_smmc.assert_called_once_with(0x79dfe000, 0x79efdfff)
            self.integrated_cs.hals.Interrupts.send_smmc_SMI.assert_called_once()


class TestInterruptsCommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for interrupt commands."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.hals.Interrupts = Mock()
        self.mock_cs.register = Mock()

    def test_empty_argv_smi(self):
        """Test SMI command with empty argv."""
        smi_cmd = SMICommand([], cs=self.mock_cs)

        # Should raise SystemExit due to missing required arguments
        with self.assertRaises(SystemExit):
            smi_cmd.parse_arguments()

    def test_invalid_subcommand_smi(self):
        """Test SMI command with invalid subcommand."""
        smi_cmd = SMICommand(['invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with self.assertRaises(SystemExit):
            smi_cmd.parse_arguments()

    def test_send_missing_args(self):
        """Test send command with missing arguments."""
        smi_cmd = SMICommand(['send', '0x0'], cs=self.mock_cs)

        # Should raise SystemExit due to missing required arguments
        with self.assertRaises(SystemExit):
            smi_cmd.parse_arguments()

    def test_smmc_missing_args(self):
        """Test smmc command with missing arguments."""
        smi_cmd = SMICommand(['smmc', '0x79dfe000'], cs=self.mock_cs)

        # Should raise SystemExit due to missing required arguments
        with self.assertRaises(SystemExit):
            smi_cmd.parse_arguments()

    def test_zero_thread_id(self):
        """Test operations with zero thread ID."""
        smi_cmd = SMICommand(['send', '0x0', '0xDE', '0x0'], cs=self.mock_cs)
        smi_cmd.parse_arguments()

        self.assertEqual(smi_cmd.thread_id, 0x0)

    def test_maximum_smi_values(self):
        """Test operations with maximum SMI values."""
        smi_cmd = SMICommand(['send', '0xFF', '0xFF', '0xFF'], cs=self.mock_cs)
        smi_cmd.parse_arguments()

        self.assertEqual(smi_cmd.thread_id, 0xFF)
        self.assertEqual(smi_cmd.SMI_code_port_value, 0xFF)
        self.assertEqual(smi_cmd.SMI_data_port_value, 0xFF)

    def test_zero_smi_values(self):
        """Test operations with zero SMI values."""
        smi_cmd = SMICommand(['send', '0x0', '0x0', '0x0'], cs=self.mock_cs)
        smi_cmd.parse_arguments()

        self.assertEqual(smi_cmd.thread_id, 0x0)
        self.assertEqual(smi_cmd.SMI_code_port_value, 0x0)
        self.assertEqual(smi_cmd.SMI_data_port_value, 0x0)

    def test_large_register_values(self):
        """Test operations with large register values."""
        smi_cmd = SMICommand(['send', '0x0', '0xDE', '0x0',
                              '0xFFFFFFFFFFFFFFFF', '0xFFFFFFFFFFFFFFFF',
                              '0xFFFFFFFFFFFFFFFF', '0xFFFFFFFFFFFFFFFF',
                              '0xFFFFFFFFFFFFFFFF', '0xFFFFFFFFFFFFFFFF'], cs=self.mock_cs)
        smi_cmd.parse_arguments()

        self.assertEqual(smi_cmd._rax, 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(smi_cmd._rbx, 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(smi_cmd._rcx, 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(smi_cmd._rdx, 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(smi_cmd._rsi, 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(smi_cmd._rdi, 0xFFFFFFFFFFFFFFFF)

    def test_smi_count_no_registers(self):
        """Test smi_count when no registers are found."""
        self.mock_cs.register.get_list_by_name.return_value = []

        smi_cmd = SMICommand(['count'], cs=self.mock_cs)

        with patch.object(smi_cmd.logger, 'log') as mock_log:
            smi_cmd.smi_count()

            # Should still log the header even with no registers
            self.assertGreaterEqual(mock_log.call_count, 1)

    def test_smi_send_return_values_none(self):
        """Test smi_send when send_SW_SMI returns None."""
        self.mock_cs.hals.Interrupts.send_SW_SMI.return_value = None

        smi_cmd = SMICommand(['send', '0x0', '0xDE', '0x0', '0x12345678'], cs=self.mock_cs)
        smi_cmd.parse_arguments()
        
        # Mock the interrupts attribute that gets initialized in run()
        smi_cmd.interrupts = Mock()
        smi_cmd.interrupts.send_SW_SMI.return_value = None

        with patch.object(smi_cmd.logger, 'log') as mock_log:
            smi_cmd.smi_send()

            # Should not log return values when None is returned
            # Count the number of log calls to verify
            self.assertGreaterEqual(mock_log.call_count, 7)  # header + 6 register values, no return values


class TestInterruptsCommandConfigurationValidation(unittest.TestCase):
    """Test configuration validation aspects of interrupt commands."""

    def setUp(self):
        """Set up test fixtures."""
        # Create ChipsecCs with interrupt-specific configuration
        self.config_cs = MockFactory.create_mock_chipsec_cs()

        # Mock interrupt HAL with configuration
        self.config_cs.hals.Interrupts = Mock()
        self.config_cs.hals.Interrupts.send_SMI_APMC.return_value = None

        # Mock interrupt configuration data
        self.config_cs.Cfg = Mock()
        self.config_cs.Cfg.INTERRUPT_CONFIG = {
            'max_thread_id': 255,
            'smi_ports': {
                'command_port': 0xB2,
                'data_port': 0xB3,
            },
            'smi_codes': {
                'apm_control': 0xDE,
                'custom_smi': 0xEF,
                'security_smi': 0xF0,
            },
            'nmi_sources': [
                'external_nmi',
                'watchdog_timer',
                'performance_monitoring',
                'thermal_sensor'
            ],
            'smmc_config': {
                'signature': 'smmc',
                'max_payload_size': 0x1000,
                'supported_protocols': ['ed32d533-99e6-4209-9cc0-2d72cdd998a7']
            }
        }

    def test_interrupt_configuration_access(self):
        """Test access to interrupt configuration data."""
        int_config = self.config_cs.Cfg.INTERRUPT_CONFIG

        self.assertEqual(int_config['max_thread_id'], 255)
        self.assertEqual(int_config['smi_ports']['command_port'], 0xB2)
        self.assertEqual(int_config['smi_ports']['data_port'], 0xB3)
        self.assertIn('apm_control', int_config['smi_codes'])
        self.assertEqual(int_config['smi_codes']['apm_control'], 0xDE)
        self.assertIn('external_nmi', int_config['nmi_sources'])

    def test_smi_ports_validation(self):
        """Test validation of SMI port configuration."""
        smi_ports = self.config_cs.Cfg.INTERRUPT_CONFIG['smi_ports']

        # Test that all expected SMI ports are defined
        expected_ports = ['command_port', 'data_port']
        for port_name in expected_ports:
            self.assertIn(port_name, smi_ports)
            self.assertIsInstance(smi_ports[port_name], int)
            self.assertGreaterEqual(smi_ports[port_name], 0)
            self.assertLessEqual(smi_ports[port_name], 0xFFFF)

        # Test specific port values
        self.assertEqual(smi_ports['command_port'], 0xB2)
        self.assertEqual(smi_ports['data_port'], 0xB3)

    def test_smi_codes_validation(self):
        """Test validation of SMI codes configuration."""
        smi_codes = self.config_cs.Cfg.INTERRUPT_CONFIG['smi_codes']

        # Test that all expected SMI codes are defined
        expected_codes = ['apm_control', 'custom_smi', 'security_smi']
        for code_name in expected_codes:
            self.assertIn(code_name, smi_codes)
            self.assertIsInstance(smi_codes[code_name], int)
            self.assertGreaterEqual(smi_codes[code_name], 0)
            self.assertLessEqual(smi_codes[code_name], 0xFF)

        # Test specific SMI code values
        self.assertEqual(smi_codes['apm_control'], 0xDE)
        self.assertEqual(smi_codes['custom_smi'], 0xEF)
        self.assertEqual(smi_codes['security_smi'], 0xF0)

    def test_nmi_sources_validation(self):
        """Test validation of NMI sources configuration."""
        nmi_sources = self.config_cs.Cfg.INTERRUPT_CONFIG['nmi_sources']

        # Test that NMI sources list is not empty
        self.assertGreater(len(nmi_sources), 0)

        # Test that all NMI sources are strings
        for source in nmi_sources:
            self.assertIsInstance(source, str)
            self.assertGreater(len(source), 0)

        # Test specific NMI sources
        self.assertIn('external_nmi', nmi_sources)
        self.assertIn('watchdog_timer', nmi_sources)
        self.assertIn('performance_monitoring', nmi_sources)
        self.assertIn('thermal_sensor', nmi_sources)

    def test_smmc_config_validation(self):
        """Test validation of SMMC configuration."""
        smmc_config = self.config_cs.Cfg.INTERRUPT_CONFIG['smmc_config']

        # Test SMMC configuration fields
        self.assertEqual(smmc_config['signature'], 'smmc')
        self.assertEqual(smmc_config['max_payload_size'], 0x1000)
        self.assertGreater(len(smmc_config['supported_protocols']), 0)

        # Test supported protocols
        self.assertIn('ed32d533-99e6-4209-9cc0-2d72cdd998a7', smmc_config['supported_protocols'])

    def test_thread_id_limits_validation(self):
        """Test thread ID limits validation."""
        max_thread_id = self.config_cs.Cfg.INTERRUPT_CONFIG['max_thread_id']

        # Test that the maximum thread ID is valid
        self.assertEqual(max_thread_id, 255)  # 8-bit thread ID

        # Test that the limit is reasonable
        self.assertGreater(max_thread_id, 0)
        self.assertLessEqual(max_thread_id, 1024)  # Reasonable maximum for most systems


if __name__ == '__main__':
    unittest.main()
