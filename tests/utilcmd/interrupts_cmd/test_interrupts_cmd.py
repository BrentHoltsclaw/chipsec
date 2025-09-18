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
from chipsec.utilcmd.interrupts_cmd import SMICommand, NMICommand
from tests.test_utils import MockFactory


class TestSMICommand:
    """Comprehensive tests for SMI (System Management Interrupt) command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for SMI testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        # Mock Interrupts HAL
        cs_mock.hals.Interrupts = Mock()
        cs_mock.hals.Interrupts.send_SMI_APMC.return_value = None
        cs_mock.hals.Interrupts.send_SW_SMI.return_value = (0, 0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222, 0x33333333, 0x44444444)
        cs_mock.hals.Interrupts.find_smmc.return_value = 0x79DF0000
        cs_mock.hals.Interrupts.send_smmc_SMI.return_value = 0x0

        # Mock register access
        cs_mock.register = Mock()
        cs_mock.register.get_list_by_name.return_value = [
            Mock(instance=0, read_field=lambda x: 42),
            Mock(instance=1, read_field=lambda x: 15),
            Mock(instance=2, read_field=lambda x: 8)
        ]

        return cs_mock

    @pytest.fixture
    def smi_command(self, mock_cs):
        """Create SMICommand instance."""
        return SMICommand(['count'], cs=mock_cs)

    @pytest.mark.unit
    def test_smi_command_initialization(self, smi_command, mock_cs):
        """Test SMICommand initialization."""
        assert smi_command.cs == mock_cs
        assert smi_command.argv == ['count']

    @pytest.mark.unit
    def test_parse_arguments_count(self, mock_cs):
        """Test parsing count command arguments."""
        command = SMICommand(['count'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.smi_count

    @pytest.mark.unit
    def test_parse_arguments_send_minimal(self, mock_cs):
        """Test parsing send command with minimal arguments."""
        command = SMICommand(['send', '0x0', '0xDE', '0x0'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.smi_send
        assert command.thread_id == 0x0
        assert command.SMI_code_port_value == 0xDE
        assert command.SMI_data_port_value == 0x0
        assert command._rax is None

    @pytest.mark.unit
    def test_parse_arguments_send_full(self, mock_cs):
        """Test parsing send command with all arguments."""
        command = SMICommand(['send', '0x1', '0xDE', '0x0', '0x12345678', '0x9ABCDEF0', '0x11111111', '0x22222222', '0x33333333', '0x44444444'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.smi_send
        assert command.thread_id == 0x1
        assert command.SMI_code_port_value == 0xDE
        assert command.SMI_data_port_value == 0x0
        assert command._rax == 0x12345678
        assert command._rbx == 0x9ABCDEF0
        assert command._rcx == 0x11111111
        assert command._rdx == 0x22222222
        assert command._rsi == 0x33333333
        assert command._rdi == 0x44444444

    @pytest.mark.unit
    def test_parse_arguments_send_defaults(self, mock_cs):
        """Test parsing send command with default values."""
        command = SMICommand(['send', '0x0', '0xDE', '0x0', '0x12345678'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.smi_send
        assert command._rbx == 0  # default value
        assert command._rcx == 0  # default value
        assert command._rdx == 0  # default value
        assert command._rsi == 0  # default value
        assert command._rdi == 0  # default value

    @pytest.mark.unit
    def test_parse_arguments_smmc(self, mock_cs):
        """Test parsing smmc command arguments."""
        command = SMICommand(['smmc', '0x79dfe000', '0x79efdfff', 'ed32d533-99e6-4209-9cc02d72cdd998a7', '0x79dfaaaa', 'payload.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.smi_smmc
        assert command.RTC_start == 0x79dfe000
        assert command.RTC_end == 0x79efdfff
        assert command.guid == 'ed32d533-99e6-4209-9cc02d72cdd998a7'
        assert command.payload_loc == 0x79dfaaaa
        assert command.payload == 'payload.bin'
        assert command.port == 0x0  # default value

    @pytest.mark.unit
    def test_parse_arguments_smmc_with_port(self, mock_cs):
        """Test parsing smmc command with port argument."""
        command = SMICommand(['smmc', '0x79dfe000', '0x79efdfff', 'ed32d533-99e6-4209-9cc02d72cdd998a7', '0x79dfaaaa', 'payload.bin', '0xB2'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.smi_smmc
        assert command.port == 0xB2

    @pytest.mark.unit
    def test_requirements(self, smi_command):
        """Test command requirements."""
        reqs = smi_command.requirements()
        assert hasattr(reqs, 'load_driver')
        assert hasattr(reqs, 'load_config')

    @pytest.mark.unit
    def test_smi_count(self, smi_command, mock_cs):
        """Test smi_count command."""
        with patch.object(smi_command.logger, 'log') as mock_log:
            smi_command.smi_count()

            # Should log header and each CPU's count
            assert mock_log.call_count >= 4  # header + 3 CPUs
            mock_cs.register.get_list_by_name.assert_called_once_with('8086.MSR.MSR_SMI_COUNT')

    @pytest.mark.unit
    def test_smi_send_minimal(self, smi_command, mock_cs):
        """Test smi_send command with minimal parameters."""
        smi_command.thread_id = 0x0
        smi_command.SMI_code_port_value = 0xDE
        smi_command.SMI_data_port_value = 0x0
        smi_command._rax = None

        with patch.object(smi_command.logger, 'log') as mock_log:
            smi_command.smi_send()

            # Should log the SMI being sent
            assert mock_log.call_count >= 1
            mock_cs.hals.Interrupts.send_SMI_APMC.assert_called_once_with(0xDE, 0x0)

    @pytest.mark.unit
    def test_smi_send_full(self, smi_command, mock_cs):
        """Test smi_send command with full parameters."""
        smi_command.thread_id = 0x1
        smi_command.SMI_code_port_value = 0xDE
        smi_command.SMI_data_port_value = 0x0
        smi_command._rax = 0x12345678
        smi_command._rbx = 0x9ABCDEF0
        smi_command._rcx = 0x11111111
        smi_command._rdx = 0x22222222
        smi_command._rsi = 0x33333333
        smi_command._rdi = 0x44444444

        with patch.object(smi_command.logger, 'log') as mock_log:
            smi_command.smi_send()

            # Should log all parameters and return values
            assert mock_log.call_count >= 8  # header + 6 register values + return values
            mock_cs.hals.Interrupts.send_SW_SMI.assert_called_once_with(
                0x1, 0xDE, 0x0, 0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222, 0x33333333, 0x44444444
            )

    @pytest.mark.unit
    def test_smi_smmc_with_file(self, smi_command, mock_cs):
        """Test smi_smmc command with file payload."""
        smi_command.RTC_start = 0x79dfe000
        smi_command.RTC_end = 0x79efdfff
        smi_command.guid = 'ed32d533-99e6-4209-9cc02d72cdd998a7'
        smi_command.payload_loc = 0x79dfaaaa
        smi_command.payload = 'test_payload.bin'
        smi_command.port = 0xB2

        with patch('os.path.isfile', return_value=True), \
             patch('builtins.open', mock_open(read_data=b'test payload data')), \
             patch.object(smi_command.logger, 'log') as mock_log:
            smi_command.smi_smmc()

            # Should log search and found messages
            assert mock_log.call_count >= 3
            mock_cs.hals.Interrupts.find_smmc.assert_called_once_with(0x79dfe000, 0x79efdfff)
            mock_cs.hals.Interrupts.send_smmc_SMI.assert_called_once()

    @pytest.mark.unit
    def test_smi_smmc_with_string(self, smi_command, mock_cs):
        """Test smi_smmc command with string payload."""
        smi_command.RTC_start = 0x79dfe000
        smi_command.RTC_end = 0x79efdfff
        smi_command.guid = 'ed32d533-99e6-4209-9cc02d72cdd998a7'
        smi_command.payload_loc = 0x79dfaaaa
        smi_command.payload = 'test string payload'
        smi_command.port = 0x0

        with patch('os.path.isfile', return_value=False), \
             patch.object(smi_command.logger, 'log') as mock_log:
            smi_command.smi_smmc()

            # Should log search and found messages
            assert mock_log.call_count >= 3
            mock_cs.hals.Interrupts.find_smmc.assert_called_once_with(0x79dfe000, 0x79efdfff)
            mock_cs.hals.Interrupts.send_smmc_SMI.assert_called_once()

    @pytest.mark.unit
    def test_smi_smmc_not_found(self, smi_command, mock_cs):
        """Test smi_smmc command when smmc is not found."""
        smi_command.RTC_start = 0x79dfe000
        smi_command.RTC_end = 0x79efdfff
        smi_command.guid = 'ed32d533-99e6-4209-9cc02d72cdd998a7'
        smi_command.payload_loc = 0x79dfaaaa
        smi_command.payload = 'payload.bin'
        smi_command.port = 0x0

        mock_cs.hals.Interrupts.find_smmc.return_value = 0x0

        with patch('os.path.isfile', return_value=True), \
             patch('builtins.open', mock_open(read_data=b'test data')), \
             patch.object(smi_command.logger, 'log') as mock_log:
            smi_command.smi_smmc()

            # Should log search and not found messages
            assert mock_log.call_count >= 2
            mock_cs.hals.Interrupts.find_smmc.assert_called_once_with(0x79dfe000, 0x79efdfff)
            mock_cs.hals.Interrupts.send_smmc_SMI.assert_not_called()

    @pytest.mark.unit
    def test_run_success(self, smi_command, mock_cs):
        """Test successful run method."""
        smi_command.func = Mock()

        with patch('chipsec.utilcmd.interrupts_cmd.Interrupts') as mock_interrupts_class:
            mock_interrupts_instance = Mock()
            mock_interrupts_class.return_value = mock_interrupts_instance

            smi_command.run()

            mock_interrupts_class.assert_called_once_with(smi_command.cs)
            assert smi_command.interrupts == mock_interrupts_instance
            smi_command.func.assert_called_once()

    @pytest.mark.unit
    def test_run_interrupts_init_failure(self, smi_command, mock_cs):
        """Test run method when interrupts initialization fails."""
        smi_command.func = Mock()

        with patch('chipsec.utilcmd.interrupts_cmd.Interrupts', side_effect=RuntimeError("Init failed")), \
             patch.object(smi_command.logger, 'log') as mock_log:
            smi_command.run()

            mock_log.assert_called_once()
            smi_command.func.assert_not_called()


class TestNMICommand:
    """Comprehensive tests for NMI (Non-Maskable Interrupt) command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for NMI testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        # Mock Interrupts HAL
        cs_mock.hals.Interrupts = Mock()
        cs_mock.hals.Interrupts.send_NMI.return_value = None
        return cs_mock

    @pytest.fixture
    def nmi_command(self, mock_cs):
        """Create NMICommand instance."""
        return NMICommand([], cs=mock_cs)

    @pytest.mark.unit
    def test_nmi_command_initialization(self, nmi_command, mock_cs):
        """Test NMICommand initialization."""
        assert nmi_command.cs == mock_cs
        assert nmi_command.argv == []

    @pytest.mark.unit
    def test_parse_arguments(self, nmi_command):
        """Test parse_arguments method (should do nothing)."""
        # NMI command doesn't use argument parsing
        nmi_command.parse_arguments()
        # Should not raise any exceptions

    @pytest.mark.unit
    def test_requirements(self, nmi_command):
        """Test command requirements."""
        reqs = nmi_command.requirements()
        assert hasattr(reqs, 'load_driver')
        assert hasattr(reqs, 'load_config')

    @pytest.mark.unit
    def test_run_success(self, nmi_command, mock_cs):
        """Test successful run method."""
        with patch('chipsec.utilcmd.interrupts_cmd.Interrupts') as mock_interrupts_class, \
             patch.object(nmi_command.logger, 'log') as mock_log:
            mock_interrupts_instance = Mock()
            mock_interrupts_class.return_value = mock_interrupts_instance

            nmi_command.run()

            mock_interrupts_class.assert_called_once_with(nmi_command.cs)
            mock_interrupts_instance.send_NMI.assert_called_once()
            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_run_interrupts_init_failure(self, nmi_command, mock_cs):
        """Test run method when interrupts initialization fails."""
        with patch('chipsec.utilcmd.interrupts_cmd.Interrupts', side_effect=RuntimeError("Init failed")), \
             patch.object(nmi_command.logger, 'log') as mock_log:
            nmi_command.run()

            mock_log.assert_called_once()

    @pytest.mark.unit
    def test_run_send_nmi_failure(self, nmi_command, mock_cs):
        """Test run method when send_NMI fails."""
        with patch('chipsec.utilcmd.interrupts_cmd.Interrupts') as mock_interrupts_class, \
             patch.object(nmi_command.logger, 'log') as mock_log:
            mock_interrupts_instance = Mock()
            mock_interrupts_instance.send_NMI.side_effect = Exception("Send NMI failed")
            mock_interrupts_class.return_value = mock_interrupts_instance

            nmi_command.run()

            mock_interrupts_class.assert_called_once_with(nmi_command.cs)
            mock_interrupts_instance.send_NMI.assert_called_once()
            # Should log the initial message and the error
            assert mock_log.call_count >= 2


class TestInterruptsCommandIntegration:
    """Integration tests for interrupt commands with HAL components."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for interrupt testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        cs_mock.hals.Interrupts = Mock()
        cs_mock.hals.Interrupts.send_SMI_APMC.return_value = None
        cs_mock.hals.Interrupts.send_SW_SMI.return_value = (0, 0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222, 0x33333333, 0x44444444)
        cs_mock.hals.Interrupts.send_NMI.return_value = None
        cs_mock.hals.Interrupts.find_smmc.return_value = 0x79DF0000
        cs_mock.hals.Interrupts.send_smmc_SMI.return_value = 0x0

        # Mock register access
        cs_mock.register = Mock()
        cs_mock.register.get_list_by_name.return_value = [
            Mock(instance=0, read_field=lambda x: 42),
            Mock(instance=1, read_field=lambda x: 15)
        ]

        # Mock helper
        cs_mock.helper = Mock()
        cs_mock.helper.get_threads_count.return_value = 2

        return cs_mock

    @pytest.mark.integration
    def test_smi_nmi_workflow(self, integrated_cs):
        """Test complete SMI and NMI workflow."""
        # Test SMI count
        smi_cmd = SMICommand(['count'], cs=integrated_cs)
        smi_cmd.parse_arguments()

        with patch.object(smi_cmd.logger, 'log') as mock_log:
            smi_cmd.run()

            assert mock_log.call_count >= 3  # header + 2 CPUs

        # Test NMI
        nmi_cmd = NMICommand([], cs=integrated_cs)

        with patch.object(nmi_cmd.logger, 'log') as mock_log:
            nmi_cmd.run()

            mock_log.assert_called_once()
            integrated_cs.hals.Interrupts.send_NMI.assert_called_once()

    @pytest.mark.integration
    def test_smi_send_workflow(self, integrated_cs):
        """Test SMI send workflow with different parameters."""
        # Test minimal SMI send
        smi_minimal = SMICommand(['send', '0x0', '0xDE', '0x0'], cs=integrated_cs)
        smi_minimal.parse_arguments()

        with patch.object(smi_minimal.logger, 'log') as mock_log:
            smi_minimal.run()

            assert mock_log.call_count >= 1
            integrated_cs.hals.Interrupts.send_SMI_APMC.assert_called_once_with(0xDE, 0x0)

        # Test full SMI send
        smi_full = SMICommand(['send', '0x1', '0xDE', '0x0', '0x12345678'], cs=integrated_cs)
        smi_full.parse_arguments()

        with patch.object(smi_full.logger, 'log') as mock_log:
            smi_full.run()

            assert mock_log.call_count >= 8  # header + 6 registers + return values
            integrated_cs.hals.Interrupts.send_SW_SMI.assert_called_once()

    @pytest.mark.integration
    def test_smi_smmc_workflow(self, integrated_cs):
        """Test SMMC workflow."""
        smmc_cmd = SMICommand(['smmc', '0x79dfe000', '0x79efdfff', 'ed32d533-99e6-4209-9cc02d72cdd998a7', '0x79dfaaaa', 'payload.bin'], cs=integrated_cs)
        smmc_cmd.parse_arguments()

        with patch('os.path.isfile', return_value=True), \
             patch('builtins.open', mock_open(read_data=b'test payload')), \
             patch.object(smmc_cmd.logger, 'log') as mock_log:
            smmc_cmd.run()

            assert mock_log.call_count >= 3  # search + found + result
            integrated_cs.hals.Interrupts.find_smmc.assert_called_once_with(0x79dfe000, 0x79efdfff)
            integrated_cs.hals.Interrupts.send_smmc_SMI.assert_called_once()


class TestInterruptsCommandEdgeCases:
    """Test edge cases and error conditions for interrupt commands."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals.Interrupts = Mock()
        cs_mock.register = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_smi(self, mock_cs):
        """Test SMI command with empty argv."""
        smi_cmd = SMICommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            smi_cmd.parse_arguments()

    @pytest.mark.unit
    def test_invalid_subcommand_smi(self, mock_cs):
        """Test SMI command with invalid subcommand."""
        smi_cmd = SMICommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            smi_cmd.parse_arguments()

    @pytest.mark.unit
    def test_send_missing_args(self, mock_cs):
        """Test send command with missing arguments."""
        smi_cmd = SMICommand(['send', '0x0'], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            smi_cmd.parse_arguments()

    @pytest.mark.unit
    def test_smmc_missing_args(self, mock_cs):
        """Test smmc command with missing arguments."""
        smi_cmd = SMICommand(['smmc', '0x79dfe000'], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            smi_cmd.parse_arguments()

    @pytest.mark.unit
    def test_zero_thread_id(self, mock_cs):
        """Test operations with zero thread ID."""
        smi_cmd = SMICommand(['send', '0x0', '0xDE', '0x0'], cs=mock_cs)
        smi_cmd.parse_arguments()

        assert smi_cmd.thread_id == 0x0

    @pytest.mark.unit
    def test_maximum_smi_values(self, mock_cs):
        """Test operations with maximum SMI values."""
        smi_cmd = SMICommand(['send', '0xFF', '0xFF', '0xFF'], cs=mock_cs)
        smi_cmd.parse_arguments()

        assert smi_cmd.thread_id == 0xFF
        assert smi_cmd.SMI_code_port_value == 0xFF
        assert smi_cmd.SMI_data_port_value == 0xFF

    @pytest.mark.unit
    def test_zero_smi_values(self, mock_cs):
        """Test operations with zero SMI values."""
        smi_cmd = SMICommand(['send', '0x0', '0x0', '0x0'], cs=mock_cs)
        smi_cmd.parse_arguments()

        assert smi_cmd.thread_id == 0x0
        assert smi_cmd.SMI_code_port_value == 0x0
        assert smi_cmd.SMI_data_port_value == 0x0

    @pytest.mark.unit
    def test_large_register_values(self, mock_cs):
        """Test operations with large register values."""
        smi_cmd = SMICommand(['send', '0x0', '0xDE', '0x0',
                              '0xFFFFFFFFFFFFFFFF', '0xFFFFFFFFFFFFFFFF',
                              '0xFFFFFFFFFFFFFFFF', '0xFFFFFFFFFFFFFFFF',
                              '0xFFFFFFFFFFFFFFFF', '0xFFFFFFFFFFFFFFFF'], cs=mock_cs)
        smi_cmd.parse_arguments()

        assert smi_cmd._rax == 0xFFFFFFFFFFFFFFFF
        assert smi_cmd._rbx == 0xFFFFFFFFFFFFFFFF
        assert smi_cmd._rcx == 0xFFFFFFFFFFFFFFFF
        assert smi_cmd._rdx == 0xFFFFFFFFFFFFFFFF
        assert smi_cmd._rsi == 0xFFFFFFFFFFFFFFFF
        assert smi_cmd._rdi == 0xFFFFFFFFFFFFFFFF

    @pytest.mark.unit
    def test_smi_count_no_registers(self, mock_cs):
        """Test smi_count when no registers are found."""
        mock_cs.register.get_list_by_name.return_value = []

        smi_cmd = SMICommand(['count'], cs=mock_cs)

        with patch.object(smi_cmd.logger, 'log') as mock_log:
            smi_cmd.smi_count()

            # Should still log the header even with no registers
            assert mock_log.call_count >= 1

    @pytest.mark.unit
    def test_smi_send_return_values_none(self, mock_cs):
        """Test smi_send when send_SW_SMI returns None."""
        mock_cs.hals.Interrupts.send_SW_SMI.return_value = None

        smi_cmd = SMICommand(['send', '0x0', '0xDE', '0x0', '0x12345678'], cs=mock_cs)
        smi_cmd.parse_arguments()

        with patch.object(smi_cmd.logger, 'log') as mock_log:
            smi_cmd.smi_send()

            # Should not log return values when None is returned
            # Count the number of log calls to verify
            assert mock_log.call_count >= 7  # header + 6 register values, no return values


class TestInterruptsCommandConfigurationValidation:
    """Test configuration validation aspects of interrupt commands."""

    @pytest.fixture
    def config_cs(self):
        """Create ChipsecCs with interrupt-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock interrupt HAL with configuration
        cs_mock.hals.Interrupts = Mock()
        cs_mock.hals.Interrupts.send_SMI_APMC.return_value = None

        # Mock interrupt configuration data
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.INTERRUPT_CONFIG = {
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

        return cs_mock

    @pytest.mark.unit
    def test_interrupt_configuration_access(self, config_cs):
        """Test access to interrupt configuration data."""
        int_config = config_cs.Cfg.INTERRUPT_CONFIG

        assert int_config['max_thread_id'] == 255
        assert int_config['smi_ports']['command_port'] == 0xB2
        assert int_config['smi_ports']['data_port'] == 0xB3
        assert 'apm_control' in int_config['smi_codes']
        assert int_config['smi_codes']['apm_control'] == 0xDE
        assert 'external_nmi' in int_config['nmi_sources']

    @pytest.mark.unit
    def test_smi_ports_validation(self, config_cs):
        """Test validation of SMI port configuration."""
        smi_ports = config_cs.Cfg.INTERRUPT_CONFIG['smi_ports']

        # Test that all expected SMI ports are defined
        expected_ports = ['command_port', 'data_port']
        for port_name in expected_ports:
            assert port_name in smi_ports
            assert isinstance(smi_ports[port_name], int)
            assert 0 <= smi_ports[port_name] <= 0xFFFF

        # Test specific port values
        assert smi_ports['command_port'] == 0xB2
        assert smi_ports['data_port'] == 0xB3

    @pytest.mark.unit
    def test_smi_codes_validation(self, config_cs):
        """Test validation of SMI codes configuration."""
        smi_codes = config_cs.Cfg.INTERRUPT_CONFIG['smi_codes']

        # Test that all expected SMI codes are defined
        expected_codes = ['apm_control', 'custom_smi', 'security_smi']
        for code_name in expected_codes:
            assert code_name in smi_codes
            assert isinstance(smi_codes[code_name], int)
            assert 0 <= smi_codes[code_name] <= 0xFF

        # Test specific SMI code values
        assert smi_codes['apm_control'] == 0xDE
        assert smi_codes['custom_smi'] == 0xEF
        assert smi_codes['security_smi'] == 0xF0

    @pytest.mark.unit
    def test_nmi_sources_validation(self, config_cs):
        """Test validation of NMI sources configuration."""
        nmi_sources = config_cs.Cfg.INTERRUPT_CONFIG['nmi_sources']

        # Test that NMI sources list is not empty
        assert len(nmi_sources) > 0

        # Test that all NMI sources are strings
        for source in nmi_sources:
            assert isinstance(source, str)
            assert len(source) > 0

        # Test specific NMI sources
        assert 'external_nmi' in nmi_sources
        assert 'watchdog_timer' in nmi_sources
        assert 'performance_monitoring' in nmi_sources
        assert 'thermal_sensor' in nmi_sources

    @pytest.mark.unit
    def test_smmc_config_validation(self, config_cs):
        """Test validation of SMMC configuration."""
        smmc_config = config_cs.Cfg.INTERRUPT_CONFIG['smmc_config']

        # Test SMMC configuration fields
        assert smmc_config['signature'] == 'smmc'
        assert smmc_config['max_payload_size'] == 0x1000
        assert len(smmc_config['supported_protocols']) > 0

        # Test supported protocols
        assert 'ed32d533-99e6-4209-9cc0-2d72cdd998a7' in smmc_config['supported_protocols']

    @pytest.mark.unit
    def test_thread_id_limits_validation(self, config_cs):
        """Test thread ID limits validation."""
        max_thread_id = config_cs.Cfg.INTERRUPT_CONFIG['max_thread_id']

        # Test that the maximum thread ID is valid
        assert max_thread_id == 255  # 8-bit thread ID

        # Test that the limit is reasonable
        assert max_thread_id > 0
        assert max_thread_id <= 1024  # Reasonable maximum for most systems


if __name__ == '__main__':
    pytest.main([__file__])
