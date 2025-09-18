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
# along with this program; if not, write to the free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

import pytest
from unittest.mock import Mock, patch, MagicMock
from chipsec.utilcmd.txt_cmd import TXTCommand
from chipsec.library.exceptions import HWAccessViolationError
from tests.test_utils import MockFactory


class TestTXTCommand:
    """Comprehensive tests for TXT utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for TXT testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock TXT-related components
        cs_mock.hals = Mock()
        cs_mock.hals.Memory = Mock()
        cs_mock.hals.CPU = Mock()
        cs_mock.hals.Msr = Mock()

        # Mock register system
        cs_mock.register = Mock()
        cs_mock.register.is_defined.return_value = True
        cs_mock.register.get_list_by_name.return_value = Mock()

        # Mock set_scope method
        cs_mock.set_scope = Mock()

        return cs_mock

    @pytest.fixture
    def txt_command(self, mock_cs):
        """Create TXTCommand instance."""
        return TXTCommand(['dump'], cs=mock_cs)

    @pytest.mark.unit
    def test_txt_command_initialization(self, txt_command, mock_cs):
        """Test TXTCommand initialization."""
        assert txt_command.cs == mock_cs
        assert txt_command.argv == ['dump']
        # Verify set_scope was called with correct parameters
        mock_cs.set_scope.assert_called_once_with({
            None: "8086.TXT",
            "IA32_FEATURE_CONTROL": "8086.MSR"
        })

    @pytest.mark.unit
    def test_parse_arguments_dump(self, mock_cs):
        """Test parsing dump command."""
        command = TXTCommand(['dump'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.txt_dump

    @pytest.mark.unit
    def test_parse_arguments_state(self, mock_cs):
        """Test parsing state command."""
        command = TXTCommand(['state'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.txt_state

    @pytest.mark.unit
    def test_parse_arguments_invalid(self, mock_cs):
        """Test parsing invalid command."""
        command = TXTCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_requirements(self, txt_command):
        """Test command requirements."""
        reqs = txt_command.requirements()
        assert hasattr(reqs, 'load_config')
        assert hasattr(reqs, 'load_driver')

    @pytest.mark.unit
    def test_txt_dump_with_data(self, txt_command, mock_cs):
        """Test txt_dump method with non-zero data."""
        # Mock memory read with some non-zero data
        test_data = b'\x00' * 16 + b'\x01\x02\x03\x04' + b'\x00' * 12 + b'\x05\x06\x07\x08' + b'\x00' * 1000
        mock_cs.hals.Memory.read_physical_mem.return_value = test_data

        with patch.object(txt_command.logger, 'log') as mock_log:
            txt_command.txt_dump()

            # Verify memory read was called correctly
            mock_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xfed30000, 0x1000)

            # Should log the non-zero data lines
            expected_calls = [
                "[CHIPSEC] FED30010: 01 02 03 04 00 00 00 00 00 00 00 00 05 06 07 08",
                "[CHIPSEC] FED30020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            ]
            for expected in expected_calls:
                mock_log.assert_any_call(expected)

    @pytest.mark.unit
    def test_txt_dump_all_zeros(self, txt_command, mock_cs):
        """Test txt_dump method with all zero data."""
        # Mock memory read with all zeros
        test_data = b'\x00' * 0x1000
        mock_cs.hals.Memory.read_physical_mem.return_value = test_data

        with patch.object(txt_command.logger, 'log') as mock_log:
            txt_command.txt_dump()

            # Should not log any data lines since all are zeros
            # Only the memory read call should happen
            mock_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xfed30000, 0x1000)

            # Should not have any log calls for data
            assert mock_log.call_count == 0

    @pytest.mark.unit
    def test_txt_dump_mixed_data(self, txt_command, mock_cs):
        """Test txt_dump method with mixed zero and non-zero data."""
        # Create data with zeros, then non-zeros, then zeros again
        test_data = b'\x00' * 32 + b'\xAA\xBB\xCC\xDD' + b'\x00' * 12 + b'\x00' * 32
        mock_cs.hals.Memory.read_physical_mem.return_value = test_data

        with patch.object(txt_command.logger, 'log') as mock_log:
            txt_command.txt_dump()

            # Should log the skip indicator and the non-zero data
            mock_log.assert_any_call("[CHIPSEC] *")
            mock_log.assert_any_call("[CHIPSEC] FED30020: AA BB CC DD 00 00 00 00 00 00 00 00 00 00 00 00")

    @pytest.mark.unit
    def test_log_register_defined(self, txt_command, mock_cs):
        """Test _log_register method with defined register."""
        reg_name = "TEST_REGISTER"
        mock_reg = Mock()
        mock_cs.register.get_list_by_name.return_value = mock_reg

        txt_command._log_register(reg_name)

        # Should check if register is defined and get the register object
        mock_cs.register.is_defined.assert_called_with(reg_name)
        mock_cs.register.get_list_by_name.assert_called_with(reg_name)
        mock_reg.read_and_print.assert_called_once()

    @pytest.mark.unit
    def test_log_register_undefined(self, txt_command, mock_cs):
        """Test _log_register method with undefined register."""
        reg_name = "UNDEFINED_REGISTER"
        mock_cs.register.is_defined.return_value = False

        txt_command._log_register(reg_name)

        # Should check if register is defined and return early
        mock_cs.register.is_defined.assert_called_with(reg_name)
        # Should not call get_list_by_name or read_and_print
        mock_cs.register.get_list_by_name.assert_not_called()

    @pytest.mark.unit
    def test_txt_state_cpuid_and_cr4(self, txt_command, mock_cs):
        """Test txt_state method CPUID and CR4 reading."""
        # Mock CPUID return values
        mock_cs.hals.CPU.cpuid.return_value = (0x12345678, 0x87654321, 0b01000000, 0xDEADBEEF)  # SMX bit set
        mock_cs.hals.CPU.read_cr.return_value = 0b010000000000000  # SMXE bit set

        # Mock register methods to avoid actual register operations
        mock_cs.register.is_defined.return_value = False

        with patch.object(txt_command.logger, 'log') as mock_log:
            txt_command.txt_state()

            # Verify CPUID and CR4 calls
            mock_cs.hals.CPU.cpuid.assert_called_once_with(0x01, 0x00)
            mock_cs.hals.CPU.read_cr.assert_called_once_with(0, 4)

            # Check SMX and VMX bit logging
            mock_log.assert_any_call("[CHIPSEC] CPUID.01H.ECX[Bit 6] = 1 << Safer Mode Extensions (SMX)")
            mock_log.assert_any_call("[CHIPSEC] CPUID.01H.ECX[Bit 5] = 0 << Virtual Machine Extensions (VMX)")
            mock_log.assert_any_call("[CHIPSEC] CR4.SMXE[Bit 14] = 1 << Safer Mode Extensions Enable")
            mock_log.assert_any_call("[CHIPSEC] CR4.VMXE[Bit 13] = 0 << Virtual Machine Extensions Enable")

    @pytest.mark.unit
    def test_txt_state_feature_control_register(self, txt_command, mock_cs):
        """Test txt_state method IA32_FEATURE_CONTROL register handling."""
        # Mock register as defined
        mock_cs.register.is_defined.return_value = True
        mock_reg = Mock()
        mock_cs.register.get_list_by_name.return_value = mock_reg

        # Mock other methods to avoid side effects
        mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        mock_cs.hals.CPU.read_cr.return_value = 0

        with patch.object(txt_command.logger, 'log') as mock_log:
            txt_command.txt_state()

            # Should call _log_register for IA32_FEATURE_CONTROL
            mock_cs.register.is_defined.assert_any_call("IA32_FEATURE_CONTROL")
            mock_reg.read_and_print.assert_called()

    @pytest.mark.unit
    def test_txt_state_public_key_hash(self, txt_command, mock_cs):
        """Test txt_state method public key hash reading."""
        # Mock register values
        mock_pub_list = Mock()
        mock_pub_list.read.return_value = [0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222]
        mock_cs.register.get_list_by_name.return_value = mock_pub_list

        # Mock other methods
        mock_cs.register.is_defined.return_value = False
        mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        mock_cs.hals.CPU.read_cr.return_value = 0

        with patch.object(txt_command.logger, 'log') as mock_log:
            txt_command.txt_state()

            # Should read public key values and log hash
            mock_pub_list.read.assert_called_once()
            expected_hash = "78563412f0debc9a1111111122222222"
            mock_log.assert_any_call(f"[CHIPSEC] TXT Public Key Hash: {expected_hash}")

    @pytest.mark.unit
    def test_txt_state_msr_public_key_success(self, txt_command, mock_cs):
        """Test txt_state method MSR public key reading success."""
        # Mock MSR reads
        mock_cs.hals.Msr.read_msr.side_effect = [
            (0x11111111, 0x22222222),  # MSR 0x20
            (0x33333333, 0x44444444),  # MSR 0x21
            (0x55555555, 0x66666666),  # MSR 0x22
            (0x77777777, 0x88888888),  # MSR 0x23
        ]

        # Mock other methods
        mock_cs.register.is_defined.return_value = False
        mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        mock_cs.hals.CPU.read_cr.return_value = 0

        with patch.object(txt_command.logger, 'log') as mock_log:
            txt_command.txt_state()

            # Should read all 4 MSRs
            expected_calls = [
                ((0, 0x20),),
                ((0, 0x21),),
                ((0, 0x22),),
                ((0, 0x23),)
            ]
            mock_cs.hals.Msr.read_msr.assert_has_calls(expected_calls)

            # Should log the MSR public key hash
            expected_msr_hash = "1111111122222222333333334444444455555555666666667777777788888888"
            mock_log.assert_any_call(f"[CHIPSEC] Public Key Hash in MSR[0x20...0x23]: {expected_msr_hash}")

    @pytest.mark.unit
    def test_txt_state_msr_public_key_failure(self, txt_command, mock_cs):
        """Test txt_state method MSR public key reading failure."""
        # Mock MSR read to raise HWAccessViolationError
        mock_cs.hals.Msr.read_msr.side_effect = HWAccessViolationError("Access denied")

        # Mock other methods
        mock_cs.register.is_defined.return_value = False
        mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        mock_cs.hals.CPU.read_cr.return_value = 0

        with patch.object(txt_command.logger, 'log') as mock_log:
            txt_command.txt_state()

            # Should log the error message
            mock_log.assert_any_call("[CHIPSEC] Unable to read Public Key Hash in MSR[0x20...0x23]: Access denied")

    @pytest.mark.unit
    def test_txt_state_status_registers(self, txt_command, mock_cs):
        """Test txt_state method status register logging."""
        # Mock register as defined
        mock_cs.register.is_defined.return_value = True
        mock_reg = Mock()
        mock_cs.register.get_list_by_name.return_value = mock_reg

        # Mock other methods
        mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        mock_cs.hals.CPU.read_cr.return_value = 0

        with patch.object(txt_command.logger, 'log') as mock_log:
            txt_command.txt_state()

            # Should call _log_register for various status registers
            status_registers = ["STS", "ESTS", "E2STS", "ERRORCODE", "SPAD", "ACM_STATUS", "FIT", "SCRATCHPAD"]
            for reg in status_registers:
                mock_cs.register.is_defined.assert_any_call(reg)
                mock_reg.read_and_print.assert_called()

    @pytest.mark.unit
    def test_txt_state_memory_area_registers(self, txt_command, mock_cs):
        """Test txt_state method memory area register logging."""
        # Mock register as defined
        mock_cs.register.is_defined.return_value = True
        mock_reg = Mock()
        mock_cs.register.get_list_by_name.return_value = mock_reg

        # Mock other methods
        mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        mock_cs.hals.CPU.read_cr.return_value = 0

        with patch.object(txt_command.logger, 'log') as mock_log:
            txt_command.txt_state()

            # Should call _log_register for memory area registers
            memory_registers = ["SINIT_BASE", "SINIT_SIZE", "MLE_JOIN", "HEAP_BASE", "HEAP_SIZE", "MSEG_BASE", "MSEG_SIZE"]
            for reg in memory_registers:
                mock_cs.register.is_defined.assert_any_call(reg)

    @pytest.mark.unit
    def test_txt_state_other_registers(self, txt_command, mock_cs):
        """Test txt_state method other register logging."""
        # Mock register as defined
        mock_cs.register.is_defined.return_value = True
        mock_reg = Mock()
        mock_cs.register.get_list_by_name.return_value = mock_reg

        # Mock other methods
        mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        mock_cs.hals.CPU.read_cr.return_value = 0

        with patch.object(txt_command.logger, 'log') as mock_log:
            txt_command.txt_state()

            # Should call _log_register for other TXT registers
            other_registers = ["DPR", "VER_FSBIF", "VER_QPIIF", "PCH_DIDVID", "INSMM"]
            for reg in other_registers:
                mock_cs.register.is_defined.assert_any_call(reg)

    @pytest.mark.unit
    def test_run_success(self, txt_command, mock_cs):
        """Test run method with successful execution."""
        # Mock successful function execution
        txt_command.func = Mock()

        txt_command.run()

        # Should call the function and set exit code to OK
        txt_command.func.assert_called_once()
        assert txt_command.ExitCode.name == "OK"

    @pytest.mark.unit
    def test_run_exception(self, txt_command, mock_cs):
        """Test run method with exception during execution."""
        # Mock function to raise exception
        txt_command.func = Mock(side_effect=Exception("Test exception"))

        txt_command.run()

        # Should call the function and set exit code to ERROR
        txt_command.func.assert_called_once()
        assert txt_command.ExitCode.name == "ERROR"


class TestTXTCommandIntegration:
    """Integration tests for TXT command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for TXT testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock TXT-related components with realistic data
        cs_mock.hals = Mock()
        cs_mock.hals.Memory = Mock()
        cs_mock.hals.CPU = Mock()
        cs_mock.hals.Msr = Mock()

        # Mock register system
        cs_mock.register = Mock()
        cs_mock.register.is_defined.return_value = True

        # Mock set_scope method
        cs_mock.set_scope = Mock()

        return cs_mock

    @pytest.mark.integration
    def test_txt_dump_integration(self, integrated_cs):
        """Test complete txt_dump workflow."""
        # Create realistic TXT public area data
        txt_data = b'\x00' * 100 + b'\x01\x02\x03\x04\x05\x06\x07\x08' + b'\x00' * 100
        integrated_cs.hals.Memory.read_physical_mem.return_value = txt_data

        txt_cmd = TXTCommand(['dump'], cs=integrated_cs)
        txt_cmd.parse_arguments()

        with patch.object(txt_cmd.logger, 'log') as mock_log:
            txt_cmd.run()

            # Should read memory and log data
            integrated_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xfed30000, 0x1000)
            mock_log.assert_any_call("[CHIPSEC] FED30064: 01 02 03 04 05 06 07 08 00 00 00 00 00 00 00 00")

    @pytest.mark.integration
    def test_txt_state_integration(self, integrated_cs):
        """Test complete txt_state workflow."""
        # Mock realistic CPUID and CR4 values
        integrated_cs.hals.CPU.cpuid.return_value = (0x206A7, 0x12345678, 0b01100000, 0xDEADBEEF)  # SMX and VMX enabled
        integrated_cs.hals.CPU.read_cr.return_value = 0b011000000000000  # SMXE and VMXE enabled

        # Mock MSR reads for public key
        integrated_cs.hals.Msr.read_msr.side_effect = [
            (0xAAAAAAAA, 0xBBBBBBBB),
            (0xCCCCCCCC, 0xDDDDDDDD),
            (0xEEEEEEEE, 0xFFFFFFFF),
            (0x11111111, 0x22222222)
        ]

        # Mock register objects
        mock_reg = Mock()
        integrated_cs.register.get_list_by_name.return_value = mock_reg

        # Mock public key register values
        mock_pub_reg = Mock()
        mock_pub_reg.read.return_value = [0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222]
        integrated_cs.register.get_list_by_name.side_effect = lambda name: mock_pub_reg if "PUBLIC_KEY" in name else mock_reg

        txt_cmd = TXTCommand(['state'], cs=integrated_cs)
        txt_cmd.parse_arguments()

        with patch.object(txt_cmd.logger, 'log') as mock_log:
            txt_cmd.run()

            # Verify CPUID and CR4 logging
            mock_log.assert_any_call("[CHIPSEC] CPUID.01H.ECX[Bit 6] = 1 << Safer Mode Extensions (SMX)")
            mock_log.assert_any_call("[CHIPSEC] CPUID.01H.ECX[Bit 5] = 1 << Virtual Machine Extensions (VMX)")
            mock_log.assert_any_call("[CHIPSEC] CR4.SMXE[Bit 14] = 1 << Safer Mode Extensions Enable")
            mock_log.assert_any_call("[CHIPSEC] CR4.VMXE[Bit 13] = 1 << Virtual Machine Extensions Enable")

            # Verify MSR public key hash logging
            expected_msr_hash = "aaaaaaaa bbbbbbbb cccccccc dddddddd eeeeeeee ffffffff 11111111 22222222".replace(" ", "")
            mock_log.assert_any_call(f"[CHIPSEC] Public Key Hash in MSR[0x20...0x23]: {expected_msr_hash}")

            # Verify TXT public key hash logging
            expected_txt_hash = "78563412f0debc9a1111111122222222"
            mock_log.assert_any_call(f"[CHIPSEC] TXT Public Key Hash: {expected_txt_hash}")


class TestTXTCommandEdgeCases:
    """Test edge cases and error conditions for TXT command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        cs_mock.hals.Memory = Mock()
        cs_mock.hals.CPU = Mock()
        cs_mock.hals.Msr = Mock()
        cs_mock.register = Mock()
        cs_mock.set_scope = Mock()
        return cs_mock

    @pytest.fixture
    def txt_command(self, mock_cs):
        """Create TXTCommand instance for edge case testing."""
        return TXTCommand(['dump'], cs=mock_cs)

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        command = TXTCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_txt_dump_empty_data(self, txt_command, mock_cs):
        """Test txt_dump with empty data."""
        mock_cs.hals.Memory.read_physical_mem.return_value = b''

        with patch.object(txt_command.logger, 'log') as mock_log:
            txt_command.txt_dump()

            # Should handle empty data gracefully
            mock_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xfed30000, 0x1000)
            # No log calls should be made for empty data

    @pytest.mark.unit
    def test_txt_dump_partial_data(self, txt_command, mock_cs):
        """Test txt_dump with partial data."""
        test_data = b'\x01\x02\x03\x04'  # Less than 16 bytes
        mock_cs.hals.Memory.read_physical_mem.return_value = test_data

        with patch.object(txt_command.logger, 'log') as mock_log:
            txt_command.txt_dump()

            # Should handle partial data
            mock_log.assert_any_call("[CHIPSEC] FED30000: 01 02 03 04")

    @pytest.mark.unit
    def test_txt_state_cpuid_error(self, txt_command, mock_cs):
        """Test txt_state with CPUID error."""
        mock_cs.hals.CPU.cpuid.side_effect = Exception("CPUID failed")

        # Mock other methods to avoid further errors
        mock_cs.register.is_defined.return_value = False

        with patch.object(txt_command.logger, 'log') as mock_log:
            # Should handle CPUID error gracefully
            with pytest.raises(Exception):
                txt_command.txt_state()

    @pytest.mark.unit
    def test_txt_state_cr4_error(self, txt_command, mock_cs):
        """Test txt_state with CR4 read error."""
        mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        mock_cs.hals.CPU.read_cr.side_effect = Exception("CR4 read failed")

        # Mock other methods to avoid further errors
        mock_cs.register.is_defined.return_value = False

        with patch.object(txt_command.logger, 'log') as mock_log:
            # Should handle CR4 error gracefully
            with pytest.raises(Exception):
                txt_command.txt_state()

    @pytest.mark.unit
    def test_txt_state_all_registers_undefined(self, txt_command, mock_cs):
        """Test txt_state with all registers undefined."""
        mock_cs.register.is_defined.return_value = False
        mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        mock_cs.hals.CPU.read_cr.return_value = 0

        with patch.object(txt_command.logger, 'log') as mock_log:
            txt_command.txt_state()

            # Should still log CPUID and CR4 information
            mock_log.assert_any_call("[CHIPSEC] CPUID.01H.ECX[Bit 6] = 0 << Safer Mode Extensions (SMX)")
            mock_log.assert_any_call("[CHIPSEC] CR4.SMXE[Bit 14] = 0 << Safer Mode Extensions Enable")

    @pytest.mark.unit
    def test_txt_state_public_key_read_error(self, txt_command, mock_cs):
        """Test txt_state with public key read error."""
        mock_pub_reg = Mock()
        mock_pub_reg.read.side_effect = Exception("Public key read failed")
        mock_cs.register.get_list_by_name.return_value = mock_pub_reg

        mock_cs.register.is_defined.return_value = False
        mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        mock_cs.hals.CPU.read_cr.return_value = 0

        with patch.object(txt_command.logger, 'log') as mock_log:
            # Should handle public key read error gracefully
            with pytest.raises(Exception):
                txt_command.txt_state()

    @pytest.mark.unit
    def test_run_with_none_func(self, txt_command, mock_cs):
        """Test run method when func is None."""
        txt_command.func = None

        # Should handle None func gracefully
        txt_command.run()

        # Should set exit code to ERROR
        assert txt_command.ExitCode.name == "ERROR"


class TestTXTCommandConfigurationValidation:
    """Test configuration validation aspects of TXT command."""

    @pytest.fixture
    def txt_cs(self):
        """Create ChipsecCs with TXT-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock TXT configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.CONFIG_TXT = {
            'TXT_PUBLIC_BASE': 0xFED30000,
            'TXT_PUBLIC_SIZE': 0x1000,
            'TXT_PRIVATE_BASE': 0xFED20000,
            'TXT_SINIT_BASE': 0xFED40000
        }

        cs_mock.hals = Mock()
        cs_mock.hals.Memory = Mock()
        cs_mock.register = Mock()
        cs_mock.set_scope = Mock()

        return cs_mock

    @pytest.mark.unit
    def test_txt_configuration_structure(self, txt_cs):
        """Test TXT configuration structure."""
        txt_config = txt_cs.Cfg.CONFIG_TXT

        # Test that required TXT configuration exists
        assert 'TXT_PUBLIC_BASE' in txt_config
        assert 'TXT_PUBLIC_SIZE' in txt_config

        # Test configuration values are reasonable
        assert txt_config['TXT_PUBLIC_BASE'] == 0xFED30000
        assert txt_config['TXT_PUBLIC_SIZE'] == 0x1000

    @pytest.mark.unit
    def test_txt_memory_regions(self, txt_cs):
        """Test TXT memory region configuration."""
        txt_config = txt_cs.Cfg.CONFIG_TXT

        # Test memory regions are properly defined
        if 'TXT_PRIVATE_BASE' in txt_config:
            assert txt_config['TXT_PRIVATE_BASE'] != txt_config['TXT_PUBLIC_BASE']

        if 'TXT_SINIT_BASE' in txt_config:
            assert txt_config['TXT_SINIT_BASE'] != txt_config['TXT_PUBLIC_BASE']

    @pytest.mark.unit
    def test_txt_dump_address_validation(self, txt_cs):
        """Test TXT dump uses correct memory address."""
        txt_cmd = TXTCommand(['dump'], cs=txt_cs)

        # Mock memory read
        txt_cs.hals.Memory.read_physical_mem.return_value = b'\x00' * 0x1000

        with patch.object(txt_cmd.logger, 'log'):
            txt_cmd.txt_dump()

            # Should read from the correct TXT public base address
            txt_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xFED30000, 0x1000)


if __name__ == '__main__':
    pytest.main([__file__])
