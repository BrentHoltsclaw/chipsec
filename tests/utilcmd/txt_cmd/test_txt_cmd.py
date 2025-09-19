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
from chipsec.utilcmd.txt_cmd import TXTCommand
from chipsec.library.exceptions import HWAccessViolationError
from tests.test_utils import MockFactory


class TestTXTCommand(unittest.TestCase):
    """Comprehensive tests for TXT utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()

        # Mock TXT-related components
        self.mock_cs.hals = Mock()
        self.mock_cs.hals.Memory = Mock()
        self.mock_cs.hals.CPU = Mock()
        self.mock_cs.hals.Msr = Mock()

        # Mock register system
        self.mock_cs.register = Mock()
        self.mock_cs.register.is_defined.return_value = True
        self.mock_cs.register.get_list_by_name.return_value = Mock()
        # Default public key register list returns 4 zero qwords
        self.mock_cs.register.get_list_by_name.return_value.read.return_value = [0, 0, 0, 0]

        # Mock set_scope method
        self.mock_cs.set_scope = Mock()

        self.txt_command = TXTCommand(['dump'], cs=self.mock_cs)

    def test_txt_command_initialization(self):
        """Test TXTCommand initialization."""
        self.assertEqual(self.txt_command.cs, self.mock_cs)
        self.assertEqual(self.txt_command.argv, ['dump'])
        # Verify set_scope was called with correct parameters
        self.mock_cs.set_scope.assert_called_once_with({
            None: "8086.TXT",
            "IA32_FEATURE_CONTROL": "8086.MSR"
        })

    def test_parse_arguments_dump(self):
        """Test parsing dump command."""
        command = TXTCommand(['dump'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.txt_dump)

    def test_parse_arguments_state(self):
        """Test parsing state command."""
        command = TXTCommand(['state'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.txt_state)

    def test_parse_arguments_invalid(self):
        """Test parsing invalid command."""
        command = TXTCommand(['invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.txt_command.requirements()
        self.assertTrue(hasattr(reqs, 'load_config'))
        self.assertTrue(hasattr(reqs, 'load_driver'))

    def test_txt_dump_with_data(self):
        """Test txt_dump method with non-zero data."""
        # Mock memory read with some non-zero data
        test_data = b'\x00' * 16 + b'\x01\x02\x03\x04' + b'\x00' * 12 + b'\x05\x06\x07\x08' + b'\x00' * 1000
        self.mock_cs.hals.Memory.read_physical_mem.return_value = test_data

        with patch.object(self.txt_command.logger, 'log') as mock_log:
            self.txt_command.txt_dump()

            # Verify memory read was called correctly
            self.mock_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xfed30000, 0x1000)

            # Should log the non-zero data lines
            # Implementation prints 16-byte aligned lines separately
            expected_calls = [
                "[CHIPSEC] FED30010: 01 02 03 04 00 00 00 00 00 00 00 00 00 00 00 00",
                "[CHIPSEC] FED30020: 05 06 07 08 00 00 00 00 00 00 00 00 00 00 00 00"
            ]
            for expected in expected_calls:
                mock_log.assert_any_call(expected)

    def test_txt_dump_all_zeros(self):
        """Test txt_dump method with all zero data."""
        # Mock memory read with all zeros
        test_data = b'\x00' * 0x1000
        self.mock_cs.hals.Memory.read_physical_mem.return_value = test_data

        with patch.object(self.txt_command.logger, 'log') as mock_log:
            self.txt_command.txt_dump()

            # Should not log any data lines since all are zeros
            # Only the memory read call should happen
            self.mock_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xfed30000, 0x1000)

            # Should not have any log calls for data
            self.assertEqual(mock_log.call_count, 0)

    def test_txt_dump_mixed_data(self):
        """Test txt_dump method with mixed zero and non-zero data."""
        # Create data with zeros, then non-zeros, then zeros again
        test_data = b'\x00' * 32 + b'\xAA\xBB\xCC\xDD' + b'\x00' * 12 + b'\x00' * 32
        self.mock_cs.hals.Memory.read_physical_mem.return_value = test_data

        with patch.object(self.txt_command.logger, 'log') as mock_log:
            self.txt_command.txt_dump()

            # Should log the skip indicator and the non-zero data
            mock_log.assert_any_call("[CHIPSEC] *")
            mock_log.assert_any_call("[CHIPSEC] FED30020: AA BB CC DD 00 00 00 00 00 00 00 00 00 00 00 00")

    def test_log_register_defined(self):
        """Test _log_register method with defined register."""
        reg_name = "TEST_REGISTER"
        mock_reg = Mock()
        self.mock_cs.register.get_list_by_name.return_value = mock_reg

        self.txt_command._log_register(reg_name)

        # Should check if register is defined and get the register object
        self.mock_cs.register.is_defined.assert_called_with(reg_name)
        self.mock_cs.register.get_list_by_name.assert_called_with(reg_name)
        mock_reg.read_and_print.assert_called_once()

    def test_log_register_undefined(self):
        """Test _log_register method with undefined register."""
        reg_name = "UNDEFINED_REGISTER"
        self.mock_cs.register.is_defined.return_value = False

        self.txt_command._log_register(reg_name)

        # Should check if register is defined and return early
        self.mock_cs.register.is_defined.assert_called_with(reg_name)
        # Should not call get_list_by_name or read_and_print
        self.mock_cs.register.get_list_by_name.assert_not_called()

    def test_txt_state_cpuid_and_cr4(self):
        """Test txt_state method CPUID and CR4 reading."""
        # Mock CPUID return values
        self.mock_cs.hals.CPU.cpuid.return_value = (0x12345678, 0x87654321, 0b01000000, 0xDEADBEEF)  # SMX bit set
        # Set only SMXE (bit 14) and leave VMXE (bit 13) cleared
        self.mock_cs.hals.CPU.read_cr.return_value = (1 << 14)

        # Mock register methods to avoid actual register operations
        self.mock_cs.register.is_defined.return_value = False
        # Provide default MSR tuple
        self.mock_cs.hals.Msr.read_msr.return_value = (0, 0)

        with patch.object(self.txt_command.logger, 'log') as mock_log:
            self.txt_command.txt_state()

            # Verify CPUID and CR4 calls
            self.mock_cs.hals.CPU.cpuid.assert_called_once_with(0x01, 0x00)
            self.mock_cs.hals.CPU.read_cr.assert_called_once_with(0, 4)

            # Check SMX and VMX bit logging
            mock_log.assert_any_call("[CHIPSEC] CPUID.01H.ECX[Bit 6] = 1 << Safer Mode Extensions (SMX)")
            mock_log.assert_any_call("[CHIPSEC] CPUID.01H.ECX[Bit 5] = 0 << Virtual Machine Extensions (VMX)")
            mock_log.assert_any_call("[CHIPSEC] CR4.SMXE[Bit 14] = 1 << Safer Mode Extensions Enable")
            mock_log.assert_any_call("[CHIPSEC] CR4.VMXE[Bit 13] = 0 << Virtual Machine Extensions Enable")

    def test_txt_state_feature_control_register(self):
        """Test txt_state method IA32_FEATURE_CONTROL register handling."""
        # Mock register as defined
        self.mock_cs.register.is_defined.return_value = True
        mock_reg = Mock()
        self.mock_cs.register.get_list_by_name.return_value = mock_reg
        # Provide public key list read returning 4 qwords to satisfy struct.pack
        mock_reg.read.return_value = [0, 0, 0, 0]

        # Mock other methods to avoid side effects
        self.mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        self.mock_cs.hals.CPU.read_cr.return_value = 0
        self.mock_cs.hals.Msr.read_msr.return_value = (0, 0)

        self.txt_command.txt_state()

        # Should call _log_register for IA32_FEATURE_CONTROL
        self.mock_cs.register.is_defined.assert_any_call("IA32_FEATURE_CONTROL")
        mock_reg.read_and_print.assert_called()

    def test_txt_state_public_key_hash(self):
        """Test txt_state method public key hash reading."""
        # Mock register values
        mock_pub_list = Mock()
        mock_pub_list.read.return_value = [0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222]
        self.mock_cs.register.get_list_by_name.return_value = mock_pub_list

        # Mock other methods
        self.mock_cs.register.is_defined.return_value = False
        self.mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        self.mock_cs.hals.CPU.read_cr.return_value = 0
        self.mock_cs.hals.Msr.read_msr.return_value = (0, 0)

        with patch.object(self.txt_command.logger, 'log') as mock_log:
            self.txt_command.txt_state()

            # Should read public key values and log hash
            mock_pub_list.read.assert_called_once()
            # struct.pack('<QQQQ') introduces 8-byte little-endian representations with padding zeros per qword
            expected_hash = "7856341200000000f0debc9a0000000011111111000000002222222200000000"
            mock_log.assert_any_call(f"[CHIPSEC] TXT Public Key Hash: {expected_hash}")

    def test_txt_state_msr_public_key_success(self):
        """Test txt_state method MSR public key reading success."""
        # Mock MSR reads
        self.mock_cs.hals.Msr.read_msr.side_effect = [
            (0x11111111, 0x22222222),  # MSR 0x20
            (0x33333333, 0x44444444),  # MSR 0x21
            (0x55555555, 0x66666666),  # MSR 0x22
            (0x77777777, 0x88888888),  # MSR 0x23
        ]

        # Mock other methods
        self.mock_cs.register.is_defined.return_value = False
        self.mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        self.mock_cs.hals.CPU.read_cr.return_value = 0
        self.mock_cs.hals.Msr.read_msr.return_value = (0, 0)

        with patch.object(self.txt_command.logger, 'log') as mock_log:
            self.txt_command.txt_state()

            # Should read all 4 MSRs
            expected_calls = [
                ((0, 0x20),),
                ((0, 0x21),),
                ((0, 0x22),),
                ((0, 0x23),)
            ]
            self.mock_cs.hals.Msr.read_msr.assert_has_calls(expected_calls)

            # Should log the MSR public key hash
            expected_msr_hash = "1111111122222222333333334444444455555555666666667777777788888888"
            mock_log.assert_any_call(f"[CHIPSEC] Public Key Hash in MSR[0x20...0x23]: {expected_msr_hash}")

    def test_txt_state_msr_public_key_failure(self):
        """Test txt_state method MSR public key reading failure."""
        # Mock MSR read to raise HWAccessViolationError
        self.mock_cs.hals.Msr.read_msr.side_effect = HWAccessViolationError("Access denied", 0)

        # Mock other methods
        self.mock_cs.register.is_defined.return_value = False
        self.mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        self.mock_cs.hals.CPU.read_cr.return_value = 0

        with patch.object(self.txt_command.logger, 'log') as mock_log:
            self.txt_command.txt_state()

            # Should log the error message
            mock_log.assert_any_call("[CHIPSEC] Unable to read Public Key Hash in MSR[0x20...0x23]: Access denied")

    def test_txt_state_status_registers(self):
        """Test txt_state method status register logging."""
        # Mock register as defined
        self.mock_cs.register.is_defined.return_value = True
        mock_reg = Mock()
        self.mock_cs.register.get_list_by_name.return_value = mock_reg
        mock_reg.read.return_value = [0, 0, 0, 0]

        # Mock other methods
        self.mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        self.mock_cs.hals.CPU.read_cr.return_value = 0
        self.mock_cs.hals.Msr.read_msr.return_value = (0, 0)

        with patch.object(self.txt_command.logger, 'log') as mock_log:
            self.txt_command.txt_state()

            # Should call _log_register for various status registers
            status_registers = ["STS", "ESTS", "E2STS", "ERRORCODE", "SPAD", "ACM_STATUS", "FIT", "SCRATCHPAD"]
            for reg in status_registers:
                self.mock_cs.register.is_defined.assert_any_call(reg)
                mock_reg.read_and_print.assert_called()

    def test_txt_state_memory_area_registers(self):
        """Test txt_state method memory area register logging."""
        # Mock register as defined
        self.mock_cs.register.is_defined.return_value = True
        mock_reg = Mock()
        self.mock_cs.register.get_list_by_name.return_value = mock_reg
        mock_reg.read.return_value = [0, 0, 0, 0]

        # Mock other methods
        self.mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        self.mock_cs.hals.CPU.read_cr.return_value = 0
        self.mock_cs.hals.Msr.read_msr.return_value = (0, 0)

        self.txt_command.txt_state()

        # Should call _log_register for memory area registers
        memory_registers = ["SINIT_BASE", "SINIT_SIZE", "MLE_JOIN", "HEAP_BASE", "HEAP_SIZE", "MSEG_BASE", "MSEG_SIZE"]
        for reg in memory_registers:
            self.mock_cs.register.is_defined.assert_any_call(reg)

    def test_txt_state_other_registers(self):
        """Test txt_state method other register logging."""
        # Mock register as defined
        self.mock_cs.register.is_defined.return_value = True
        mock_reg = Mock()
        self.mock_cs.register.get_list_by_name.return_value = mock_reg
        mock_reg.read.return_value = [0, 0, 0, 0]

        # Mock other methods
        self.mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        self.mock_cs.hals.CPU.read_cr.return_value = 0
        self.mock_cs.hals.Msr.read_msr.return_value = (0, 0)

        with patch.object(self.txt_command.logger, 'log') as mock_log:
            self.txt_command.txt_state()

            # Should call _log_register for other TXT registers
            other_registers = ["DPR", "VER_FSBIF", "VER_QPIIF", "PCH_DIDVID", "INSMM"]
            for reg in other_registers:
                self.mock_cs.register.is_defined.assert_any_call(reg)

    def test_run_success(self):
        """Test run method with successful execution."""
        # Mock successful function execution
        self.txt_command.func = Mock()

        self.txt_command.run()

        # Should call the function and set exit code to OK
        self.txt_command.func.assert_called_once()
        from chipsec.testcase import ExitCode
        self.assertEqual(self.txt_command.ExitCode, ExitCode.OK)

    def test_run_exception(self):
        """Test run method with exception during execution."""
        # Mock function to raise exception
        self.txt_command.func = Mock(side_effect=Exception("Test exception"))

        self.txt_command.run()

        # Should call the function and set exit code to ERROR
        self.txt_command.func.assert_called_once()
        from chipsec.testcase import ExitCode
        self.assertEqual(self.txt_command.ExitCode, ExitCode.ERROR)


class TestTXTCommandIntegration(unittest.TestCase):
    """Integration tests for TXT command with realistic data."""

    def setUp(self):
        """Set up test fixtures."""
        # Create integrated ChipsecCs for TXT testing
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock TXT-related components with realistic data
        self.integrated_cs.hals = Mock()
        self.integrated_cs.hals.Memory = Mock()
        self.integrated_cs.hals.CPU = Mock()
        self.integrated_cs.hals.Msr = Mock()

        # Mock register system
        self.integrated_cs.register = Mock()
        self.integrated_cs.register.is_defined.return_value = True
        # Default register list returns zeros for public key
        self.integrated_cs.register.get_list_by_name.return_value = Mock()
        self.integrated_cs.register.get_list_by_name.return_value.read.return_value = [0, 0, 0, 0]

        # Mock set_scope method
        self.integrated_cs.set_scope = Mock()

    def test_txt_dump_integration(self):
        """Test complete txt_dump workflow."""
        # Create realistic TXT public area data
        txt_data = b'\x00' * 100 + b'\x01\x02\x03\x04\x05\x06\x07\x08' + b'\x00' * 100
        self.integrated_cs.hals.Memory.read_physical_mem.return_value = txt_data

        txt_cmd = TXTCommand(['dump'], cs=self.integrated_cs)
        txt_cmd.parse_arguments()

        with patch.object(txt_cmd.logger, 'log') as mock_log:
            txt_cmd.run()

            # Should read memory and log data
            self.integrated_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xfed30000, 0x1000)
            mock_log.assert_any_call("[CHIPSEC] FED30060: 00 00 00 00 01 02 03 04 05 06 07 08 00 00 00 00")

    def test_txt_state_integration(self):
        """Test complete txt_state workflow."""
        # Mock realistic CPUID and CR4 values
        self.integrated_cs.hals.CPU.cpuid.return_value = (0x206A7, 0x12345678, 0b01100000, 0xDEADBEEF)  # SMX and VMX enabled
        # Set bits 14 and 13 (SMXE, VMXE)
        self.integrated_cs.hals.CPU.read_cr.return_value = (1 << 14) | (1 << 13)

        # Mock MSR reads for public key
        self.integrated_cs.hals.Msr.read_msr.side_effect = [
            (0xAAAAAAAA, 0xBBBBBBBB),
            (0xCCCCCCCC, 0xDDDDDDDD),
            (0xEEEEEEEE, 0xFFFFFFFF),
            (0x11111111, 0x22222222)
        ]

        # Mock register objects
        mock_reg = Mock()
        self.integrated_cs.register.get_list_by_name.return_value = mock_reg

        # Mock public key register values
        mock_pub_reg = Mock()
        mock_pub_reg.read.return_value = [0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222]
        self.integrated_cs.register.get_list_by_name.side_effect = lambda name: mock_pub_reg if "PUBLIC_KEY" in name else mock_reg

        txt_cmd = TXTCommand(['state'], cs=self.integrated_cs)
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
            # struct.pack('<QQQQ') produces padded little-endian qword layout
            expected_txt_hash = "7856341200000000f0debc9a0000000011111111000000002222222200000000"
            mock_log.assert_any_call(f"[CHIPSEC] TXT Public Key Hash: {expected_txt_hash}")


class TestTXTCommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for TXT command."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.hals = Mock()
        self.mock_cs.hals.Memory = Mock()
        self.mock_cs.hals.CPU = Mock()
        self.mock_cs.hals.Msr = Mock()
        self.mock_cs.register = Mock()
        self.mock_cs.register.get_list_by_name.return_value = Mock()
        self.mock_cs.register.get_list_by_name.return_value.read.return_value = [0, 0, 0, 0]
        self.mock_cs.set_scope = Mock()
        self.txt_command = TXTCommand(['dump'], cs=self.mock_cs)

    def test_empty_argv_handling(self):
        """Test handling of empty argv."""
        command = TXTCommand([], cs=self.mock_cs)
        # Parsing with no subcommand should leave func unset without raising
        command.parse_arguments()
        self.assertFalse(hasattr(command, 'func'))

    def test_txt_dump_empty_data(self):
        """Test txt_dump with empty data."""
        self.mock_cs.hals.Memory.read_physical_mem.return_value = b''

        with patch.object(self.txt_command.logger, 'log') as mock_log:
            self.txt_command.txt_dump()

            # Should handle empty data gracefully
            self.mock_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xfed30000, 0x1000)
            # No log calls should be made for empty data

    def test_txt_dump_partial_data(self):
        """Test txt_dump with partial data."""
        test_data = b'\x01\x02\x03\x04'  # Less than 16 bytes
        self.mock_cs.hals.Memory.read_physical_mem.return_value = test_data

        with patch.object(self.txt_command.logger, 'log') as mock_log:
            self.txt_command.txt_dump()

            # Should handle partial data
            mock_log.assert_any_call("[CHIPSEC] FED30000: 01 02 03 04")

    def test_txt_state_cpuid_error(self):
        """Test txt_state with CPUID error."""
        self.mock_cs.hals.CPU.cpuid.side_effect = Exception("CPUID failed")

        # Mock other methods to avoid further errors
        self.mock_cs.register.is_defined.return_value = False

        with patch.object(self.txt_command.logger, 'log') as mock_log:
            # Should handle CPUID error gracefully
            with self.assertRaises(Exception):
                self.txt_command.txt_state()

    def test_txt_state_cr4_error(self):
        """Test txt_state with CR4 read error."""
        self.mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        self.mock_cs.hals.CPU.read_cr.side_effect = Exception("CR4 read failed")

        # Mock other methods to avoid further errors
        self.mock_cs.register.is_defined.return_value = False

        with patch.object(self.txt_command.logger, 'log') as mock_log:
            # Should handle CR4 error gracefully
            with self.assertRaises(Exception):
                self.txt_command.txt_state()

    def test_txt_state_all_registers_undefined(self):
        """Test txt_state with all registers undefined."""
        self.mock_cs.register.is_defined.return_value = False
        self.mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        self.mock_cs.hals.CPU.read_cr.return_value = 0
        self.mock_cs.hals.Msr.read_msr.return_value = (0, 0)

        with patch.object(self.txt_command.logger, 'log') as mock_log:
            self.txt_command.txt_state()

            # Should still log CPUID and CR4 information
            mock_log.assert_any_call("[CHIPSEC] CPUID.01H.ECX[Bit 6] = 0 << Safer Mode Extensions (SMX)")
            mock_log.assert_any_call("[CHIPSEC] CR4.SMXE[Bit 14] = 0 << Safer Mode Extensions Enable")

    def test_txt_state_public_key_read_error(self):
        """Test txt_state with public key read error."""
        mock_pub_reg = Mock()
        mock_pub_reg.read.side_effect = Exception("Public key read failed")
        self.mock_cs.register.get_list_by_name.return_value = mock_pub_reg

        self.mock_cs.register.is_defined.return_value = False
        self.mock_cs.hals.CPU.cpuid.return_value = (0, 0, 0, 0)
        self.mock_cs.hals.CPU.read_cr.return_value = 0

        with patch.object(self.txt_command.logger, 'log') as mock_log:
            # Should handle public key read error gracefully
            with self.assertRaises(Exception):
                self.txt_command.txt_state()

    def test_run_with_none_func(self):
        """Test run method when func is None."""
        self.txt_command.func = None

        # Should handle None func gracefully
        self.txt_command.run()

        # Should set exit code to ERROR
        from chipsec.testcase import ExitCode
        self.assertEqual(self.txt_command.ExitCode, ExitCode.ERROR)


class TestTXTCommandConfigurationValidation(unittest.TestCase):
    """Test configuration validation aspects of TXT command."""

    def setUp(self):
        """Set up test fixtures."""
        # Create ChipsecCs with TXT-specific configuration
        self.txt_cs = MockFactory.create_mock_chipsec_cs()

        # Mock TXT configuration
        self.txt_cs.Cfg = Mock()
        self.txt_cs.Cfg.CONFIG_TXT = {
            'TXT_PUBLIC_BASE': 0xFED30000,
            'TXT_PUBLIC_SIZE': 0x1000,
            'TXT_PRIVATE_BASE': 0xFED20000,
            'TXT_SINIT_BASE': 0xFED40000
        }

        self.txt_cs.hals = Mock()
        self.txt_cs.hals.Memory = Mock()
        self.txt_cs.register = Mock()
        self.txt_cs.set_scope = Mock()

    def test_txt_configuration_structure(self):
        """Test TXT configuration structure."""
        txt_config = self.txt_cs.Cfg.CONFIG_TXT

        # Test that required TXT configuration exists
        self.assertIn('TXT_PUBLIC_BASE', txt_config)
        self.assertIn('TXT_PUBLIC_SIZE', txt_config)

        # Test configuration values are reasonable
        self.assertEqual(txt_config['TXT_PUBLIC_BASE'], 0xFED30000)
        self.assertEqual(txt_config['TXT_PUBLIC_SIZE'], 0x1000)

    def test_txt_memory_regions(self):
        """Test TXT memory region configuration."""
        txt_config = self.txt_cs.Cfg.CONFIG_TXT

        # Test memory regions are properly defined
        if 'TXT_PRIVATE_BASE' in txt_config:
            self.assertNotEqual(txt_config['TXT_PRIVATE_BASE'], txt_config['TXT_PUBLIC_BASE'])

        if 'TXT_SINIT_BASE' in txt_config:
            self.assertNotEqual(txt_config['TXT_SINIT_BASE'], txt_config['TXT_PUBLIC_BASE'])

    def test_txt_dump_address_validation(self):
        """Test TXT dump uses correct memory address."""
        txt_cmd = TXTCommand(['dump'], cs=self.txt_cs)

        # Mock memory read
        self.txt_cs.hals.Memory.read_physical_mem.return_value = b'\x00' * 0x1000

        with patch.object(txt_cmd.logger, 'log'):
            txt_cmd.txt_dump()

            # Should read from the correct TXT public base address
            self.txt_cs.hals.Memory.read_physical_mem.assert_called_once_with(0xFED30000, 0x1000)


if __name__ == '__main__':
    unittest.main()
