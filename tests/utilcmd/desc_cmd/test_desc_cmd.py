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
from chipsec.utilcmd.desc_cmd import IDTCommand, GDTCommand, LDTCommand
from tests.test_utils import MockFactory


class TestIDTCommand:
    """Comprehensive tests for IDT (Interrupt Descriptor Table) command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for IDT testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock MSR HAL component
        cs_mock.hals = Mock()
        cs_mock.hals.Msr = Mock()

        return cs_mock

    @pytest.fixture
    def idt_command(self, mock_cs):
        """Create IDTCommand instance."""
        return IDTCommand(['0'], cs=mock_cs)

    @pytest.mark.unit
    def test_idt_command_initialization(self, idt_command, mock_cs):
        """Test IDTCommand initialization."""
        assert idt_command.cs == mock_cs
        assert idt_command.argv == ['0']

    @pytest.mark.unit
    def test_requirements(self, idt_command):
        """Test command requirements."""
        reqs = idt_command.requirements()
        assert reqs == idt_command.toLoad.Driver

    @pytest.mark.unit
    def test_parse_arguments_with_thread(self, mock_cs):
        """Test parsing arguments with specific thread."""
        command = IDTCommand(['2'], cs=mock_cs)
        command.parse_arguments()
        assert command._thread == 2

    @pytest.mark.unit
    def test_parse_arguments_without_thread(self, mock_cs):
        """Test parsing arguments without specific thread."""
        command = IDTCommand([], cs=mock_cs)
        command.parse_arguments()
        assert command._thread is None

    @pytest.mark.unit
    def test_parse_arguments_invalid_thread(self, mock_cs):
        """Test parsing arguments with invalid thread."""
        command = IDTCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid int conversion
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_run_specific_thread(self, idt_command, mock_cs):
        """Test run method with specific thread."""
        idt_command._thread = 1
        idt_command._cs.hals.Msr.get_cpu_thread_count.return_value = 4

        with patch.object(idt_command.logger, 'log') as mock_log:
            idt_command.run()

            idt_command._cs.hals.Msr.IDT.assert_called_once_with(1, 4)
            mock_log.assert_called_with('[CHIPSEC] Dumping IDT of CPU thread 1')

    @pytest.mark.unit
    def test_run_specific_thread_out_of_range(self, idt_command, mock_cs):
        """Test run method with thread out of range."""
        idt_command._thread = 5
        idt_command._cs.hals.Msr.get_cpu_thread_count.return_value = 4

        with patch.object(idt_command.logger, 'log') as mock_log:
            idt_command.run()

            # Should dump all threads when thread is out of range
            idt_command._cs.hals.Msr.IDT_all.assert_called_once_with(4)
            mock_log.assert_called_with('[CHIPSEC] Dumping IDT of 4 CPU threads')

    @pytest.mark.unit
    def test_run_all_threads(self, idt_command, mock_cs):
        """Test run method for all threads."""
        idt_command._thread = None
        idt_command._cs.hals.Msr.get_cpu_thread_count.return_value = 8

        with patch.object(idt_command.logger, 'log') as mock_log:
            idt_command.run()

            idt_command._cs.hals.Msr.IDT_all.assert_called_once_with(4)
            mock_log.assert_called_with('[CHIPSEC] Dumping IDT of 8 CPU threads')

    @pytest.mark.unit
    def test_run_single_cpu_system(self, idt_command, mock_cs):
        """Test run method on single CPU system."""
        idt_command._thread = None
        idt_command._cs.hals.Msr.get_cpu_thread_count.return_value = 1

        with patch.object(idt_command.logger, 'log') as mock_log:
            idt_command.run()

            idt_command._cs.hals.Msr.IDT_all.assert_called_once_with(4)
            mock_log.assert_called_with('[CHIPSEC] Dumping IDT of 1 CPU threads')


class TestGDTCommand:
    """Comprehensive tests for GDT (Global Descriptor Table) command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for GDT testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock MSR HAL component
        cs_mock.hals = Mock()
        cs_mock.hals.Msr = Mock()

        return cs_mock

    @pytest.fixture
    def gdt_command(self, mock_cs):
        """Create GDTCommand instance."""
        return GDTCommand(['1'], cs=mock_cs)

    @pytest.mark.unit
    def test_gdt_command_initialization(self, gdt_command, mock_cs):
        """Test GDTCommand initialization."""
        assert gdt_command.cs == mock_cs
        assert gdt_command.argv == ['1']

    @pytest.mark.unit
    def test_requirements(self, gdt_command):
        """Test command requirements."""
        reqs = gdt_command.requirements()
        assert reqs == gdt_command.toLoad.Driver

    @pytest.mark.unit
    def test_parse_arguments_with_thread(self, mock_cs):
        """Test parsing arguments with specific thread."""
        command = GDTCommand(['3'], cs=mock_cs)
        command.parse_arguments()
        assert command._thread == 3

    @pytest.mark.unit
    def test_parse_arguments_without_thread(self, mock_cs):
        """Test parsing arguments without specific thread."""
        command = GDTCommand([], cs=mock_cs)
        command.parse_arguments()
        assert command._thread is None

    @pytest.mark.unit
    def test_run_specific_thread(self, gdt_command, mock_cs):
        """Test run method with specific thread."""
        gdt_command._thread = 2
        gdt_command._cs.hals.Msr.get_cpu_thread_count.return_value = 6

        with patch.object(gdt_command.logger, 'log') as mock_log:
            gdt_command.run()

            gdt_command._cs.hals.Msr.GDT.assert_called_once_with(2, 4)
            mock_log.assert_called_with('[CHIPSEC] Dumping IDT of CPU thread 2')

    @pytest.mark.unit
    def test_run_specific_thread_boundary(self, gdt_command, mock_cs):
        """Test run method with thread at boundary."""
        gdt_command._thread = 3
        gdt_command._cs.hals.Msr.get_cpu_thread_count.return_value = 4

        with patch.object(gdt_command.logger, 'log') as mock_log:
            gdt_command.run()

            # Thread 3 is valid (0-3 for 4 threads)
            gdt_command._cs.hals.Msr.GDT.assert_called_once_with(3, 4)
            mock_log.assert_called_with('[CHIPSEC] Dumping IDT of CPU thread 3')

    @pytest.mark.unit
    def test_run_all_threads(self, gdt_command, mock_cs):
        """Test run method for all threads."""
        gdt_command._thread = None
        gdt_command._cs.hals.Msr.get_cpu_thread_count.return_value = 2

        with patch.object(gdt_command.logger, 'log') as mock_log:
            gdt_command.run()

            gdt_command._cs.hals.Msr.GDT_all.assert_called_once_with(4)
            mock_log.assert_called_with('[CHIPSEC] Dumping IDT of 2 CPU threads')

    @pytest.mark.unit
    def test_run_zero_threads(self, gdt_command, mock_cs):
        """Test run method with zero threads (edge case)."""
        gdt_command._thread = None
        gdt_command._cs.hals.Msr.get_cpu_thread_count.return_value = 0

        with patch.object(gdt_command.logger, 'log') as mock_log:
            gdt_command.run()

            gdt_command._cs.hals.Msr.GDT_all.assert_called_once_with(4)
            mock_log.assert_called_with('[CHIPSEC] Dumping IDT of 0 CPU threads')


class TestLDTCommand:
    """Comprehensive tests for LDT (Local Descriptor Table) command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for LDT testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        return cs_mock

    @pytest.fixture
    def ldt_command(self, mock_cs):
        """Create LDTCommand instance."""
        return LDTCommand([], cs=mock_cs)

    @pytest.mark.unit
    def test_ldt_command_initialization(self, ldt_command, mock_cs):
        """Test LDTCommand initialization."""
        assert ldt_command.cs == mock_cs
        assert ldt_command.argv == []

    @pytest.mark.unit
    def test_requirements(self, ldt_command):
        """Test command requirements."""
        reqs = ldt_command.requirements()
        assert reqs == ldt_command.toLoad.Nil

    @pytest.mark.unit
    def test_parse_arguments(self, ldt_command, mock_cs):
        """Test parse_arguments method."""
        # LDT command doesn't parse arguments
        ldt_command.parse_arguments()
        # Should not raise any exceptions

    @pytest.mark.unit
    def test_run(self, ldt_command, mock_cs):
        """Test run method."""
        with patch.object(ldt_command.logger, 'log_error') as mock_log_error:
            ldt_command.run()

            mock_log_error.assert_called_with('[CHIPSEC] ldt not implemented')


class TestDescriptorCommandsIntegration:
    """Integration tests for descriptor table commands."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for descriptor testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock MSR components with realistic data
        cs_mock.hals = Mock()
        cs_mock.hals.Msr = Mock()

        return cs_mock

    @pytest.mark.integration
    def test_idt_command_integration(self, integrated_cs):
        """Test complete IDT command workflow."""
        idt_cmd = IDTCommand(['1'], cs=integrated_cs)
        idt_cmd._cs.hals.Msr.get_cpu_thread_count.return_value = 4

        with patch.object(idt_cmd.logger, 'log'):
            idt_cmd.run()

            idt_cmd._cs.hals.Msr.IDT.assert_called_once_with(1, 4)

    @pytest.mark.integration
    def test_gdt_command_integration(self, integrated_cs):
        """Test complete GDT command workflow."""
        gdt_cmd = GDTCommand([], cs=integrated_cs)
        gdt_cmd._cs.hals.Msr.get_cpu_thread_count.return_value = 2

        with patch.object(gdt_cmd.logger, 'log'):
            gdt_cmd.run()

            gdt_cmd._cs.hals.Msr.GDT_all.assert_called_once_with(4)

    @pytest.mark.integration
    def test_ldt_command_integration(self, integrated_cs):
        """Test complete LDT command workflow."""
        ldt_cmd = LDTCommand([], cs=integrated_cs)

        with patch.object(ldt_cmd.logger, 'log_error'):
            ldt_cmd.run()

            # LDT should log error about not being implemented


class TestDescriptorCommandsEdgeCases:
    """Test edge cases and error conditions for descriptor commands."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        cs_mock.hals.Msr = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_idt_thread_boundary_conditions(self, mock_cs):
        """Test IDT command with various thread boundary conditions."""
        test_cases = [
            (0, 4, True),   # Valid thread 0
            (3, 4, True),   # Valid thread 3 (last)
            (4, 4, False),  # Invalid thread 4
            (10, 4, False), # Invalid thread 10
        ]

        for thread, total_threads, should_call_single in test_cases:
            command = IDTCommand([str(thread)], cs=mock_cs)
            command._cs.hals.Msr.get_cpu_thread_count.return_value = total_threads

            with patch.object(command.logger, 'log'):
                command.run()

                if should_call_single:
                    command._cs.hals.Msr.IDT.assert_called_with(thread, 4)
                else:
                    command._cs.hals.Msr.IDT_all.assert_called_with(4)

    @pytest.mark.unit
    def test_gdt_thread_boundary_conditions(self, mock_cs):
        """Test GDT command with various thread boundary conditions."""
        test_cases = [
            (0, 2, True),   # Valid thread 0
            (1, 2, True),   # Valid thread 1 (last)
            (2, 2, False),  # Invalid thread 2
            (5, 2, False),  # Invalid thread 5
        ]

        for thread, total_threads, should_call_single in test_cases:
            command = GDTCommand([str(thread)], cs=mock_cs)
            command._cs.hals.Msr.get_cpu_thread_count.return_value = total_threads

            with patch.object(command.logger, 'log'):
                command.run()

                if should_call_single:
                    command._cs.hals.Msr.GDT.assert_called_with(thread, 4)
                else:
                    command._cs.hals.Msr.GDT_all.assert_called_with(4)

    @pytest.mark.unit
    def test_idt_hex_thread_parsing(self, mock_cs):
        """Test IDT command with hex thread parsing."""
        test_cases = [
            ('0x0', 0x0),
            ('0x1', 0x1),
            ('0xA', 0xA),
            ('0xF', 0xF),
        ]

        for hex_str, expected_thread in test_cases:
            command = IDTCommand([hex_str], cs=mock_cs)
            command.parse_arguments()
            assert command._thread == expected_thread

    @pytest.mark.unit
    def test_gdt_hex_thread_parsing(self, mock_cs):
        """Test GDT command with hex thread parsing."""
        test_cases = [
            ('0x0', 0x0),
            ('0x2', 0x2),
            ('0x8', 0x8),
            ('0xF', 0xF),
        ]

        for hex_str, expected_thread in test_cases:
            command = GDTCommand([hex_str], cs=mock_cs)
            command.parse_arguments()
            assert command._thread == expected_thread

    @pytest.mark.unit
    def test_descriptor_commands_error_handling(self, mock_cs):
        """Test descriptor commands error handling."""
        # Test IDT error handling
        idt_command = IDTCommand(['0'], cs=mock_cs)
        idt_command._cs.hals.Msr.IDT.side_effect = Exception("IDT access failed")

        with pytest.raises(Exception):
            idt_command.run()

        # Test GDT error handling
        gdt_command = GDTCommand(['0'], cs=mock_cs)
        gdt_command._cs.hals.Msr.GDT.side_effect = Exception("GDT access failed")

        with pytest.raises(Exception):
            gdt_command.run()

    @pytest.mark.unit
    def test_descriptor_commands_large_thread_counts(self, mock_cs):
        """Test descriptor commands with large thread counts."""
        large_thread_counts = [16, 32, 64, 128]

        for thread_count in large_thread_counts:
            # Test IDT
            idt_command = IDTCommand([], cs=mock_cs)
            idt_command._cs.hals.Msr.get_cpu_thread_count.return_value = thread_count

            with patch.object(idt_command.logger, 'log'):
                idt_command.run()

                idt_command._cs.hals.Msr.IDT_all.assert_called_with(4)

            # Test GDT
            gdt_command = GDTCommand([], cs=mock_cs)
            gdt_command._cs.hals.Msr.get_cpu_thread_count.return_value = thread_count

            with patch.object(gdt_command.logger, 'log'):
                gdt_command.run()

                gdt_command._cs.hals.Msr.GDT_all.assert_called_with(4)


class TestDescriptorCommandsConfigurationValidation:
    """Test configuration validation aspects of descriptor commands."""

    @pytest.fixture
    def desc_cs(self):
        """Create ChipsecCs with descriptor-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock descriptor configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.CPU = {
            'MAX_THREADS': 64,
            'DESCRIPTOR_TABLE_SIZE': 0x1000
        }

        cs_mock.hals = Mock()
        cs_mock.hals.Msr = Mock()

        return cs_mock

    @pytest.mark.unit
    def test_descriptor_configuration_structure(self, desc_cs):
        """Test descriptor configuration structure."""
        cpu_config = desc_cs.Cfg.CPU

        # Test that required CPU configuration exists
        assert 'MAX_THREADS' in cpu_config
        assert 'DESCRIPTOR_TABLE_SIZE' in cpu_config

        # Test configuration values are reasonable
        assert cpu_config['MAX_THREADS'] > 0
        assert cpu_config['DESCRIPTOR_TABLE_SIZE'] > 0

    @pytest.mark.unit
    def test_idt_thread_validation(self, desc_cs):
        """Test IDT thread validation."""
        # Test various thread values
        test_cases = [
            ('0', 0),
            ('1', 1),
            ('15', 15),
            ('63', 63)
        ]

        for thread_str, expected_thread in test_cases:
            command = IDTCommand([thread_str], cs=desc_cs)
            command.parse_arguments()

            assert command._thread == expected_thread

    @pytest.mark.unit
    def test_gdt_thread_validation(self, desc_cs):
        """Test GDT thread validation."""
        # Test various thread values
        test_cases = [
            ('0', 0),
            ('2', 2),
            ('10', 10),
            ('31', 31)
        ]

        for thread_str, expected_thread in test_cases:
            command = GDTCommand([thread_str], cs=desc_cs)
            command.parse_arguments()

            assert command._thread == expected_thread

    @pytest.mark.unit
    def test_descriptor_commands_thread_range_validation(self, desc_cs):
        """Test descriptor commands thread range validation."""
        max_threads = desc_cs.Cfg.CPU['MAX_THREADS']

        # Test valid thread ranges
        for thread in range(min(8, max_threads)):  # Test first 8 threads
            # IDT command
            idt_command = IDTCommand([str(thread)], cs=desc_cs)
            idt_command.parse_arguments()
            assert idt_command._thread == thread

            # GDT command
            gdt_command = GDTCommand([str(thread)], cs=desc_cs)
            gdt_command.parse_arguments()
            assert gdt_command._thread == thread

    @pytest.mark.unit
    def test_descriptor_commands_empty_argv_handling(self, desc_cs):
        """Test descriptor commands empty argv handling."""
        # Test IDT with empty argv
        idt_command = IDTCommand([], cs=desc_cs)
        idt_command.parse_arguments()
        assert idt_command._thread is None

        # Test GDT with empty argv
        gdt_command = GDTCommand([], cs=desc_cs)
        gdt_command.parse_arguments()
        assert gdt_command._thread is None

    @pytest.mark.unit
    def test_ldt_command_not_implemented_message(self, desc_cs):
        """Test LDT command not implemented message."""
        ldt_command = LDTCommand([], cs=desc_cs)

        with patch.object(ldt_command.logger, 'log_error') as mock_log_error:
            ldt_command.run()

            mock_log_error.assert_called_with('[CHIPSEC] ldt not implemented')

    @pytest.mark.unit
    def test_descriptor_commands_msr_integration(self, desc_cs):
        """Test descriptor commands MSR integration."""
        # Test IDT MSR calls
        idt_command = IDTCommand(['0'], cs=desc_cs)
        idt_command._cs.hals.Msr.get_cpu_thread_count.return_value = 1

        with patch.object(idt_command.logger, 'log'):
            idt_command.run()

            idt_command._cs.hals.Msr.IDT.assert_called_with(0, 4)

        # Test GDT MSR calls
        gdt_command = GDTCommand(['0'], cs=desc_cs)
        gdt_command._cs.hals.Msr.get_cpu_thread_count.return_value = 1

        with patch.object(gdt_command.logger, 'log'):
            gdt_command.run()

            gdt_command._cs.hals.Msr.GDT.assert_called_with(0, 4)


if __name__ == '__main__':
    pytest.main([__file__])
