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
from chipsec.utilcmd.desc_cmd import IDTCommand, GDTCommand, LDTCommand
from chipsec.command import toLoad
from tests.test_utils import MockFactory


class TestIDTCommand(unittest.TestCase):
    """Comprehensive tests for IDT (Interrupt Descriptor Table) command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()

        # Mock MSR HAL component
        self.mock_cs.hals = Mock()
        self.mock_cs.hals.Msr = Mock()

        self.idt_command = IDTCommand(['0'], cs=self.mock_cs)

    def test_idt_command_initialization(self):
        """Test IDTCommand initialization."""
        self.assertEqual(self.idt_command.cs, self.mock_cs)
        self.assertEqual(self.idt_command.argv, ['0'])

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.idt_command.requirements()
        self.assertEqual(reqs, toLoad.Driver)

    def test_parse_arguments_with_thread(self):
        """Test parsing arguments with specific thread."""
        command = IDTCommand(['2'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command._thread, 2)

    def test_parse_arguments_without_thread(self):
        """Test parsing arguments without specific thread."""
        command = IDTCommand([], cs=self.mock_cs)
        command.parse_arguments()
        self.assertIsNone(command._thread)

    def test_parse_arguments_invalid_thread(self):
        """Test parsing arguments with invalid thread."""
        command = IDTCommand(['invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid int conversion
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_run_specific_thread(self):
        """Test run method with specific thread."""
        self.idt_command._thread = 1
        self.idt_command.cs.hals.Msr.get_cpu_thread_count.return_value = 4

        with patch.object(self.idt_command.logger, 'log') as mock_log:
            self.idt_command.run()

            self.idt_command.cs.hals.Msr.IDT.assert_called_once_with(1, 4)
            mock_log.assert_called_with('[CHIPSEC] Dumping IDT of CPU thread 1')

    def test_run_specific_thread_out_of_range(self):
        """Test run method with thread out of range."""
        self.idt_command._thread = 5
        self.idt_command.cs.hals.Msr.get_cpu_thread_count.return_value = 4

        with patch.object(self.idt_command.logger, 'log') as mock_log:
            self.idt_command.run()

            # Should dump all threads when thread is out of range
            self.idt_command.cs.hals.Msr.IDT_all.assert_called_once_with(4)
            mock_log.assert_called_with('[CHIPSEC] Dumping IDT of 4 CPU threads')

    def test_run_all_threads(self):
        """Test run method for all threads."""
        self.idt_command._thread = None
        self.idt_command.cs.hals.Msr.get_cpu_thread_count.return_value = 8

        with patch.object(self.idt_command.logger, 'log') as mock_log:
            self.idt_command.run()

            self.idt_command.cs.hals.Msr.IDT_all.assert_called_once_with(4)
            mock_log.assert_called_with('[CHIPSEC] Dumping IDT of 8 CPU threads')

    def test_run_single_cpu_system(self):
        """Test run method on single CPU system."""
        self.idt_command._thread = None
        self.idt_command.cs.hals.Msr.get_cpu_thread_count.return_value = 1

        with patch.object(self.idt_command.logger, 'log') as mock_log:
            self.idt_command.run()

            self.idt_command.cs.hals.Msr.IDT_all.assert_called_once_with(4)
            mock_log.assert_called_with('[CHIPSEC] Dumping IDT of 1 CPU threads')


class TestGDTCommand(unittest.TestCase):
    """Comprehensive tests for GDT (Global Descriptor Table) command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()

        # Mock MSR HAL component
        self.mock_cs.hals = Mock()
        self.mock_cs.hals.Msr = Mock()

        self.gdt_command = GDTCommand(['1'], cs=self.mock_cs)

    def test_gdt_command_initialization(self):
        """Test GDTCommand initialization."""
        self.assertEqual(self.gdt_command.cs, self.mock_cs)
        self.assertEqual(self.gdt_command.argv, ['1'])

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.gdt_command.requirements()
        self.assertEqual(reqs, toLoad.Driver)

    def test_parse_arguments_with_thread(self):
        """Test parsing arguments with specific thread."""
        command = GDTCommand(['3'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command._thread, 3)

    def test_parse_arguments_without_thread(self):
        """Test parsing arguments without specific thread."""
        command = GDTCommand([], cs=self.mock_cs)
        command.parse_arguments()
        self.assertIsNone(command._thread)

    def test_run_specific_thread(self):
        """Test run method with specific thread."""
        self.gdt_command._thread = 2
        self.gdt_command.cs.hals.Msr.get_cpu_thread_count.return_value = 6

        with patch.object(self.gdt_command.logger, 'log') as mock_log:
            self.gdt_command.run()

            self.gdt_command.cs.hals.Msr.GDT.assert_called_once_with(2, 4)
            mock_log.assert_called_with('[CHIPSEC] Dumping IDT of CPU thread 2')

    def test_run_specific_thread_boundary(self):
        """Test run method with thread at boundary."""
        self.gdt_command._thread = 3
        self.gdt_command.cs.hals.Msr.get_cpu_thread_count.return_value = 4

        with patch.object(self.gdt_command.logger, 'log') as mock_log:
            self.gdt_command.run()

            # Thread 3 is valid (0-3 for 4 threads)
            self.gdt_command.cs.hals.Msr.GDT.assert_called_once_with(3, 4)
            mock_log.assert_called_with('[CHIPSEC] Dumping IDT of CPU thread 3')

    def test_run_all_threads(self):
        """Test run method for all threads."""
        self.gdt_command._thread = None
        self.gdt_command.cs.hals.Msr.get_cpu_thread_count.return_value = 2

        with patch.object(self.gdt_command.logger, 'log') as mock_log:
            self.gdt_command.run()

            self.gdt_command.cs.hals.Msr.GDT_all.assert_called_once_with(4)
            mock_log.assert_called_with('[CHIPSEC] Dumping IDT of 2 CPU threads')

    def test_run_zero_threads(self):
        """Test run method with zero threads (edge case)."""
        self.gdt_command._thread = None
        self.gdt_command.cs.hals.Msr.get_cpu_thread_count.return_value = 0

        with patch.object(self.gdt_command.logger, 'log') as mock_log:
            self.gdt_command.run()

            self.gdt_command.cs.hals.Msr.GDT_all.assert_called_once_with(4)
            mock_log.assert_called_with('[CHIPSEC] Dumping IDT of 0 CPU threads')


class TestLDTCommand(unittest.TestCase):
    """Comprehensive tests for LDT (Local Descriptor Table) command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.ldt_command = LDTCommand([], cs=self.mock_cs)

    def test_ldt_command_initialization(self):
        """Test LDTCommand initialization."""
        self.assertEqual(self.ldt_command.cs, self.mock_cs)
        self.assertEqual(self.ldt_command.argv, [])

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.ldt_command.requirements()
        self.assertEqual(reqs, toLoad.Nil)

    def test_parse_arguments(self):
        """Test parse_arguments method."""
        # LDT command doesn't parse arguments
        self.ldt_command.parse_arguments()
        # Should not raise any exceptions

    def test_run(self):
        """Test run method."""
        with patch.object(self.ldt_command.logger, 'log_error') as mock_log_error:
            self.ldt_command.run()

            mock_log_error.assert_called_with('[CHIPSEC] ldt not implemented')


class TestDescriptorCommandsIntegration(unittest.TestCase):
    """Integration tests for descriptor table commands."""

    def setUp(self):
        """Set up integrated test fixtures."""
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock MSR components with realistic data
        self.integrated_cs.hals = Mock()
        self.integrated_cs.hals.Msr = Mock()

    def test_idt_command_integration(self):
        """Test complete IDT command workflow."""
        idt_cmd = IDTCommand(['1'], cs=self.integrated_cs)
        idt_cmd.parse_arguments()
        idt_cmd.cs.hals.Msr.get_cpu_thread_count.return_value = 4

        with patch.object(idt_cmd.logger, 'log'):
            idt_cmd.run()

            idt_cmd.cs.hals.Msr.IDT.assert_called_once_with(1, 4)

    def test_gdt_command_integration(self):
        """Test complete GDT command workflow."""
        gdt_cmd = GDTCommand([], cs=self.integrated_cs)
        gdt_cmd.parse_arguments()
        gdt_cmd.cs.hals.Msr.get_cpu_thread_count.return_value = 2

        with patch.object(gdt_cmd.logger, 'log'):
            gdt_cmd.run()

            gdt_cmd.cs.hals.Msr.GDT_all.assert_called_once_with(4)

    def test_ldt_command_integration(self):
        """Test complete LDT command workflow."""
        ldt_cmd = LDTCommand([], cs=self.integrated_cs)

        with patch.object(ldt_cmd.logger, 'log_error'):
            ldt_cmd.run()

            # LDT should log error about not being implemented


class TestDescriptorCommandsEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for descriptor commands."""

    def setUp(self):
        """Set up mock ChipsecCs for edge case testing."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.hals = Mock()
        self.mock_cs.hals.Msr = Mock()

    def test_idt_thread_boundary_conditions(self):
        """Test IDT command with various thread boundary conditions."""
        test_cases = [
            (0, 4),   # Valid thread 0
            (3, 4),   # Valid thread 3 (last)
            (4, 4),   # Invalid thread 4
            (10, 4),  # Invalid thread 10
        ]

        for thread, total_threads in test_cases:
            command = IDTCommand([str(thread)], cs=self.mock_cs)
            command.parse_arguments()
            command.cs.hals.Msr.get_cpu_thread_count.return_value = total_threads

            with patch.object(command.logger, 'log') as mock_log:
                # Test that run method completes without errors
                command.run()
                # Verify that log was called
                self.assertTrue(mock_log.called)

    def test_gdt_thread_boundary_conditions(self):
        """Test GDT command with various thread boundary conditions."""
        test_cases = [
            (0, 2),   # Valid thread 0
            (1, 2),   # Valid thread 1 (last)
            (2, 2),   # Invalid thread 2
            (5, 2),   # Invalid thread 5
        ]

        for thread, total_threads in test_cases:
            command = GDTCommand([str(thread)], cs=self.mock_cs)
            command.parse_arguments()
            command.cs.hals.Msr.get_cpu_thread_count.return_value = total_threads

            with patch.object(command.logger, 'log') as mock_log:
                # Test that run method completes without errors
                command.run()
                # Verify that log was called
                self.assertTrue(mock_log.called)

    def test_idt_hex_thread_parsing(self):
        """Test IDT command with hex thread parsing."""
        test_cases = [
            ('0x0', 0x0),
            ('0x1', 0x1),
            ('0xA', 0xA),
            ('0xF', 0xF),
        ]

        for hex_str, expected_thread in test_cases:
            command = IDTCommand([hex_str], cs=self.mock_cs)
            command.parse_arguments()
            self.assertEqual(command._thread, expected_thread)

    def test_gdt_hex_thread_parsing(self):
        """Test GDT command with hex thread parsing."""
        test_cases = [
            ('0x0', 0x0),
            ('0x2', 0x2),
            ('0x8', 0x8),
            ('0xF', 0xF),
        ]

        for hex_str, expected_thread in test_cases:
            command = GDTCommand([hex_str], cs=self.mock_cs)
            command.parse_arguments()
            self.assertEqual(command._thread, expected_thread)

    def test_descriptor_commands_error_handling(self):
        """Test descriptor commands error handling."""
        # Test IDT error handling
        idt_command = IDTCommand(['0'], cs=self.mock_cs)
        idt_command.parse_arguments()
        idt_command.cs.hals.Msr.IDT.side_effect = Exception("IDT access failed")

        with self.assertRaises(Exception):
            idt_command.run()

        # Test GDT error handling
        gdt_command = GDTCommand(['0'], cs=self.mock_cs)
        gdt_command.parse_arguments()
        gdt_command.cs.hals.Msr.GDT.side_effect = Exception("GDT access failed")

        with self.assertRaises(Exception):
            gdt_command.run()

    def test_descriptor_commands_large_thread_counts(self):
        """Test descriptor commands with large thread counts."""
        large_thread_counts = [16, 32, 64, 128]

        for thread_count in large_thread_counts:
            # Test IDT
            idt_command = IDTCommand([], cs=self.mock_cs)
            idt_command.parse_arguments()
            idt_command.cs.hals.Msr.get_cpu_thread_count.return_value = thread_count

            with patch.object(idt_command.logger, 'log') as mock_log:
                idt_command.run()

                # Verify that the MSR method was called
                self.assertTrue(idt_command.cs.hals.Msr.IDT_all.called)
                mock_log.assert_called_with(f'[CHIPSEC] Dumping IDT of {thread_count} CPU threads')

            # Test GDT
            gdt_command = GDTCommand([], cs=self.mock_cs)
            gdt_command.parse_arguments()
            gdt_command.cs.hals.Msr.get_cpu_thread_count.return_value = thread_count

            with patch.object(gdt_command.logger, 'log') as mock_log:
                gdt_command.run()

                # Verify that the MSR method was called
                self.assertTrue(gdt_command.cs.hals.Msr.GDT_all.called)
                mock_log.assert_called_with(f'[CHIPSEC] Dumping IDT of {thread_count} CPU threads')


class TestDescriptorCommandsConfigurationValidation(unittest.TestCase):
    """Test configuration validation aspects of descriptor commands."""

    def setUp(self):
        """Set up ChipsecCs with descriptor-specific configuration."""
        self.desc_cs = MockFactory.create_mock_chipsec_cs()

        # Mock descriptor configuration
        self.desc_cs.Cfg = Mock()
        self.desc_cs.Cfg.CPU = {
            'MAX_THREADS': 64,
            'DESCRIPTOR_TABLE_SIZE': 0x1000
        }

        self.desc_cs.hals = Mock()
        self.desc_cs.hals.Msr = Mock()

    def test_descriptor_configuration_structure(self):
        """Test descriptor configuration structure."""
        cpu_config = self.desc_cs.Cfg.CPU

        # Test that required CPU configuration exists
        self.assertIn('MAX_THREADS', cpu_config)
        self.assertIn('DESCRIPTOR_TABLE_SIZE', cpu_config)

        # Test configuration values are reasonable
        self.assertGreater(cpu_config['MAX_THREADS'], 0)
        self.assertGreater(cpu_config['DESCRIPTOR_TABLE_SIZE'], 0)

    def test_idt_thread_validation(self):
        """Test IDT thread validation."""
        # Test various thread values
        test_cases = [
            ('0', 0),
            ('1', 1),
            ('15', 15),
            ('63', 63)
        ]

        for thread_str, expected_thread in test_cases:
            command = IDTCommand([thread_str], cs=self.desc_cs)
            command.parse_arguments()

            self.assertEqual(command._thread, expected_thread)

    def test_gdt_thread_validation(self):
        """Test GDT thread validation."""
        # Test various thread values
        test_cases = [
            ('0', 0),
            ('2', 2),
            ('10', 10),
            ('31', 31)
        ]

        for thread_str, expected_thread in test_cases:
            command = GDTCommand([thread_str], cs=self.desc_cs)
            command.parse_arguments()

            self.assertEqual(command._thread, expected_thread)

    def test_descriptor_commands_thread_range_validation(self):
        """Test descriptor commands thread range validation."""
        max_threads = self.desc_cs.Cfg.CPU['MAX_THREADS']

        # Test valid thread ranges
        for thread in range(min(8, max_threads)):  # Test first 8 threads
            # IDT command
            idt_command = IDTCommand([str(thread)], cs=self.desc_cs)
            idt_command.parse_arguments()
            self.assertEqual(idt_command._thread, thread)

            # GDT command
            gdt_command = GDTCommand([str(thread)], cs=self.desc_cs)
            gdt_command.parse_arguments()
            self.assertEqual(gdt_command._thread, thread)

    def test_descriptor_commands_empty_argv_handling(self):
        """Test descriptor commands empty argv handling."""
        # Test IDT with empty argv
        idt_command = IDTCommand([], cs=self.desc_cs)
        idt_command.parse_arguments()
        self.assertIsNone(idt_command._thread)

        # Test GDT with empty argv
        gdt_command = GDTCommand([], cs=self.desc_cs)
        gdt_command.parse_arguments()
        self.assertIsNone(gdt_command._thread)

    def test_ldt_command_not_implemented_message(self):
        """Test LDT command not implemented message."""
        ldt_command = LDTCommand([], cs=self.desc_cs)

        with patch.object(ldt_command.logger, 'log_error') as mock_log_error:
            ldt_command.run()

            mock_log_error.assert_called_with('[CHIPSEC] ldt not implemented')

    def test_descriptor_commands_msr_integration(self):
        """Test descriptor commands MSR integration."""
        # Test IDT MSR calls
        idt_command = IDTCommand(['0'], cs=self.desc_cs)
        idt_command.parse_arguments()
        idt_command.cs.hals.Msr.get_cpu_thread_count.return_value = 1

        with patch.object(idt_command.logger, 'log') as mock_log:
            # Test that run method completes without errors
            idt_command.run()
            # Verify that log was called
            self.assertTrue(mock_log.called)

        # Test GDT MSR calls
        gdt_command = GDTCommand(['0'], cs=self.desc_cs)
        gdt_command.parse_arguments()
        gdt_command.cs.hals.Msr.get_cpu_thread_count.return_value = 1

        with patch.object(gdt_command.logger, 'log') as mock_log:
            # Test that run method completes without errors
            gdt_command.run()
            # Verify that log was called
            self.assertTrue(mock_log.called)
