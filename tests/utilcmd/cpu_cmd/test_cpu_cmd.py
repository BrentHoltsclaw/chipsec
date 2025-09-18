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
import pytest
from unittest.mock import Mock
from chipsec.utilcmd.cpu_cmd import CPUCommand
from tests.test_utils import MockFactory


class TestCPUCommand(unittest.TestCase):
    """Test CPU utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock ChipsecCs object
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        # Mock CPU HAL
        self.mock_cs.hals.CPU = Mock()
        self.mock_cs.hals.Msr = Mock()
        self.mock_cs.helper = Mock()

        # Create CPUCommand instance
        self.cpu_command = CPUCommand(['info'], cs=self.mock_cs)

    @pytest.mark.unit
    def test_cpu_command_initialization(self):
        """Test CPUCommand initialization."""
        assert self.cpu_command.cs == self.mock_cs
        assert self.cpu_command.argv == ['info']

    @pytest.mark.unit
    def test_parse_arguments_info(self):
        """Test parsing info command arguments."""
        command = CPUCommand(['info'], cs=self.mock_cs)
        command.parse_arguments()
        assert hasattr(command, 'func')
        assert command.func == command.cpu_info

    @pytest.mark.unit
    def test_parse_arguments_cr_read(self):
        """Test parsing CR read command arguments."""
        command = CPUCommand(['cr', '0', '3'], cs=self.mock_cs)
        command.parse_arguments()
        assert command.thread == 0
        assert command.cr_number == 3
        assert command.value is None
        assert command.func == command.cpu_cr

    @pytest.mark.unit
    def test_parse_arguments_cr_write(self):
        """Test parsing CR write command arguments."""
        command = CPUCommand(['cr', '1', '4', '0x12345678'], cs=self.mock_cs)
        command.parse_arguments()
        assert command.thread == 1
        assert command.cr_number == 4
        assert command.value == 0x12345678
        assert command.func == command.cpu_cr

    @pytest.mark.unit
    def test_parse_arguments_cpuid(self):
        """Test parsing CPUID command arguments."""
        command = CPUCommand(['cpuid', '0x40000000'], cs=self.mock_cs)
        command.parse_arguments()
        assert command.eax == 0x40000000
        assert command.ecx == 0
        assert command.func == command.cpu_cpuid

    @pytest.mark.unit
    def test_parse_arguments_cpuid_with_ecx(self):
        """Test parsing CPUID command arguments with ECX."""
        command = CPUCommand(['cpuid', '0x40000000', '0x1'], cs=self.mock_cs)
        command.parse_arguments()
        assert command.eax == 0x40000000
        assert command.ecx == 0x1
        assert command.func == command.cpu_cpuid

    @pytest.mark.unit
    def test_parse_arguments_pt(self):
        """Test parsing page table command arguments."""
        command = CPUCommand(['pt'], cs=self.mock_cs)
        command.parse_arguments()
        assert command.cr3 is None
        assert command.func == command.cpu_pt

    @pytest.mark.unit
    def test_parse_arguments_pt_with_cr3(self):
        """Test parsing page table command arguments with CR3."""
        command = CPUCommand(['pt', '0x12345678'], cs=self.mock_cs)
        command.parse_arguments()
        assert command.cr3 == 0x12345678
        assert command.func == command.cpu_pt

    @pytest.mark.unit
    def test_parse_arguments_topology(self):
        """Test parsing topology command arguments."""
        command = CPUCommand(['topology'], cs=self.mock_cs)
        command.parse_arguments()
        assert command.func == command.cpu_topology

    @pytest.mark.unit
    def test_requirements(self):
        """Test command requirements."""
        reqs = self.cpu_command.requirements()
        assert hasattr(reqs, 'load_driver')
        assert hasattr(reqs, 'load_config')

    @pytest.mark.unit
    def test_cpu_info(self):
        """Test cpu_info command execution."""
        # Mock CPU HAL methods
        self.mock_cs.hals.CPU.is_HT_active.return_value = True
        self.mock_cs.hals.CPU.get_number_logical_processor_per_core.return_value = 2
        self.mock_cs.hals.CPU.get_number_logical_processor_per_package.return_value = 8
        self.mock_cs.hals.CPU.get_number_physical_processor_per_package.return_value = 4
        self.mock_cs.hals.CPU.get_number_threads_from_APIC_table.return_value = 8
        self.mock_cs.hals.CPU.get_number_sockets_from_APIC_table.return_value = 1

        self.cpu_command.cpu_info()

        # Verify CPU HAL methods were called
        self.mock_cs.hals.CPU.is_HT_active.assert_called_once()
        self.mock_cs.hals.CPU.get_number_logical_processor_per_core.assert_called_once()
        self.mock_cs.hals.CPU.get_number_logical_processor_per_package.assert_called_once()
        self.mock_cs.hals.CPU.get_number_physical_processor_per_package.assert_called_once()
        self.mock_cs.hals.CPU.get_number_threads_from_APIC_table.assert_called_once()
        self.mock_cs.hals.CPU.get_number_sockets_from_APIC_table.assert_called_once()

    @pytest.mark.unit
    def test_cpu_info_exception_handling(self):
        """Test cpu_info command with exception handling."""
        # Mock CPU HAL methods to raise exceptions
        self.mock_cs.hals.CPU.is_HT_active.return_value = True
        self.mock_cs.hals.CPU.get_number_logical_processor_per_core.return_value = 2
        self.mock_cs.hals.CPU.get_number_logical_processor_per_package.return_value = 8
        self.mock_cs.hals.CPU.get_number_physical_processor_per_package.return_value = 4
        self.mock_cs.hals.CPU.get_number_threads_from_APIC_table.side_effect = Exception("APIC error")
        self.mock_cs.hals.CPU.get_number_sockets_from_APIC_table.side_effect = Exception("Socket error")

        # Should not raise exception
        self.cpu_command.cpu_info()

    @pytest.mark.unit
    def test_cpu_cr_read_specific(self):
        """Test cpu_cr command reading specific CR."""
        self.cpu_command.thread = 0
        self.cpu_command.cr_number = 3
        self.cpu_command.value = None

        self.mock_cs.hals.CPU.read_cr.return_value = 0x12345678

        result = self.cpu_command.cpu_cr()

        assert result == 0x12345678
        self.mock_cs.hals.CPU.read_cr.assert_called_once_with(0, 3)

    @pytest.mark.unit
    def test_cpu_cr_write(self):
        """Test cpu_cr command writing CR."""
        self.cpu_command.thread = 1
        self.cpu_command.cr_number = 4
        self.cpu_command.value = 0x87654321

        self.mock_cs.hals.CPU.write_cr.return_value = True

        result = self.cpu_command.cpu_cr()

        assert result is True
        self.mock_cs.hals.CPU.write_cr.assert_called_once_with(1, 4, 0x87654321)

    @pytest.mark.unit
    def test_cpu_cr_read_all(self):
        """Test cpu_cr command reading all CRs."""
        self.cpu_command.thread = None
        self.cpu_command.cr_number = None
        self.cpu_command.value = None

        self.mock_cs.hals.Msr.get_cpu_thread_count.return_value = 1
        self.mock_cs.hals.CPU.read_cr.side_effect = [0x12345678, 0x11111111, 0x22222222, 0x33333333, 0x44444444]

        result = self.cpu_command.cpu_cr()

        assert result is None  # No specific return value
        assert self.mock_cs.hals.CPU.read_cr.call_count == 5  # CR0, CR2, CR3, CR4, CR8

    @pytest.mark.unit
    def test_cpu_cpuid(self):
        """Test cpu_cpuid command execution."""
        self.cpu_command.eax = 0x40000000
        self.cpu_command.ecx = 0x1

        self.mock_cs.hals.CPU.cpuid.return_value = (0x12345678, 0x11111111, 0x22222222, 0x33333333)

        self.cpu_command.cpu_cpuid()

        self.mock_cs.hals.CPU.cpuid.assert_called_once_with(0x40000000, 0x1)

    @pytest.mark.unit
    def test_cpu_pt_specific_cr3(self):
        """Test cpu_pt command with specific CR3."""
        self.cpu_command.cr3 = 0x12345678

        self.cpu_command.cpu_pt()

        self.mock_cs.hals.CPU.dump_page_tables.assert_called_once_with(0x12345678, 'pt_12345678')

    @pytest.mark.unit
    def test_cpu_pt_all_threads(self):
        """Test cpu_pt command for all threads."""
        self.cpu_command.cr3 = None

        self.mock_cs.hals.Msr.get_cpu_thread_count.return_value = 2
        self.mock_cs.hals.CPU.read_cr.side_effect = [0x11111111, 0x22222222]

        self.cpu_command.cpu_pt()

        assert self.mock_cs.hals.CPU.dump_page_tables.call_count == 2
        self.mock_cs.hals.CPU.dump_page_tables.assert_any_call(0x11111111, 'cpu0_pt_11111111')
        self.mock_cs.hals.CPU.dump_page_tables.assert_any_call(0x22222222, 'cpu1_pt_22222222')

    @pytest.mark.unit
    def test_cpu_topology(self):
        """Test cpu_topology command execution."""
        # Mock CPU HAL methods
        self.mock_cs.hals.CPU.is_HT_active.return_value = True
        self.mock_cs.hals.CPU.get_number_logical_processor_per_core.return_value = 2
        self.mock_cs.hals.CPU.get_number_logical_processor_per_package.return_value = 8
        self.mock_cs.hals.CPU.get_number_physical_processor_per_package.return_value = 4
        self.mock_cs.helper.get_threads_count.return_value = 8

        mock_topology = {
            'packages': {0: [0, 1, 2, 3, 4, 5, 6, 7]},
            'cores': {0: [0, 4], 1: [1, 5], 2: [2, 6], 3: [3, 7]},
            'threads': 8
        }
        self.mock_cs.hals.CPU.get_cpu_topology.return_value = mock_topology

        result = self.cpu_command.cpu_topology()

        assert result == mock_topology
        self.mock_cs.hals.CPU.get_cpu_topology.assert_called_once()

    @pytest.mark.unit
    def test_commands_dictionary(self):
        """Test commands dictionary is properly defined."""
        from chipsec.utilcmd.cpu_cmd import commands
        assert 'cpu' in commands
        assert commands['cpu'] == CPUCommand


if __name__ == '__main__':
    pytest.main([__file__])
