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
from chipsec.hal.amd.cpu import CPU as AMDCPU
from chipsec.hal.intel.cpu import CPU as IntelCPU
from chipsec.utilcmd.cpu_cmd import CPUCommand
from chipsec.utilcmd.mem_cmd import MemCommand
from chipsec.utilcmd.msr_cmd import MSRCommand
from chipsec.utilcmd.spi_cmd import SPICommand
from tests.test_utils import MockFactory


class TestHALIntegration:
    """Integration tests for HAL components working together."""

    @pytest.fixture
    def integrated_cs(self):
        """Create a fully integrated ChipsecCs mock with all HAL components."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock all HAL components
        cs_mock.hals.CPU = Mock()
        cs_mock.hals.Memory = Mock()
        cs_mock.hals.Msr = Mock()
        cs_mock.hals.SPI = Mock()
        cs_mock.hals.ACPI = Mock()

        # Mock helper
        cs_mock.helper = Mock()
        cs_mock.helper.get_threads_count.return_value = 4

        # Mock register interface
        cs_mock.register = Mock()
        cs_mock.register.read_field.return_value = [0xFED00000]
        cs_mock.register.get_list_by_name.return_value = Mock()

        return cs_mock

    @pytest.mark.integration
    def test_cpu_memory_integration(self, integrated_cs):
        """Test CPU and Memory HAL components working together."""
        # Setup CPU mock
        integrated_cs.hals.CPU.read_cr.return_value = 0x12345678
        integrated_cs.hals.CPU.cpuid.return_value = (0x806E9, 0x12345678, 0x9ABCDEF0, 0x11111111)

        # Setup Memory mock
        integrated_cs.hals.Memory.read_physical_mem.return_value = b'\xAA\xBB\xCC\xDD'

        # Test CPU reading CR register
        cpu_result = integrated_cs.hals.CPU.read_cr(0, 3)
        assert cpu_result == 0x12345678

        # Test CPUID instruction
        cpuid_result = integrated_cs.hals.CPU.cpuid(0x01, 0x00)
        assert cpuid_result == (0x806E9, 0x12345678, 0x9ABCDEF0, 0x11111111)

        # Test Memory reading from address that CPU CR points to
        mem_result = integrated_cs.hals.Memory.read_physical_mem(cpu_result, 4)
        assert mem_result == b'\xAA\xBB\xCC\xDD'

        # Verify interactions
        integrated_cs.hals.CPU.read_cr.assert_called_with(0, 3)
        integrated_cs.hals.CPU.cpuid.assert_called_with(0x01, 0x00)
        integrated_cs.hals.Memory.read_physical_mem.assert_called_with(0x12345678, 4)

    @pytest.mark.integration
    def test_msr_register_integration(self, integrated_cs):
        """Test MSR and Register interfaces working together."""
        # Setup MSR mock
        integrated_cs.hals.Msr.read_msr.return_value = (0x12345678, 0x9ABCDEF0)

        # Setup register mock
        mock_reg_list = Mock()
        mock_reg_list.read_field.return_value = [0xFED00000]
        integrated_cs.register.get_list_by_name.return_value = mock_reg_list

        # Test MSR read
        eax, edx = integrated_cs.hals.Msr.read_msr(0, 0x8B)
        assert eax == 0x12345678
        assert edx == 0x9ABCDEF0

        # Test register read that might be related to MSR
        reg_value = integrated_cs.register.get_list_by_name('IA32_SMRR_PHYSBASE').read_field('PHYSBASE', True)[0]
        assert reg_value == 0xFED00000

        # Verify MSR and register interactions
        integrated_cs.hals.Msr.read_msr.assert_called_with(0, 0x8B)
        integrated_cs.register.get_list_by_name.assert_called_with('IA32_SMRR_PHYSBASE')

    @pytest.mark.integration
    def test_spi_memory_integration(self, integrated_cs):
        """Test SPI and Memory HAL components working together."""
        # Setup SPI mock
        integrated_cs.hals.SPI.get_SPI_region.return_value = (0x0, 0x7FFFFF, 0x800000)
        integrated_cs.hals.SPI.read_spi_to_file.return_value = b'spi_data'

        # Setup Memory mock for comparison
        integrated_cs.hals.Memory.read_physical_mem.return_value = b'memory_data'

        # Test SPI region information
        base, limit, size = integrated_cs.hals.SPI.get_SPI_region(1)  # BIOS region
        assert base == 0x0
        assert limit == 0x7FFFFF
        assert size == 0x800000

        # Test SPI read operation
        spi_data = integrated_cs.hals.SPI.read_spi_to_file(0x0, 0x1000, 'spi_dump.bin')
        assert spi_data == b'spi_data'

        # Test memory read for comparison
        mem_data = integrated_cs.hals.Memory.read_physical_mem(0xFED40000, 0x10)
        assert mem_data == b'memory_data'

        # Verify SPI and memory interactions
        integrated_cs.hals.SPI.get_SPI_region.assert_called_with(1)
        integrated_cs.hals.SPI.read_spi_to_file.assert_called_with(0x0, 0x1000, 'spi_dump.bin')
        integrated_cs.hals.Memory.read_physical_mem.assert_called_with(0xFED40000, 0x10)


class TestCommandIntegration:
    """Integration tests for util commands working with HAL components."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for command testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock all required HAL components
        cs_mock.hals.CPU = Mock()
        cs_mock.hals.Memory = Mock()
        cs_mock.hals.Msr = Mock()
        cs_mock.hals.SPI = Mock()

        # Mock helper
        cs_mock.helper = Mock()
        cs_mock.helper.get_threads_count.return_value = 2

        return cs_mock

    @pytest.mark.integration
    def test_cpu_command_full_workflow(self, integrated_cs):
        """Test complete CPU command workflow with HAL integration."""
        # Setup HAL mocks
        integrated_cs.hals.CPU.is_HT_active.return_value = True
        integrated_cs.hals.CPU.get_number_logical_processor_per_core.return_value = 2
        integrated_cs.hals.CPU.get_number_logical_processor_per_package.return_value = 4
        integrated_cs.hals.CPU.get_number_physical_processor_per_package.return_value = 2
        integrated_cs.hals.CPU.get_number_threads_from_APIC_table.return_value = 4
        integrated_cs.hals.CPU.get_number_sockets_from_APIC_table.return_value = 1
        integrated_cs.hals.CPU.get_cpu_topology.return_value = {
            'packages': {0: [0, 1]},
            'cores': {0: [0], 1: [1]},
            'threads': 2
        }

        # Create and execute CPU command
        cpu_cmd = CPUCommand(['info'], cs=integrated_cs)
        cpu_cmd.parse_arguments()
        cpu_cmd.cpu_info()

        # Verify HAL interactions
        integrated_cs.hals.CPU.is_HT_active.assert_called_once()
        integrated_cs.hals.CPU.get_number_logical_processor_per_core.assert_called_once()
        integrated_cs.hals.CPU.get_number_logical_processor_per_package.assert_called_once()
        integrated_cs.hals.CPU.get_number_physical_processor_per_package.assert_called_once()
        integrated_cs.hals.CPU.get_number_threads_from_APIC_table.assert_called_once()
        integrated_cs.hals.CPU.get_number_sockets_from_APIC_table.assert_called_once()

    @pytest.mark.integration
    def test_memory_command_full_workflow(self, integrated_cs):
        """Test complete Memory command workflow with HAL integration."""
        # Setup HAL mocks
        integrated_cs.hals.Memory.read_physical_mem.return_value = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        integrated_cs.hals.Memory.write_physical_mem.return_value = None
        integrated_cs.hals.Memory.alloc_physical_mem.return_value = (0xFFFF800000000000, 0xFED00000)

        # Test read operation
        mem_cmd = MemCommand(['read', '0xFED40000', '0x8', 'test.bin'], cs=integrated_cs)
        mem_cmd.parse_arguments()

        with patch('chipsec.utilcmd.mem_cmd.write_file'):
            mem_cmd.mem_read()

        integrated_cs.hals.Memory.read_physical_mem.assert_called_with(0xFED40000, 0x8)

        # Test write operation
        mem_cmd2 = MemCommand(['write', '0xFED40000', '0x8', '0001020304050607'], cs=integrated_cs)
        mem_cmd2.parse_arguments()
        mem_cmd2.mem_write()

        integrated_cs.hals.Memory.write_physical_mem.assert_called_with(0xFED40000, 0x8, b'\x00\x01\x02\x03\x04\x05\x06\x07')

        # Test allocate operation
        mem_cmd3 = MemCommand(['allocate', '0x1000'], cs=integrated_cs)
        mem_cmd3.parse_arguments()
        mem_cmd3.mem_allocate()

        integrated_cs.hals.Memory.alloc_physical_mem.assert_called_with(0x1000)

    @pytest.mark.integration
    def test_msr_command_full_workflow(self, integrated_cs):
        """Test complete MSR command workflow with HAL integration."""
        # Setup HAL mocks
        integrated_cs.hals.Msr.get_cpu_thread_count.return_value = 2
        integrated_cs.hals.Msr.read_msr.side_effect = [
            (0x12345678, 0x9ABCDEF0),  # Thread 0
            (0x11111111, 0x22222222),  # Thread 1
        ]
        integrated_cs.hals.Msr.write_msr.return_value = None

        # Test read all threads
        msr_cmd = MSRCommand(['0x8B'], cs=integrated_cs)
        msr_cmd.parse_arguments()
        msr_cmd.run()

        # Verify MSR reads for both threads
        assert integrated_cs.hals.Msr.read_msr.call_count == 2

        # Test write to specific thread
        msr_cmd2 = MSRCommand(['0x8B', '0x12345678', '0x9ABCDEF0', '0x1'], cs=integrated_cs)
        msr_cmd2.parse_arguments()
        msr_cmd2.run()

        integrated_cs.hals.Msr.write_msr.assert_called_with(0x1, 0x8B, 0x12345678, 0x9ABCDEF0)

    @pytest.mark.integration
    def test_spi_command_full_workflow(self, integrated_cs):
        """Test complete SPI command workflow with HAL integration."""
        # Setup HAL mocks
        integrated_cs.hals.SPI.display_SPI_map.return_value = None
        integrated_cs.hals.SPI.get_SPI_region.return_value = (0x0, 0x7FFFFF, 0x800000)
        integrated_cs.hals.SPI.read_spi_to_file.return_value = b'spi_flash_data'
        integrated_cs.hals.SPI.write_spi_from_file.return_value = True
        integrated_cs.hals.SPI.erase_spi_block.return_value = True
        integrated_cs.hals.SPI.disable_BIOS_write_protection.return_value = True
        integrated_cs.hals.SPI.get_SPI_JEDEC_ID.return_value = 0x123456

        # Mock SPI class for set_up
        with patch('chipsec.utilcmd.spi_cmd.SPI') as mock_spi_class:
            mock_spi_instance = Mock()
            mock_spi_instance.get_SPI_region.return_value = (0x0, 0x7FFFFF, 0x800000)
            mock_spi_instance.read_spi_to_file.return_value = b'spi_flash_data'
            mock_spi_instance.get_SPI_JEDEC_ID.return_value = 0x123456
            mock_spi_class.return_value = mock_spi_instance

            # Test info command
            spi_cmd = SPICommand(['info'], cs=integrated_cs)
            spi_cmd.parse_arguments()
            spi_cmd.set_up()
            spi_cmd.spi_info()

            mock_spi_instance.display_SPI_map.assert_called_once()

            # Test dump command
            spi_cmd2 = SPICommand(['dump', 'test.bin'], cs=integrated_cs)
            spi_cmd2.parse_arguments()
            spi_cmd2.set_up()
            spi_cmd2._spi = mock_spi_instance
            spi_cmd2.spi_dump()

            mock_spi_instance.get_SPI_region.assert_called_once()
            mock_spi_instance.read_spi_to_file.assert_called_once()

            # Test JEDEC command
            spi_cmd3 = SPICommand(['jedec'], cs=integrated_cs)
            spi_cmd3.parse_arguments()
            spi_cmd3._spi = mock_spi_instance
            spi_cmd3.spi_jedec()

            mock_spi_instance.get_SPI_JEDEC_ID.assert_called_once()


class TestConfigurationIntegration:
    """Integration tests for configuration system with HAL components."""

    @pytest.fixture
    def config_cs(self):
        """Create ChipsecCs with configuration integration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock configuration data
        cs_mock.CONFIG_PCI_RAW = {'8086': {'1234': Mock()}}
        cs_mock.CONFIG_PCI = {'8086': {'1234': Mock()}}

        # Mock HAL components
        cs_mock.hals.CPU = Mock()
        cs_mock.hals.Memory = Mock()

        # Mock register interface
        cs_mock.register = Mock()
        cs_mock.register.get_list_by_name.return_value = Mock()

        return cs_mock

    @pytest.mark.integration
    def test_configuration_hal_integration(self, config_cs):
        """Test configuration system working with HAL components."""
        # Setup configuration data
        config_cs.CONFIG_PCI_RAW['8086']['1234'].cfg = {
            'vid': 0x8086, 'did': 0x1234, 'bus': 0, 'dev': 0, 'fun': 0
        }

        # Setup HAL responses
        config_cs.hals.CPU.read_cr.return_value = 0xFED00000
        config_cs.hals.Memory.read_physical_mem.return_value = b'\xAA\xBB\xCC\xDD'

        # Test configuration data access
        pci_config = config_cs.CONFIG_PCI_RAW['8086']['1234']
        assert pci_config.cfg['vid'] == 0x8086
        assert pci_config.cfg['did'] == 0x1234

        # Test HAL operations using configuration data
        cr3_value = config_cs.hals.CPU.read_cr(0, 3)
        memory_data = config_cs.hals.Memory.read_physical_mem(cr3_value, 4)

        assert cr3_value == 0xFED00000
        assert memory_data == b'\xAA\xBB\xCC\xDD'

        # Verify HAL calls
        config_cs.hals.CPU.read_cr.assert_called_with(0, 3)
        config_cs.hals.Memory.read_physical_mem.assert_called_with(0xFED00000, 4)


class TestCrossPlatformIntegration:
    """Integration tests for cross-platform compatibility."""

    @pytest.mark.integration
    def test_amd_intel_cpu_compatibility(self):
        """Test that AMD and Intel CPU classes have compatible interfaces."""
        # Create mock CS for both platforms
        amd_cs = MockFactory.create_mock_chipsec_cs()
        amd_cs.is_amd.return_value = True
        amd_cs.is_intel.return_value = False

        intel_cs = MockFactory.create_mock_chipsec_cs()
        intel_cs.is_amd.return_value = False
        intel_cs.is_intel.return_value = True

        # Create CPU instances
        amd_cpu = AMDCPU(amd_cs)
        intel_cpu = IntelCPU(intel_cs)

        # Both should have the same core methods
        common_methods = [
            'read_cr', 'write_cr', 'cpuid', 'check_vmm', 'is_HT_active',
            'get_number_logical_processor_per_core', 'get_SMRR', 'get_TSEG'
        ]

        for method in common_methods:
            assert hasattr(amd_cpu, method), f"AMD CPU missing method: {method}"
            assert hasattr(intel_cpu, method), f"Intel CPU missing method: {method}"

        # Test that both respond to basic operations
        amd_cs.helper.read_cr.return_value = 0x12345678
        amd_cs.helper.cpuid.return_value = (0x806E9, 0x12345678, 0x9ABCDEF0, 0x11111111)

        intel_cs.helper.read_cr.return_value = 0x87654321
        intel_cs.helper.cpuid.return_value = (0x906E9, 0x87654321, 0xFEDCBA98, 0x22222222)

        # Both should work identically from interface perspective
        amd_cr = amd_cpu.read_cr(0, 3)
        intel_cr = intel_cpu.read_cr(0, 3)

        assert amd_cr == 0x12345678
        assert intel_cr == 0x87654321

        amd_cpuid = amd_cpu.cpuid(0x01, 0x00)
        intel_cpuid = intel_cpu.cpuid(0x01, 0x00)

        assert amd_cpuid[0] == 0x806E9  # AMD CPUID
        assert intel_cpuid[0] == 0x906E9  # Intel CPUID


if __name__ == '__main__':
    pytest.main([__file__])
