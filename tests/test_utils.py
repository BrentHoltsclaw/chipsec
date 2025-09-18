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

"""
Test utilities and helper functions for CHIPSEC testing framework.

This module provides common utilities, test data generators, and helper functions
to support comprehensive testing across the CHIPSEC codebase.
"""

import os
import tempfile
import random
import struct
from typing import Dict, Any, Optional
from unittest.mock import Mock


class TestDataGenerator:
    """Generate test data for various CHIPSEC components."""

    @staticmethod
    def generate_pci_config_data(vendor_id: int = 0x8086,
                                 device_id: int = 0x1234,
                                 revision_id: int = 0x01) -> bytes:
        """Generate PCI configuration space data."""
        # Standard PCI config space (256 bytes)
        config_data = bytearray(256)

        # Vendor ID and Device ID
        struct.pack_into('<HH', config_data, 0, vendor_id, device_id)

        # Command and Status registers
        struct.pack_into('<HH', config_data, 4, 0x0000, 0x0010)

        # Revision ID and Class codes
        config_data[8] = revision_id
        config_data[9] = 0x00  # Programming interface
        config_data[10] = 0x00  # Subclass
        config_data[11] = 0x06  # Base class (Bridge)

        # Header type
        config_data[14] = 0x00  # Standard header

        return bytes(config_data)

    @staticmethod
    def generate_uefi_firmware_volume(size: int = 0x10000,
                                     guid: str = "24400798-3807-4A42-B413-A1ECEE205DD8") -> bytes:
        """Generate a basic UEFI firmware volume."""
        from uuid import UUID

        fv_data = bytearray(size)

        # FV Header
        fv_guid = UUID(guid)
        fv_guid_bytes = fv_guid.bytes_le

        # Zero Vector (16 bytes)
        # File System GUID
        struct.pack_into('<16s', fv_data, 16, fv_guid_bytes)
        # FV Length
        struct.pack_into('<Q', fv_data, 32, size)
        # Signature (_FVH)
        struct.pack_into('<4s', fv_data, 40, b'_FVH')
        # Attributes
        struct.pack_into('<I', fv_data, 44, 0x0004FEFF)
        # Header Length
        struct.pack_into('<H', fv_data, 48, 0x48)
        # Checksum
        struct.pack_into('<H', fv_data, 50, 0x0000)
        # Ext Header Offset
        struct.pack_into('<H', fv_data, 52, 0x0000)
        # Reserved
        struct.pack_into('<B', fv_data, 54, 0x00)
        # Revision
        struct.pack_into('<B', fv_data, 55, 0x02)

        return bytes(fv_data)

    @staticmethod
    def generate_register_data(name: str = "TEST_REG",
                              size: int = 4,
                              fields: Optional[Dict[str, Dict]] = None) -> Dict[str, Any]:
        """Generate register definition data."""
        if fields is None:
            fields = {
                'FIELD1': {'bit': 0, 'size': 16, 'desc': 'Test field 1'},
                'FIELD2': {'bit': 16, 'size': 16, 'desc': 'Test field 2'}
            }

        return {
            'name': name,
            'desc': f'Test register {name}',
            'register_type': 'pcicfg',
            'device': '0:0:0',
            'offset': '0x0',
            'size': f'0x{size:X}',
            'FIELDS': fields
        }

    @staticmethod
    def generate_random_bytes(size: int, seed: Optional[int] = None) -> bytes:
        """Generate random bytes for testing."""
        if seed is not None:
            random.seed(seed)
        return bytes([random.randint(0, 255) for _ in range(size)])


class MockFactory:
    """Factory for creating mock objects used in testing."""

    @staticmethod
    def create_mock_register(name: str = "MOCK_REG",
                           value: int = 0x1234,
                           fields: Optional[Dict] = None) -> Mock:
        """Create a mock register object."""
        mock_reg = Mock()
        mock_reg.name = name
        mock_reg.value = value
        mock_reg.read.return_value = value
        mock_reg.write.return_value = None
        mock_reg.get_instance.return_value = 0
        mock_reg.is_enabled.return_value = True

        if fields:
            mock_reg.fields = fields
            mock_reg.has_field.side_effect = lambda f: f in fields
            mock_reg.get_field.side_effect = lambda f, **kwargs: fields.get(f, {}).get('default', 0x42) if f in fields else 0
        else:
            mock_reg.fields = {}
            mock_reg.has_field.return_value = False
            mock_reg.get_field.return_value = 0

        return mock_reg

    @staticmethod
    def create_mock_chipsec_cs() -> Mock:
        """Create a comprehensive mock ChipsecCs object."""
        cs_mock = Mock()

        # Mock configuration with enhanced register support
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.get_reglist = Mock(return_value=[])
        cs_mock.Cfg.get_scope = Mock(return_value='')
        cs_mock.Cfg.convert_platform_scope = Mock(return_value=['8086', '0', 'TEST_REG'])

        # Enhanced platform mock with proper register handling
        cs_mock.Cfg.platform = Mock()
        mock_register = MockFactory.create_mock_register("TEST_REG", 0x1234)
        cs_mock.Cfg.platform.get_register_from_scope = Mock(return_value=mock_register)

        # Enhanced PCI configuration with multiple devices
        mock_pci_device = Mock()
        mock_pci_device.bus = 0
        mock_pci_device.dev = 0
        mock_pci_device.fun = 0
        mock_pci_device.vid = 0x8086
        mock_pci_device.did = 0x1234

        cs_mock.Cfg.CONFIG_PCI = {'8086': {'0': mock_pci_device}}
        cs_mock.Cfg.CONFIG_PCI_RAW = {
            '8086': {
                '0': Mock(cfg={
                    'bus': 0, 'dev': 0, 'fun': 0,
                    'vid': 0x8086, 'did': 0x1234, 'rid': 0x01,
                    'class': 0x060000, 'subclass': 0x00
                })
            }
        }

        # Enhanced platform info
        cs_mock.Cfg.platform_info = Mock()
        cs_mock.Cfg.platform_info.code = 'TEST'
        cs_mock.Cfg.platform_info.vid = 0x8086
        cs_mock.Cfg.platform_info.did = 0x1234
        cs_mock.Cfg.platform_info.name = 'Test Platform'

        # Enhanced helper with comprehensive mocking
        cs_mock.helper = Mock()
        cs_mock.helper.enum_ACPI_tables = Mock(return_value=[b'FACP', b'APIC', b'MCFG', b'XSDT'])
        cs_mock.helper.read_phys_mem = Mock(side_effect=lambda addr, size: b'\x12\x34' if size == 2 else b'\x12\x34\x56\x78' * (size // 4))
        cs_mock.helper.write_phys_mem = Mock(return_value=4)
        cs_mock.helper.read_pci_reg = Mock(return_value=0x8086)
        cs_mock.helper.write_pci_reg = Mock(return_value=True)
        cs_mock.helper.get_threads_count = Mock(return_value=4)
        cs_mock.helper.get_page_size = Mock(return_value=0x1000)

        # Mock HAL components with enhanced functionality
        cs_mock.hals = Mock()

        # Enhanced Memory HAL with proper size handling
        cs_mock.hals.Memory = Mock()
        cs_mock.hals.Memory.read_physical_mem = Mock(side_effect=lambda addr, size: b'\x12\x34' if size == 2 else b'\x12\x34\x56\x78' * (size // 4))
        cs_mock.hals.Memory.write_physical_mem = Mock(return_value=4)
        cs_mock.hals.Memory.alloc_physical_mem = Mock(return_value=(0xFFFF800000000000, 0xFED00000))
        cs_mock.hals.Memory.get_available_ranges = Mock(return_value=[(0x0, 0x100000)])

        # Enhanced CPU HAL with proper register operations
        cs_mock.hals.CPU = Mock()
        cs_mock.hals.CPU.read_cr = Mock(side_effect=lambda reg: 0x12345678 + reg)
        cs_mock.hals.CPU.write_cr = Mock(return_value=None)
        cs_mock.hals.CPU.cpuid = Mock(side_effect=lambda eax, ecx=0: (0x806E9 + eax, 0x12345678, 0x9ABCDEF0, 0x11111111))
        cs_mock.hals.CPU.get_vmm = Mock(return_value=None)  # No VMM detected
        cs_mock.hals.CPU.get_smt = Mock(return_value=True)  # SMT enabled
        cs_mock.hals.CPU.get_topology = Mock(return_value={'cores': 4, 'threads': 8, 'packages': 1})

        # Enhanced MSR HAL
        cs_mock.hals.Msr = Mock()
        cs_mock.hals.Msr.read_msr = Mock(side_effect=lambda msr_addr, thread=0: (0x12345678 + msr_addr, 0x9ABCDEF0))
        cs_mock.hals.Msr.write_msr = Mock(return_value=None)

        # Enhanced SPI HAL with proper region handling
        cs_mock.hals.SPI = Mock()
        cs_mock.hals.SPI.get_SPI_region = Mock(side_effect=lambda region: (0x0, 0x7FFFFF, 0x800000) if region == 0 else (0x800000, 0xFFFFFF, 0x1000000))
        cs_mock.hals.SPI.read_spi_to_file = Mock(return_value=b'spi_data')
        cs_mock.hals.SPI.get_SPI_flash_info = Mock(return_value={'vendor': 'Test', 'size': 0x800000})

        # Enhanced ACPI HAL with proper table handling
        cs_mock.hals.ACPI = Mock()
        cs_mock.hals.ACPI.enum_ACPI_tables = Mock(return_value=[b'FACP', b'APIC', b'MCFG', b'XSDT'])
        cs_mock.hals.ACPI.get_ACPI_table = Mock(side_effect=lambda name, isfile=False: MockFactory._mock_acpi_table_data(name))
        cs_mock.hals.ACPI.is_ACPI_table_present = Mock(side_effect=lambda name: name in ['FACP', 'APIC', 'MCFG', 'XSDT'])
        cs_mock.hals.ACPI.print_ACPI_table_list = Mock(return_value=None)
        cs_mock.hals.ACPI.dump_ACPI_table = Mock(return_value=None)

        # Additional HAL components for completeness
        cs_mock.hals.PCI = Mock()
        cs_mock.hals.PCI.enumerate_devices = Mock(return_value=[(0, 0, 0), (0, 1, 0)])
        cs_mock.hals.PCI.read_dword = Mock(return_value=0x80861234)
        cs_mock.hals.PCI.write_dword = Mock(return_value=None)

        cs_mock.hals.IO = Mock()
        cs_mock.hals.IO.read_port_byte = Mock(return_value=0x12)
        cs_mock.hals.IO.write_port_byte = Mock(return_value=None)

        return cs_mock

    @staticmethod
    def _mock_acpi_table_data(table_name: str) -> tuple:
        """Generate mock ACPI table data."""
        if table_name == 'FACP':
            # Mock FACP table data
            facp_data = b'FACP\x84\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00INTL\x00\x00\x00\x00' + b'\x00' * 116
            return (facp_data, b'')
        elif table_name == 'APIC':
            # Mock APIC table data
            apic_data = b'APIC\x68\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00INTL\x00\x00\x00\x00' + b'\x00' * 88
            return (apic_data, b'')
        elif table_name == 'MCFG':
            # Mock MCFG table data
            mcfg_data = b'MCFG\x3C\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00INTL\x00\x00\x00\x00' + b'\x00' * 60
            return (mcfg_data, b'')
        else:
            # Generic table data
            generic_data = f'{table_name}\x24\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00INTL\x00\x00\x00\x00'.encode() + b'\x00' * 36
            return (generic_data, b'')

    @staticmethod
    def create_mock_helper() -> Mock:
        """Create a mock helper object."""
        helper_mock = Mock()
        helper_mock.create = Mock(return_value=True)
        helper_mock.start = Mock(return_value=True)
        helper_mock.delete = Mock(return_value=True)
        helper_mock.read_pci_reg = Mock(return_value=0x8086)
        helper_mock.write_pci_reg = Mock(return_value=True)
        helper_mock.read_phys_mem = Mock(return_value=b'\x12\x34\x56\x78')
        helper_mock.write_phys_mem = Mock(return_value=4)
        return helper_mock


class FileTestHelper:
    """Helper class for file-based testing operations."""

    @staticmethod
    def create_temp_file(content: bytes = b'test data',
                        suffix: str = '.bin') -> str:
        """Create a temporary file with given content."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as f:
            f.write(content)
            return f.name

    @staticmethod
    def create_temp_dir() -> str:
        """Create a temporary directory."""
        return tempfile.mkdtemp()

    @staticmethod
    def cleanup_temp_file(file_path: str) -> None:
        """Clean up temporary file."""
        try:
            os.unlink(file_path)
        except OSError:
            pass

    @staticmethod
    def cleanup_temp_dir(dir_path: str) -> None:
        """Clean up temporary directory."""
        try:
            import shutil
            shutil.rmtree(dir_path)
        except OSError:
            pass


class AssertionHelpers:
    """Custom assertion helpers for CHIPSEC-specific testing."""

    @staticmethod
    def assert_register_value_equal(register, expected_value: int,
                                  field_name: Optional[str] = None) -> None:
        """Assert that a register or register field has the expected value."""
        if field_name:
            actual_value = register.get_field(field_name)
            assert actual_value == expected_value, \
                f"Register {register.name} field {field_name}: expected {expected_value:#x}, got {actual_value:#x}"
        else:
            actual_value = register.read()
            assert actual_value == expected_value, \
                f"Register {register.name}: expected {expected_value:#x}, got {actual_value:#x}"

    @staticmethod
    def assert_pci_config_equal(actual_config: bytes,
                               expected_vendor: int,
                               expected_device: int) -> None:
        """Assert PCI configuration has expected vendor and device IDs."""
        vendor_id = struct.unpack('<H', actual_config[0:2])[0]
        device_id = struct.unpack('<H', actual_config[2:4])[0]

        assert vendor_id == expected_vendor, \
            f"PCI Vendor ID: expected {expected_vendor:#x}, got {vendor_id:#x}"
        assert device_id == expected_device, \
            f"PCI Device ID: expected {expected_device:#x}, got {device_id:#x}"

    @staticmethod
    def assert_firmware_volume_valid(fv_data: bytes) -> None:
        """Assert that firmware volume data is valid."""
        # Check FV signature
        signature = fv_data[40:44]
        assert signature == b'_FVH', f"Invalid FV signature: {signature}"

        # Check FV length
        fv_length = struct.unpack('<Q', fv_data[32:40])[0]
        assert fv_length == len(fv_data), \
            f"FV length mismatch: expected {fv_length}, got {len(fv_data)}"


class PerformanceTestHelper:
    """Helper for performance testing."""

    @staticmethod
    def time_function_execution(func, *args, **kwargs) -> float:
        """Time the execution of a function."""
        import time
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        return end_time - start_time, result

    @staticmethod
    def benchmark_function(func, iterations: int = 100,
                          *args, **kwargs) -> Dict[str, float]:
        """Benchmark a function over multiple iterations."""
        import statistics

        times = []
        for _ in range(iterations):
            execution_time, _ = PerformanceTestHelper.time_function_execution(
                func, *args, **kwargs)
            times.append(execution_time)

        return {
            'min': min(times),
            'max': max(times),
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'stdev': statistics.stdev(times) if len(times) > 1 else 0
        }


# Export commonly used functions
__all__ = [
    'TestDataGenerator',
    'MockFactory',
    'FileTestHelper',
    'AssertionHelpers',
    'PerformanceTestHelper'
]
