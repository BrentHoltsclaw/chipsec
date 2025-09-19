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
import sys
import os
from unittest.mock import Mock, MagicMock
from typing import Any, Dict, List, Optional, Union

# Add the project root to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class ChipsecMock(MagicMock):
    """Enhanced mock for CHIPSEC objects with proper format string handling."""
    def __format__(self, format_spec: str) -> str:
        """Handle format string operations properly."""
        if hasattr(self, '_mock_return_value'):
            return format(self._mock_return_value, format_spec)
        return '0' * 16  # Default for hex format

    def __len__(self) -> int:
        """Handle len() operations."""
        if hasattr(self, '_mock_return_value') and isinstance(self._mock_return_value, (bytes, list, str)):
            return len(self._mock_return_value)
        return 16  # Default length for buffers

    def __iter__(self):
        """Handle iteration operations."""
        if hasattr(self, '_mock_return_value') and isinstance(self._mock_return_value, (list, tuple)):
            return iter(self._mock_return_value)
        return iter([0] * 16)  # Default iteration


class BaseCommandMock(ChipsecMock):
    """Base mock for command testing with common attributes."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.toLoad = True
        self._smbus = ChipsecMock()
        self._spd = ChipsecMock()
        self.func = ChipsecMock()
        self.port = 0x00
        self.module_name = "test_module"
        self.module_id = 12345
        self.ucode_filename = "test.bin"
        self.fd_file = ChipsecMock()
        self._force_32 = False
        self._thread = 0
        self.engine = ChipsecMock()
        self.interrupts = ChipsecMock()
        self._prev_log = ChipsecMock()
        self.dev_addr = 0x50


@pytest.fixture(scope="session")
def mock_modules():
    """Mock Windows-specific modules for cross-platform testing."""
    modules_to_mock = [
        'fcntl', 'resource', 'pywintypes', 'win32service',
        'winerror', 'win32file', 'win32api', 'win32process',
        'win32security', 'win32serviceutil'
    ]

    for mod in modules_to_mock:
        if mod not in sys.modules:
            sys.modules[mod] = Mock()

    yield

    # Cleanup
    for mod in modules_to_mock:
        if mod in sys.modules and isinstance(sys.modules[mod], Mock):
            del sys.modules[mod]


@pytest.fixture
def mock_chipsec_cs():
    """Mock ChipsecCs object for testing."""
    cs_mock = ChipsecMock()
    cs_mock.Cfg = ChipsecMock()
    cs_mock.Cfg.get_reglist = ChipsecMock(return_value=[])
    cs_mock.Cfg.get_scope = ChipsecMock(return_value='')
    cs_mock.Cfg.convert_platform_scope = ChipsecMock(return_value=['8086', '0', 'TEST_REG'])
    cs_mock.Cfg.platform = ChipsecMock()
    cs_mock.Cfg.platform.get_register_from_scope = ChipsecMock(return_value=ChipsecMock())
    
    # Add hardware interface mocks
    cs_mock.hals = ChipsecMock()
    cs_mock.hals.Pci = ChipsecMock()
    cs_mock.hals.Mmio = ChipsecMock()
    cs_mock.hals.Vmm = ChipsecMock()
    cs_mock.hals.CPU = ChipsecMock()
    cs_mock.hals.Memory = ChipsecMock()
    cs_mock.hals.SPI = ChipsecMock()
    
    # Configure default returns for common operations
    cs_mock.hals.Pci.dump_pci_config = ChipsecMock(return_value=bytes(range(256)))
    cs_mock.hals.Memory.read_physical_mem = ChipsecMock(return_value=bytes(range(16)))
    cs_mock.hals.Vmm.hypercall = ChipsecMock(return_value=0)
    
    return cs_mock


@pytest.fixture
def sample_register_data():
    """Sample register data for testing."""
    return {
        'name': 'TEST_REGISTER',
        'desc': 'Test register for unit testing',
        'register_type': 'pcicfg',
        'device': '0:0:0',
        'offset': '0x0',
        'size': '0x4',
        'FIELDS': {
            'TEST_FIELD': {
                'bit': 0,
                'size': 8,
                'desc': 'Test field'
            }
        }
    }


@pytest.fixture
def mock_helper():
    """Mock helper for testing."""
    helper_mock = ChipsecMock()
    helper_mock.create = ChipsecMock(return_value=True)
    helper_mock.start = ChipsecMock(return_value=True)
    helper_mock.delete = ChipsecMock(return_value=True)
    helper_mock.read_pci_reg = ChipsecMock(return_value=0x8086)
    helper_mock.write_pci_reg = ChipsecMock(return_value=True)
    return helper_mock


def configure_mock_for_hardware(mock_obj: ChipsecMock, operations: Dict[str, Any]) -> None:
    """Configure hardware operation mocks properly."""
    for op, return_value in operations.items():
        if isinstance(return_value, Exception):
            setattr(mock_obj, op, ChipsecMock(side_effect=return_value))
        else:
            setattr(mock_obj, op, ChipsecMock(return_value=return_value))


@pytest.fixture
def configure_mock():
    """Fixture to provide the configure_mock_for_hardware function."""
    return configure_mock_for_hardware


@pytest.fixture(autouse=True)
def setup_test_environment(mock_modules):
    """Setup test environment with mocked modules."""
    pass


# Custom markers
def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "hardware: marks tests that require hardware access"
    )
    config.addinivalue_line(
        "markers", "mock: marks tests that use mocking extensively"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )
    config.addinivalue_line(
        "markers", "security: marks tests as security-related tests"
    )


@pytest.fixture
def temp_test_file(tmp_path):
    """Create a temporary test file."""
    test_file = tmp_path / "test_file.bin"
    test_file.write_bytes(b"test data")
    return test_file


@pytest.fixture
def mock_logger():
    """Mock logger for testing."""
    logger_mock = ChipsecMock()
    logger_mock.log = ChipsecMock()
    logger_mock.log_error = ChipsecMock()
    logger_mock.log_warning = ChipsecMock()
    logger_mock.log_good = ChipsecMock()
    logger_mock.log_bad = ChipsecMock()
    return logger_mock


@pytest.fixture
def mock_cs(mock_chipsec_cs):
    """Mock chipsec_cs object for testing."""
    return mock_chipsec_cs


# Command fixtures for utilcmd tests
@pytest.fixture
def base_command():
    """Base command fixture with common attributes."""
    return BaseCommandMock()


@pytest.fixture
def decode_command(base_command):
    """Mock decode command for testing."""
    cmd_mock = base_command
    cmd_mock.run = ChipsecMock(return_value=True)
    return cmd_mock


@pytest.fixture
def smbus_command(base_command):
    """Mock SMBus command for testing."""
    from types import MethodType
    from chipsec.utilcmd.smbus_cmd import SMBusCommand

    cmd_mock = base_command

    # Provide a minimal SMBus-like HAL with the methods the real implementation expects
    cmd_mock._smbus.read_byte = ChipsecMock(return_value=[0x12])
    cmd_mock._smbus.read_word = ChipsecMock(return_value=[0x12, 0x34])
    cmd_mock._smbus.read_block = ChipsecMock(return_value=[0x12, 0x34, 0x56, 0x78])
    cmd_mock._smbus.write_byte = ChipsecMock(return_value=True)
    cmd_mock._smbus.write_word = ChipsecMock(return_value=True)
    cmd_mock._smbus.process_call = ChipsecMock(return_value=[0xAB, 0xCD])
    cmd_mock._smbus.quick_write = ChipsecMock(return_value=True)
    cmd_mock._smbus.is_SMBus_supported = ChipsecMock(return_value=True)
    cmd_mock._smbus.display_SMBus_info = ChipsecMock(return_value=None)

    # Attributes expected by SMBusCommand methods
    cmd_mock.offset = 0x0
    cmd_mock.size = 0x4
    cmd_mock.write_data = 0x1234
    cmd_mock.is_addr_8b = False
    cmd_mock.is_OnSemi = False
    cmd_mock.is_mmio = False
    cmd_mock.is_i2c = False
    cmd_mock.command = 'read'

    # Bind real implementations so tests exercise logic instead of MagicMock stubs
    cmd_mock._read_range = MethodType(SMBusCommand._read_range, cmd_mock)
    cmd_mock._write_range = MethodType(SMBusCommand._write_range, cmd_mock)
    cmd_mock.read = MethodType(SMBusCommand.read, cmd_mock)
    cmd_mock.write = MethodType(SMBusCommand.write, cmd_mock)
    cmd_mock.readblock = MethodType(SMBusCommand.readblock, cmd_mock)
    cmd_mock.process_call = MethodType(SMBusCommand.process_call, cmd_mock)
    cmd_mock.scan = MethodType(SMBusCommand.scan, cmd_mock)
    cmd_mock.scan_range = MethodType(SMBusCommand.scan_range, cmd_mock)
    cmd_mock.dump_dev = MethodType(SMBusCommand.dump_dev, cmd_mock)
    cmd_mock.pretty_print_buffer = MethodType(SMBusCommand.pretty_print_buffer, cmd_mock)

    # Provide a lightweight configure that mirrors successful path
    def _configure(self):
        # Real configure sets _smbus and enables it; our mock already has _smbus
        return True
    cmd_mock.configure = MethodType(_configure, cmd_mock)

    # Use real run implementation
    cmd_mock.run = MethodType(SMBusCommand.run, cmd_mock)

    # Default func used when run() is invoked without tests overriding
    cmd_mock.func = cmd_mock.read

    return cmd_mock


@pytest.fixture
def vmm_command(base_command):
    """Mock VMM command for testing."""
    cmd_mock = base_command
    cmd_mock.run = ChipsecMock(return_value=True)
    
    # Add VMM-specific mock configurations
    cmd_mock.cs = ChipsecMock()
    cmd_mock.cs.hals = ChipsecMock()
    cmd_mock.cs.hals.Vmm = ChipsecMock()
    cmd_mock.cs.hals.Vmm.hypercall = ChipsecMock(return_value=0x12345678)
    cmd_mock.cs.hals.Vmm.dump_ept = ChipsecMock(return_value=True)
    
    # Configure PCI operations
    cmd_mock.cs.hals.Pci = ChipsecMock()
    cmd_mock.cs.hals.Pci.dump_pci_config = ChipsecMock(return_value=bytes(range(256)))
    
    # Configure logger
    cmd_mock.logger = ChipsecMock()
    cmd_mock.logger.log = ChipsecMock()
    
    return cmd_mock


@pytest.fixture
def pci_command():
    """Mock PCI command for testing."""
    cmd_mock = Mock()
    cmd_mock.run = Mock(return_value=True)
    return cmd_mock


@pytest.fixture
def reg_command():
    """Mock register command for testing."""
    cmd_mock = Mock()
    cmd_mock.run = Mock(return_value=True)
    return cmd_mock


@pytest.fixture
def mmio_command():
    """Mock MMIO command for testing."""
    cmd_mock = Mock()
    cmd_mock.run = Mock(return_value=True)
    return cmd_mock


@pytest.fixture
def spidesc_command():
    """Mock SPI descriptor command for testing."""
    cmd_mock = Mock()
    cmd_mock.run = Mock(return_value=True)
    cmd_mock.fd_file = Mock()
    cmd_mock.parse_spi_flash_descriptor = Mock(return_value=True)
    return cmd_mock


@pytest.fixture
def smbios_command():
    """Mock SMBIOS command for testing."""
    cmd_mock = Mock()
    cmd_mock.run = Mock(return_value=True)
    cmd_mock._force_32 = Mock(return_value=False)
    return cmd_mock


@pytest.fixture
def spd_command():
    """Mock SPD command for testing."""
    cmd_mock = Mock()
    cmd_mock.run = Mock(return_value=True)
    cmd_mock._spd = Mock()
    cmd_mock.dev_addr = Mock(return_value=0x50)
    return cmd_mock


@pytest.fixture
def ucode_command():
    """Mock microcode command for testing."""
    cmd_mock = Mock()
    cmd_mock.run = Mock(return_value=True)
    cmd_mock._cs = Mock()
    cmd_mock.ucode_filename = Mock(return_value="test.bin")
    return cmd_mock


@pytest.fixture
def uefi_command():
    """Mock UEFI command for testing."""
    cmd_mock = Mock()
    cmd_mock.run = Mock(return_value=True)
    return cmd_mock


@pytest.fixture
def vmem_command():
    """Mock virtual memory command for testing."""
    cmd_mock = Mock()
    cmd_mock.run = Mock(return_value=True)
    return cmd_mock


@pytest.fixture
def module_id_command():
    """Mock module ID command for testing."""
    cmd_mock = Mock()
    cmd_mock.run = Mock(return_value=True)
    cmd_mock.toLoad = Mock(return_value=True)
    cmd_mock.module_name = Mock(return_value="test_module")
    cmd_mock.module_id = Mock(return_value=12345)
    return cmd_mock


@pytest.fixture
def msgbus_command():
    """Mock message bus command for testing."""
    cmd_mock = Mock()
    cmd_mock.run = Mock(return_value=True)
    cmd_mock.toLoad = Mock(return_value=True)
    cmd_mock.func = Mock(return_value=True)
    cmd_mock.port = Mock(return_value=0x00)
    return cmd_mock


@pytest.fixture
def txt_command():
    """Mock TXT command for testing."""
    cmd_mock = Mock()
    cmd_mock.run = Mock(return_value=True)
    return cmd_mock


@pytest.fixture
def tpm_command():
    """Mock TPM command for testing."""
    cmd_mock = Mock()
    cmd_mock.run = Mock(return_value=True)
    return cmd_mock
