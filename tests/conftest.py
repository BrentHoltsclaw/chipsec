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
from unittest.mock import Mock

# Add the project root to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


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
    cs_mock = Mock()
    cs_mock.Cfg = Mock()
    cs_mock.Cfg.get_reglist = Mock(return_value=[])
    cs_mock.Cfg.get_scope = Mock(return_value='')
    cs_mock.Cfg.convert_platform_scope = Mock(return_value=['8086', '0', 'TEST_REG'])
    cs_mock.Cfg.platform = Mock()
    cs_mock.Cfg.platform.get_register_from_scope = Mock(return_value=Mock())
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
    helper_mock = Mock()
    helper_mock.create = Mock(return_value=True)
    helper_mock.start = Mock(return_value=True)
    helper_mock.delete = Mock(return_value=True)
    helper_mock.read_pci_reg = Mock(return_value=0x8086)
    helper_mock.write_pci_reg = Mock(return_value=True)
    return helper_mock


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
    logger_mock = Mock()
    logger_mock.log = Mock()
    logger_mock.log_error = Mock()
    logger_mock.log_warning = Mock()
    logger_mock.log_good = Mock()
    logger_mock.log_bad = Mock()
    return logger_mock


@pytest.fixture
def mock_cs(mock_chipsec_cs):
    """Mock chipsec_cs object for testing."""
    return mock_chipsec_cs


# Command fixtures for utilcmd tests
@pytest.fixture
def decode_command():
    """Mock decode command for testing."""
    cmd_mock = Mock()
    cmd_mock.run = Mock(return_value=True)
    return cmd_mock


@pytest.fixture
def smbus_command():
    """Mock SMBus command for testing."""
    cmd_mock = Mock()
    cmd_mock.run = Mock(return_value=True)
    cmd_mock._smbus = Mock()
    cmd_mock._smbus.read_byte = Mock(return_value=0x12)
    cmd_mock._smbus.read_word = Mock(return_value=0x1234)
    cmd_mock._smbus.write_byte = Mock(return_value=True)
    cmd_mock._smbus.write_word = Mock(return_value=True)
    return cmd_mock


@pytest.fixture
def vmm_command():
    """Mock VMM command for testing."""
    cmd_mock = Mock()
    cmd_mock.run = Mock(return_value=True)
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
