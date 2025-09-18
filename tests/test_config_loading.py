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
# Foundation, Inc, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

import pytest
import os
from unittest.mock import Mock, patch
from chipsec.config import (
    Cfg, PlatformInfo, PCHInfo, CPUInfo, ConfigurationState,
    PlatformDetector, ConfigurationValidator, ScopeManager
)
from chipsec.library.exceptions import CSConfigError, PlatformDetectionError
from tests.test_utils import MockFactory


class TestPlatformInfo:
    """Test PlatformInfo data class."""

    @pytest.mark.unit
    def test_platform_info_initialization(self):
        """Test PlatformInfo initialization with defaults."""
        info = PlatformInfo()
        assert info.vid == 0xFFFF
        assert info.did == 0xFFFF
        assert info.rid == 0xFF
        assert info.code == ''
        assert info.longname == 'Unrecognized Platform'
        assert info.name == 'Unknown'
        assert info.req_pch is None
        assert info.detect == []

    @pytest.mark.unit
    def test_platform_info_custom_values(self):
        """Test PlatformInfo with custom values."""
        detect_patterns = ['8086:1234', '8086:5678']
        info = PlatformInfo(
            vid=0x8086,
            did=0x1234,
            rid=0x01,
            code='TEST',
            longname='Test Platform',
            name='Test',
            req_pch=True,
            detect=detect_patterns
        )
        assert info.vid == 0x8086
        assert info.did == 0x1234
        assert info.rid == 0x01
        assert info.code == 'TEST'
        assert info.longname == 'Test Platform'
        assert info.name == 'Test'
        assert info.req_pch is True
        assert info.detect == detect_patterns


class TestPCHInfo:
    """Test PCHInfo data class."""

    @pytest.mark.unit
    def test_pch_info_initialization(self):
        """Test PCHInfo initialization with defaults."""
        info = PCHInfo()
        assert info.vid == 0xFFFF
        assert info.did == 0xFFFF
        assert info.rid == 0xFF
        assert info.code == ''
        assert info.longname == 'Unrecognized PCH'

    @pytest.mark.unit
    def test_pch_info_custom_values(self):
        """Test PCHInfo with custom values."""
        info = PCHInfo(
            vid=0x8086,
            did=0xABCD,
            rid=0x02,
            code='TEST_PCH',
            longname='Test PCH Platform'
        )
        assert info.vid == 0x8086
        assert info.did == 0xABCD
        assert info.rid == 0x02
        assert info.code == 'TEST_PCH'
        assert info.longname == 'Test PCH Platform'


class TestCPUInfo:
    """Test CPUInfo data class."""

    @pytest.mark.unit
    def test_cpu_info_initialization(self):
        """Test CPUInfo initialization with defaults."""
        info = CPUInfo()
        assert info.cpuid == 0xFFFFF
        assert info.mfgid == 'Unknown CPU'

    @pytest.mark.unit
    def test_cpu_info_custom_values(self):
        """Test CPUInfo with custom values."""
        info = CPUInfo(
            cpuid=0x12345678,
            mfgid='Intel'
        )
        assert info.cpuid == 0x12345678
        assert info.mfgid == 'Intel'


class TestConfigurationState:
    """Test ConfigurationState data class."""

    @pytest.mark.unit
    def test_configuration_state_initialization(self):
        """Test ConfigurationState initialization with defaults."""
        state = ConfigurationState()
        assert state.xml_config_loaded is False
        assert state.parsers_loaded is False
        assert state.platform_detected is False
        assert state.validation_passed is False

    @pytest.mark.unit
    def test_configuration_state_updates(self):
        """Test ConfigurationState with updated values."""
        state = ConfigurationState(
            xml_config_loaded=True,
            parsers_loaded=True,
            platform_detected=True,
            validation_passed=True
        )
        assert state.xml_config_loaded is True
        assert state.parsers_loaded is True
        assert state.platform_detected is True
        assert state.validation_passed is True


class TestPlatformDetector:
    """Test PlatformDetector functionality."""

    @pytest.fixture
    def mock_logger(self):
        """Create mock logger."""
        return Mock()

    @pytest.fixture
    def detector(self, mock_logger):
        """Create PlatformDetector instance."""
        return PlatformDetector(mock_logger)

    @pytest.mark.unit
    def test_platform_detector_initialization(self, detector):
        """Test PlatformDetector initialization."""
        assert detector.vid_set == set()
        assert detector.config_pci_raw == {}

    @pytest.mark.unit
    def test_check_vendor_compatibility(self, detector):
        """Test vendor compatibility checking."""
        config_pci_raw = {'8086': {'1234': {}}, '1022': {'5678': {}}}
        detector.config_pci_raw = config_pci_raw

        # Test with matching vendors
        result = detector._check_vendor_compatibility({'8086': {}, '1022': {}}, config_pci_raw)
        assert result is True
        assert '8086' in detector.vid_set
        assert '1022' in detector.vid_set

        # Test with no matching vendors
        detector.vid_set = set()
        result = detector._check_vendor_compatibility({'8086': {}}, {'ABCD': {}})
        assert result is False
        assert detector.vid_set == set()

    @pytest.mark.unit
    def test_get_detection_value(self, detector):
        """Test detection value extraction."""
        dev000 = {'vid': 0x8086, 'did': 0x1234}
        result = detector._get_detection_value(dev000)
        assert result == '8086:1234'

    @pytest.mark.unit
    def test_get_unknown_platform(self, detector):
        """Test unknown platform creation."""
        dev000 = {'vid': 0x8086, 'did': 0x1234, 'rid': 0x01}
        result = detector._get_unknown_platform(dev000)

        assert result['vid'] == 0x8086
        assert result['did'] == [0x1234]
        assert result['name'] == 'Unknown'
        assert result['code'] == ''
        assert result['longname'] == 'Unknown Platform'
        assert result['req_pch'] is None
        assert result['detect'] == []


class TestConfigurationValidator:
    """Test ConfigurationValidator functionality."""

    @pytest.fixture
    def mock_logger(self):
        """Create mock logger."""
        return Mock()

    @pytest.fixture
    def validator(self, mock_logger):
        """Create ConfigurationValidator instance."""
        return ConfigurationValidator(mock_logger)

    @pytest.mark.unit
    def test_configuration_validator_initialization(self, validator):
        """Test ConfigurationValidator initialization."""
        assert hasattr(validator, 'logger')

    @pytest.mark.unit
    def test_validate_config_success(self, validator):
        """Test successful configuration validation."""
        config_data = {
            'CONFIG_PCI_RAW': {'8086': {'1234': {}}},
            'CONFIG_PCI': {'8086': {'1234': {}}}
        }

        result = validator.validate_config(config_data)
        assert result is True

    @pytest.mark.unit
    def test_validate_config_missing_keys(self, validator):
        """Test configuration validation with missing keys."""
        config_data = {'CONFIG_PCI_RAW': {}}  # Missing CONFIG_PCI

        with pytest.raises(Exception):  # Should raise ConfigurationValidationError
            validator.validate_config(config_data)

    @pytest.mark.unit
    def test_validate_config_invalid_structure(self, validator):
        """Test configuration validation with invalid structure."""
        config_data = {
            'CONFIG_PCI_RAW': {'8086': {'1234': {}}},
            'CONFIG_PCI': 'invalid'  # Should be dict
        }

        with pytest.raises(Exception):  # Should raise ConfigurationValidationError
            validator.validate_config(config_data)


class TestScopeManager:
    """Test ScopeManager functionality."""

    @pytest.fixture
    def scope_manager(self):
        """Create ScopeManager instance."""
        return ScopeManager()

    @pytest.mark.unit
    def test_scope_manager_initialization(self, scope_manager):
        """Test ScopeManager initialization."""
        assert len(scope_manager.parent_keys) > 0
        assert len(scope_manager.child_keys) > 0
        assert 'CONFIG_PCI_RAW' in scope_manager.parent_keys
        assert 'REGISTERS' in scope_manager.child_keys

    @pytest.mark.unit
    def test_apply_scope_no_pattern(self, scope_manager):
        """Test scope application with no pattern."""
        config_data = {'key1': 'value1', 'key2': 'value2'}
        result = scope_manager.apply_scope(config_data, '')
        assert result == config_data

    @pytest.mark.unit
    def test_apply_scope_with_pattern(self, scope_manager):
        """Test scope application with pattern."""
        config_data = {
            '8086': {'data': 'intel_data'},
            '1022': {'data': 'amd_data'}
        }
        result = scope_manager.apply_scope(config_data, '8086*')
        assert '8086' in result
        assert '1022' not in result

    @pytest.mark.unit
    def test_matches_scope(self, scope_manager):
        """Test scope matching."""
        assert scope_manager._matches_scope('8086', '8086*') is True
        assert scope_manager._matches_scope('1022', '8086*') is False
        assert scope_manager._matches_scope('8086.1234', '8086*') is True


class TestCfg:
    """Test main Cfg class functionality."""

    @pytest.fixture
    def mock_logger(self):
        """Create mock logger."""
        return Mock()

    @pytest.fixture
    def cfg_instance(self, mock_logger):
        """Create Cfg instance with mocked logger."""
        with patch('chipsec.config.logger', return_value=mock_logger):
            return Cfg()

    @pytest.mark.unit
    def test_cfg_initialization(self, cfg_instance):
        """Test Cfg initialization."""
        assert hasattr(cfg_instance, 'logger')
        assert hasattr(cfg_instance, 'platform_detector')
        assert hasattr(cfg_instance, 'config_validator')
        assert hasattr(cfg_instance, 'scope_manager')
        assert hasattr(cfg_instance, 'platform_info')
        assert hasattr(cfg_instance, 'pch_info')
        assert hasattr(cfg_instance, 'cpu_info')
        assert hasattr(cfg_instance, 'config_state')

    @pytest.mark.unit
    def test_legacy_properties(self, cfg_instance):
        """Test legacy property access."""
        # Test platform info properties
        cfg_instance.platform_info.vid = 0x8086
        assert cfg_instance.vid == 0x8086

        cfg_instance.platform_info.did = 0x1234
        assert cfg_instance.did == 0x1234

        cfg_instance.platform_info.code = 'TEST'
        assert cfg_instance.code == 'TEST'

        cfg_instance.platform_info.longname = 'Test Platform'
        assert cfg_instance.longname == 'Test Platform'

        cfg_instance.platform_info.req_pch = True
        assert cfg_instance.req_pch is True

        cfg_instance.platform_info.rid = 0x01
        assert cfg_instance.rid == 0x01

        # Test PCH info properties
        cfg_instance.pch_info.vid = 0x8086
        assert cfg_instance.pch_vid == 0x8086

        cfg_instance.pch_info.did = 0xABCD
        assert cfg_instance.pch_did == 0xABCD

        cfg_instance.pch_info.code = 'TEST_PCH'
        assert cfg_instance.pch_code == 'TEST_PCH'

        cfg_instance.pch_info.longname = 'Test PCH'
        assert cfg_instance.pch_longname == 'Test PCH'

        cfg_instance.pch_info.rid = 0x02
        assert cfg_instance.pch_rid == 0x02

        # Test CPU info properties
        cfg_instance.cpu_info.cpuid = 0x12345678
        assert cfg_instance.cpuid == 0x12345678

        cfg_instance.cpu_info.mfgid = 'Intel'
        assert cfg_instance.mfgid == 'Intel'

    @pytest.mark.unit
    def test_set_cpuid(self, cfg_instance):
        """Test CPUID setting."""
        cfg_instance.set_cpuid(0x12345678)
        assert cfg_instance.cpu_info.cpuid == 0x12345678

    @pytest.mark.unit
    def test_set_mfgid(self, cfg_instance):
        """Test manufacturer ID setting."""
        cfg_instance.set_mfgid('AMD')
        assert cfg_instance.cpu_info.mfgid == 'AMD'

    @pytest.mark.unit
    def test_set_topology(self, cfg_instance, mock_logger):
        """Test topology setting."""
        topology = {'packages': {0: [0, 1]}, 'cores': {0: [0], 1: [1]}, 'threads': 2}
        cfg_instance.set_topology(topology)

        assert hasattr(cfg_instance, 'CPU')
        assert cfg_instance.CPU == topology
        mock_logger.log_hal.assert_called()

    @pytest.mark.unit
    def test_get_chipset_code(self, cfg_instance):
        """Test chipset code retrieval."""
        cfg_instance.platform_info.code = 'TEST'
        assert cfg_instance.get_chipset_code() == 'TEST'

    @pytest.mark.unit
    def test_get_pch_code(self, cfg_instance):
        """Test PCH code retrieval."""
        cfg_instance.pch_info.code = 'TEST_PCH'
        assert cfg_instance.get_pch_code() == 'TEST_PCH'

    @pytest.mark.unit
    def test_is_pch_req(self, cfg_instance):
        """Test PCH requirement check."""
        cfg_instance.platform_info.req_pch = True
        assert cfg_instance.is_pch_req() is True

        cfg_instance.platform_info.req_pch = False
        assert cfg_instance.is_pch_req() is False

    @pytest.mark.unit
    def test_print_platform_info(self, cfg_instance, mock_logger):
        """Test platform info printing."""
        cfg_instance.cpu_info.mfgid = 'Intel'
        cfg_instance.platform_info.longname = 'Test Platform'
        cfg_instance.cpu_info.cpuid = 0x12345678
        cfg_instance.platform_info.vid = 0x8086
        cfg_instance.platform_info.did = 0x1234
        cfg_instance.platform_info.rid = 0x01

        cfg_instance.print_platform_info()

        # Verify logger calls
        assert mock_logger.log.call_count >= 5

    @pytest.mark.unit
    def test_print_pch_info(self, cfg_instance, mock_logger):
        """Test PCH info printing."""
        cfg_instance.pch_info.longname = 'Test PCH'
        cfg_instance.pch_info.vid = 0x8086
        cfg_instance.pch_info.did = 0xABCD
        cfg_instance.pch_info.rid = 0x02

        cfg_instance.print_pch_info()

        # Verify logger calls
        assert mock_logger.log.call_count >= 4

    @pytest.mark.unit
    def test_set_scope(self, cfg_instance):
        """Test scope setting."""
        scope = {'test': '8086.0'}
        cfg_instance.set_scope(scope)
        assert cfg_instance.scope['test'] == '8086.0'

    @pytest.mark.unit
    def test_clear_scope(self, cfg_instance):
        """Test scope clearing."""
        cfg_instance.scope = {'test': '8086.0', None: ''}
        cfg_instance.clear_scope()
        assert cfg_instance.scope == {None: ''}

    @pytest.mark.unit
    def test_get_scope(self, cfg_instance):
        """Test scope retrieval."""
        cfg_instance.scope = {'test': '8086.0', None: 'default'}
        assert cfg_instance.get_scope('test') == '8086.0'
        assert cfg_instance.get_scope('unknown') == 'default'

    @pytest.mark.unit
    def test_convert_platform_scope(self, cfg_instance):
        """Test platform scope conversion."""
        result = cfg_instance.convert_platform_scope('8086.0', 'TEST_REG')
        assert result == ['8086', '0', 'TEST_REG']

        result = cfg_instance.convert_platform_scope('', 'TEST_REG')
        assert result == ['TEST_REG']

    @pytest.mark.unit
    def test_get_platform_info(self, cfg_instance):
        """Test platform info retrieval."""
        result = cfg_instance.get_platform_info()
        assert isinstance(result, PlatformInfo)

    @pytest.mark.unit
    def test_get_pch_info(self, cfg_instance):
        """Test PCH info retrieval."""
        result = cfg_instance.get_pch_info()
        assert isinstance(result, PCHInfo)

    @pytest.mark.unit
    def test_get_cpu_info(self, cfg_instance):
        """Test CPU info retrieval."""
        result = cfg_instance.get_cpu_info()
        assert isinstance(result, CPUInfo)

    @pytest.mark.unit
    def test_get_config_state(self, cfg_instance):
        """Test configuration state retrieval."""
        result = cfg_instance.get_config_state()
        assert isinstance(result, ConfigurationState)

    @pytest.mark.unit
    def test_is_platform_detected(self, cfg_instance):
        """Test platform detection status."""
        cfg_instance.config_state.platform_detected = True
        cfg_instance.platform_info.code = 'TEST'
        assert cfg_instance.is_platform_detected() is True

        cfg_instance.platform_info.code = ''
        assert cfg_instance.is_platform_detected() is False

    @pytest.mark.unit
    def test_is_config_validated(self, cfg_instance):
        """Test configuration validation status."""
        cfg_instance.config_state.validation_passed = True
        assert cfg_instance.is_config_validated() is True

    @pytest.mark.unit
    def test_reset_configuration(self, cfg_instance):
        """Test configuration reset."""
        # Set some values
        cfg_instance.config_state.xml_config_loaded = True
        cfg_instance.platform_info.code = 'TEST'
        cfg_instance.pch_info.code = 'TEST_PCH'
        cfg_instance.cpu_info.cpuid = 0x12345678

        # Reset
        cfg_instance.reset_configuration()

        # Verify reset
        assert cfg_instance.config_state.xml_config_loaded is False
        assert cfg_instance.platform_info.code == ''
        assert cfg_instance.pch_info.code == ''
        assert cfg_instance.cpu_info.cpuid == 0xFFFFF


if __name__ == '__main__':
    pytest.main([__file__])
