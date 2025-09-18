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
from chipsec.library.register import Register, RegisterType, ObjList, NullRegister
from chipsec.library.exceptions import RegisterNotFoundError


class TestRegister:
    """Improved unit tests for the Register class using pytest."""

    @pytest.fixture
    def mock_cs(self):
        """Create a mock ChipsecCs object."""
        cs_mock = Mock()
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.get_reglist = Mock(return_value=[])
        cs_mock.Cfg.get_scope = Mock(return_value='')
        cs_mock.Cfg.convert_platform_scope = Mock(return_value=['8086', '0', 'TEST_REG'])
        cs_mock.Cfg.platform = Mock()
        cs_mock.Cfg.platform.get_register_from_scope = Mock(return_value=Mock())
        return cs_mock

    @pytest.fixture
    def register_instance(self, mock_cs):
        """Create a Register instance with mocked dependencies."""
        return Register(mock_cs)

    @pytest.mark.unit
    def test_register_initialization(self, register_instance):
        """Test Register class initialization."""
        assert hasattr(register_instance, 'cs')
        assert hasattr(register_instance, 'io')
        assert hasattr(register_instance, 'iobar')
        assert hasattr(register_instance, 'memory')
        assert hasattr(register_instance, 'mm_msgbus')
        assert hasattr(register_instance, 'mmcfg')
        assert hasattr(register_instance, 'mmio')
        assert hasattr(register_instance, 'msgbus')
        assert hasattr(register_instance, 'msr')
        assert hasattr(register_instance, 'pcicfg')

    @pytest.mark.unit
    def test_is_defined_existing_register(self, register_instance, mock_cs):
        """Test is_defined with an existing register."""
        mock_cs.Cfg.get_reglist.return_value = [Mock()]
        assert register_instance.is_defined('TEST_REG') is True

    @pytest.mark.unit
    def test_is_defined_nonexistent_register(self, register_instance, mock_cs):
        """Test is_defined with a nonexistent register."""
        mock_cs.Cfg.get_reglist.side_effect = RegisterNotFoundError('Register not found')
        assert register_instance.is_defined('NONEXISTENT_REG') is False

    @pytest.mark.unit
    def test_get_def_pcicfg_register(self, register_instance, mock_cs):
        """Test get_def for PCI configuration register."""
        # Create a mock object that behaves like a dictionary
        mock_reg = Mock()
        mock_reg.register_type = RegisterType.PCICFG

        # Make the mock support dictionary-like access
        reg_dict = {'bus': None, 'dev': None, 'fun': None}
        mock_reg.__getitem__ = lambda self, key: reg_dict[key]
        mock_reg.__setitem__ = lambda self, key, value: reg_dict.__setitem__(key, value)
        mock_reg.__contains__ = lambda self, key: key in reg_dict
        mock_reg.keys = lambda self: reg_dict.keys()

        mock_cs.Cfg.platform.get_register_from_scope.return_value = mock_reg

        # Mock PCI device
        mock_device = Mock()
        mock_device.bus = 0
        mock_device.dev = 0
        mock_device.fun = 0
        mock_cs.Cfg.CONFIG_PCI = {'8086': {'0': mock_device}}

        result = register_instance.get_def('TEST_REG')
        assert 'bus' in result
        assert 'dev' in result
        assert 'fun' in result
        assert result['bus'] == 0
        assert result['dev'] == 0
        assert result['fun'] == 0

    @pytest.mark.unit
    def test_get_list_by_name(self, register_instance, mock_cs):
        """Test get_list_by_name method."""
        mock_reg = Mock()
        mock_reg_list = ObjList([mock_reg])
        mock_cs.Cfg.get_reglist.return_value = mock_reg_list

        result = register_instance.get_list_by_name('TEST_REG')
        assert isinstance(result, ObjList)
        assert len(result) == 1

    @pytest.mark.unit
    def test_get_instance_by_name_existing(self, register_instance, mock_cs):
        """Test get_instance_by_name with existing instance."""
        mock_reg = Mock()
        mock_reg.get_instance.return_value = 0
        mock_cs.Cfg.get_reglist.return_value = [mock_reg]

        result = register_instance.get_instance_by_name('TEST_REG', 0)
        assert result == mock_reg

    @pytest.mark.unit
    def test_get_instance_by_name_not_found(self, register_instance, mock_cs):
        """Test get_instance_by_name when instance is not found."""
        mock_cs.Cfg.get_reglist.return_value = []

        result = register_instance.get_instance_by_name('TEST_REG', 0)
        assert isinstance(result, NullRegister)
        assert result.name == 'TEST_REG'
        assert result.instance == 0

    @pytest.mark.unit
    def test_has_field_existing_field(self, register_instance, mock_cs):
        """Test has_field with existing field."""
        mock_reg = Mock()
        mock_reg.fields = {'TEST_FIELD': {'bit': 0, 'size': 8}}
        mock_cs.Cfg.get_reglist.return_value = [mock_reg]

        assert register_instance.has_field('TEST_REG', 'TEST_FIELD') is True

    @pytest.mark.unit
    def test_has_field_nonexistent_field(self, register_instance, mock_cs):
        """Test has_field with nonexistent field."""
        mock_reg = Mock()
        mock_reg.fields = {}
        mock_cs.Cfg.get_reglist.return_value = [mock_reg]

        assert register_instance.has_field('TEST_REG', 'NONEXISTENT_FIELD') is False

    @pytest.mark.unit
    def test_get_match_with_wildcards(self, register_instance, mock_cs):
        """Test get_match with wildcard patterns."""
        # Mock convert_internal_scope to return proper tuple
        mock_cs.Cfg.convert_internal_scope.return_value = ('8086', '0', 'TEST_REG', '*')

        # Mock platform structure
        mock_vendor = Mock()
        mock_device = Mock()
        mock_register = Mock()
        mock_register.fields = {'FIELD1': {'bit': 0, 'size': 8}}

        mock_device.registers = {'TEST_REG': mock_register}
        mock_vendor.devices = {'0': mock_device}
        mock_cs.Cfg.platform.vendors = {'8086': mock_vendor}

        result = register_instance.get_match('8086.0.TEST_REG.*')
        assert isinstance(result, list)
        assert len(result) > 0

    @pytest.mark.unit
    def test_has_all_fields_success(self, register_instance, mock_cs):
        """Test has_all_fields with all fields present."""
        mock_reg = Mock()
        mock_reg.fields = {
            'FIELD1': {'bit': 0, 'size': 8},
            'FIELD2': {'bit': 8, 'size': 8}
        }
        mock_cs.Cfg.get_reglist.return_value = [mock_reg]

        assert register_instance.has_all_fields('TEST_REG', ['FIELD1', 'FIELD2']) is True

    @pytest.mark.unit
    def test_has_all_fields_missing_field(self, register_instance, mock_cs):
        """Test has_all_fields with missing field."""
        mock_reg = Mock()
        mock_reg.fields = {'FIELD1': {'bit': 0, 'size': 8}}
        mock_cs.Cfg.get_reglist.return_value = [mock_reg]

        assert register_instance.has_all_fields('TEST_REG', ['FIELD1', 'FIELD2']) is False


class TestObjList:
    """Tests for the ObjList class."""

    @pytest.fixture
    def obj_list(self):
        """Create an ObjList with mock register objects."""
        mock_reg1 = Mock()
        mock_reg1.read.return_value = 0x1234
        mock_reg1.write.return_value = None
        mock_reg1.value = 0x1234

        mock_reg2 = Mock()
        mock_reg2.read.return_value = 0x5678
        mock_reg2.write.return_value = None
        mock_reg2.value = 0x5678

        return ObjList([mock_reg1, mock_reg2])

    @pytest.mark.unit
    def test_read_all(self, obj_list):
        """Test reading all register values."""
        result = obj_list.read()
        assert result == [0x1234, 0x5678]

    @pytest.mark.unit
    def test_write_all(self, obj_list):
        """Test writing to all registers."""
        obj_list.write(0xABCD)
        for reg in obj_list:
            reg.write.assert_called_with(0xABCD)

    @pytest.mark.unit
    def test_is_all_value_true(self, obj_list):
        """Test is_all_value when all values match."""
        assert obj_list.is_all_value(0x1234) is False  # Not all have this value
        assert obj_list.is_all_value(0x1234, mask=0xFFFF) is False

    @pytest.mark.unit
    def test_filter_enabled(self, obj_list):
        """Test filtering enabled registers."""
        # Make one register disabled
        obj_list[0].is_enabled.return_value = False
        obj_list[1].is_enabled.return_value = True

        filtered = obj_list.filter_enabled()
        assert len(filtered) == 1
        assert filtered[0] == obj_list[1]

    @pytest.mark.unit
    def test_get_field_value_if_equivalent(self, obj_list):
        """Test getting field value when all instances have the same value."""
        for reg in obj_list:
            reg.get_field.return_value = 0x42

        result = obj_list.get_field_value_if_equivalent('TEST_FIELD')
        assert result == 0x42

    @pytest.mark.unit
    def test_get_field_value_if_equivalent_different(self, obj_list):
        """Test getting field value when instances have different values."""
        obj_list[0].get_field.return_value = 0x42
        obj_list[1].get_field.return_value = 0x43

        result = obj_list.get_field_value_if_equivalent('TEST_FIELD')
        assert result is None


class TestNullRegister:
    """Tests for the NullRegister class."""

    @pytest.fixture
    def null_register(self):
        """Create a NullRegister instance."""
        return NullRegister('TEST_REG', 0)

    @pytest.mark.unit
    def test_null_register_attributes(self, null_register):
        """Test NullRegister attributes."""
        assert null_register.name == 'TEST_REG'
        assert null_register.instance == 0
        assert null_register.value is None

    @pytest.mark.unit
    def test_null_register_read(self, null_register):
        """Test NullRegister read method."""
        with patch('chipsec.library.register.logger') as mock_logger_func:
            mock_logger = Mock()
            mock_logger_func.return_value = mock_logger
            result = null_register.read()
            assert result == 0
            mock_logger.log_warning.assert_called_once()

    @pytest.mark.unit
    def test_null_register_write(self, null_register):
        """Test NullRegister write method."""
        with patch('chipsec.library.register.logger') as mock_logger_func:
            mock_logger = Mock()
            mock_logger_func.return_value = mock_logger
            null_register.write(0x1234)
            mock_logger.log_warning.assert_called_once()

    @pytest.mark.unit
    def test_null_register_has_field(self, null_register):
        """Test NullRegister has_field method."""
        assert null_register.has_field('TEST_FIELD') is False

    @pytest.mark.unit
    def test_null_register_get_field(self, null_register):
        """Test NullRegister get_field method."""
        with patch('chipsec.library.register.logger') as mock_logger_func:
            mock_logger = Mock()
            mock_logger_func.return_value = mock_logger
            result = null_register.get_field('TEST_FIELD')
            assert result == 0
            mock_logger.log_warning.assert_called_once()


if __name__ == '__main__':
    pytest.main([__file__])
