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
from chipsec.utilcmd.reg_cmd import RegisterCommand
from tests.test_utils import MockFactory


class TestRegisterCommand:
    """Comprehensive tests for Register utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for Register testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock register access
        cs_mock.register = Mock()
        cs_mock.register.get_list_by_name.return_value = Mock()
        cs_mock.register.has_field.return_value = True

        # Mock control access
        cs_mock.control = Mock()
        cs_mock.control.is_defined.return_value = True
        cs_mock.control.get_list_by_name.return_value = [Mock()]

        return cs_mock

    @pytest.fixture
    def reg_command(self, mock_cs):
        """Create RegisterCommand instance."""
        return RegisterCommand(['read', 'SMBUS_VID'], cs=mock_cs)

    @pytest.mark.unit
    def test_register_command_initialization(self, reg_command, mock_cs):
        """Test RegisterCommand initialization."""
        assert reg_command.cs == mock_cs
        assert reg_command.argv == ['read', 'SMBUS_VID']

    @pytest.mark.unit
    def test_parse_arguments_read(self, mock_cs):
        """Test parsing read command arguments."""
        command = RegisterCommand(['read', 'SMBUS_VID'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.reg_read
        assert command.reg_name == 'SMBUS_VID'
        assert command.field_name is None

    @pytest.mark.unit
    def test_parse_arguments_read_with_field(self, mock_cs):
        """Test parsing read command with field arguments."""
        command = RegisterCommand(['read', 'HSFC', 'FGO'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.reg_read
        assert command.reg_name == 'HSFC'
        assert command.field_name == 'FGO'

    @pytest.mark.unit
    def test_parse_arguments_read_field(self, mock_cs):
        """Test parsing read_field command arguments."""
        command = RegisterCommand(['read_field', 'HSFC', 'FGO'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.reg_read_field
        assert command.reg_name == 'HSFC'
        assert command.field_name == 'FGO'

    @pytest.mark.unit
    def test_parse_arguments_write(self, mock_cs):
        """Test parsing write command arguments."""
        command = RegisterCommand(['write', 'SMBUS_VID', '0x8088'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.reg_write
        assert command.reg_name == 'SMBUS_VID'
        assert command.value == 0x8088

    @pytest.mark.unit
    def test_parse_arguments_write_field(self, mock_cs):
        """Test parsing write_field command arguments."""
        command = RegisterCommand(['write_field', 'BC', 'BLE', '0x1'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.reg_write_field
        assert command.reg_name == 'BC'
        assert command.field_name == 'BLE'
        assert command.value == 0x1

    @pytest.mark.unit
    def test_parse_arguments_get_control(self, mock_cs):
        """Test parsing get_control command arguments."""
        command = RegisterCommand(['get_control', 'BiosWriteEnable'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.reg_get_control
        assert command.control_name == 'BiosWriteEnable'

    @pytest.mark.unit
    def test_parse_arguments_set_control(self, mock_cs):
        """Test parsing set_control command arguments."""
        command = RegisterCommand(['set_control', 'BiosLockEnable', '0x1'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.reg_set_control
        assert command.control_name == 'BiosLockEnable'
        assert command.value == 0x1

    @pytest.mark.unit
    def test_requirements(self, reg_command):
        """Test command requirements."""
        reqs = reg_command.requirements()
        assert hasattr(reqs, 'load_driver')
        assert hasattr(reqs, 'load_config')

    @pytest.mark.unit
    def test_reg_read_without_field(self, reg_command, mock_cs):
        """Test reg_read without field name."""
        reg_command.reg_name = 'SMBUS_VID'
        reg_command.field_name = None

        mock_reglist = Mock()
        mock_cs.register.get_list_by_name.return_value = mock_reglist

        with patch.object(reg_command.logger, 'log') as mock_log:
            reg_command.reg_read()

            mock_cs.register.get_list_by_name.assert_called_with('SMBUS_VID')
            mock_reglist.read_and_print.assert_called_once()

    @pytest.mark.unit
    def test_reg_read_with_field(self, reg_command, mock_cs):
        """Test reg_read with field name."""
        reg_command.reg_name = 'HSFC'
        reg_command.field_name = 'FGO'

        mock_reglist = Mock()
        mock_reglist.read_field.return_value = [0x1234, 0x5678]
        mock_cs.register.get_list_by_name.return_value = mock_reglist

        with patch.object(reg_command.logger, 'log') as mock_log:
            reg_command.reg_read()

            mock_reglist.read_field.assert_called_once_with('FGO')
            assert mock_log.call_count == 2  # One for each CPU

    @pytest.mark.unit
    def test_reg_read_no_register_found(self, reg_command, mock_cs):
        """Test reg_read when no register is found."""
        reg_command.reg_name = 'NONEXISTENT_REG'
        reg_command.field_name = None

        mock_reglist = Mock()
        mock_reglist.__len__ = Mock(return_value=0)
        mock_cs.register.get_list_by_name.return_value = mock_reglist

        with patch.object(reg_command.logger, 'log') as mock_log:
            reg_command.reg_read()

            mock_log.assert_called_once_with('No register found with the name NONEXISTENT_REG')

    @pytest.mark.unit
    def test_reg_read_field_valid(self, reg_command, mock_cs):
        """Test reg_read_field with valid field."""
        reg_command.reg_name = 'HSFC'
        reg_command.field_name = 'FGO'

        mock_reglist = Mock()
        mock_reglist.read_field.return_value = [0xABCD]
        mock_cs.register.get_list_by_name.return_value = mock_reglist

        with patch.object(reg_command.logger, 'log') as mock_log:
            reg_command.reg_read_field()

            mock_reglist.read_field.assert_called_once_with('FGO')
            mock_log.assert_called_once_with('[CHIPSEC] HSFC.FGO = 0xABCD')

    @pytest.mark.unit
    def test_reg_read_field_invalid(self, reg_command, mock_cs):
        """Test reg_read_field with invalid field."""
        reg_command.reg_name = 'HSFC'
        reg_command.field_name = 'INVALID_FIELD'

        mock_cs.register.has_field.return_value = False

        with patch.object(reg_command.logger, 'log_error') as mock_error:
            reg_command.reg_read_field()

            mock_error.assert_called_once()
            mock_error.assert_called_with("[CHIPSEC] Register 'HSFC' doesn't have field 'INVALID_FIELD' defined")

    @pytest.mark.unit
    def test_reg_write(self, reg_command, mock_cs):
        """Test reg_write command."""
        reg_command.reg_name = 'SMBUS_VID'
        reg_command.value = 0x8088

        mock_reglist = Mock()
        mock_cs.register.get_list_by_name.return_value = mock_reglist

        with patch.object(reg_command.logger, 'log') as mock_log:
            reg_command.reg_write()

            mock_reglist.write.assert_called_once_with(0x8088)
            mock_log.assert_called_once_with('[CHIPSEC] Writing SMBUS_VID < 0x8088')

    @pytest.mark.unit
    def test_reg_write_field_valid(self, reg_command, mock_cs):
        """Test reg_write_field with valid field."""
        reg_command.reg_name = 'BC'
        reg_command.field_name = 'BLE'
        reg_command.value = 0x1

        mock_reglist = Mock()
        mock_cs.register.get_list_by_name.return_value = mock_reglist

        with patch.object(reg_command.logger, 'log') as mock_log:
            reg_command.reg_write_field()

            mock_reglist.write_field.assert_called_once_with('BLE', 0x1)
            mock_log.assert_called_once_with('[CHIPSEC] Writing BC.BLE < 0x1')

    @pytest.mark.unit
    def test_reg_write_field_invalid(self, reg_command, mock_cs):
        """Test reg_write_field with invalid field."""
        reg_command.reg_name = 'BC'
        reg_command.field_name = 'INVALID_FIELD'
        reg_command.value = 0x1

        mock_cs.register.has_field.return_value = False

        with patch.object(reg_command.logger, 'log_error') as mock_error:
            reg_command.reg_write_field()

            mock_error.assert_called_once_with("[CHIPSEC] Register 'BC' doesn't have field 'INVALID_FIELD' defined")

    @pytest.mark.unit
    def test_reg_get_control_valid(self, reg_command, mock_cs):
        """Test reg_get_control with valid control."""
        reg_command.control_name = 'BiosWriteEnable'

        mock_ctrl = Mock()
        mock_ctrl.value = 0x1234
        mock_cs.control.get_list_by_name.return_value = [mock_ctrl]

        with patch.object(reg_command.logger, 'log') as mock_log:
            reg_command.reg_get_control()

            mock_ctrl.read.assert_called_once()
            mock_log.assert_called_once_with('[CHIPSEC] BiosWriteEnable = 0x1234')

    @pytest.mark.unit
    def test_reg_get_control_invalid(self, reg_command, mock_cs):
        """Test reg_get_control with invalid control."""
        reg_command.control_name = 'InvalidControl'

        mock_cs.control.is_defined.return_value = False

        with patch.object(reg_command.logger, 'log_error') as mock_error:
            reg_command.reg_get_control()

            mock_error.assert_called_once_with("[CHIPSEC] Control 'InvalidControl' isn't defined")

    @pytest.mark.unit
    def test_reg_set_control_valid(self, reg_command, mock_cs):
        """Test reg_set_control with valid control."""
        reg_command.control_name = 'BiosLockEnable'
        reg_command.value = 0x1

        mock_ctrl_list = Mock()
        mock_cs.control.get_list_by_name.return_value = mock_ctrl_list

        with patch.object(reg_command.logger, 'log') as mock_log:
            reg_command.reg_set_control()

            mock_ctrl_list.write.assert_called_once_with(0x1)
            mock_log.assert_called_once_with('[CHIPSEC] Setting control BiosLockEnable < 0x1')

    @pytest.mark.unit
    def test_reg_set_control_invalid(self, reg_command, mock_cs):
        """Test reg_set_control with invalid control."""
        reg_command.control_name = 'InvalidControl'
        reg_command.value = 0x1

        mock_cs.control.is_defined.return_value = False

        with patch.object(reg_command.logger, 'log_error') as mock_error:
            reg_command.reg_set_control()

            mock_error.assert_called_once_with("[CHIPSEC] Control 'InvalidControl' isn't defined")


class TestRegisterCommandIntegration:
    """Integration tests for Register command with HAL components."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for Register testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock register access with realistic behavior
        cs_mock.register = Mock()
        mock_reglist = Mock()
        mock_reglist.read_field.return_value = [0xABCD, 0xEF01]
        mock_reglist.write.return_value = None
        mock_reglist.write_field.return_value = None
        mock_reglist.read_and_print.return_value = None
        cs_mock.register.get_list_by_name.return_value = mock_reglist
        cs_mock.register.has_field.return_value = True

        # Mock control access
        cs_mock.control = Mock()
        cs_mock.control.is_defined.return_value = True
        mock_ctrl = Mock()
        mock_ctrl.value = 0xDEADBEEF
        cs_mock.control.get_list_by_name.return_value = [mock_ctrl]

        # Mock helper
        cs_mock.helper = Mock()
        cs_mock.helper.get_threads_count.return_value = 2

        return cs_mock

    @pytest.mark.integration
    def test_register_read_write_workflow(self, integrated_cs):
        """Test complete register read/write workflow."""
        # Test read operation
        read_cmd = RegisterCommand(['read', 'SMBUS_VID'], cs=integrated_cs)
        read_cmd.parse_arguments()

        with patch.object(read_cmd.logger, 'log') as mock_log:
            read_cmd.run()

            integrated_cs.register.get_list_by_name.assert_called_with('SMBUS_VID')
            # Should call read_and_print for register without field
            integrated_cs.register.get_list_by_name.return_value.read_and_print.assert_called_once()

        # Test write operation
        write_cmd = RegisterCommand(['write', 'SMBUS_VID', '0x8088'], cs=integrated_cs)
        write_cmd.parse_arguments()

        with patch.object(write_cmd.logger, 'log') as mock_log:
            write_cmd.run()

            integrated_cs.register.get_list_by_name.return_value.write.assert_called_once_with(0x8088)
            mock_log.assert_called_once()

    @pytest.mark.integration
    def test_register_field_operations_workflow(self, integrated_cs):
        """Test register field operations workflow."""
        # Test read field operation
        read_field_cmd = RegisterCommand(['read_field', 'HSFC', 'FGO'], cs=integrated_cs)
        read_field_cmd.parse_arguments()

        with patch.object(read_field_cmd.logger, 'log') as mock_log:
            read_field_cmd.run()

            integrated_cs.register.get_list_by_name.return_value.read_field.assert_called_once_with('FGO')
            mock_log.assert_called_once()

        # Test write field operation
        write_field_cmd = RegisterCommand(['write_field', 'BC', 'BLE', '0x1'], cs=integrated_cs)
        write_field_cmd.parse_arguments()

        with patch.object(write_field_cmd.logger, 'log') as mock_log:
            write_field_cmd.run()

            integrated_cs.register.get_list_by_name.return_value.write_field.assert_called_once_with('BLE', 0x1)
            mock_log.assert_called_once()

    @pytest.mark.integration
    def test_control_operations_workflow(self, integrated_cs):
        """Test control operations workflow."""
        # Test get control operation
        get_ctrl_cmd = RegisterCommand(['get_control', 'BiosWriteEnable'], cs=integrated_cs)
        get_ctrl_cmd.parse_arguments()

        with patch.object(get_ctrl_cmd.logger, 'log') as mock_log:
            get_ctrl_cmd.run()

            integrated_cs.control.get_list_by_name.return_value[0].read.assert_called_once()
            mock_log.assert_called_once()

        # Test set control operation
        set_ctrl_cmd = RegisterCommand(['set_control', 'BiosLockEnable', '0x1'], cs=integrated_cs)
        set_ctrl_cmd.parse_arguments()

        with patch.object(set_ctrl_cmd.logger, 'log') as mock_log:
            set_ctrl_cmd.run()

            integrated_cs.control.get_list_by_name.return_value.write.assert_called_once_with(0x1)
            mock_log.assert_called_once()


class TestRegisterCommandEdgeCases:
    """Test edge cases and error conditions for Register command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.register = Mock()
        cs_mock.control = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        reg_cmd = RegisterCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            reg_cmd.parse_arguments()

    @pytest.mark.unit
    def test_invalid_subcommand(self, mock_cs):
        """Test handling of invalid subcommand."""
        reg_cmd = RegisterCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            reg_cmd.parse_arguments()

    @pytest.mark.unit
    def test_read_missing_register_name(self, mock_cs):
        """Test read command with missing register name."""
        reg_cmd = RegisterCommand(['read'], cs=mock_cs)

        # Should raise SystemExit due to missing register name
        with pytest.raises(SystemExit):
            reg_cmd.parse_arguments()

    @pytest.mark.unit
    def test_write_missing_value(self, mock_cs):
        """Test write command with missing value."""
        reg_cmd = RegisterCommand(['write', 'SMBUS_VID'], cs=mock_cs)

        # Should raise SystemExit due to missing value
        with pytest.raises(SystemExit):
            reg_cmd.parse_arguments()

    @pytest.mark.unit
    def test_write_field_missing_value(self, mock_cs):
        """Test write_field command with missing value."""
        reg_cmd = RegisterCommand(['write_field', 'BC', 'BLE'], cs=mock_cs)

        # Should raise SystemExit due to missing value
        with pytest.raises(SystemExit):
            reg_cmd.parse_arguments()

    @pytest.mark.unit
    def test_get_control_missing_name(self, mock_cs):
        """Test get_control command with missing control name."""
        reg_cmd = RegisterCommand(['get_control'], cs=mock_cs)

        # Should raise SystemExit due to missing control name
        with pytest.raises(SystemExit):
            reg_cmd.parse_arguments()

    @pytest.mark.unit
    def test_set_control_missing_value(self, mock_cs):
        """Test set_control command with missing value."""
        reg_cmd = RegisterCommand(['set_control', 'BiosLockEnable'], cs=mock_cs)

        # Should raise SystemExit due to missing value
        with pytest.raises(SystemExit):
            reg_cmd.parse_arguments()

    @pytest.mark.unit
    def test_hex_value_parsing(self, mock_cs):
        """Test hex value parsing in various commands."""
        # Test write command with hex value
        write_cmd = RegisterCommand(['write', 'SMBUS_VID', '0x8088'], cs=mock_cs)
        write_cmd.parse_arguments()
        assert write_cmd.value == 0x8088

        # Test write command with decimal value
        write_cmd2 = RegisterCommand(['write', 'SMBUS_VID', '32888'], cs=mock_cs)
        write_cmd2.parse_arguments()
        assert write_cmd2.value == 32888

        # Test write_field command with hex value
        write_field_cmd = RegisterCommand(['write_field', 'BC', 'BLE', '0x1'], cs=mock_cs)
        write_field_cmd.parse_arguments()
        assert write_field_cmd.value == 0x1

    @pytest.mark.unit
    def test_case_insensitive_hex_parsing(self, mock_cs):
        """Test case insensitive hex value parsing."""
        # Test with uppercase hex
        write_cmd1 = RegisterCommand(['write', 'SMBUS_VID', '0xABCD'], cs=mock_cs)
        write_cmd1.parse_arguments()
        assert write_cmd1.value == 0xABCD

        # Test with lowercase hex
        write_cmd2 = RegisterCommand(['write', 'SMBUS_VID', '0xabcd'], cs=mock_cs)
        write_cmd2.parse_arguments()
        assert write_cmd2.value == 0xABCD

        # Test with mixed case hex
        write_cmd3 = RegisterCommand(['write', 'SMBUS_VID', '0xAbCd'], cs=mock_cs)
        write_cmd3.parse_arguments()
        assert write_cmd3.value == 0xABCD

    @pytest.mark.unit
    def test_zero_values(self, mock_cs):
        """Test operations with zero values."""
        # Test write with zero value
        write_cmd = RegisterCommand(['write', 'SMBUS_VID', '0x0'], cs=mock_cs)
        write_cmd.parse_arguments()
        assert write_cmd.value == 0x0

        # Test write_field with zero value
        write_field_cmd = RegisterCommand(['write_field', 'BC', 'BLE', '0x0'], cs=mock_cs)
        write_field_cmd.parse_arguments()
        assert write_field_cmd.value == 0x0

        # Test set_control with zero value
        set_ctrl_cmd = RegisterCommand(['set_control', 'BiosLockEnable', '0x0'], cs=mock_cs)
        set_ctrl_cmd.parse_arguments()
        assert set_ctrl_cmd.value == 0x0

    @pytest.mark.unit
    def test_maximum_values(self, mock_cs):
        """Test operations with maximum values."""
        # Test write with maximum 32-bit value
        write_cmd = RegisterCommand(['write', 'SMBUS_VID', '0xFFFFFFFF'], cs=mock_cs)
        write_cmd.parse_arguments()
        assert write_cmd.value == 0xFFFFFFFF

        # Test write_field with maximum value
        write_field_cmd = RegisterCommand(['write_field', 'BC', 'BLE', '0xFFFF'], cs=mock_cs)
        write_field_cmd.parse_arguments()
        assert write_field_cmd.value == 0xFFFF

    @pytest.mark.unit
    def test_register_name_case_sensitivity(self, mock_cs):
        """Test register name case sensitivity."""
        # Test with uppercase register name
        read_cmd1 = RegisterCommand(['read', 'SMBUS_VID'], cs=mock_cs)
        read_cmd1.parse_arguments()
        assert read_cmd1.reg_name == 'SMBUS_VID'

        # Test with lowercase register name
        read_cmd2 = RegisterCommand(['read', 'smbus_vid'], cs=mock_cs)
        read_cmd2.parse_arguments()
        assert read_cmd2.reg_name == 'smbus_vid'

        # Test with mixed case register name
        read_cmd3 = RegisterCommand(['read', 'Smbus_Vid'], cs=mock_cs)
        read_cmd3.parse_arguments()
        assert read_cmd3.reg_name == 'Smbus_Vid'

    @pytest.mark.unit
    def test_field_name_case_sensitivity(self, mock_cs):
        """Test field name case sensitivity."""
        # Test with uppercase field name
        read_field_cmd1 = RegisterCommand(['read_field', 'HSFC', 'FGO'], cs=mock_cs)
        read_field_cmd1.parse_arguments()
        assert read_field_cmd1.field_name == 'FGO'

        # Test with lowercase field name
        read_field_cmd2 = RegisterCommand(['read_field', 'HSFC', 'fgo'], cs=mock_cs)
        read_field_cmd2.parse_arguments()
        assert read_field_cmd2.field_name == 'fgo'

        # Test with mixed case field name
        read_field_cmd3 = RegisterCommand(['read_field', 'HSFC', 'Fgo'], cs=mock_cs)
        read_field_cmd3.parse_arguments()
        assert read_field_cmd3.field_name == 'Fgo'

    @pytest.mark.unit
    def test_control_name_case_sensitivity(self, mock_cs):
        """Test control name case sensitivity."""
        # Test with uppercase control name
        get_ctrl_cmd1 = RegisterCommand(['get_control', 'BiosWriteEnable'], cs=mock_cs)
        get_ctrl_cmd1.parse_arguments()
        assert get_ctrl_cmd1.control_name == 'BiosWriteEnable'

        # Test with lowercase control name
        get_ctrl_cmd2 = RegisterCommand(['get_control', 'bioswriteenable'], cs=mock_cs)
        get_ctrl_cmd2.parse_arguments()
        assert get_ctrl_cmd2.control_name == 'bioswriteenable'

        # Test with mixed case control name
        get_ctrl_cmd3 = RegisterCommand(['get_control', 'BiosWriteEnable'], cs=mock_cs)
        get_ctrl_cmd3.parse_arguments()
        assert get_ctrl_cmd3.control_name == 'BiosWriteEnable'


class TestRegisterCommandConfigurationValidation:
    """Test configuration validation aspects of Register command."""

    @pytest.fixture
    def config_cs(self):
        """Create ChipsecCs with register-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock register access with configuration
        cs_mock.register = Mock()
        mock_reglist = Mock()
        mock_reglist.read_field.return_value = [0x12345678]
        mock_reglist.write.return_value = None
        mock_reglist.write_field.return_value = None
        cs_mock.register.get_list_by_name.return_value = mock_reglist
        cs_mock.register.has_field.return_value = True

        # Mock control access
        cs_mock.control = Mock()
        cs_mock.control.is_defined.return_value = True
        mock_ctrl = Mock()
        mock_ctrl.value = 0x9ABCDEF0
        cs_mock.control.get_list_by_name.return_value = [mock_ctrl]

        # Mock register configuration data
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.REGISTER_CONFIG = {
            'max_register_value': 0xFFFFFFFF,
            'supported_register_types': ['mmio', 'pci', 'msr', 'iobar'],
            'security_registers': {
                'bios_control': 'BC',
                'bios_write_enable': 'BIOS_WE',
                'bios_lock_enable': 'BIOS_LE',
                'spi_bar': 'SPIBAR',
                'flash_descriptor': 'FD',
            },
            'control_definitions': {
                'BiosWriteEnable': {'register': 'BC', 'field': 'BIOSWE'},
                'BiosLockEnable': {'register': 'BC', 'field': 'BLE'},
                'SpiBiosLockEnable': {'register': 'HSFC', 'field': 'FLOCKDN'},
            }
        }

        return cs_mock

    @pytest.mark.unit
    def test_register_configuration_access(self, config_cs):
        """Test access to register configuration data."""
        reg_config = config_cs.Cfg.REGISTER_CONFIG

        assert reg_config['max_register_value'] == 0xFFFFFFFF
        assert 'mmio' in reg_config['supported_register_types']
        assert 'pci' in reg_config['supported_register_types']
        assert 'bios_control' in reg_config['security_registers']
        assert reg_config['security_registers']['bios_control'] == 'BC'

    @pytest.mark.unit
    def test_supported_register_types_validation(self, config_cs):
        """Test validation of supported register types."""
        supported_types = config_cs.Cfg.REGISTER_CONFIG['supported_register_types']

        # Test that all expected register types are supported
        expected_types = ['mmio', 'pci', 'msr', 'iobar']
        for reg_type in expected_types:
            assert reg_type in supported_types

        # Test that types list is not empty
        assert len(supported_types) > 0

    @pytest.mark.unit
    def test_security_registers_validation(self, config_cs):
        """Test validation of security registers configuration."""
        security_regs = config_cs.Cfg.REGISTER_CONFIG['security_registers']

        # Test that all expected security registers are defined
        expected_regs = ['bios_control', 'bios_write_enable', 'bios_lock_enable', 'spi_bar', 'flash_descriptor']
        for reg_name in expected_regs:
            assert reg_name in security_regs
            assert isinstance(security_regs[reg_name], str)
            assert len(security_regs[reg_name]) > 0

        # Test specific security register mappings
        assert security_regs['bios_control'] == 'BC'
        assert security_regs['spi_bar'] == 'SPIBAR'
        assert security_regs['flash_descriptor'] == 'FD'

    @pytest.mark.unit
    def test_control_definitions_validation(self, config_cs):
        """Test validation of control definitions configuration."""
        control_defs = config_cs.Cfg.REGISTER_CONFIG['control_definitions']

        # Test that all expected controls are defined
        expected_controls = ['BiosWriteEnable', 'BiosLockEnable', 'SpiBiosLockEnable']
        for ctrl_name in expected_controls:
            assert ctrl_name in control_defs
            assert 'register' in control_defs[ctrl_name]
            assert 'field' in control_defs[ctrl_name]
            assert isinstance(control_defs[ctrl_name]['register'], str)
            assert isinstance(control_defs[ctrl_name]['field'], str)

        # Test specific control definitions
        assert control_defs['BiosWriteEnable']['register'] == 'BC'
        assert control_defs['BiosWriteEnable']['field'] == 'BIOSWE'
        assert control_defs['BiosLockEnable']['register'] == 'BC'
        assert control_defs['BiosLockEnable']['field'] == 'BLE'
        assert control_defs['SpiBiosLockEnable']['register'] == 'HSFC'
        assert control_defs['SpiBiosLockEnable']['field'] == 'FLOCKDN'

    @pytest.mark.unit
    def test_register_value_limits_validation(self, config_cs):
        """Test register value limits validation."""
        max_value = config_cs.Cfg.REGISTER_CONFIG['max_register_value']

        # Test that the maximum register value is valid
        assert max_value == 0xFFFFFFFF  # 32-bit maximum

        # Test that the limit is reasonable
        assert max_value > 0
        assert max_value >= 0xFFFF  # At least 16-bit


if __name__ == '__main__':
    pytest.main([__file__])
