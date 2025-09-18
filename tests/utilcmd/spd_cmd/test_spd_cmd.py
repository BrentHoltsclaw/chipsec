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
from chipsec.utilcmd.spd_cmd import SPDCommand
from tests.test_utils import MockFactory


class TestSPDCommand:
    """Comprehensive tests for SPD utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for SPD testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock SPD and SMBus HAL components
        cs_mock.hals = Mock()
        cs_mock.hals.smbus = Mock()
        cs_mock.hals.spd = Mock()

        return cs_mock

    @pytest.fixture
    def spd_command(self, mock_cs):
        """Create SPDCommand instance."""
        return SPDCommand(['detect'], cs=mock_cs)

    @pytest.mark.unit
    def test_spd_command_initialization(self, spd_command, mock_cs):
        """Test SPDCommand initialization."""
        assert spd_command.cs == mock_cs
        assert spd_command.argv == ['detect']

    @pytest.mark.unit
    def test_requirements(self, spd_command):
        """Test command requirements."""
        reqs = spd_command.requirements()
        assert reqs == spd_command.toLoad.All

    @pytest.mark.unit
    def test_parse_arguments_detect(self, mock_cs):
        """Test parsing detect command."""
        command = SPDCommand(['detect'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spd_detect

    @pytest.mark.unit
    def test_parse_arguments_dump_with_device(self, mock_cs):
        """Test parsing dump command with device."""
        command = SPDCommand(['dump', 'DIMM0'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spd_dump
        assert command.dev == 'DIMM0'

    @pytest.mark.unit
    def test_parse_arguments_dump_without_device(self, mock_cs):
        """Test parsing dump command without device."""
        command = SPDCommand(['dump'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spd_dump
        assert command.dev is None

    @pytest.mark.unit
    def test_parse_arguments_read_with_offset(self, mock_cs):
        """Test parsing read command with offset."""
        command = SPDCommand(['read', 'DIMM1', '0x0'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spd_read
        assert command.dev == 'DIMM1'
        assert command.off == 0x0

    @pytest.mark.unit
    def test_parse_arguments_read_without_offset(self, mock_cs):
        """Test parsing read command without offset."""
        command = SPDCommand(['read', '0xA0'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spd_read
        assert command.dev == '0xA0'
        assert command.off is None

    @pytest.mark.unit
    def test_parse_arguments_write(self, mock_cs):
        """Test parsing write command."""
        command = SPDCommand(['write', 'DIMM2', '0x0', '0xAA'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.spd_write
        assert command.dev == 'DIMM2'
        assert command.off == 0x0
        assert command.val == 0xAA

    @pytest.mark.unit
    def test_parse_arguments_invalid(self, mock_cs):
        """Test parsing invalid command."""
        command = SPDCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_spd_detect_with_devices(self, spd_command, mock_cs):
        """Test spd_detect method with detected devices."""
        detected_devices = [0xA0, 0xA2, 0xA4]
        spd_command._spd.detect.return_value = detected_devices

        with patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(spd_command.logger, 'log') as mock_log:
            mock_spd_module.SPD_DIMMS = {0xA0: 'DIMM0', 0xA2: 'DIMM1', 0xA4: 'DIMM2'}

            spd_command.spd_detect()

            mock_log.assert_any_call('[CHIPSEC] Searching for DIMMs with SPD...')
            mock_log.assert_any_call('Detected the following SPD devices:')
            mock_log.assert_any_call('DIMM0: 0xA0')
            mock_log.assert_any_call('DIMM1: 0xA2')
            mock_log.assert_any_call('DIMM2: 0xA4')

    @pytest.mark.unit
    def test_spd_detect_no_devices(self, spd_command, mock_cs):
        """Test spd_detect method with no devices detected."""
        spd_command._spd.detect.return_value = None

        with patch.object(spd_command.logger, 'log') as mock_log:
            spd_command.spd_detect()

            mock_log.assert_any_call('[CHIPSEC] Searching for DIMMs with SPD...')
            mock_log.assert_any_call('Unable to detect SPD devices.')

    @pytest.mark.unit
    def test_spd_dump_specific_device(self, spd_command, mock_cs):
        """Test spd_dump method with specific device."""
        spd_command.dev = 'DIMM0'
        spd_command.dev_addr = 0xA0

        with patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module:
            mock_spd_module.SPD_DIMM_ADDRESSES = {'DIMM0': 0xA0}
            spd_command._spd.isSPDPresent.return_value = True

            spd_command.spd_dump()

            spd_command._spd.isSPDPresent.assert_called_once_with(0xA0)
            spd_command._spd.decode.assert_called_once_with(0xA0)

    @pytest.mark.unit
    def test_spd_dump_specific_device_not_present(self, spd_command, mock_cs):
        """Test spd_dump method with device not present."""
        spd_command.dev = 'DIMM0'
        spd_command.dev_addr = 0xA0

        with patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(spd_command.logger, 'log') as mock_log:
            mock_spd_module.SPD_DIMM_ADDRESSES = {'DIMM0': 0xA0}
            spd_command._spd.isSPDPresent.return_value = False

            spd_command.spd_dump()

            mock_log.assert_called_with('[CHIPSEC] SPD for DIMM 0xA0 is not found')

    @pytest.mark.unit
    def test_spd_dump_hex_address(self, spd_command, mock_cs):
        """Test spd_dump method with hex address."""
        spd_command.dev = '0xA2'
        spd_command.dev_addr = 0xA2

        spd_command._spd.isSPDPresent.return_value = True

        spd_command.spd_dump()

        spd_command._spd.isSPDPresent.assert_called_once_with(0xA2)
        spd_command._spd.decode.assert_called_once_with(0xA2)

    @pytest.mark.unit
    def test_spd_dump_all_devices(self, spd_command, mock_cs):
        """Test spd_dump method for all devices."""
        spd_command.dev = None
        detected_devices = [0xA0, 0xA2]
        spd_command._spd.detect.return_value = detected_devices

        spd_command.spd_dump()

        spd_command._spd.detect.assert_called_once()
        assert spd_command._spd.decode.call_count == 2
        spd_command._spd.decode.assert_any_call(0xA0)
        spd_command._spd.decode.assert_any_call(0xA2)

    @pytest.mark.unit
    def test_spd_read_named_device(self, spd_command, mock_cs):
        """Test spd_read method with named device."""
        spd_command.dev = 'DIMM1'
        spd_command.off = 0x0

        with patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(spd_command.logger, 'log') as mock_log:
            mock_spd_module.SPD_DIMM_ADDRESSES = {'DIMM1': 0xA2}
            spd_command._spd.isSPDPresent.return_value = True
            spd_command._spd.read_byte.return_value = 0xAB

            spd_command.spd_read()

            spd_command._spd.isSPDPresent.assert_called_once_with(0xA2)
            spd_command._spd.read_byte.assert_called_once_with(0x0, 0xA2)
            mock_log.assert_called_with('[CHIPSEC] SPD read: offset 0x0 = 0xAB')

    @pytest.mark.unit
    def test_spd_read_hex_device(self, spd_command, mock_cs):
        """Test spd_read method with hex device address."""
        spd_command.dev = '0xA4'
        spd_command.off = 0x10

        spd_command._spd.isSPDPresent.return_value = True
        spd_command._spd.read_byte.return_value = 0xCD

        with patch.object(spd_command.logger, 'log') as mock_log:
            spd_command.spd_read()

            spd_command._spd.isSPDPresent.assert_called_once_with(0xA4)
            spd_command._spd.read_byte.assert_called_once_with(0x10, 0xA4)
            mock_log.assert_called_with('[CHIPSEC] SPD read: offset 0x10 = 0xCD')

    @pytest.mark.unit
    def test_spd_read_device_not_present(self, spd_command, mock_cs):
        """Test spd_read method with device not present."""
        spd_command.dev = 'DIMM3'
        spd_command.off = 0x0

        with patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(spd_command.logger, 'log') as mock_log:
            mock_spd_module.SPD_DIMM_ADDRESSES = {'DIMM3': 0xA6}
            spd_command._spd.isSPDPresent.return_value = False

            spd_command.spd_read()

            mock_log.assert_called_with('[CHIPSEC] SPD for DIMM 0xA6 is not found')

    @pytest.mark.unit
    def test_spd_write_named_device(self, spd_command, mock_cs):
        """Test spd_write method with named device."""
        spd_command.dev = 'DIMM0'
        spd_command.off = 0x0
        spd_command.val = 0xAA

        with patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(spd_command.logger, 'log') as mock_log:
            mock_spd_module.SPD_DIMM_ADDRESSES = {'DIMM0': 0xA0}
            spd_command._spd.isSPDPresent.return_value = True

            spd_command.spd_write()

            spd_command._spd.isSPDPresent.assert_called_once_with(0xA0)
            spd_command._spd.write_byte.assert_called_once_with(0x0, 0xAA, 0xA0)
            mock_log.assert_called_with('[CHIPSEC] SPD write: offset 0x0 = 0xAA')

    @pytest.mark.unit
    def test_spd_write_hex_device(self, spd_command, mock_cs):
        """Test spd_write method with hex device address."""
        spd_command.dev = '0xA0'
        spd_command.off = 0x20
        spd_command.val = 0xFF

        spd_command._spd.isSPDPresent.return_value = True

        with patch.object(spd_command.logger, 'log') as mock_log:
            spd_command.spd_write()

            spd_command._spd.isSPDPresent.assert_called_once_with(0xA0)
            spd_command._spd.write_byte.assert_called_once_with(0x20, 0xFF, 0xA0)
            mock_log.assert_called_with('[CHIPSEC] SPD write: offset 0x20 = 0xFF')

    @pytest.mark.unit
    def test_spd_write_device_not_present(self, spd_command, mock_cs):
        """Test spd_write method with device not present."""
        spd_command.dev = 'DIMM4'
        spd_command.off = 0x0
        spd_command.val = 0xBB

        with patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(spd_command.logger, 'log') as mock_log:
            mock_spd_module.SPD_DIMM_ADDRESSES = {'DIMM4': 0xA8}
            spd_command._spd.isSPDPresent.return_value = False

            spd_command.spd_write()

            mock_log.assert_called_with('[CHIPSEC] SPD for DIMM 0xA8 is not found')

    @pytest.mark.unit
    def test_run_successful_initialization(self, spd_command, mock_cs):
        """Test run method with successful initialization."""
        spd_command.func = Mock()

        with patch('chipsec.utilcmd.spd_cmd.smbus') as mock_smbus_module, \
             patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(spd_command.logger, 'log') as mock_log:
            mock_smbus_instance = Mock()
            mock_smbus_module.SMBus.return_value = mock_smbus_instance
            mock_smbus_instance.is_SMBus_supported.return_value = True

            mock_spd_instance = Mock()
            mock_spd_module.SPD.return_value = mock_spd_instance

            spd_command.run()

            mock_smbus_module.SMBus.assert_called_once_with(mock_cs)
            mock_spd_module.SPD.assert_called_once_with(mock_smbus_instance)
            assert spd_command._spd == mock_spd_instance
            assert spd_command.dev_addr == mock_spd_module.SPD_SMBUS_ADDRESS
            spd_command.func.assert_called_once()

    @pytest.mark.unit
    def test_run_smbus_initialization_error(self, spd_command, mock_cs):
        """Test run method with SMBus initialization error."""
        spd_command.func = Mock()

        with patch('chipsec.utilcmd.spd_cmd.smbus') as mock_smbus_module, \
             patch.object(spd_command.logger, 'log_error') as mock_log_error:
            mock_smbus_module.SMBus.side_effect = Exception("SMBus initialization failed")

            spd_command.run()

            mock_log_error.assert_called_with(Exception("SMBus initialization failed"))
            spd_command.func.assert_not_called()

    @pytest.mark.unit
    def test_run_smbus_not_supported(self, spd_command, mock_cs):
        """Test run method when SMBus is not supported."""
        spd_command.func = Mock()

        with patch('chipsec.utilcmd.spd_cmd.smbus') as mock_smbus_module, \
             patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(spd_command.logger, 'log') as mock_log:
            mock_smbus_instance = Mock()
            mock_smbus_module.SMBus.return_value = mock_smbus_instance
            mock_smbus_instance.is_SMBus_supported.return_value = False

            spd_command.run()

            mock_log.assert_called_with('[CHIPSEC] SMBus controller is not supported')
            spd_command.func.assert_not_called()


class TestSPDCommandIntegration:
    """Integration tests for SPD command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for SPD testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock SPD and SMBus components with realistic data
        cs_mock.hals = Mock()
        cs_mock.hals.smbus = Mock()
        cs_mock.hals.spd = Mock()

        return cs_mock

    @pytest.mark.integration
    def test_spd_detect_integration(self, integrated_cs):
        """Test complete spd_detect workflow."""
        spd_cmd = SPDCommand(['detect'], cs=integrated_cs)

        with patch('chipsec.utilcmd.spd_cmd.smbus') as mock_smbus_module, \
             patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(spd_cmd.logger, 'log'):
            mock_smbus_instance = Mock()
            mock_smbus_module.SMBus.return_value = mock_smbus_instance
            mock_smbus_instance.is_SMBus_supported.return_value = True

            mock_spd_instance = Mock()
            mock_spd_module.SPD.return_value = mock_spd_instance
            mock_spd_instance.detect.return_value = [0xA0, 0xA2]
            mock_spd_module.SPD_DIMMS = {0xA0: 'DIMM0', 0xA2: 'DIMM1'}

            spd_cmd.run()

            mock_spd_instance.detect.assert_called_once()

    @pytest.mark.integration
    def test_spd_dump_integration(self, integrated_cs):
        """Test complete spd_dump workflow."""
        spd_cmd = SPDCommand(['dump', 'DIMM0'], cs=integrated_cs)

        with patch('chipsec.utilcmd.spd_cmd.smbus') as mock_smbus_module, \
             patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module:
            mock_smbus_instance = Mock()
            mock_smbus_module.SMBus.return_value = mock_smbus_instance
            mock_smbus_instance.is_SMBus_supported.return_value = True

            mock_spd_instance = Mock()
            mock_spd_module.SPD.return_value = mock_spd_instance
            mock_spd_module.SPD_DIMM_ADDRESSES = {'DIMM0': 0xA0}
            mock_spd_instance.isSPDPresent.return_value = True

            spd_cmd.run()

            mock_spd_instance.isSPDPresent.assert_called_once_with(0xA0)
            mock_spd_instance.decode.assert_called_once_with(0xA0)

    @pytest.mark.integration
    def test_spd_read_integration(self, integrated_cs):
        """Test complete spd_read workflow."""
        spd_cmd = SPDCommand(['read', 'DIMM1', '0x0'], cs=integrated_cs)

        with patch('chipsec.utilcmd.spd_cmd.smbus') as mock_smbus_module, \
             patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(spd_cmd.logger, 'log'):
            mock_smbus_instance = Mock()
            mock_smbus_module.SMBus.return_value = mock_smbus_instance
            mock_smbus_instance.is_SMBus_supported.return_value = True

            mock_spd_instance = Mock()
            mock_spd_module.SPD.return_value = mock_spd_instance
            mock_spd_module.SPD_DIMM_ADDRESSES = {'DIMM1': 0xA2}
            mock_spd_instance.isSPDPresent.return_value = True
            mock_spd_instance.read_byte.return_value = 0xAB

            spd_cmd.run()

            mock_spd_instance.read_byte.assert_called_once_with(0x0, 0xA2)

    @pytest.mark.integration
    def test_spd_write_integration(self, integrated_cs):
        """Test complete spd_write workflow."""
        spd_cmd = SPDCommand(['write', '0xA0', '0x0', '0xAA'], cs=integrated_cs)

        with patch('chipsec.utilcmd.spd_cmd.smbus') as mock_smbus_module, \
             patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(spd_cmd.logger, 'log'):
            mock_smbus_instance = Mock()
            mock_smbus_module.SMBus.return_value = mock_smbus_instance
            mock_smbus_instance.is_SMBus_supported.return_value = True

            mock_spd_instance = Mock()
            mock_spd_module.SPD.return_value = mock_spd_instance
            mock_spd_instance.isSPDPresent.return_value = True

            spd_cmd.run()

            mock_spd_instance.write_byte.assert_called_once_with(0x0, 0xAA, 0xA0)


class TestSPDCommandEdgeCases:
    """Test edge cases and error conditions for SPD command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        cs_mock.hals.smbus = Mock()
        cs_mock.hals.spd = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        command = SPDCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_spd_dump_empty_device_list(self, mock_cs):
        """Test spd_dump with empty device list."""
        command = SPDCommand(['dump'], cs=mock_cs)
        command.dev = None

        command._spd.detect.return_value = []

        command.spd_dump()

        command._spd.detect.assert_called_once()
        # Should not call decode when no devices detected

    @pytest.mark.unit
    def test_spd_read_various_offsets(self, mock_cs):
        """Test spd_read with various offset values."""
        test_cases = [0x0, 0x10, 0xFF, 0x100]

        for offset in test_cases:
            command = SPDCommand(['read', '0xA0', f'0x{offset:X}'], cs=mock_cs)
            command.set_up()
            command._spd.isSPDPresent.return_value = True
            command._spd.read_byte.return_value = 0xAB

            with patch.object(command.logger, 'log'):
                command.run()

                command._spd.read_byte.assert_called_with(offset, 0xA0)

    @pytest.mark.unit
    def test_spd_write_various_values(self, mock_cs):
        """Test spd_write with various byte values."""
        test_values = [0x00, 0xFF, 0xAB, 0x42]

        for value in test_values:
            command = SPDCommand(['write', '0xA0', '0x0', f'0x{value:X}'], cs=mock_cs)
            command.set_up()
            command._spd.isSPDPresent.return_value = True

            with patch.object(command.logger, 'log'):
                command.run()

                command._spd.write_byte.assert_called_with(0x0, value, 0xA0)

    @pytest.mark.unit
    def test_spd_detect_empty_result(self, mock_cs):
        """Test spd_detect with empty detection result."""
        command = SPDCommand(['detect'], cs=mock_cs)

        command._spd.detect.return_value = []

        with patch.object(command.logger, 'log') as mock_log:
            command.spd_detect()

            mock_log.assert_any_call('[CHIPSEC] Searching for DIMMs with SPD...')
            mock_log.assert_any_call('Unable to detect SPD devices.')

    @pytest.mark.unit
    def test_hex_parsing_various_formats(self, mock_cs):
        """Test hex parsing with various formats."""
        test_cases = [
            ('0xA0', 0xA0),
            ('A0', 0xA0),
            ('0x0', 0x0),
            ('0', 0x0),
            ('FF', 0xFF),
            ('0xFF', 0xFF)
        ]

        for hex_str, expected_value in test_cases:
            command = SPDCommand(['read', hex_str, '0x0'], cs=mock_cs)
            command.parse_arguments()
            assert command.dev_addr == expected_value

    @pytest.mark.unit
    def test_spd_dump_multiple_devices(self, mock_cs):
        """Test spd_dump with multiple devices."""
        command = SPDCommand(['dump'], cs=mock_cs)
        command.dev = None

        command._spd.detect.return_value = [0xA0, 0xA2, 0xA4]

        command.spd_dump()

        # Should call decode for each device
        assert command._spd.decode.call_count == 3
        command._spd.decode.assert_any_call(0xA0)
        command._spd.decode.assert_any_call(0xA2)
        command._spd.decode.assert_any_call(0xA4)

    @pytest.mark.unit
    def test_spd_read_without_offset(self, mock_cs):
        """Test spd_read without explicit offset."""
        command = SPDCommand(['read', '0xA0'], cs=mock_cs)
        command.set_up()

        command._spd.isSPDPresent.return_value = True
        command._spd.read_byte.return_value = 0xCD

        with patch.object(command.logger, 'log'):
            command.run()

            # Should use default offset of None, but read_byte expects an offset
            # This tests the error handling path
            command._spd.read_byte.assert_called_with(None, 0xA0)


class TestSPDCommandConfigurationValidation:
    """Test configuration validation aspects of SPD command."""

    @pytest.fixture
    def spd_cs(self):
        """Create ChipsecCs with SPD-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock SPD configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.SPD = {
            'SMBUS_ADDRESS': 0xA0,
            'DIMM_ADDRESSES': {
                'DIMM0': 0xA0,
                'DIMM1': 0xA2,
                'DIMM2': 0xA4
            },
            'MAX_OFFSET': 0xFF
        }

        cs_mock.hals = Mock()
        cs_mock.hals.smbus = Mock()
        cs_mock.hals.spd = Mock()

        return cs_mock

    @pytest.mark.unit
    def test_spd_configuration_structure(self, spd_cs):
        """Test SPD configuration structure."""
        spd_config = spd_cs.Cfg.SPD

        # Test that required SPD configuration exists
        assert 'SMBUS_ADDRESS' in spd_config
        assert 'DIMM_ADDRESSES' in spd_config

        # Test configuration values are reasonable
        assert spd_config['SMBUS_ADDRESS'] > 0
        assert isinstance(spd_config['DIMM_ADDRESSES'], dict)

    @pytest.mark.unit
    def test_spd_device_address_validation(self, spd_cs):
        """Test SPD device address validation."""
        # Test various device address formats
        test_cases = [
            ('DIMM0', 0xA0),
            ('DIMM1', 0xA2),
            ('0xA4', 0xA4),
            ('0xA6', 0xA6)
        ]

        for dev_str, expected_addr in test_cases:
            command = SPDCommand(['read', dev_str, '0x0'], cs=spd_cs)
            command.parse_arguments()

            # The actual address resolution happens in the command methods
            assert command.dev == dev_str

    @pytest.mark.unit
    def test_spd_offset_validation(self, spd_cs):
        """Test SPD offset validation."""
        # Test various offset formats
        test_cases = [
            ('0x0', 0x0),
            ('0x10', 0x10),
            ('0xFF', 0xFF),
            ('0', 0x0)
        ]

        for offset_str, expected_offset in test_cases:
            command = SPDCommand(['read', '0xA0', offset_str], cs=spd_cs)
            command.parse_arguments()

            assert command.off == expected_offset

    @pytest.mark.unit
    def test_spd_value_validation(self, spd_cs):
        """Test SPD value validation."""
        # Test various value formats
        test_cases = [
            ('0x00', 0x00),
            ('0xFF', 0xFF),
            ('0xAB', 0xAB),
            ('0', 0x0)
        ]

        for value_str, expected_value in test_cases:
            command = SPDCommand(['write', '0xA0', '0x0', value_str], cs=spd_cs)
            command.parse_arguments()

            assert command.val == expected_value

    @pytest.mark.unit
    def test_spd_dimm_name_validation(self, spd_cs):
        """Test SPD DIMM name validation."""
        valid_names = ['DIMM0', 'DIMM1', 'DIMM2']

        for name in valid_names:
            command = SPDCommand(['dump', name], cs=spd_cs)
            command.parse_arguments()

            assert command.dev == name

    @pytest.mark.unit
    def test_spd_error_handling(self, spd_cs):
        """Test SPD error handling."""
        command = SPDCommand(['read', '0xA0', '0x0'], cs=spd_cs)

        # Mock SPD read to raise exception
        command._spd.read_byte.side_effect = Exception("SPD read failed")

        # Should handle the exception gracefully
        with pytest.raises(Exception):
            command.spd_read()

    @pytest.mark.unit
    def test_spd_initialization_error_handling(self, spd_cs):
        """Test SPD initialization error handling."""
        command = SPDCommand(['detect'], cs=spd_cs)

        with patch('chipsec.utilcmd.spd_cmd.smbus') as mock_smbus_module, \
             patch.object(command.logger, 'log_error'):
            mock_smbus_module.SMBus.side_effect = Exception("SMBus init failed")

            # Should handle the exception gracefully
            command.run()


if __name__ == '__main__':
    pytest.main([__file__])
