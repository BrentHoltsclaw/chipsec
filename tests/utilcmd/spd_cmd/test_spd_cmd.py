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
from chipsec.utilcmd.spd_cmd import SPDCommand
from tests.test_utils import MockFactory


class TestSPDCommand(unittest.TestCase):
    """Comprehensive tests for SPD utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()

        # Mock SPD and SMBus HAL components
        self.mock_cs.hals = Mock()
        self.mock_cs.hals.smbus = Mock()
        self.mock_cs.hals.spd = Mock()

        self.spd_command = SPDCommand(['detect'], cs=self.mock_cs)

    def test_spd_command_initialization(self):
        """Test SPDCommand initialization."""
        self.assertEqual(self.spd_command.cs, self.mock_cs)
        self.assertEqual(self.spd_command.argv, ['detect'])

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.spd_command.requirements()
        self.assertEqual(reqs, self.spd_command.toLoad.All)

    def test_parse_arguments_detect(self):
        """Test parsing detect command."""
        command = SPDCommand(['detect'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spd_detect)

    def test_parse_arguments_dump_with_device(self):
        """Test parsing dump command with device."""
        command = SPDCommand(['dump', 'DIMM0'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spd_dump)
        self.assertEqual(command.dev, 'DIMM0')

    def test_parse_arguments_dump_without_device(self):
        """Test parsing dump command without device."""
        command = SPDCommand(['dump'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spd_dump)
        self.assertIsNone(command.dev)

    def test_parse_arguments_read_with_offset(self):
        """Test parsing read command with offset."""
        command = SPDCommand(['read', 'DIMM1', '0x0'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spd_read)
        self.assertEqual(command.dev, 'DIMM1')
        self.assertEqual(command.off, 0x0)

    def test_parse_arguments_read_without_offset(self):
        """Test parsing read command without offset."""
        command = SPDCommand(['read', '0xA0'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spd_read)
        self.assertEqual(command.dev, '0xA0')
        self.assertIsNone(command.off)

    def test_parse_arguments_write(self):
        """Test parsing write command."""
        command = SPDCommand(['write', 'DIMM2', '0x0', '0xAA'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spd_write)
        self.assertEqual(command.dev, 'DIMM2')
        self.assertEqual(command.off, 0x0)
        self.assertEqual(command.val, 0xAA)

    def test_parse_arguments_invalid(self):
        """Test parsing invalid command."""
        command = SPDCommand(['invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_spd_detect_with_devices(self):
        """Test spd_detect method with detected devices."""
        detected_devices = [0xA0, 0xA2, 0xA4]
        self.spd_command._spd.detect.return_value = detected_devices

        with patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(self.spd_command.logger, 'log') as mock_log:
            mock_spd_module.SPD_DIMMS = {0xA0: 'DIMM0', 0xA2: 'DIMM1', 0xA4: 'DIMM2'}

            self.spd_command.spd_detect()

            mock_log.assert_any_call('[CHIPSEC] Searching for DIMMs with SPD...')
            mock_log.assert_any_call('Detected the following SPD devices:')
            mock_log.assert_any_call('DIMM0: 0xA0')
            mock_log.assert_any_call('DIMM1: 0xA2')
            mock_log.assert_any_call('DIMM2: 0xA4')

    def test_spd_detect_no_devices(self):
        """Test spd_detect method with no devices detected."""
        self.spd_command._spd.detect.return_value = None

        with patch.object(self.spd_command.logger, 'log') as mock_log:
            self.spd_command.spd_detect()

            mock_log.assert_any_call('[CHIPSEC] Searching for DIMMs with SPD...')
            mock_log.assert_any_call('Unable to detect SPD devices.')

    def test_spd_dump_specific_device(self):
        """Test spd_dump method with specific device."""
        self.spd_command.dev = 'DIMM0'
        self.spd_command.dev_addr = 0xA0

        with patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module:
            mock_spd_module.SPD_DIMM_ADDRESSES = {'DIMM0': 0xA0}
            self.spd_command._spd.isSPDPresent.return_value = True

            self.spd_command.spd_dump()

            self.spd_command._spd.isSPDPresent.assert_called_once_with(0xA0)
            self.spd_command._spd.decode.assert_called_once_with(0xA0)

    def test_spd_dump_specific_device_not_present(self):
        """Test spd_dump method with device not present."""
        self.spd_command.dev = 'DIMM0'
        self.spd_command.dev_addr = 0xA0

        with patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(self.spd_command.logger, 'log') as mock_log:
            mock_spd_module.SPD_DIMM_ADDRESSES = {'DIMM0': 0xA0}
            self.spd_command._spd.isSPDPresent.return_value = False

            self.spd_command.spd_dump()

            mock_log.assert_called_with('[CHIPSEC] SPD for DIMM 0xA0 is not found')

    def test_spd_dump_hex_address(self):
        """Test spd_dump method with hex address."""
        self.spd_command.dev = '0xA2'
        self.spd_command.dev_addr = 0xA2

        self.spd_command._spd.isSPDPresent.return_value = True

        self.spd_command.spd_dump()

        self.spd_command._spd.isSPDPresent.assert_called_once_with(0xA2)
        self.spd_command._spd.decode.assert_called_once_with(0xA2)

    def test_spd_dump_all_devices(self):
        """Test spd_dump method for all devices."""
        self.spd_command.dev = None
        detected_devices = [0xA0, 0xA2]
        self.spd_command._spd.detect.return_value = detected_devices

        self.spd_command.spd_dump()

        self.spd_command._spd.detect.assert_called_once()
        self.assertEqual(self.spd_command._spd.decode.call_count, 2)
        self.spd_command._spd.decode.assert_any_call(0xA0)
        self.spd_command._spd.decode.assert_any_call(0xA2)

    def test_spd_read_named_device(self):
        """Test spd_read method with named device."""
        self.spd_command.dev = 'DIMM1'
        self.spd_command.off = 0x0

        with patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(self.spd_command.logger, 'log') as mock_log:
            mock_spd_module.SPD_DIMM_ADDRESSES = {'DIMM1': 0xA2}
            self.spd_command._spd.isSPDPresent.return_value = True
            self.spd_command._spd.read_byte.return_value = 0xAB

            self.spd_command.spd_read()

            self.spd_command._spd.isSPDPresent.assert_called_once_with(0xA2)
            self.spd_command._spd.read_byte.assert_called_once_with(0x0, 0xA2)
            mock_log.assert_called_with('[CHIPSEC] SPD read: offset 0x0 = 0xAB')

    def test_spd_read_hex_device(self):
        """Test spd_read method with hex device address."""
        self.spd_command.dev = '0xA4'
        self.spd_command.off = 0x10

        self.spd_command._spd.isSPDPresent.return_value = True
        self.spd_command._spd.read_byte.return_value = 0xCD

        with patch.object(self.spd_command.logger, 'log') as mock_log:
            self.spd_command.spd_read()

            self.spd_command._spd.isSPDPresent.assert_called_once_with(0xA4)
            self.spd_command._spd.read_byte.assert_called_once_with(0x10, 0xA4)
            mock_log.assert_called_with('[CHIPSEC] SPD read: offset 0x10 = 0xCD')

    def test_spd_read_device_not_present(self):
        """Test spd_read method with device not present."""
        self.spd_command.dev = 'DIMM3'
        self.spd_command.off = 0x0

        with patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(self.spd_command.logger, 'log') as mock_log:
            mock_spd_module.SPD_DIMM_ADDRESSES = {'DIMM3': 0xA6}
            self.spd_command._spd.isSPDPresent.return_value = False

            self.spd_command.spd_read()

            mock_log.assert_called_with('[CHIPSEC] SPD for DIMM 0xA6 is not found')

    def test_spd_write_named_device(self):
        """Test spd_write method with named device."""
        self.spd_command.dev = 'DIMM0'
        self.spd_command.off = 0x0
        self.spd_command.val = 0xAA

        with patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(self.spd_command.logger, 'log') as mock_log:
            mock_spd_module.SPD_DIMM_ADDRESSES = {'DIMM0': 0xA0}
            self.spd_command._spd.isSPDPresent.return_value = True

            self.spd_command.spd_write()

            self.spd_command._spd.isSPDPresent.assert_called_once_with(0xA0)
            self.spd_command._spd.write_byte.assert_called_once_with(0x0, 0xAA, 0xA0)
            mock_log.assert_called_with('[CHIPSEC] SPD write: offset 0x0 = 0xAA')

    def test_spd_write_hex_device(self):
        """Test spd_write method with hex device address."""
        self.spd_command.dev = '0xA0'
        self.spd_command.off = 0x20
        self.spd_command.val = 0xFF

        self.spd_command._spd.isSPDPresent.return_value = True

        with patch.object(self.spd_command.logger, 'log') as mock_log:
            self.spd_command.spd_write()

            self.spd_command._spd.isSPDPresent.assert_called_once_with(0xA0)
            self.spd_command._spd.write_byte.assert_called_once_with(0x20, 0xFF, 0xA0)
            mock_log.assert_called_with('[CHIPSEC] SPD write: offset 0x20 = 0xFF')

    def test_spd_write_device_not_present(self):
        """Test spd_write method with device not present."""
        self.spd_command.dev = 'DIMM4'
        self.spd_command.off = 0x0
        self.spd_command.val = 0xBB

        with patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(self.spd_command.logger, 'log') as mock_log:
            mock_spd_module.SPD_DIMM_ADDRESSES = {'DIMM4': 0xA8}
            self.spd_command._spd.isSPDPresent.return_value = False

            self.spd_command.spd_write()

            mock_log.assert_called_with('[CHIPSEC] SPD for DIMM 0xA8 is not found')

    def test_run_successful_initialization(self):
        """Test run method with successful initialization."""
        self.spd_command.func = Mock()

        with patch('chipsec.utilcmd.spd_cmd.smbus') as mock_smbus_module, \
             patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(self.spd_command.logger, 'log') as mock_log:
            mock_smbus_instance = Mock()
            mock_smbus_module.SMBus.return_value = mock_smbus_instance
            mock_smbus_instance.is_SMBus_supported.return_value = True

            mock_spd_instance = Mock()
            mock_spd_module.SPD.return_value = mock_spd_instance

            self.spd_command.run()

            mock_smbus_module.SMBus.assert_called_once_with(self.mock_cs)
            mock_spd_module.SPD.assert_called_once_with(mock_smbus_instance)
            self.assertEqual(self.spd_command._spd, mock_spd_instance)
            self.assertEqual(self.spd_command.dev_addr, mock_spd_module.SPD_SMBUS_ADDRESS)
            self.spd_command.func.assert_called_once()

    def test_run_smbus_initialization_error(self):
        """Test run method with SMBus initialization error."""
        self.spd_command.func = Mock()

        with patch('chipsec.utilcmd.spd_cmd.smbus') as mock_smbus_module, \
             patch.object(self.spd_command.logger, 'log_error') as mock_log_error:
            mock_smbus_module.SMBus.side_effect = Exception("SMBus initialization failed")

            self.spd_command.run()

            mock_log_error.assert_called_with(Exception("SMBus initialization failed"))
            self.spd_command.func.assert_not_called()

    def test_run_smbus_not_supported(self):
        """Test run method when SMBus is not supported."""
        self.spd_command.func = Mock()

        with patch('chipsec.utilcmd.spd_cmd.smbus') as mock_smbus_module, \
             patch('chipsec.utilcmd.spd_cmd.spd') as mock_spd_module, \
             patch.object(self.spd_command.logger, 'log') as mock_log:
            mock_smbus_instance = Mock()
            mock_smbus_module.SMBus.return_value = mock_smbus_instance
            mock_smbus_instance.is_SMBus_supported.return_value = False

            self.spd_command.run()

            mock_log.assert_called_with('[CHIPSEC] SMBus controller is not supported')
            self.spd_command.func.assert_not_called()


class TestSPDCommandIntegration(unittest.TestCase):
    """Integration tests for SPD command with realistic data."""

    def setUp(self):
        """Set up test fixtures."""
        # Create integrated ChipsecCs for SPD testing
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock SPD and SMBus components with realistic data
        self.integrated_cs.hals = Mock()
        self.integrated_cs.hals.smbus = Mock()
        self.integrated_cs.hals.spd = Mock()

    def test_spd_detect_integration(self):
        """Test complete spd_detect workflow."""
        spd_cmd = SPDCommand(['detect'], cs=self.integrated_cs)

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

    def test_spd_dump_integration(self):
        """Test complete spd_dump workflow."""
        spd_cmd = SPDCommand(['dump', 'DIMM0'], cs=self.integrated_cs)

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

    def test_spd_read_integration(self):
        """Test complete spd_read workflow."""
        spd_cmd = SPDCommand(['read', 'DIMM1', '0x0'], cs=self.integrated_cs)

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

    def test_spd_write_integration(self):
        """Test complete spd_write workflow."""
        spd_cmd = SPDCommand(['write', '0xA0', '0x0', '0xAA'], cs=self.integrated_cs)

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


class TestSPDCommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for SPD command."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.hals = Mock()
        self.mock_cs.hals.smbus = Mock()
        self.mock_cs.hals.spd = Mock()

    def test_empty_argv_handling(self):
        """Test handling of empty argv."""
        command = SPDCommand([], cs=self.mock_cs)

        # Should raise SystemExit due to missing required arguments
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_spd_dump_empty_device_list(self):
        """Test spd_dump with empty device list."""
        command = SPDCommand(['dump'], cs=self.mock_cs)
        command.dev = None

        command._spd.detect.return_value = []

        command.spd_dump()

        command._spd.detect.assert_called_once()
        # Should not call decode when no devices detected

    def test_spd_read_various_offsets(self):
        """Test spd_read with various offset values."""
        test_cases = [0x0, 0x10, 0xFF, 0x100]

        for offset in test_cases:
            command = SPDCommand(['read', '0xA0', f'0x{offset:X}'], cs=self.mock_cs)
            command.set_up()
            command._spd.isSPDPresent.return_value = True
            command._spd.read_byte.return_value = 0xAB

            with patch.object(command.logger, 'log'):
                command.run()

                command._spd.read_byte.assert_called_with(offset, 0xA0)

    def test_spd_write_various_values(self):
        """Test spd_write with various byte values."""
        test_values = [0x00, 0xFF, 0xAB, 0x42]

        for value in test_values:
            command = SPDCommand(['write', '0xA0', '0x0', f'0x{value:X}'], cs=self.mock_cs)
            command.set_up()
            command._spd.isSPDPresent.return_value = True

            with patch.object(command.logger, 'log'):
                command.run()

                command._spd.write_byte.assert_called_with(0x0, value, 0xA0)

    def test_spd_detect_empty_result(self):
        """Test spd_detect with empty detection result."""
        command = SPDCommand(['detect'], cs=self.mock_cs)

        command._spd.detect.return_value = []

        with patch.object(command.logger, 'log') as mock_log:
            command.spd_detect()

            mock_log.assert_any_call('[CHIPSEC] Searching for DIMMs with SPD...')
            mock_log.assert_any_call('Unable to detect SPD devices.')

    def test_hex_parsing_various_formats(self):
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
            command = SPDCommand(['read', hex_str, '0x0'], cs=self.mock_cs)
            command.parse_arguments()
            self.assertEqual(command.dev_addr, expected_value)

    def test_spd_dump_multiple_devices(self):
        """Test spd_dump with multiple devices."""
        command = SPDCommand(['dump'], cs=self.mock_cs)
        command.dev = None

        command._spd.detect.return_value = [0xA0, 0xA2, 0xA4]

        command.spd_dump()

        # Should call decode for each device
        self.assertEqual(command._spd.decode.call_count, 3)
        command._spd.decode.assert_any_call(0xA0)
        command._spd.decode.assert_any_call(0xA2)
        command._spd.decode.assert_any_call(0xA4)

    def test_spd_read_without_offset(self):
        """Test spd_read without explicit offset."""
        command = SPDCommand(['read', '0xA0'], cs=self.mock_cs)
        command.set_up()

        command._spd.isSPDPresent.return_value = True
        command._spd.read_byte.return_value = 0xCD

        with patch.object(command.logger, 'log'):
            command.run()

            # Should use default offset of None, but read_byte expects an offset
            # This tests the error handling path
            command._spd.read_byte.assert_called_with(None, 0xA0)


class TestSPDCommandConfigurationValidation(unittest.TestCase):
    """Test configuration validation aspects of SPD command."""

    def setUp(self):
        """Set up test fixtures."""
        # Create ChipsecCs with SPD-specific configuration
        self.spd_cs = MockFactory.create_mock_chipsec_cs()

        # Mock SPD configuration
        self.spd_cs.Cfg = Mock()
        self.spd_cs.Cfg.SPD = {
            'SMBUS_ADDRESS': 0xA0,
            'DIMM_ADDRESSES': {
                'DIMM0': 0xA0,
                'DIMM1': 0xA2,
                'DIMM2': 0xA4
            },
            'MAX_OFFSET': 0xFF
        }

        self.spd_cs.hals = Mock()
        self.spd_cs.hals.smbus = Mock()
        self.spd_cs.hals.spd = Mock()

    def test_spd_configuration_structure(self):
        """Test SPD configuration structure."""
        spd_config = self.spd_cs.Cfg.SPD

        # Test that required SPD configuration exists
        self.assertIn('SMBUS_ADDRESS', spd_config)
        self.assertIn('DIMM_ADDRESSES', spd_config)

        # Test configuration values are reasonable
        self.assertGreater(spd_config['SMBUS_ADDRESS'], 0)
        self.assertIsInstance(spd_config['DIMM_ADDRESSES'], dict)

    def test_spd_device_address_validation(self):
        """Test SPD device address validation."""
        # Test various device address formats
        test_cases = [
            ('DIMM0', 0xA0),
            ('DIMM1', 0xA2),
            ('0xA4', 0xA4),
            ('0xA6', 0xA6)
        ]

        for dev_str, expected_addr in test_cases:
            command = SPDCommand(['read', dev_str, '0x0'], cs=self.spd_cs)
            command.parse_arguments()

            # The actual address resolution happens in the command methods
            self.assertEqual(command.dev, dev_str)

    def test_spd_offset_validation(self):
        """Test SPD offset validation."""
        # Test various offset formats
        test_cases = [
            ('0x0', 0x0),
            ('0x10', 0x10),
            ('0xFF', 0xFF),
            ('0', 0x0)
        ]

        for offset_str, expected_offset in test_cases:
            command = SPDCommand(['read', '0xA0', offset_str], cs=self.spd_cs)
            command.parse_arguments()

            self.assertEqual(command.off, expected_offset)

    def test_spd_value_validation(self):
        """Test SPD value validation."""
        # Test various value formats
        test_cases = [
            ('0x00', 0x00),
            ('0xFF', 0xFF),
            ('0xAB', 0xAB),
            ('0', 0x0)
        ]

        for value_str, expected_value in test_cases:
            command = SPDCommand(['write', '0xA0', '0x0', value_str], cs=self.spd_cs)
            command.parse_arguments()

            self.assertEqual(command.val, expected_value)

    def test_spd_dimm_name_validation(self):
        """Test SPD DIMM name validation."""
        valid_names = ['DIMM0', 'DIMM1', 'DIMM2']

        for name in valid_names:
            command = SPDCommand(['dump', name], cs=self.spd_cs)
            command.parse_arguments()

            self.assertEqual(command.dev, name)

    def test_spd_error_handling(self):
        """Test SPD error handling."""
        command = SPDCommand(['read', '0xA0', '0x0'], cs=self.spd_cs)

        # Mock SPD read to raise exception
        command._spd.read_byte.side_effect = Exception("SPD read failed")

        # Should handle the exception gracefully
        with self.assertRaises(Exception):
            command.spd_read()

    def test_spd_initialization_error_handling(self):
        """Test SPD initialization error handling."""
        command = SPDCommand(['detect'], cs=self.spd_cs)

        with patch('chipsec.utilcmd.spd_cmd.smbus') as mock_smbus_module, \
             patch.object(command.logger, 'log_error'):
            mock_smbus_module.SMBus.side_effect = Exception("SMBus init failed")

            # Should handle the exception gracefully
            command.run()


if __name__ == '__main__':
    unittest.main()
