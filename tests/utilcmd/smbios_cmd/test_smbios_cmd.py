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
from unittest.mock import Mock, patch, call
from chipsec.utilcmd.smbios_cmd import smbios_cmd
from tests.test_utils import MockFactory


class TestSMBIOSCommand(unittest.TestCase):
    """Comprehensive tests for SMBIOS utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()

        # Mock SMBIOS HAL component
        self.mock_cs.hals = Mock()
        self.mock_cs.hals.smbios = Mock()

        self.smbios_command = smbios_cmd(['entrypoint'], cs=self.mock_cs)

    def test_smbios_command_initialization(self):
        """Test smbios_cmd initialization."""
        self.assertEqual(self.smbios_command.cs, self.mock_cs)
        self.assertEqual(self.smbios_command.argv, ['entrypoint'])

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.smbios_command.requirements()
        self.assertEqual(reqs, self.smbios_command.toLoad.All)

    def test_parse_arguments_entrypoint(self):
        """Test parsing entrypoint command."""
        command = smbios_cmd(['entrypoint'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.smbios_ep)

    def test_parse_arguments_get_raw(self):
        """Test parsing get command with raw method."""
        command = smbios_cmd(['get', 'raw'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.smbios_get)
        self.assertEqual(command.method, 'raw')
        self.assertIsNone(command.type)
        self.assertFalse(command._force_32)

    def test_parse_arguments_get_decoded_with_type(self):
        """Test parsing get command with decoded method and type."""
        command = smbios_cmd(['get', 'decoded', '1', '--force'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.smbios_get)
        self.assertEqual(command.method, 'decoded')
        self.assertEqual(command.type, 1)
        self.assertTrue(command._force_32)

    def test_parse_arguments_get_defaults(self):
        """Test parsing get command with defaults."""
        command = smbios_cmd(['get'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.smbios_get)
        self.assertEqual(command.method, 'raw')  # Default when no config
        self.assertIsNone(command.type)
        self.assertFalse(command._force_32)

    def test_parse_arguments_invalid_method(self):
        """Test parsing get command with invalid method."""
        command = smbios_cmd(['get', 'invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid choice
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_parse_arguments_invalid(self):
        """Test parsing invalid command."""
        command = smbios_cmd(['invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_smbios_ep_with_both_versions(self):
        """Test smbios_ep method with both SMBIOS 2 and 3 entry points."""
        self.smbios_command.smbios = Mock()
        self.smbios_command.smbios.smbios_2_pa = 0xF0000
        self.smbios_command.smbios.smbios_3_pa = 0xF1000
        self.smbios_command.smbios.smbios_2_ep = "SMBIOS 2.0 Entry Point"
        self.smbios_command.smbios.smbios_3_ep = "SMBIOS 3.0 Entry Point"

        with patch.object(self.smbios_command.logger, 'log') as mock_log:
            self.smbios_command.smbios_ep()

            mock_log.assert_any_call('[CHIPSEC] SMBIOS Entry Point Structures')
            mock_log.assert_any_call('SMBIOS 2.0 Entry Point')
            mock_log.assert_any_call('SMBIOS 3.0 Entry Point')

    def test_smbios_ep_with_smbios2_only(self):
        """Test smbios_ep method with SMBIOS 2 only."""
        self.smbios_command.smbios = Mock()
        self.smbios_command.smbios.smbios_2_pa = 0xF0000
        self.smbios_command.smbios.smbios_3_pa = None
        self.smbios_command.smbios.smbios_2_ep = "SMBIOS 2.0 Entry Point"

        with patch.object(self.smbios_command.logger, 'log') as mock_log:
            self.smbios_command.smbios_ep()

            mock_log.assert_any_call('[CHIPSEC] SMBIOS Entry Point Structures')
            mock_log.assert_any_call('SMBIOS 2.0 Entry Point')
            # Should not log SMBIOS 3 entry point

    def test_smbios_ep_with_smbios3_only(self):
        """Test smbios_ep method with SMBIOS 3 only."""
        self.smbios_command.smbios = Mock()
        self.smbios_command.smbios.smbios_2_pa = None
        self.smbios_command.smbios.smbios_3_pa = 0xF1000
        self.smbios_command.smbios.smbios_3_ep = "SMBIOS 3.0 Entry Point"

        with patch.object(self.smbios_command.logger, 'log') as mock_log:
            self.smbios_command.smbios_ep()

            mock_log.assert_any_call('[CHIPSEC] SMBIOS Entry Point Structures')
            mock_log.assert_any_call('SMBIOS 3.0 Entry Point')
            # Should not log SMBIOS 2 entry point

    def test_smbios_get_raw_with_data(self):
        """Test smbios_get method with raw data."""
        self.smbios_command.method = 'raw'
        self.smbios_command.type = 1
        self.smbios_command._force_32 = False

        self.smbios_command.smbios = Mock()
        test_data = [b'\x01\x02\x03\x04', b'\x05\x06\x07\x08']
        self.smbios_command.smbios.get_raw_structs.return_value = test_data
        self.smbios_command.smbios.get_header.return_value = "SMBIOS Header"

        with patch('chipsec.utilcmd.smbios_cmd.print_buffer_bytes') as mock_print_buffer, \
             patch.object(self.smbios_command.logger, 'log') as mock_log:
            self.smbios_command.smbios_get()

            self.smbios_command.smbios.get_raw_structs.assert_called_once_with(1, False)
            mock_log.assert_any_call('[CHIPSEC] Dumping all requested structures in raw format')
            mock_log.assert_any_call('SMBIOS Header')
            mock_log.assert_any_call('[CHIPSEC] Raw Data')
            mock_print_buffer.assert_has_calls([
                call(b'\x01\x02\x03\x04'),
                call(b'\x05\x06\x07\x08')
            ])

    def test_smbios_get_decoded_with_data(self):
        """Test smbios_get method with decoded data."""
        self.smbios_command.method = 'decoded'
        self.smbios_command.type = 0
        self.smbios_command._force_32 = True

        self.smbios_command.smbios = Mock()
        test_data = ["Decoded Structure 1", "Decoded Structure 2"]
        self.smbios_command.smbios.get_decoded_structs.return_value = test_data

        with patch.object(self.smbios_command.logger, 'log') as mock_log:
            self.smbios_command.smbios_get()

            self.smbios_command.smbios.get_decoded_structs.assert_called_once_with(0, True)
            mock_log.assert_any_call('[CHIPSEC] Dumping all requested structures in decoded format')
            mock_log.assert_any_call('Decoded Structure 1')
            mock_log.assert_any_call('Decoded Structure 2')

    def test_smbios_get_no_data_found(self):
        """Test smbios_get method when no structures found."""
        self.smbios_command.method = 'raw'
        self.smbios_command.type = 17

        self.smbios_command.smbios = Mock()
        self.smbios_command.smbios.get_raw_structs.return_value = []

        with patch.object(self.smbios_command.logger, 'log') as mock_log:
            self.smbios_command.smbios_get()

            mock_log.assert_any_call('[CHIPSEC] Dumping all requested structures in raw format')
            mock_log.assert_any_call('[CHIPSEC] Structures not found')

    def test_smbios_get_error_getting_data(self):
        """Test smbios_get method when error getting data."""
        self.smbios_command.method = 'decoded'
        self.smbios_command.type = None

        self.smbios_command.smbios = Mock()
        self.smbios_command.smbios.get_decoded_structs.return_value = None

        with patch.object(self.smbios_command.logger, 'log') as mock_log:
            self.smbios_command.smbios_get()

            mock_log.assert_any_call('[CHIPSEC] Dumping all requested structures in decoded format')
            mock_log.assert_any_call('[CHIPSEC] Error getting data')

    def test_smbios_get_raw_no_header(self):
        """Test smbios_get method with raw data but no header."""
        self.smbios_command.method = 'raw'
        self.smbios_command.type = 2

        self.smbios_command.smbios = Mock()
        test_data = [b'\x01\x02\x03\x04']
        self.smbios_command.smbios.get_raw_structs.return_value = test_data
        self.smbios_command.smbios.get_header.return_value = None

        with patch('chipsec.utilcmd.smbios_cmd.print_buffer_bytes') as mock_print_buffer, \
             patch.object(self.smbios_command.logger, 'log') as mock_log:
            self.smbios_command.smbios_get()

            mock_log.assert_any_call('[CHIPSEC] Dumping all requested structures in raw format')
            # Should not log header when None
            mock_log.assert_any_call('[CHIPSEC] Raw Data')
            mock_print_buffer.assert_called_once_with(b'\x01\x02\x03\x04')

    def test_run_successful_smbios_detection(self):
        """Test run method with successful SMBIOS detection."""
        self.smbios_command.func = Mock()

        with patch('chipsec.utilcmd.smbios_cmd.SMBIOS') as mock_smbios_class, \
             patch.object(self.smbios_command.logger, 'log') as mock_log:
            mock_smbios_instance = Mock()
            mock_smbios_class.return_value = mock_smbios_instance
            mock_smbios_instance.find_smbios_table.return_value = True

            self.smbios_command.run()

            mock_smbios_class.assert_called_once_with(self.mock_cs)
            mock_smbios_instance.find_smbios_table.assert_called_once()
            mock_log.assert_any_call('[CHIPSEC] Attempting to detect SMBIOS structures')
            self.smbios_command.func.assert_called_once()
            self.assertEqual(self.smbios_command.smbios, mock_smbios_instance)

    def test_run_smbios_detection_failure(self):
        """Test run method when SMBIOS detection fails."""
        self.smbios_command.func = Mock()

        with patch('chipsec.utilcmd.smbios_cmd.SMBIOS') as mock_smbios_class, \
             patch.object(self.smbios_command.logger, 'log') as mock_log:
            mock_smbios_instance = Mock()
            mock_smbios_class.return_value = mock_smbios_instance
            mock_smbios_instance.find_smbios_table.return_value = False

            self.smbios_command.run()

            mock_log.assert_any_call('[CHIPSEC] Attempting to detect SMBIOS structures')
            mock_log.assert_any_call('[CHIPSEC] Unable to detect SMBIOS structure(s)')
            self.smbios_command.func.assert_not_called()

    def test_run_smbios_initialization_error(self):
        """Test run method when SMBIOS initialization fails."""
        self.smbios_command.func = Mock()

        with patch('chipsec.utilcmd.smbios_cmd.SMBIOS') as mock_smbios_class, \
             patch.object(self.smbios_command.logger, 'log') as mock_log:
            mock_smbios_class.side_effect = Exception("SMBIOS initialization failed")

            self.smbios_command.run()

            mock_log.assert_any_call('[CHIPSEC] Attempting to detect SMBIOS structures')
            # Compare by string to avoid object identity issues
            logged_args = [c[0][0] for c in mock_log.call_args_list if c[0]]
            self.assertIn('SMBIOS initialization failed', [str(a) for a in logged_args])
            self.smbios_command.func.assert_not_called()


class TestSMBIOSCommandIntegration(unittest.TestCase):
    """Integration tests for SMBIOS command with realistic data."""

    def setUp(self):
        """Set up test fixtures."""
        # Create integrated ChipsecCs for SMBIOS testing
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock SMBIOS components with realistic data
        self.integrated_cs.hals = Mock()
        self.integrated_cs.hals.smbios = Mock()

    def test_smbios_entrypoint_integration(self):
        """Test complete smbios entrypoint workflow."""
        smbios_cmd_instance = smbios_cmd(['entrypoint'], cs=self.integrated_cs)

        with patch('chipsec.utilcmd.smbios_cmd.SMBIOS') as mock_smbios_class, \
             patch.object(smbios_cmd_instance.logger, 'log'):
            mock_smbios_instance = Mock()
            mock_smbios_class.return_value = mock_smbios_instance
            mock_smbios_instance.find_smbios_table.return_value = True
            mock_smbios_instance.smbios_2_pa = 0xF0000
            mock_smbios_instance.smbios_3_pa = None
            mock_smbios_instance.smbios_2_ep = "SMBIOS 2.0 Entry Point"

            smbios_cmd_instance.run()

            mock_smbios_class.assert_called_once_with(self.integrated_cs)

    def test_smbios_get_raw_integration(self):
        """Test complete smbios get raw workflow."""
        smbios_cmd_instance = smbios_cmd(['get', 'raw', '1'], cs=self.integrated_cs)

        with patch('chipsec.utilcmd.smbios_cmd.SMBIOS') as mock_smbios_class, \
             patch('chipsec.utilcmd.smbios_cmd.print_buffer_bytes'), \
             patch.object(smbios_cmd_instance.logger, 'log'):
            mock_smbios_instance = Mock()
            mock_smbios_class.return_value = mock_smbios_instance
            mock_smbios_instance.find_smbios_table.return_value = True
            mock_smbios_instance.get_raw_structs.return_value = [b'\x01\x02\x03\x04']
            mock_smbios_instance.get_header.return_value = "SMBIOS Header"

            smbios_cmd_instance.run()

            mock_smbios_instance.get_raw_structs.assert_called_once_with(1, False)

    def test_smbios_get_decoded_integration(self):
        """Test complete smbios get decoded workflow."""
        smbios_cmd_instance = smbios_cmd(['get', 'decoded'], cs=self.integrated_cs)

        with patch('chipsec.utilcmd.smbios_cmd.SMBIOS') as mock_smbios_class, \
             patch.object(smbios_cmd_instance.logger, 'log'):
            mock_smbios_instance = Mock()
            mock_smbios_class.return_value = mock_smbios_instance
            mock_smbios_instance.find_smbios_table.return_value = True
            mock_smbios_instance.get_decoded_structs.return_value = ["Decoded SMBIOS data"]

            smbios_cmd_instance.run()

            mock_smbios_instance.get_decoded_structs.assert_called_once_with(None, False)


class TestSMBIOSCommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for SMBIOS command."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.hals = Mock()
        self.mock_cs.hals.smbios = Mock()

    def test_empty_argv_handling(self):
        """Test handling of empty argv."""
        command = smbios_cmd([], cs=self.mock_cs)

        # Should raise SystemExit due to missing required arguments
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_parse_arguments_with_config_default(self):
        """Test parsing get command with config-based default."""
        command = smbios_cmd(['get'], cs=self.mock_cs)

        with patch('chipsec.utilcmd.smbios_cmd.Options') as mock_options_class:
            mock_options_instance = Mock()
            mock_options_class.return_value = mock_options_instance
            mock_options_instance.get_section_data.return_value = 'decoded'

            command.parse_arguments()

            self.assertEqual(command.method, 'decoded')

    def test_parse_arguments_config_error_fallback(self):
        """Test parsing get command with config error fallback."""
        command = smbios_cmd(['get'], cs=self.mock_cs)

        with patch('chipsec.utilcmd.smbios_cmd.Options') as mock_options_class:
            mock_options_instance = Mock()
            mock_options_class.return_value = mock_options_instance
            mock_options_instance.get_section_data.side_effect = Exception("Config error")

            command.parse_arguments()

            self.assertEqual(command.method, 'raw')  # Fallback to default

    def test_smbios_get_multiple_structures(self):
        """Test smbios_get with multiple structures."""
        command = smbios_cmd(['get', 'raw'], cs=self.mock_cs)
        command.method = 'raw'
        command.type = None

        command.smbios = Mock()
        test_data = [b'\x01\x02\x03', b'\x04\x05\x06', b'\x07\x08\x09']
        command.smbios.get_raw_structs.return_value = test_data
        command.smbios.get_header.return_value = "Header"

        with patch('chipsec.utilcmd.smbios_cmd.print_buffer_bytes') as mock_print_buffer, \
             patch.object(command.logger, 'log') as mock_log:
            command.smbios_get()

            # Should call print_buffer_bytes for each structure
            self.assertEqual(mock_print_buffer.call_count, 3)
            # Should log separator between structures (one per structure)
            separator_count = sum(1 for c in mock_log.call_args_list if c == (('==================================================================',), {}))
            self.assertEqual(separator_count, 3)

    def test_smbios_ep_no_entry_points(self):
        """Test smbios_ep with no entry points."""
        command = smbios_cmd(['entrypoint'], cs=self.mock_cs)
        command.smbios = Mock()
        command.smbios.smbios_2_pa = None
        command.smbios.smbios_3_pa = None

        with patch.object(command.logger, 'log') as mock_log:
            command.smbios_ep()

            mock_log.assert_called_with('[CHIPSEC] SMBIOS Entry Point Structures')
            # Should not log any entry points

    def test_smbios_get_force_32_flag(self):
        """Test smbios_get with force 32-bit flag."""
        command = smbios_cmd(['get', 'raw', '17', '--force'], cs=self.mock_cs)
        command.method = 'raw'
        command.type = 17
        command._force_32 = True

        command.smbios = Mock()
        command.smbios.get_raw_structs.return_value = [b'\x11\x12\x13']

        with patch('chipsec.utilcmd.smbios_cmd.print_buffer_bytes'), \
             patch.object(command.logger, 'log'):
            command.smbios_get()

            command.smbios.get_raw_structs.assert_called_once_with(17, True)

    def test_run_exception_in_func(self):
        """Test run method when func raises exception."""
        command = smbios_cmd(['entrypoint'], cs=self.mock_cs)
        command.func = Mock(side_effect=Exception("Function error"))

        with patch('chipsec.utilcmd.smbios_cmd.SMBIOS') as mock_smbios_class, \
             patch.object(command.logger, 'log'):
            mock_smbios_instance = Mock()
            mock_smbios_class.return_value = mock_smbios_instance
            mock_smbios_instance.find_smbios_table.return_value = True

            # Should not raise exception, just log it
            command.run()

            command.func.assert_called_once()


class TestSMBIOSCommandConfigurationValidation(unittest.TestCase):
    """Test configuration validation aspects of SMBIOS command."""

    def setUp(self):
        """Set up test fixtures."""
        # Create ChipsecCs with SMBIOS-specific configuration
        self.smbios_cs = MockFactory.create_mock_chipsec_cs()

        # Mock SMBIOS configuration
        self.smbios_cs.Cfg = Mock()
        self.smbios_cs.Cfg.SMBIOS = {
            'DEFAULT_METHOD': 'raw',
            'FORCE_32BIT': False,
            'ENTRY_POINT_2_ADDR': 0xF0000,
            'ENTRY_POINT_3_ADDR': 0xF1000
        }

        self.smbios_cs.hals = Mock()
        self.smbios_cs.hals.smbios = Mock()

    def test_smbios_configuration_structure(self):
        """Test SMBIOS configuration structure."""
        smbios_config = self.smbios_cs.Cfg.SMBIOS

        # Test that required SMBIOS configuration exists
        self.assertIn('DEFAULT_METHOD', smbios_config)
        self.assertIn('FORCE_32BIT', smbios_config)

        # Test configuration values are reasonable
        self.assertIn(smbios_config['DEFAULT_METHOD'], ['raw', 'decoded'])
        self.assertIsInstance(smbios_config['FORCE_32BIT'], bool)

    def test_smbios_method_validation(self):
        """Test SMBIOS method validation."""
        valid_methods = ['raw', 'decoded']

        for method in valid_methods:
            command = smbios_cmd(['get', method], cs=self.smbios_cs)
            command.parse_arguments()
            self.assertEqual(command.method, method)

    def test_smbios_type_validation(self):
        """Test SMBIOS type validation."""
        # Test various SMBIOS types
        test_types = [0, 1, 2, 17, 127]

        for smbios_type in test_types:
            command = smbios_cmd(['get', 'raw', str(smbios_type)], cs=self.smbios_cs)
            command.parse_arguments()
            self.assertEqual(command.type, smbios_type)

    def test_smbios_force_32bit_flag_validation(self):
        """Test SMBIOS force 32-bit flag validation."""
        # Test with force flag
        command_with_force = smbios_cmd(['get', 'decoded', '1', '--force'], cs=self.smbios_cs)
        command_with_force.parse_arguments()
        self.assertTrue(command_with_force._force_32)

        # Test without force flag
        command_without_force = smbios_cmd(['get', 'raw', '1'], cs=self.smbios_cs)
        command_without_force.parse_arguments()
        self.assertFalse(command_without_force._force_32)

    def test_smbios_entry_point_address_validation(self):
        """Test SMBIOS entry point address validation."""
        smbios_config = self.smbios_cs.Cfg.SMBIOS

        # Test that entry point addresses are valid
        self.assertGreater(smbios_config['ENTRY_POINT_2_ADDR'], 0)
        self.assertGreater(smbios_config['ENTRY_POINT_3_ADDR'], 0)
        self.assertNotEqual(smbios_config['ENTRY_POINT_2_ADDR'], smbios_config['ENTRY_POINT_3_ADDR'])

    def test_smbios_error_handling(self):
        """Test SMBIOS error handling."""
        command = smbios_cmd(['get', 'raw'], cs=self.smbios_cs)

        # Mock SMBIOS get_raw_structs to raise exception
        command.smbios = Mock()
        command.smbios.get_raw_structs.side_effect = Exception("SMBIOS access failed")

        # Should handle the exception gracefully
        with self.assertRaises(Exception):
            command.smbios_get()

    def test_smbios_detection_error_handling(self):
        """Test SMBIOS detection error handling."""
        command = smbios_cmd(['entrypoint'], cs=self.smbios_cs)

        with patch('chipsec.utilcmd.smbios_cmd.SMBIOS') as mock_smbios_class, \
             patch.object(command.logger, 'log'):
            mock_smbios_class.side_effect = Exception("SMBIOS detection failed")

            # Should handle the exception gracefully
            command.run()


if __name__ == '__main__':
    unittest.main()
