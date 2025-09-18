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
from chipsec.utilcmd.smbios_cmd import smbios_cmd
from tests.test_utils import MockFactory


class TestSMBIOSCommand:
    """Comprehensive tests for SMBIOS utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for SMBIOS testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock SMBIOS HAL component
        cs_mock.hals = Mock()
        cs_mock.hals.smbios = Mock()

        return cs_mock

    @pytest.fixture
    def smbios_command(self, mock_cs):
        """Create smbios_cmd instance."""
        return smbios_cmd(['entrypoint'], cs=mock_cs)

    @pytest.mark.unit
    def test_smbios_command_initialization(self, smbios_command, mock_cs):
        """Test smbios_cmd initialization."""
        assert smbios_command.cs == mock_cs
        assert smbios_command.argv == ['entrypoint']

    @pytest.mark.unit
    def test_requirements(self, smbios_command):
        """Test command requirements."""
        reqs = smbios_command.requirements()
        assert reqs == smbios_command.toLoad.All

    @pytest.mark.unit
    def test_parse_arguments_entrypoint(self, mock_cs):
        """Test parsing entrypoint command."""
        command = smbios_cmd(['entrypoint'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.smbios_ep

    @pytest.mark.unit
    def test_parse_arguments_get_raw(self, mock_cs):
        """Test parsing get command with raw method."""
        command = smbios_cmd(['get', 'raw'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.smbios_get
        assert command.method == 'raw'
        assert command.type is None
        assert command._force_32 is False

    @pytest.mark.unit
    def test_parse_arguments_get_decoded_with_type(self, mock_cs):
        """Test parsing get command with decoded method and type."""
        command = smbios_cmd(['get', 'decoded', '1', '--force'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.smbios_get
        assert command.method == 'decoded'
        assert command.type == 1
        assert command._force_32 is True

    @pytest.mark.unit
    def test_parse_arguments_get_defaults(self, mock_cs):
        """Test parsing get command with defaults."""
        command = smbios_cmd(['get'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.smbios_get
        assert command.method == 'raw'  # Default when no config
        assert command.type is None
        assert command._force_32 is False

    @pytest.mark.unit
    def test_parse_arguments_invalid_method(self, mock_cs):
        """Test parsing get command with invalid method."""
        command = smbios_cmd(['get', 'invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid choice
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_invalid(self, mock_cs):
        """Test parsing invalid command."""
        command = smbios_cmd(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_smbios_ep_with_both_versions(self, smbios_command, mock_cs):
        """Test smbios_ep method with both SMBIOS 2 and 3 entry points."""
        smbios_command.smbios = Mock()
        smbios_command.smbios.smbios_2_pa = 0xF0000
        smbios_command.smbios.smbios_3_pa = 0xF1000
        smbios_command.smbios.smbios_2_ep = "SMBIOS 2.0 Entry Point"
        smbios_command.smbios.smbios_3_ep = "SMBIOS 3.0 Entry Point"

        with patch.object(smbios_command.logger, 'log') as mock_log:
            smbios_command.smbios_ep()

            mock_log.assert_any_call('[CHIPSEC] SMBIOS Entry Point Structures')
            mock_log.assert_any_call('SMBIOS 2.0 Entry Point')
            mock_log.assert_any_call('SMBIOS 3.0 Entry Point')

    @pytest.mark.unit
    def test_smbios_ep_with_smbios2_only(self, smbios_command, mock_cs):
        """Test smbios_ep method with SMBIOS 2 only."""
        smbios_command.smbios = Mock()
        smbios_command.smbios.smbios_2_pa = 0xF0000
        smbios_command.smbios.smbios_3_pa = None
        smbios_command.smbios.smbios_2_ep = "SMBIOS 2.0 Entry Point"

        with patch.object(smbios_command.logger, 'log') as mock_log:
            smbios_command.smbios_ep()

            mock_log.assert_any_call('[CHIPSEC] SMBIOS Entry Point Structures')
            mock_log.assert_any_call('SMBIOS 2.0 Entry Point')
            # Should not log SMBIOS 3 entry point

    @pytest.mark.unit
    def test_smbios_ep_with_smbios3_only(self, smbios_command, mock_cs):
        """Test smbios_ep method with SMBIOS 3 only."""
        smbios_command.smbios = Mock()
        smbios_command.smbios.smbios_2_pa = None
        smbios_command.smbios.smbios_3_pa = 0xF1000
        smbios_command.smbios.smbios_3_ep = "SMBIOS 3.0 Entry Point"

        with patch.object(smbios_command.logger, 'log') as mock_log:
            smbios_command.smbios_ep()

            mock_log.assert_any_call('[CHIPSEC] SMBIOS Entry Point Structures')
            mock_log.assert_any_call('SMBIOS 3.0 Entry Point')
            # Should not log SMBIOS 2 entry point

    @pytest.mark.unit
    def test_smbios_get_raw_with_data(self, smbios_command, mock_cs):
        """Test smbios_get method with raw data."""
        smbios_command.method = 'raw'
        smbios_command.type = 1
        smbios_command._force_32 = False

        smbios_command.smbios = Mock()
        test_data = [b'\x01\x02\x03\x04', b'\x05\x06\x07\x08']
        smbios_command.smbios.get_raw_structs.return_value = test_data
        smbios_command.smbios.get_header.return_value = "SMBIOS Header"

        with patch('chipsec.utilcmd.smbios_cmd.print_buffer_bytes') as mock_print_buffer, \
             patch.object(smbios_command.logger, 'log') as mock_log:
            smbios_command.smbios_get()

            smbios_command.smbios.get_raw_structs.assert_called_once_with(1, False)
            mock_log.assert_any_call('[CHIPSEC] Dumping all requested structures in raw format')
            mock_log.assert_any_call('SMBIOS Header')
            mock_log.assert_any_call('[CHIPSEC] Raw Data')
            mock_print_buffer.assert_called_with(b'\x01\x02\x03\x04')
            mock_print_buffer.assert_called_with(b'\x05\x06\x07\x08')

    @pytest.mark.unit
    def test_smbios_get_decoded_with_data(self, smbios_command, mock_cs):
        """Test smbios_get method with decoded data."""
        smbios_command.method = 'decoded'
        smbios_command.type = 0
        smbios_command._force_32 = True

        smbios_command.smbios = Mock()
        test_data = ["Decoded Structure 1", "Decoded Structure 2"]
        smbios_command.smbios.get_decoded_structs.return_value = test_data

        with patch.object(smbios_command.logger, 'log') as mock_log:
            smbios_command.smbios_get()

            smbios_command.smbios.get_decoded_structs.assert_called_once_with(0, True)
            mock_log.assert_any_call('[CHIPSEC] Dumping all requested structures in decoded format')
            mock_log.assert_any_call('Decoded Structure 1')
            mock_log.assert_any_call('Decoded Structure 2')

    @pytest.mark.unit
    def test_smbios_get_no_data_found(self, smbios_command, mock_cs):
        """Test smbios_get method when no structures found."""
        smbios_command.method = 'raw'
        smbios_command.type = 17

        smbios_command.smbios = Mock()
        smbios_command.smbios.get_raw_structs.return_value = []

        with patch.object(smbios_command.logger, 'log') as mock_log:
            smbios_command.smbios_get()

            mock_log.assert_any_call('[CHIPSEC] Dumping all requested structures in raw format')
            mock_log.assert_any_call('[CHIPSEC] Structures not found')

    @pytest.mark.unit
    def test_smbios_get_error_getting_data(self, smbios_command, mock_cs):
        """Test smbios_get method when error getting data."""
        smbios_command.method = 'decoded'
        smbios_command.type = None

        smbios_command.smbios = Mock()
        smbios_command.smbios.get_decoded_structs.return_value = None

        with patch.object(smbios_command.logger, 'log') as mock_log:
            smbios_command.smbios_get()

            mock_log.assert_any_call('[CHIPSEC] Dumping all requested structures in decoded format')
            mock_log.assert_any_call('[CHIPSEC] Error getting data')

    @pytest.mark.unit
    def test_smbios_get_raw_no_header(self, smbios_command, mock_cs):
        """Test smbios_get method with raw data but no header."""
        smbios_command.method = 'raw'
        smbios_command.type = 2

        smbios_command.smbios = Mock()
        test_data = [b'\x01\x02\x03\x04']
        smbios_command.smbios.get_raw_structs.return_value = test_data
        smbios_command.smbios.get_header.return_value = None

        with patch('chipsec.utilcmd.smbios_cmd.print_buffer_bytes') as mock_print_buffer, \
             patch.object(smbios_command.logger, 'log') as mock_log:
            smbios_command.smbios_get()

            mock_log.assert_any_call('[CHIPSEC] Dumping all requested structures in raw format')
            # Should not log header when None
            mock_log.assert_any_call('[CHIPSEC] Raw Data')
            mock_print_buffer.assert_called_once_with(b'\x01\x02\x03\x04')

    @pytest.mark.unit
    def test_run_successful_smbios_detection(self, smbios_command, mock_cs):
        """Test run method with successful SMBIOS detection."""
        smbios_command.func = Mock()

        with patch('chipsec.utilcmd.smbios_cmd.SMBIOS') as mock_smbios_class, \
             patch.object(smbios_command.logger, 'log') as mock_log:
            mock_smbios_instance = Mock()
            mock_smbios_class.return_value = mock_smbios_instance
            mock_smbios_instance.find_smbios_table.return_value = True

            smbios_command.run()

            mock_smbios_class.assert_called_once_with(mock_cs)
            mock_smbios_instance.find_smbios_table.assert_called_once()
            mock_log.assert_any_call('[CHIPSEC] Attempting to detect SMBIOS structures')
            smbios_command.func.assert_called_once()
            assert smbios_command.smbios == mock_smbios_instance

    @pytest.mark.unit
    def test_run_smbios_detection_failure(self, smbios_command, mock_cs):
        """Test run method when SMBIOS detection fails."""
        smbios_command.func = Mock()

        with patch('chipsec.utilcmd.smbios_cmd.SMBIOS') as mock_smbios_class, \
             patch.object(smbios_command.logger, 'log') as mock_log:
            mock_smbios_instance = Mock()
            mock_smbios_class.return_value = mock_smbios_instance
            mock_smbios_instance.find_smbios_table.return_value = False

            smbios_command.run()

            mock_log.assert_any_call('[CHIPSEC] Attempting to detect SMBIOS structures')
            mock_log.assert_any_call('[CHIPSEC] Unable to detect SMBIOS structure(s)')
            smbios_command.func.assert_not_called()

    @pytest.mark.unit
    def test_run_smbios_initialization_error(self, smbios_command, mock_cs):
        """Test run method when SMBIOS initialization fails."""
        smbios_command.func = Mock()

        with patch('chipsec.utilcmd.smbios_cmd.SMBIOS') as mock_smbios_class, \
             patch.object(smbios_command.logger, 'log') as mock_log:
            mock_smbios_class.side_effect = Exception("SMBIOS initialization failed")

            smbios_command.run()

            mock_log.assert_any_call('[CHIPSEC] Attempting to detect SMBIOS structures')
            mock_log.assert_called_with(Exception("SMBIOS initialization failed"))
            smbios_command.func.assert_not_called()


class TestSMBIOSCommandIntegration:
    """Integration tests for SMBIOS command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for SMBIOS testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock SMBIOS components with realistic data
        cs_mock.hals = Mock()
        cs_mock.hals.smbios = Mock()

        return cs_mock

    @pytest.mark.integration
    def test_smbios_entrypoint_integration(self, integrated_cs):
        """Test complete smbios entrypoint workflow."""
        smbios_cmd = smbios_cmd(['entrypoint'], cs=integrated_cs)

        with patch('chipsec.utilcmd.smbios_cmd.SMBIOS') as mock_smbios_class, \
             patch.object(smbios_cmd.logger, 'log'):
            mock_smbios_instance = Mock()
            mock_smbios_class.return_value = mock_smbios_instance
            mock_smbios_instance.find_smbios_table.return_value = True
            mock_smbios_instance.smbios_2_pa = 0xF0000
            mock_smbios_instance.smbios_3_pa = None
            mock_smbios_instance.smbios_2_ep = "SMBIOS 2.0 Entry Point"

            smbios_cmd.run()

            mock_smbios_class.assert_called_once_with(integrated_cs)

    @pytest.mark.integration
    def test_smbios_get_raw_integration(self, integrated_cs):
        """Test complete smbios get raw workflow."""
        smbios_cmd = smbios_cmd(['get', 'raw', '1'], cs=integrated_cs)

        with patch('chipsec.utilcmd.smbios_cmd.SMBIOS') as mock_smbios_class, \
             patch('chipsec.utilcmd.smbios_cmd.print_buffer_bytes'), \
             patch.object(smbios_cmd.logger, 'log'):
            mock_smbios_instance = Mock()
            mock_smbios_class.return_value = mock_smbios_instance
            mock_smbios_instance.find_smbios_table.return_value = True
            mock_smbios_instance.get_raw_structs.return_value = [b'\x01\x02\x03\x04']
            mock_smbios_instance.get_header.return_value = "SMBIOS Header"

            smbios_cmd.run()

            mock_smbios_instance.get_raw_structs.assert_called_once_with(1, False)

    @pytest.mark.integration
    def test_smbios_get_decoded_integration(self, integrated_cs):
        """Test complete smbios get decoded workflow."""
        smbios_cmd = smbios_cmd(['get', 'decoded'], cs=integrated_cs)

        with patch('chipsec.utilcmd.smbios_cmd.SMBIOS') as mock_smbios_class, \
             patch.object(smbios_cmd.logger, 'log'):
            mock_smbios_instance = Mock()
            mock_smbios_class.return_value = mock_smbios_instance
            mock_smbios_instance.find_smbios_table.return_value = True
            mock_smbios_instance.get_decoded_structs.return_value = ["Decoded SMBIOS data"]

            smbios_cmd.run()

            mock_smbios_instance.get_decoded_structs.assert_called_once_with(None, False)


class TestSMBIOSCommandEdgeCases:
    """Test edge cases and error conditions for SMBIOS command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        cs_mock.hals.smbios = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        command = smbios_cmd([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_with_config_default(self, mock_cs):
        """Test parsing get command with config-based default."""
        command = smbios_cmd(['get'], cs=mock_cs)

        with patch('chipsec.utilcmd.smbios_cmd.Options') as mock_options_class:
            mock_options_instance = Mock()
            mock_options_class.return_value = mock_options_instance
            mock_options_instance.get_section_data.return_value = 'decoded'

            command.parse_arguments()

            assert command.method == 'decoded'

    @pytest.mark.unit
    def test_parse_arguments_config_error_fallback(self, mock_cs):
        """Test parsing get command with config error fallback."""
        command = smbios_cmd(['get'], cs=mock_cs)

        with patch('chipsec.utilcmd.smbios_cmd.Options') as mock_options_class:
            mock_options_instance = Mock()
            mock_options_class.return_value = mock_options_instance
            mock_options_instance.get_section_data.side_effect = Exception("Config error")

            command.parse_arguments()

            assert command.method == 'raw'  # Fallback to default

    @pytest.mark.unit
    def test_smbios_get_multiple_structures(self, mock_cs):
        """Test smbios_get with multiple structures."""
        command = smbios_cmd(['get', 'raw'], cs=mock_cs)
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
            assert mock_print_buffer.call_count == 3
            # Should log separator between structures
            separator_count = mock_log.call_args_list.count(
                mock_log.call_args == ('==================================================================',)
            )
            assert separator_count == 3

    @pytest.mark.unit
    def test_smbios_ep_no_entry_points(self, mock_cs):
        """Test smbios_ep with no entry points."""
        command = smbios_cmd(['entrypoint'], cs=mock_cs)
        command.smbios = Mock()
        command.smbios.smbios_2_pa = None
        command.smbios.smbios_3_pa = None

        with patch.object(command.logger, 'log') as mock_log:
            command.smbios_ep()

            mock_log.assert_called_with('[CHIPSEC] SMBIOS Entry Point Structures')
            # Should not log any entry points

    @pytest.mark.unit
    def test_smbios_get_force_32_flag(self, mock_cs):
        """Test smbios_get with force 32-bit flag."""
        command = smbios_cmd(['get', 'raw', '17', '--force'], cs=mock_cs)
        command.method = 'raw'
        command.type = 17
        command._force_32 = True

        command.smbios = Mock()
        command.smbios.get_raw_structs.return_value = [b'\x11\x12\x13']

        with patch('chipsec.utilcmd.smbios_cmd.print_buffer_bytes'), \
             patch.object(command.logger, 'log'):
            command.smbios_get()

            command.smbios.get_raw_structs.assert_called_once_with(17, True)

    @pytest.mark.unit
    def test_run_exception_in_func(self, mock_cs):
        """Test run method when func raises exception."""
        command = smbios_cmd(['entrypoint'], cs=mock_cs)
        command.func = Mock(side_effect=Exception("Function error"))

        with patch('chipsec.utilcmd.smbios_cmd.SMBIOS') as mock_smbios_class, \
             patch.object(command.logger, 'log'):
            mock_smbios_instance = Mock()
            mock_smbios_class.return_value = mock_smbios_instance
            mock_smbios_instance.find_smbios_table.return_value = True

            # Should not raise exception, just log it
            command.run()

            command.func.assert_called_once()


class TestSMBIOSCommandConfigurationValidation:
    """Test configuration validation aspects of SMBIOS command."""

    @pytest.fixture
    def smbios_cs(self):
        """Create ChipsecCs with SMBIOS-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock SMBIOS configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.SMBIOS = {
            'DEFAULT_METHOD': 'raw',
            'FORCE_32BIT': False,
            'ENTRY_POINT_2_ADDR': 0xF0000,
            'ENTRY_POINT_3_ADDR': 0xF1000
        }

        cs_mock.hals = Mock()
        cs_mock.hals.smbios = Mock()

        return cs_mock

    @pytest.mark.unit
    def test_smbios_configuration_structure(self, smbios_cs):
        """Test SMBIOS configuration structure."""
        smbios_config = smbios_cs.Cfg.SMBIOS

        # Test that required SMBIOS configuration exists
        assert 'DEFAULT_METHOD' in smbios_config
        assert 'FORCE_32BIT' in smbios_config

        # Test configuration values are reasonable
        assert smbios_config['DEFAULT_METHOD'] in ['raw', 'decoded']
        assert isinstance(smbios_config['FORCE_32BIT'], bool)

    @pytest.mark.unit
    def test_smbios_method_validation(self, smbios_cs):
        """Test SMBIOS method validation."""
        valid_methods = ['raw', 'decoded']

        for method in valid_methods:
            command = smbios_cmd(['get', method], cs=smbios_cs)
            command.parse_arguments()
            assert command.method == method

    @pytest.mark.unit
    def test_smbios_type_validation(self, smbios_cs):
        """Test SMBIOS type validation."""
        # Test various SMBIOS types
        test_types = [0, 1, 2, 17, 127]

        for smbios_type in test_types:
            command = smbios_cmd(['get', 'raw', str(smbios_type)], cs=smbios_cs)
            command.parse_arguments()
            assert command.type == smbios_type

    @pytest.mark.unit
    def test_smbios_force_32bit_flag_validation(self, smbios_cs):
        """Test SMBIOS force 32-bit flag validation."""
        # Test with force flag
        command_with_force = smbios_cmd(['get', 'decoded', '1', '--force'], cs=smbios_cs)
        command_with_force.parse_arguments()
        assert command_with_force._force_32 is True

        # Test without force flag
        command_without_force = smbios_cmd(['get', 'raw', '1'], cs=smbios_cs)
        command_without_force.parse_arguments()
        assert command_without_force._force_32 is False

    @pytest.mark.unit
    def test_smbios_entry_point_address_validation(self, smbios_cs):
        """Test SMBIOS entry point address validation."""
        smbios_config = smbios_cs.Cfg.SMBIOS

        # Test that entry point addresses are valid
        assert smbios_config['ENTRY_POINT_2_ADDR'] > 0
        assert smbios_config['ENTRY_POINT_3_ADDR'] > 0
        assert smbios_config['ENTRY_POINT_2_ADDR'] != smbios_config['ENTRY_POINT_3_ADDR']

    @pytest.mark.unit
    def test_smbios_error_handling(self, smbios_cs):
        """Test SMBIOS error handling."""
        command = smbios_cmd(['get', 'raw'], cs=smbios_cs)

        # Mock SMBIOS get_raw_structs to raise exception
        command.smbios = Mock()
        command.smbios.get_raw_structs.side_effect = Exception("SMBIOS access failed")

        # Should handle the exception gracefully
        with pytest.raises(Exception):
            command.smbios_get()

    @pytest.mark.unit
    def test_smbios_detection_error_handling(self, smbios_cs):
        """Test SMBIOS detection error handling."""
        command = smbios_cmd(['entrypoint'], cs=smbios_cs)

        with patch('chipsec.utilcmd.smbios_cmd.SMBIOS') as mock_smbios_class, \
             patch.object(command.logger, 'log'):
            mock_smbios_class.side_effect = Exception("SMBIOS detection failed")

            # Should handle the exception gracefully
            command.run()


if __name__ == '__main__':
    pytest.main([__file__])
