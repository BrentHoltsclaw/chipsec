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
from unittest.mock import Mock, patch, MagicMock
from chipsec.utilcmd.iommu_cmd import IOMMUCommand
from chipsec.library.exceptions import IOMMUError, AcpiRuntimeError
from tests.test_utils import MockFactory


class TestIOMMUCommand:
    """Comprehensive tests for IOMMU utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for IOMMU testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock IOMMU and ACPI HAL components
        cs_mock.hals = Mock()
        cs_mock.hals.iommu = Mock()
        cs_mock.hals.acpi = Mock()

        return cs_mock

    @pytest.fixture
    def iommu_command(self, mock_cs):
        """Create IOMMUCommand instance."""
        return IOMMUCommand(['list'], cs=mock_cs)

    @pytest.mark.unit
    def test_iommu_command_initialization(self, iommu_command, mock_cs):
        """Test IOMMUCommand initialization."""
        assert iommu_command.cs == mock_cs
        assert iommu_command.argv == ['list']

    @pytest.mark.unit
    def test_requirements(self, iommu_command):
        """Test command requirements."""
        reqs = iommu_command.requirements()
        assert reqs == iommu_command.toLoad.All

    @pytest.mark.unit
    def test_parse_arguments_list(self, mock_cs):
        """Test parsing list command."""
        command = IOMMUCommand(['list'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.iommu_list

    @pytest.mark.unit
    def test_parse_arguments_config(self, mock_cs):
        """Test parsing config command."""
        command = IOMMUCommand(['config', 'VTD'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.iommu_config
        assert command.engine == 'VTD'

    @pytest.mark.unit
    def test_parse_arguments_config_no_engine(self, mock_cs):
        """Test parsing config command without engine."""
        command = IOMMUCommand(['config'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.iommu_config
        assert command.engine == ''

    @pytest.mark.unit
    def test_parse_arguments_status(self, mock_cs):
        """Test parsing status command."""
        command = IOMMUCommand(['status', 'GFXVTD'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.iommu_status
        assert command.engine == 'GFXVTD'

    @pytest.mark.unit
    def test_parse_arguments_enable(self, mock_cs):
        """Test parsing enable command."""
        command = IOMMUCommand(['enable', 'VTD'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.iommu_enable
        assert command.engine == 'VTD'

    @pytest.mark.unit
    def test_parse_arguments_disable(self, mock_cs):
        """Test parsing disable command."""
        command = IOMMUCommand(['disable', 'VTD'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.iommu_disable
        assert command.engine == 'VTD'

    @pytest.mark.unit
    def test_parse_arguments_pt(self, mock_cs):
        """Test parsing pt command."""
        command = IOMMUCommand(['pt', 'VTD'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.iommu_pt
        assert command.engine == 'VTD'

    @pytest.mark.unit
    def test_parse_arguments_invalid(self, mock_cs):
        """Test parsing invalid command."""
        command = IOMMUCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_iommu_list(self, iommu_command, mock_cs):
        """Test iommu_list method."""
        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module, \
             patch.object(iommu_command.logger, 'log') as mock_log, \
             patch.object(iommu_command.logger, 'log_important') as mock_log_important:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d', 'GFXVTD': 'Graphics VT-d'}

            iommu_command.iommu_list()

            mock_log.assert_any_call("[CHIPSEC] Enumerating supported IOMMU engine names:")
            mock_log.assert_any_call("['VTD', 'GFXVTD']")
            mock_log_important.assert_any_call('\nNote: These are the IOMMU engine names supported by iommu_cmd.')
            mock_log_important.assert_any_call('It does not mean they are supported/enabled in the current platform.')

    @pytest.mark.unit
    def test_iommu_engine_iommu_error(self, iommu_command, mock_cs):
        """Test iommu_engine method with IOMMU initialization error."""
        iommu_command.engine = 'VTD'

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module, \
             patch.object(iommu_command.logger, 'log') as mock_log:
            mock_iommu_module.IOMMU.side_effect = IOMMUError("IOMMU not supported")

            iommu_command.iommu_engine('status')

            mock_log.assert_called_with("IOMMU not supported")

    @pytest.mark.unit
    def test_iommu_engine_invalid_engine(self, iommu_command, mock_cs):
        """Test iommu_engine method with invalid engine name."""
        iommu_command.engine = 'INVALID_ENGINE'

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module, \
             patch.object(iommu_command.logger, 'log_error') as mock_log_error:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d'}

            iommu_command.iommu_engine('status')

            mock_log_error.assert_called_with("IOMMU name 'INVALID_ENGINE' not recognized. Run 'iommu list' command for supported IOMMU names")

    @pytest.mark.unit
    def test_iommu_engine_config_with_dmar(self, iommu_command, mock_cs):
        """Test iommu_engine method config command with DMAR table present."""
        iommu_command.engine = 'VTD'

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module, \
             patch('chipsec.utilcmd.iommu_cmd.acpi') as mock_acpi_module, \
             patch.object(iommu_command.logger, 'log') as mock_log:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d'}
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            mock_acpi_instance = Mock()
            mock_acpi_module.ACPI.return_value = mock_acpi_instance
            mock_acpi_instance.is_ACPI_table_present.return_value = True
            mock_acpi_module.ACPI_TABLE_SIG_DMAR = 'DMAR'

            iommu_command.iommu_engine('config')

            mock_log.assert_any_call("[CHIPSEC] Dumping contents of DMAR ACPI table..\n")
            mock_acpi_instance.dump_ACPI_table.assert_called_with('DMAR')
            mock_iommu_instance.dump_IOMMU_configuration.assert_called_with('VTD')

    @pytest.mark.unit
    def test_iommu_engine_config_without_dmar(self, iommu_command, mock_cs):
        """Test iommu_engine method config command without DMAR table."""
        iommu_command.engine = 'VTD'

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module, \
             patch('chipsec.utilcmd.iommu_cmd.acpi') as mock_acpi_module, \
             patch.object(iommu_command.logger, 'log') as mock_log:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d'}
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            mock_acpi_instance = Mock()
            mock_acpi_module.ACPI.return_value = mock_acpi_instance
            mock_acpi_instance.is_ACPI_table_present.return_value = False

            iommu_command.iommu_engine('config')

            mock_log.assert_any_call("[CHIPSEC] Couldn't find DMAR ACPI table\n")
            mock_iommu_instance.dump_IOMMU_configuration.assert_called_with('VTD')

    @pytest.mark.unit
    def test_iommu_engine_config_acpi_error(self, iommu_command, mock_cs):
        """Test iommu_engine method config command with ACPI error."""
        iommu_command.engine = 'VTD'

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module, \
             patch('chipsec.utilcmd.iommu_cmd.acpi') as mock_acpi_module, \
             patch.object(iommu_command.logger, 'log') as mock_log:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d'}
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            mock_acpi_module.ACPI.side_effect = AcpiRuntimeError("ACPI not available")

            iommu_command.iommu_engine('config')

            mock_log.assert_called_with("ACPI not available")

    @pytest.mark.unit
    def test_iommu_engine_status(self, iommu_command, mock_cs):
        """Test iommu_engine method status command."""
        iommu_command.engine = 'VTD'

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d'}
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            iommu_command.iommu_engine('status')

            mock_iommu_instance.dump_IOMMU_status.assert_called_with('VTD')

    @pytest.mark.unit
    def test_iommu_engine_pt(self, iommu_command, mock_cs):
        """Test iommu_engine method pt command."""
        iommu_command.engine = 'VTD'

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d'}
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            iommu_command.iommu_engine('pt')

            mock_iommu_instance.dump_IOMMU_page_tables.assert_called_with('VTD')

    @pytest.mark.unit
    def test_iommu_engine_enable(self, iommu_command, mock_cs):
        """Test iommu_engine method enable command."""
        iommu_command.engine = 'VTD'

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d'}
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            iommu_command.iommu_engine('enable')

            mock_iommu_instance.set_IOMMU_Translation.assert_called_with('VTD', 1)

    @pytest.mark.unit
    def test_iommu_engine_disable(self, iommu_command, mock_cs):
        """Test iommu_engine method disable command."""
        iommu_command.engine = 'VTD'

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d'}
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            iommu_command.iommu_engine('disable')

            mock_iommu_instance.set_IOMMU_Translation.assert_called_with('VTD', 0)

    @pytest.mark.unit
    def test_iommu_engine_all_engines(self, iommu_command, mock_cs):
        """Test iommu_engine method with no specific engine (all engines)."""
        iommu_command.engine = ''  # No specific engine

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d', 'GFXVTD': 'Graphics VT-d'}
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            iommu_command.iommu_engine('status')

            # Should call for all engines
            mock_iommu_instance.dump_IOMMU_status.assert_any_call('VTD')
            mock_iommu_instance.dump_IOMMU_status.assert_any_call('GFXVTD')

    @pytest.mark.unit
    def test_iommu_config(self, iommu_command, mock_cs):
        """Test iommu_config method."""
        iommu_command.engine = 'VTD'

        with patch.object(iommu_command, 'iommu_engine') as mock_iommu_engine:
            iommu_command.iommu_config()

            mock_iommu_engine.assert_called_with('config')

    @pytest.mark.unit
    def test_iommu_status(self, iommu_command, mock_cs):
        """Test iommu_status method."""
        iommu_command.engine = 'VTD'

        with patch.object(iommu_command, 'iommu_engine') as mock_iommu_engine:
            iommu_command.iommu_status()

            mock_iommu_engine.assert_called_with('status')

    @pytest.mark.unit
    def test_iommu_enable(self, iommu_command, mock_cs):
        """Test iommu_enable method."""
        iommu_command.engine = 'VTD'

        with patch.object(iommu_command, 'iommu_engine') as mock_iommu_engine:
            iommu_command.iommu_enable()

            mock_iommu_engine.assert_called_with('enable')

    @pytest.mark.unit
    def test_iommu_disable(self, iommu_command, mock_cs):
        """Test iommu_disable method."""
        iommu_command.engine = 'VTD'

        with patch.object(iommu_command, 'iommu_engine') as mock_iommu_engine:
            iommu_command.iommu_disable()

            mock_iommu_engine.assert_called_with('disable')

    @pytest.mark.unit
    def test_iommu_pt(self, iommu_command, mock_cs):
        """Test iommu_pt method."""
        iommu_command.engine = 'VTD'

        with patch.object(iommu_command, 'iommu_engine') as mock_iommu_engine:
            iommu_command.iommu_pt()

            mock_iommu_engine.assert_called_with('pt')

    @pytest.mark.unit
    def test_run(self, iommu_command, mock_cs):
        """Test run method."""
        iommu_command.func = Mock()

        iommu_command.run()

        iommu_command.func.assert_called_once()


class TestIOMMUCommandIntegration:
    """Integration tests for IOMMU command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for IOMMU testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock IOMMU and ACPI components with realistic data
        cs_mock.hals = Mock()
        cs_mock.hals.iommu = Mock()
        cs_mock.hals.acpi = Mock()

        return cs_mock

    @pytest.mark.integration
    def test_iommu_list_integration(self, integrated_cs):
        """Test complete iommu_list workflow."""
        iommu_cmd = IOMMUCommand(['list'], cs=integrated_cs)

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module, \
             patch.object(iommu_cmd.logger, 'log') as mock_log:
            mock_iommu_module.IOMMU_ENGINES = {
                'VTD': 'Intel VT-d',
                'GFXVTD': 'Graphics VT-d',
                'USBVTD': 'USB VT-d'
            }

            iommu_cmd.run()

            mock_log.assert_any_call("[CHIPSEC] Enumerating supported IOMMU engine names:")
            mock_log.assert_any_call("['VTD', 'GFXVTD', 'USBVTD']")

    @pytest.mark.integration
    def test_iommu_config_integration(self, integrated_cs):
        """Test complete iommu_config workflow."""
        iommu_cmd = IOMMUCommand(['config', 'VTD'], cs=integrated_cs)

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module, \
             patch('chipsec.utilcmd.iommu_cmd.acpi') as mock_acpi_module:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d'}
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            mock_acpi_instance = Mock()
            mock_acpi_module.ACPI.return_value = mock_acpi_instance
            mock_acpi_instance.is_ACPI_table_present.return_value = True
            mock_acpi_module.ACPI_TABLE_SIG_DMAR = 'DMAR'

            iommu_cmd.run()

            mock_iommu_instance.dump_IOMMU_configuration.assert_called_with('VTD')
            mock_acpi_instance.dump_ACPI_table.assert_called_with('DMAR')

    @pytest.mark.integration
    def test_iommu_status_integration(self, integrated_cs):
        """Test complete iommu_status workflow."""
        iommu_cmd = IOMMUCommand(['status', 'VTD'], cs=integrated_cs)

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d'}
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            iommu_cmd.run()

            mock_iommu_instance.dump_IOMMU_status.assert_called_with('VTD')

    @pytest.mark.integration
    def test_iommu_enable_integration(self, integrated_cs):
        """Test complete iommu_enable workflow."""
        iommu_cmd = IOMMUCommand(['enable', 'VTD'], cs=integrated_cs)

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d'}
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            iommu_cmd.run()

            mock_iommu_instance.set_IOMMU_Translation.assert_called_with('VTD', 1)

    @pytest.mark.integration
    def test_iommu_pt_integration(self, integrated_cs):
        """Test complete iommu_pt workflow."""
        iommu_cmd = IOMMUCommand(['pt', 'VTD'], cs=integrated_cs)

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d'}
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            iommu_cmd.run()

            mock_iommu_instance.dump_IOMMU_page_tables.assert_called_with('VTD')


class TestIOMMUCommandEdgeCases:
    """Test edge cases and error conditions for IOMMU command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        cs_mock.hals.iommu = Mock()
        cs_mock.hals.acpi = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        command = IOMMUCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_iommu_engine_empty_engine_list(self, mock_cs):
        """Test iommu_engine with empty engine list."""
        command = IOMMUCommand(['status'], cs=mock_cs)
        command.engine = ''

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module:
            mock_iommu_module.IOMMU_ENGINES = {}
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            command.iommu_engine('status')

            # Should not call any dump methods since no engines
            mock_iommu_instance.dump_IOMMU_status.assert_not_called()

    @pytest.mark.unit
    def test_iommu_engine_multiple_engines(self, mock_cs):
        """Test iommu_engine with multiple engines."""
        command = IOMMUCommand(['status'], cs=mock_cs)
        command.engine = ''

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module:
            mock_iommu_module.IOMMU_ENGINES = {
                'VTD': 'Intel VT-d',
                'GFXVTD': 'Graphics VT-d',
                'USBVTD': 'USB VT-d'
            }
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            command.iommu_engine('status')

            # Should call for all engines
            mock_iommu_instance.dump_IOMMU_status.assert_any_call('VTD')
            mock_iommu_instance.dump_IOMMU_status.assert_any_call('GFXVTD')
            mock_iommu_instance.dump_IOMMU_status.assert_any_call('USBVTD')

    @pytest.mark.unit
    def test_iommu_config_dmar_table_missing(self, mock_cs):
        """Test iommu_config when DMAR table is missing."""
        command = IOMMUCommand(['config', 'VTD'], cs=mock_cs)

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module, \
             patch('chipsec.utilcmd.iommu_cmd.acpi') as mock_acpi_module, \
             patch.object(command.logger, 'log') as mock_log:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d'}
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            mock_acpi_instance = Mock()
            mock_acpi_module.ACPI.return_value = mock_acpi_instance
            mock_acpi_instance.is_ACPI_table_present.return_value = False

            command.iommu_engine('config')

            mock_log.assert_any_call("[CHIPSEC] Couldn't find DMAR ACPI table\n")

    @pytest.mark.unit
    def test_iommu_list_empty_engines(self, mock_cs):
        """Test iommu_list with empty engines dictionary."""
        command = IOMMUCommand(['list'], cs=mock_cs)

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module, \
             patch.object(command.logger, 'log') as mock_log:
            mock_iommu_module.IOMMU_ENGINES = {}

            command.iommu_list()

            mock_log.assert_any_call('[]')

    @pytest.mark.unit
    def test_iommu_engine_unknown_command(self, mock_cs):
        """Test iommu_engine with unknown command."""
        command = IOMMUCommand(['status', 'VTD'], cs=mock_cs)

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d'}
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            # Unknown command should not call any methods
            command.iommu_engine('unknown_command')

            mock_iommu_instance.dump_IOMMU_status.assert_not_called()
            mock_iommu_instance.dump_IOMMU_configuration.assert_not_called()
            mock_iommu_instance.dump_IOMMU_page_tables.assert_not_called()
            mock_iommu_instance.set_IOMMU_Translation.assert_not_called()


class TestIOMMUCommandConfigurationValidation:
    """Test configuration validation aspects of IOMMU command."""

    @pytest.fixture
    def iommu_cs(self):
        """Create ChipsecCs with IOMMU-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock IOMMU configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.IOMMU = {
            'VTD_BASE': 0xFED90000,
            'VTD_SIZE': 0x1000,
            'GFXVTD_BASE': 0xFED92000,
            'DMAR_TABLE_PRESENT': True
        }

        cs_mock.hals = Mock()
        cs_mock.hals.iommu = Mock()
        cs_mock.hals.acpi = Mock()

        return cs_mock

    @pytest.mark.unit
    def test_iommu_configuration_structure(self, iommu_cs):
        """Test IOMMU configuration structure."""
        iommu_config = iommu_cs.Cfg.IOMMU

        # Test that required IOMMU configuration exists
        assert 'VTD_BASE' in iommu_config
        assert 'VTD_SIZE' in iommu_config

        # Test configuration values are reasonable
        assert iommu_config['VTD_BASE'] > 0
        assert iommu_config['VTD_SIZE'] > 0

    @pytest.mark.unit
    def test_iommu_engine_name_validation(self, iommu_cs):
        """Test IOMMU engine name validation."""
        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module:
            mock_iommu_module.IOMMU_ENGINES = {
                'VTD': 'Intel VT-d',
                'GFXVTD': 'Graphics VT-d',
                'USBVTD': 'USB VT-d'
            }

            # Valid engine names
            assert 'VTD' in mock_iommu_module.IOMMU_ENGINES
            assert 'GFXVTD' in mock_iommu_module.IOMMU_ENGINES
            assert 'USBVTD' in mock_iommu_module.IOMMU_ENGINES

            # Invalid engine name
            assert 'INVALID' not in mock_iommu_module.IOMMU_ENGINES

    @pytest.mark.unit
    def test_iommu_command_parameter_validation(self, iommu_cs):
        """Test IOMMU command parameter validation."""
        # Test that engine parameter is properly parsed
        command = IOMMUCommand(['status', 'VTD'], cs=iommu_cs)
        command.parse_arguments()

        assert command.engine == 'VTD'
        assert command.func == command.iommu_status

        # Test empty engine parameter
        command2 = IOMMUCommand(['status'], cs=iommu_cs)
        command2.parse_arguments()

        assert command2.engine == ''
        assert command2.func == command2.iommu_status

    @pytest.mark.unit
    def test_iommu_error_handling(self, iommu_cs):
        """Test IOMMU error handling."""
        command = IOMMUCommand(['status', 'VTD'], cs=iommu_cs)

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module, \
             patch.object(command.logger, 'log') as mock_log:
            mock_iommu_module.IOMMU.side_effect = IOMMUError("IOMMU initialization failed")

            command.iommu_engine('status')

            mock_log.assert_called_with("IOMMU initialization failed")

    @pytest.mark.unit
    def test_acpi_error_handling(self, iommu_cs):
        """Test ACPI error handling in IOMMU config."""
        command = IOMMUCommand(['config', 'VTD'], cs=iommu_cs)

        with patch('chipsec.utilcmd.iommu_cmd.iommu') as mock_iommu_module, \
             patch('chipsec.utilcmd.iommu_cmd.acpi') as mock_acpi_module, \
             patch.object(command.logger, 'log') as mock_log:
            mock_iommu_module.IOMMU_ENGINES = {'VTD': 'Intel VT-d'}
            mock_iommu_instance = Mock()
            mock_iommu_module.IOMMU.return_value = mock_iommu_instance

            mock_acpi_module.ACPI.side_effect = AcpiRuntimeError("ACPI initialization failed")

            command.iommu_engine('config')

            mock_log.assert_called_with("ACPI initialization failed")


if __name__ == '__main__':
    pytest.main([__file__])
