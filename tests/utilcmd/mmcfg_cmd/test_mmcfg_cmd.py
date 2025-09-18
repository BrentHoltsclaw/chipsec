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
from chipsec.utilcmd.mmcfg_cmd import MMCfgCommand
from tests.test_utils import MockFactory


class TestMMCfgCommand:
    """Comprehensive tests for MMCFG utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for MMCFG testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock MMCFG and PCI HAL components
        cs_mock.hals = Mock()
        cs_mock.hals.MMCFG = Mock()
        cs_mock.hals.Pci = Mock()

        return cs_mock

    @pytest.fixture
    def mmcfg_command(self, mock_cs):
        """Create MMCfgCommand instance."""
        return MMCfgCommand(['base'], cs=mock_cs)

    @pytest.mark.unit
    def test_mmcfg_command_initialization(self, mmcfg_command, mock_cs):
        """Test MMCfgCommand initialization."""
        assert mmcfg_command.cs == mock_cs
        assert mmcfg_command.argv == ['base']

    @pytest.mark.unit
    def test_requirements(self, mmcfg_command):
        """Test command requirements."""
        reqs = mmcfg_command.requirements()
        assert reqs == mmcfg_command.toLoad.All

    @pytest.mark.unit
    def test_parse_arguments_base(self, mock_cs):
        """Test parsing base command."""
        command = MMCfgCommand(['base'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.base

    @pytest.mark.unit
    def test_parse_arguments_read(self, mock_cs):
        """Test parsing read command."""
        command = MMCfgCommand(['read', '0x0', '0x1F', '0x0', '0x200', '4'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.read
        assert command.bus == 0x0
        assert command.device == 0x1F
        assert command.function == 0x0
        assert command.offset == 0x200
        assert command.width == 4

    @pytest.mark.unit
    def test_parse_arguments_write(self, mock_cs):
        """Test parsing write command."""
        command = MMCfgCommand(['write', '0x0', '0x1F', '0x0', '0x200', '1', '0x1A'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.write
        assert command.bus == 0x0
        assert command.device == 0x1F
        assert command.function == 0x0
        assert command.offset == 0x200
        assert command.width == 1
        assert command.value == 0x1A

    @pytest.mark.unit
    def test_parse_arguments_ec(self, mock_cs):
        """Test parsing ec command."""
        command = MMCfgCommand(['ec'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.ec

    @pytest.mark.unit
    def test_parse_arguments_invalid_width(self, mock_cs):
        """Test parsing command with invalid width."""
        command = MMCfgCommand(['read', '0x0', '0x1F', '0x0', '0x200', '8'], cs=mock_cs)

        # Should raise SystemExit due to invalid width choice
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_invalid(self, mock_cs):
        """Test parsing invalid command."""
        command = MMCfgCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_base(self, mmcfg_command, mock_cs):
        """Test base method."""
        mmcfg_command._cs.hals.MMCFG.get_MMCFG_base_address.return_value = (0xE0000000, 0x10000000)

        with patch.object(mmcfg_command.logger, 'log') as mock_log:
            mmcfg_command.base()

            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Base: 0xE0000000')
            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Size: 0x10000000')

    @pytest.mark.unit
    def test_read_byte(self, mmcfg_command, mock_cs):
        """Test read method with byte width."""
        mmcfg_command.bus = 0x0
        mmcfg_command.device = 0x1F
        mmcfg_command.function = 0x0
        mmcfg_command.offset = 0x200
        mmcfg_command.width = 1

        mmcfg_command._cs.hals.MMCFG.read_mmcfg_reg.return_value = 0xAB

        with patch.object(mmcfg_command.logger, 'log') as mock_log:
            mmcfg_command.read()

            mmcfg_command._cs.hals.MMCFG.read_mmcfg_reg.assert_called_once_with(0x0, 0x1F, 0x0, 0x200, 1)
            mock_log.assert_called_with('[CHIPSEC] Reading MMCFG register (00:31.0 + 0x200): 0xAB')

    @pytest.mark.unit
    def test_read_word(self, mmcfg_command, mock_cs):
        """Test read method with word width."""
        mmcfg_command.bus = 0x1
        mmcfg_command.device = 0x0
        mmcfg_command.function = 0x0
        mmcfg_command.offset = 0x10
        mmcfg_command.width = 2

        mmcfg_command._cs.hals.MMCFG.read_mmcfg_reg.return_value = 0xABCD

        with patch.object(mmcfg_command.logger, 'log') as mock_log:
            mmcfg_command.read()

            mmcfg_command._cs.hals.MMCFG.read_mmcfg_reg.assert_called_once_with(0x1, 0x0, 0x0, 0x10, 2)
            mock_log.assert_called_with('[CHIPSEC] Reading MMCFG register (01:00.0 + 0x10): 0xABCD')

    @pytest.mark.unit
    def test_read_dword(self, mmcfg_command, mock_cs):
        """Test read method with dword width."""
        mmcfg_command.bus = 0x2
        mmcfg_command.device = 0x1
        mmcfg_command.function = 0x1
        mmcfg_command.offset = 0x4
        mmcfg_command.width = 4

        mmcfg_command._cs.hals.MMCFG.read_mmcfg_reg.return_value = 0x12345678

        with patch.object(mmcfg_command.logger, 'log') as mock_log:
            mmcfg_command.read()

            mmcfg_command._cs.hals.MMCFG.read_mmcfg_reg.assert_called_once_with(0x2, 0x1, 0x1, 0x4, 4)
            mock_log.assert_called_with('[CHIPSEC] Reading MMCFG register (02:01.1 + 0x4): 0x12345678')

    @pytest.mark.unit
    def test_write_byte(self, mmcfg_command, mock_cs):
        """Test write method with byte width."""
        mmcfg_command.bus = 0x0
        mmcfg_command.device = 0x1F
        mmcfg_command.function = 0x0
        mmcfg_command.offset = 0x200
        mmcfg_command.width = 1
        mmcfg_command.value = 0x1A

        with patch.object(mmcfg_command.logger, 'log') as mock_log:
            mmcfg_command.write()

            mmcfg_command._cs.hals.MMCFG.write_mmcfg_reg.assert_called_once_with(0x0, 0x1F, 0x0, 0x200, 1, 0x1A)
            mock_log.assert_called_with('[CHIPSEC] Writing MMCFG register (00:31.0 + 0x200): 0x1A')

    @pytest.mark.unit
    def test_write_word(self, mmcfg_command, mock_cs):
        """Test write method with word width."""
        mmcfg_command.bus = 0x1
        mmcfg_command.device = 0x0
        mmcfg_command.function = 0x0
        mmcfg_command.offset = 0x10
        mmcfg_command.width = 2
        mmcfg_command.value = 0xABCD

        with patch.object(mmcfg_command.logger, 'log') as mock_log:
            mmcfg_command.write()

            mmcfg_command._cs.hals.MMCFG.write_mmcfg_reg.assert_called_once_with(0x1, 0x0, 0x0, 0x10, 2, 0xABCD)
            mock_log.assert_called_with('[CHIPSEC] Writing MMCFG register (01:00.0 + 0x10): 0xABCD')

    @pytest.mark.unit
    def test_write_dword(self, mmcfg_command, mock_cs):
        """Test write method with dword width."""
        mmcfg_command.bus = 0x2
        mmcfg_command.device = 0x1
        mmcfg_command.function = 0x1
        mmcfg_command.offset = 0x4
        mmcfg_command.width = 4
        mmcfg_command.value = 0x12345678

        with patch.object(mmcfg_command.logger, 'log') as mock_log:
            mmcfg_command.write()

            mmcfg_command._cs.hals.MMCFG.write_mmcfg_reg.assert_called_once_with(0x2, 0x1, 0x1, 0x4, 4, 0x12345678)
            mock_log.assert_called_with('[CHIPSEC] Writing MMCFG register (02:01.1 + 0x4): 0x12345678')

    @pytest.mark.unit
    def test_ec_no_devices(self, mmcfg_command, mock_cs):
        """Test ec method with no devices."""
        mmcfg_command._cs.hals.Pci.enumerate_devices.return_value = []

        with patch.object(mmcfg_command.logger, 'log') as mock_log:
            mmcfg_command.ec()

            # Should not log anything since no devices
            mmcfg_command._cs.hals.Pci.enumerate_devices.assert_called_once()
            # No extended capabilities to log

    @pytest.mark.unit
    def test_ec_with_devices_no_capabilities(self, mmcfg_command, mock_cs):
        """Test ec method with devices but no extended capabilities."""
        mmcfg_command._cs.hals.Pci.enumerate_devices.return_value = [
            (0x0, 0x1F, 0x0, 0x8086, 0x1234, 'LPC Bridge'),
            (0x0, 0x2, 0x0, 0x10DE, 0xABCD, 'VGA Controller')
        ]
        mmcfg_command._cs.hals.MMCFG.get_extended_capabilities.return_value = []

        with patch.object(mmcfg_command.logger, 'log') as mock_log:
            mmcfg_command.ec()

            mmcfg_command._cs.hals.Pci.enumerate_devices.assert_called_once()
            # Should call get_extended_capabilities for each device
            assert mmcfg_command._cs.hals.MMCFG.get_extended_capabilities.call_count == 2
            # Should not log any capabilities

    @pytest.mark.unit
    def test_ec_with_devices_and_capabilities(self, mmcfg_command, mock_cs):
        """Test ec method with devices and extended capabilities."""
        mmcfg_command._cs.hals.Pci.enumerate_devices.return_value = [
            (0x0, 0x1F, 0x0, 0x8086, 0x1234, 'LPC Bridge')
        ]

        # Mock capability object
        mock_cap = Mock()
        mock_cap.id = 0x1
        mock_cap.off = 0x100

        mmcfg_command._cs.hals.MMCFG.get_extended_capabilities.return_value = [mock_cap]

        with patch.object(mmcfg_command.logger, 'log') as mock_log:
            mmcfg_command.ec()

            mock_log.assert_any_call('Extended Capabilities for 00:1F.0:')
            mock_log.assert_any_call(f'{mock_cap}')

    @pytest.mark.unit
    def test_ec_with_vsec_capability(self, mmcfg_command, mock_cs):
        """Test ec method with VSEC capability."""
        mmcfg_command._cs.hals.Pci.enumerate_devices.return_value = [
            (0x0, 0x1F, 0x0, 0x8086, 0x1234, 'LPC Bridge')
        ]

        # Mock VSEC capability
        mock_cap = Mock()
        mock_cap.id = 0xB  # VSEC capability ID
        mock_cap.off = 0x100

        mock_vsec = Mock()
        mock_vsec.__str__ = Mock(return_value='VSEC data')

        mmcfg_command._cs.hals.MMCFG.get_extended_capabilities.return_value = [mock_cap]
        mmcfg_command._cs.hals.MMCFG.get_vsec.return_value = mock_vsec

        with patch.object(mmcfg_command.logger, 'log') as mock_log:
            mmcfg_command.ec()

            mock_log.assert_any_call('Extended Capabilities for 00:1F.0:')
            mock_log.assert_any_call(f'{mock_cap}')
            mock_log.assert_any_call('\tVSEC data')
            mmcfg_command._cs.hals.MMCFG.get_vsec.assert_called_once_with(0x0, 0x1F, 0x0, 0x100)

    @pytest.mark.unit
    def test_run(self, mmcfg_command, mock_cs):
        """Test run method."""
        mmcfg_command.func = Mock()

        mmcfg_command.run()

        mmcfg_command.func.assert_called_once()


class TestMMCfgCommandIntegration:
    """Integration tests for MMCFG command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for MMCFG testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock MMCFG and PCI components with realistic data
        cs_mock.hals = Mock()
        cs_mock.hals.MMCFG = Mock()
        cs_mock.hals.Pci = Mock()

        return cs_mock

    @pytest.mark.integration
    def test_mmcfg_base_integration(self, integrated_cs):
        """Test complete mmcfg_base workflow."""
        mmcfg_cmd = MMCfgCommand(['base'], cs=integrated_cs)
        mmcfg_cmd.set_up()

        mmcfg_cmd._cs.hals.MMCFG.get_MMCFG_base_address.return_value = (0xE0000000, 0x10000000)

        with patch.object(mmcfg_cmd.logger, 'log'):
            mmcfg_cmd.run()

            mmcfg_cmd._cs.hals.MMCFG.get_MMCFG_base_address.assert_called_once()

    @pytest.mark.integration
    def test_mmcfg_read_integration(self, integrated_cs):
        """Test complete mmcfg_read workflow."""
        mmcfg_cmd = MMCfgCommand(['read', '0x0', '0x1F', '0x0', '0x200', '4'], cs=integrated_cs)
        mmcfg_cmd.set_up()

        mmcfg_cmd._cs.hals.MMCFG.read_mmcfg_reg.return_value = 0x12345678

        with patch.object(mmcfg_cmd.logger, 'log'):
            mmcfg_cmd.run()

            mmcfg_cmd._cs.hals.MMCFG.read_mmcfg_reg.assert_called_once_with(0x0, 0x1F, 0x0, 0x200, 4)

    @pytest.mark.integration
    def test_mmcfg_write_integration(self, integrated_cs):
        """Test complete mmcfg_write workflow."""
        mmcfg_cmd = MMCfgCommand(['write', '0x0', '0x1F', '0x0', '0x200', '1', '0x1A'], cs=integrated_cs)
        mmcfg_cmd.set_up()

        with patch.object(mmcfg_cmd.logger, 'log'):
            mmcfg_cmd.run()

            mmcfg_cmd._cs.hals.MMCFG.write_mmcfg_reg.assert_called_once_with(0x0, 0x1F, 0x0, 0x200, 1, 0x1A)

    @pytest.mark.integration
    def test_mmcfg_ec_integration(self, integrated_cs):
        """Test complete mmcfg_ec workflow."""
        mmcfg_cmd = MMCfgCommand(['ec'], cs=integrated_cs)
        mmcfg_cmd.set_up()

        mmcfg_cmd._cs.hals.Pci.enumerate_devices.return_value = [
            (0x0, 0x1F, 0x0, 0x8086, 0x1234, 'LPC Bridge')
        ]
        mmcfg_cmd._cs.hals.MMCFG.get_extended_capabilities.return_value = []

        with patch.object(mmcfg_cmd.logger, 'log'):
            mmcfg_cmd.run()

            mmcfg_cmd._cs.hals.Pci.enumerate_devices.assert_called_once()
            mmcfg_cmd._cs.hals.MMCFG.get_extended_capabilities.assert_called_once_with(0x0, 0x1F, 0x0)


class TestMMCfgCommandEdgeCases:
    """Test edge cases and error conditions for MMCFG command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        cs_mock.hals.MMCFG = Mock()
        cs_mock.hals.Pci = Mock()
        return cs_mock

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        command = MMCfgCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_read_boundary_values(self, mock_cs):
        """Test read method with boundary values."""
        command = MMCfgCommand(['read', '0xFF', '0x1F', '0x7', '0xFFF', '4'], cs=mock_cs)
        command.set_up()

        command._cs.hals.MMCFG.read_mmcfg_reg.return_value = 0xFFFFFFFF

        with patch.object(command.logger, 'log'):
            command.run()

            command._cs.hals.MMCFG.read_mmcfg_reg.assert_called_once_with(0xFF, 0x1F, 0x7, 0xFFF, 4)

    @pytest.mark.unit
    def test_write_boundary_values(self, mock_cs):
        """Test write method with boundary values."""
        command = MMCfgCommand(['write', '0xFF', '0x1F', '0x7', '0xFFF', '4', '0xFFFFFFFF'], cs=mock_cs)
        command.set_up()

        with patch.object(command.logger, 'log'):
            command.run()

            command._cs.hals.MMCFG.write_mmcfg_reg.assert_called_once_with(0xFF, 0x1F, 0x7, 0xFFF, 4, 0xFFFFFFFF)

    @pytest.mark.unit
    def test_read_zero_values(self, mock_cs):
        """Test read method with zero values."""
        command = MMCfgCommand(['read', '0x0', '0x0', '0x0', '0x0', '1'], cs=mock_cs)
        command.set_up()

        command._cs.hals.MMCFG.read_mmcfg_reg.return_value = 0x0

        with patch.object(command.logger, 'log'):
            command.run()

            command._cs.hals.MMCFG.read_mmcfg_reg.assert_called_once_with(0x0, 0x0, 0x0, 0x0, 1)

    @pytest.mark.unit
    def test_write_zero_values(self, mock_cs):
        """Test write method with zero values."""
        command = MMCfgCommand(['write', '0x0', '0x0', '0x0', '0x0', '1', '0x0'], cs=mock_cs)
        command.set_up()

        with patch.object(command.logger, 'log'):
            command.run()

            command._cs.hals.MMCFG.write_mmcfg_reg.assert_called_once_with(0x0, 0x0, 0x0, 0x0, 1, 0x0)

    @pytest.mark.unit
    def test_ec_multiple_devices(self, mock_cs):
        """Test ec method with multiple devices."""
        command = MMCfgCommand(['ec'], cs=mock_cs)

        command._cs.hals.Pci.enumerate_devices.return_value = [
            (0x0, 0x0, 0x0, 0x8086, 0x1234, 'Host Bridge'),
            (0x0, 0x1F, 0x0, 0x8086, 0x5678, 'LPC Bridge'),
            (0x1, 0x0, 0x0, 0x10DE, 0xABCD, 'VGA Controller')
        ]
        command._cs.hals.MMCFG.get_extended_capabilities.return_value = []

        with patch.object(command.logger, 'log'):
            command.run()

            # Should call get_extended_capabilities for each device
            assert command._cs.hals.MMCFG.get_extended_capabilities.call_count == 3

    @pytest.mark.unit
    def test_base_zero_values(self, mock_cs):
        """Test base method with zero values."""
        command = MMCfgCommand(['base'], cs=mock_cs)

        command._cs.hals.MMCFG.get_MMCFG_base_address.return_value = (0x0, 0x0)

        with patch.object(command.logger, 'log'):
            command.run()

            command._cs.hals.MMCFG.get_MMCFG_base_address.assert_called_once()

    @pytest.mark.unit
    def test_read_hex_parsing(self, mock_cs):
        """Test read method with various hex formats."""
        test_cases = [
            ('0x0', 0x0),
            ('0xFF', 0xFF),
            ('0x100', 0x100),
            ('FF', 0xFF),
            ('100', 0x100)
        ]

        for hex_str, expected_value in test_cases:
            command = MMCfgCommand(['read', hex_str, '0x1F', '0x0', '0x200', '4'], cs=mock_cs)
            command.parse_arguments()
            assert command.bus == expected_value

    @pytest.mark.unit
    def test_write_hex_parsing(self, mock_cs):
        """Test write method with various hex formats."""
        test_cases = [
            ('0x0', 0x0),
            ('0xFF', 0xFF),
            ('0x100', 0x100),
            ('FF', 0xFF),
            ('100', 0x100)
        ]

        for hex_str, expected_value in test_cases:
            command = MMCfgCommand(['write', '0x0', '0x1F', '0x0', '0x200', '4', hex_str], cs=mock_cs)
            command.parse_arguments()
            assert command.value == expected_value


class TestMMCfgCommandConfigurationValidation:
    """Test configuration validation aspects of MMCFG command."""

    @pytest.fixture
    def mmcfg_cs(self):
        """Create ChipsecCs with MMCFG-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock MMCFG configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.MMCFG = {
            'BASE_ADDRESS': 0xE0000000,
            'SIZE': 0x10000000,
            'BUS_RANGE': (0x0, 0xFF),
            'DEVICE_RANGE': (0x0, 0x1F),
            'FUNCTION_RANGE': (0x0, 0x7)
        }

        cs_mock.hals = Mock()
        cs_mock.hals.MMCFG = Mock()
        cs_mock.hals.Pci = Mock()

        return cs_mock

    @pytest.mark.unit
    def test_mmcfg_configuration_structure(self, mmcfg_cs):
        """Test MMCFG configuration structure."""
        mmcfg_config = mmcfg_cs.Cfg.MMCFG

        # Test that required MMCFG configuration exists
        assert 'BASE_ADDRESS' in mmcfg_config
        assert 'SIZE' in mmcfg_config

        # Test configuration values are reasonable
        assert mmcfg_config['BASE_ADDRESS'] > 0
        assert mmcfg_config['SIZE'] > 0

    @pytest.mark.unit
    def test_mmcfg_address_validation(self, mmcfg_cs):
        """Test MMCFG address validation."""
        command = MMCfgCommand(['read', '0x0', '0x1F', '0x0', '0x200', '4'], cs=mmcfg_cs)
        command.parse_arguments()

        # Test that parsed values are within valid ranges
        assert 0 <= command.bus <= 0xFF
        assert 0 <= command.device <= 0x1F
        assert 0 <= command.function <= 0x7
        assert command.offset >= 0
        assert command.width in [1, 2, 4]

    @pytest.mark.unit
    def test_mmcfg_offset_alignment(self, mmcfg_cs):
        """Test MMCFG offset alignment for different widths."""
        test_cases = [
            (1, 0x200),  # Byte alignment
            (2, 0x200),  # Word alignment
            (4, 0x200),  # Dword alignment
        ]

        for width, offset in test_cases:
            command = MMCfgCommand(['read', '0x0', '0x1F', '0x0', f'0x{offset:X}', f'{width}'], cs=mmcfg_cs)
            command.parse_arguments()

            # Test that offset is properly aligned for the width
            assert command.offset % width == 0

    @pytest.mark.unit
    def test_mmcfg_width_validation(self, mmcfg_cs):
        """Test MMCFG data width validation."""
        valid_widths = [1, 2, 4]

        for width in valid_widths:
            command = MMCfgCommand(['read', '0x0', '0x1F', '0x0', '0x200', f'{width}'], cs=mmcfg_cs)
            command.parse_arguments()  # Should not raise exception

            assert command.width == width

    @pytest.mark.unit
    def test_mmcfg_bus_device_function_ranges(self, mmcfg_cs):
        """Test MMCFG bus, device, and function range validation."""
        # Test boundary values
        test_cases = [
            (0x0, 0x0, 0x0),      # Minimum values
            (0xFF, 0x1F, 0x7),    # Maximum values
            (0x80, 0x10, 0x3),    # Middle values
        ]

        for bus, device, function in test_cases:
            command = MMCfgCommand(['read', f'0x{bus:X}', f'0x{device:X}', f'0x{function:X}', '0x200', '4'], cs=mmcfg_cs)
            command.parse_arguments()

            assert command.bus == bus
            assert command.device == device
            assert command.function == function

    @pytest.mark.unit
    def test_mmcfg_error_handling(self, mmcfg_cs):
        """Test MMCFG error handling."""
        command = MMCfgCommand(['read', '0x0', '0x1F', '0x0', '0x200', '4'], cs=mmcfg_cs)

        # Mock MMCFG read to raise exception
        command._cs.hals.MMCFG.read_mmcfg_reg.side_effect = Exception("MMCFG access failed")

        # Should handle the exception gracefully
        with pytest.raises(Exception):
            command.read()

    @pytest.mark.unit
    def test_mmcfg_pci_enumeration_error_handling(self, mmcfg_cs):
        """Test MMCFG PCI enumeration error handling."""
        command = MMCfgCommand(['ec'], cs=mmcfg_cs)

        # Mock PCI enumeration to raise exception
        command._cs.hals.Pci.enumerate_devices.side_effect = Exception("PCI enumeration failed")

        # Should handle the exception gracefully
        with pytest.raises(Exception):
            command.ec()


if __name__ == '__main__':
    pytest.main([__file__])
