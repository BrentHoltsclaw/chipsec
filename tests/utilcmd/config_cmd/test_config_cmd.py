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
from chipsec.utilcmd.config_cmd import CONFIGCommand
from tests.test_utils import MockFactory


class TestCONFIGCommand:
    """Comprehensive tests for CONFIG utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for CONFIG testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock configuration data
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.CONFIG_PCI = {
            'TEST_DEVICE': {
                'bus': 0x00,
                'dev': 0x1F,
                'fun': 0x00,
                'vid': 0x8086,
                'did': 0x1234,
                'config': 'LPC'
            },
            'TEST_COMPONENT': {
                'component': 'TEST_COMP',
                'config': 'TEST_CFG'
            }
        }

        cs_mock.Cfg.REGISTERS = {
            'TEST_PCICFG_REG': {
                'type': 'pcicfg',
                'bus': 0x00,
                'dev': 0x1F,
                'fun': 0x00,
                'offset': 0x00,
                'size': 4,
                'FIELDS': {
                    'TEST_FIELD': {'bit': 0, 'size': 8}
                }
            },
            'TEST_MMIO_REG': {
                'type': 'mmio',
                'bar': 'TEST_BAR',
                'offset': 0x10,
                'size': 8
            },
            'TEST_IO_REG': {
                'type': 'io',
                'port': 0x80,
                'size': 1
            },
            'TEST_MSR_REG': {
                'type': 'msr',
                'msr': 0x1B,
                'size': 8
            }
        }

        cs_mock.Cfg.MMIO_BARS = {
            'TEST_MMIO_BAR': {
                'register': 'TEST_REG',
                'base_field': 'BASE',
                'size': 0x1000,
                'fixed_address': 0xFED00000
            },
            'TEST_MMIO_BAR2': {
                'bus': 0x00,
                'dev': 0x1F,
                'fun': 0x00,
                'mask': 0xFFFFF000,
                'width': 32,
                'size': 0x1000
            }
        }

        cs_mock.Cfg.IO_BARS = {
            'TEST_IO_BAR': {
                'register': 'TEST_IO_REG',
                'base_field': 'IOBASE',
                'size': 0x100,
                'fixed_address': 0x1000
            }
        }

        cs_mock.Cfg.MEMORY_RANGES = {
            'TEST_MEM_RANGE': {
                'access': 'read-write',
                'address': 0x100000,
                'size': 0x1000
            }
        }

        cs_mock.Cfg.CONTROLS = {
            'TEST_CONTROL': {
                'register': 'TEST_REG',
                'field': 'TEST_FIELD'
            }
        }

        cs_mock.Cfg.LOCKS = {
            'TEST_LOCK': {
                'register': 'TEST_REG',
                'field': 'LOCK_FIELD',
                'value': 0x1
            }
        }

        cs_mock.Cfg.BUS = {
            'TEST_BUS': '0x00'
        }

        return cs_mock

    @pytest.fixture
    def config_command(self, mock_cs):
        """Create CONFIGCommand instance."""
        return CONFIGCommand(['show', 'ALL'], cs=mock_cs)

    @pytest.mark.unit
    def test_config_command_initialization(self, config_command, mock_cs):
        """Test CONFIGCommand initialization."""
        assert config_command.cs == mock_cs
        assert config_command.argv == ['show', 'ALL']

    @pytest.mark.unit
    def test_parse_arguments_show_all(self, mock_cs):
        """Test parsing show command with ALL argument."""
        command = CONFIGCommand(['show', 'ALL'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.show
        assert command.config == 'ALL'
        assert command.name == []

    @pytest.mark.unit
    def test_parse_arguments_show_specific(self, mock_cs):
        """Test parsing show command with specific config type."""
        command = CONFIGCommand(['show', 'REGISTERS', 'TEST_PCICFG_REG'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.show
        assert command.config == 'REGISTERS'
        assert command.name == ['TEST_PCICFG_REG']

    @pytest.mark.unit
    def test_parse_arguments_show_multiple_names(self, mock_cs):
        """Test parsing show command with multiple names."""
        command = CONFIGCommand(['show', 'CONFIG_PCI', 'TEST_DEVICE', 'TEST_COMPONENT'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.show
        assert command.config == 'CONFIG_PCI'
        assert command.name == ['TEST_DEVICE', 'TEST_COMPONENT']

    @pytest.mark.unit
    def test_requirements(self, config_command):
        """Test command requirements."""
        reqs = config_command.requirements()
        assert hasattr(reqs, 'load_config')
        assert hasattr(reqs, 'load_driver')

    @pytest.mark.unit
    def test_show_all_config(self, config_command, mock_cs):
        """Test show method with ALL config."""
        config_command.config = 'ALL'
        config_command.name = []

        with patch.object(config_command.logger, 'log') as mock_log:
            config_command.show()

            # Should log all config categories
            expected_calls = [
                'CONFIG_PCI',
                'REGISTERS',
                'MMIO_BARS',
                'IO_BARS',
                'MEMORY_RANGES',
                'CONTROLS',
                'BUS',
                'LOCKS'
            ]

            for expected in expected_calls:
                mock_log.assert_any_call(expected)

    @pytest.mark.unit
    def test_show_specific_config(self, config_command, mock_cs):
        """Test show method with specific config type."""
        config_command.config = 'REGISTERS'
        config_command.name = ['TEST_PCICFG_REG']

        with patch.object(config_command.logger, 'log') as mock_log:
            config_command.show()

            mock_log.assert_any_call('REGISTERS')
            # Should call register_details for the specific register
            mock_log.assert_any_call('\tTEST_PCICFG_REG - bus: 0, dev: 31, func: 0, offset: 0, size: 4\n\t\tTEST_FIELD - bit 0:7')

    @pytest.mark.unit
    def test_show_config_with_multiple_names(self, config_command, mock_cs):
        """Test show method with multiple specific names."""
        config_command.config = 'CONFIG_PCI'
        config_command.name = ['TEST_DEVICE', 'TEST_COMPONENT']

        with patch.object(config_command.logger, 'log') as mock_log:
            config_command.show()

            mock_log.assert_any_call('CONFIG_PCI')
            # Should show both devices
            mock_log.assert_any_call('\tTEST_DEVICE - bus: 0, dev: 31, func: 0, vid: 32902, did: 4660')
            mock_log.assert_any_call('\tTEST_COMPONENT - Component: TEST_COMP, Config: TEST_CFG')

    @pytest.mark.unit
    def test_register_details_pcicfg(self, config_command, mock_cs):
        """Test register_details method for pcicfg type."""
        regi = mock_cs.Cfg.REGISTERS['TEST_PCICFG_REG']
        result = config_command.register_details(regi)

        assert 'bus: 0' in result
        assert 'dev: 31' in result
        assert 'func: 0' in result
        assert 'offset: 0' in result
        assert 'size: 4' in result
        assert 'TEST_FIELD - bit 0:7' in result

    @pytest.mark.unit
    def test_register_details_mmio(self, config_command, mock_cs):
        """Test register_details method for mmio type."""
        regi = mock_cs.Cfg.REGISTERS['TEST_MMIO_REG']
        result = config_command.register_details(regi)

        assert 'bar: TEST_BAR' in result
        assert 'offset: 16' in result
        assert 'size: 8' in result

    @pytest.mark.unit
    def test_register_details_io(self, config_command, mock_cs):
        """Test register_details method for io type."""
        regi = mock_cs.Cfg.REGISTERS['TEST_IO_REG']
        result = config_command.register_details(regi)

        assert 'port: 128' in result
        assert 'size: 1' in result

    @pytest.mark.unit
    def test_register_details_msr(self, config_command, mock_cs):
        """Test register_details method for msr type."""
        regi = mock_cs.Cfg.REGISTERS['TEST_MSR_REG']
        result = config_command.register_details(regi)

        assert 'msr: 27' in result
        assert 'size: 8' in result

    @pytest.mark.unit
    def test_register_details_pcicfg_device_format(self, config_command, mock_cs):
        """Test register_details method for pcicfg with device format."""
        regi = {
            'type': 'pcicfg',
            'device': 'TEST_DEVICE',
            'offset': 0x10,
            'size': 2
        }
        result = config_command.register_details(regi)

        assert 'device: TEST_DEVICE' in result
        assert 'offset: 16' in result
        assert 'size: 2' in result

    @pytest.mark.unit
    def test_register_details_mm_msgbus(self, config_command, mock_cs):
        """Test register_details method for mm_msgbus type."""
        regi = {
            'type': 'mm_msgbus',
            'port': 0x1234,
            'offset': 0x20,
            'size': 4
        }
        result = config_command.register_details(regi)

        assert 'port: 4660' in result
        assert 'offset: 32' in result
        assert 'size: 4' in result

    @pytest.mark.unit
    def test_register_details_iobar(self, config_command, mock_cs):
        """Test register_details method for iobar type."""
        regi = {
            'type': 'iobar',
            'bar': 'TEST_IO_BAR',
            'offset': 0x4,
            'size': 4
        }
        result = config_command.register_details(regi)

        assert 'bar: TEST_IO_BAR' in result
        assert 'offset: 4' in result
        assert 'size: 4' in result

    @pytest.mark.unit
    def test_register_details_memory(self, config_command, mock_cs):
        """Test register_details method for memory type."""
        regi = {
            'type': 'memory',
            'access': 'read-write',
            'address': 0x100000,
            'offset': 0x0,
            'size': 0x1000
        }
        result = config_command.register_details(regi)

        assert 'access: read-write' in result
        assert 'address: 1048576' in result
        assert 'offset: 0' in result
        assert 'size: 4096' in result

    @pytest.mark.unit
    def test_register_details_r_byte(self, config_command, mock_cs):
        """Test register_details method for R Byte type."""
        regi = {
            'type': 'R Byte',
            'offset': 0x10,
            'size': 1
        }
        result = config_command.register_details(regi)

        assert 'offset: 16' in result
        assert 'size: 1' in result

    @pytest.mark.unit
    def test_register_details_no_fields(self, config_command, mock_cs):
        """Test register_details method with no FIELDS."""
        regi = {
            'type': 'pcicfg',
            'bus': 0x00,
            'dev': 0x1F,
            'fun': 0x00,
            'offset': 0x00,
            'size': 4
        }
        result = config_command.register_details(regi)

        assert 'bus: 0' in result
        assert 'dev: 31' in result
        assert 'func: 0' in result
        assert 'offset: 0' in result
        assert 'size: 4' in result
        assert 'FIELDS' not in result

    @pytest.mark.unit
    def test_pci_details_with_bus(self, config_command, mock_cs):
        """Test pci_details method with bus information."""
        regi = mock_cs.Cfg.CONFIG_PCI['TEST_DEVICE']
        result = config_command.pci_details(regi)

        assert 'bus: 0' in result
        assert 'dev: 31' in result
        assert 'func: 0' in result
        assert 'vid: 32902' in result
        assert 'did: 4660' in result

    @pytest.mark.unit
    def test_pci_details_with_component(self, config_command, mock_cs):
        """Test pci_details method with component information."""
        regi = mock_cs.Cfg.CONFIG_PCI['TEST_COMPONENT']
        result = config_command.pci_details(regi)

        assert 'Component: TEST_COMP' in result
        assert 'Config: TEST_CFG' in result

    @pytest.mark.unit
    def test_pci_details_no_did(self, config_command, mock_cs):
        """Test pci_details method without DID."""
        regi = {
            'bus': 0x00,
            'dev': 0x1F,
            'fun': 0x00,
            'vid': 0x8086
        }
        result = config_command.pci_details(regi)

        assert 'bus: 0' in result
        assert 'dev: 31' in result
        assert 'func: 0' in result
        assert 'vid: 32902' in result
        assert 'did: None' in result

    @pytest.mark.unit
    def test_mmio_details_with_register(self, config_command, mock_cs):
        """Test mmio_details method with register information."""
        regi = mock_cs.Cfg.MMIO_BARS['TEST_MMIO_BAR']
        result = config_command.mmio_details(regi)

        assert 'register: TEST_REG' in result
        assert 'base_field: BASE' in result
        assert 'size: 4096' in result
        assert 'fixed_address: 4273995776' in result

    @pytest.mark.unit
    def test_mmio_details_with_bus(self, config_command, mock_cs):
        """Test mmio_details method with bus information."""
        regi = mock_cs.Cfg.MMIO_BARS['TEST_MMIO_BAR2']
        result = config_command.mmio_details(regi)

        assert 'bus: 0' in result
        assert 'dev: 31' in result
        assert 'func: 0' in result
        assert 'mask: 4294963200' in result
        assert 'width: 32' in result
        assert 'size: 4096' in result

    @pytest.mark.unit
    def test_mmio_details_no_size(self, config_command, mock_cs):
        """Test mmio_details method without size."""
        regi = {
            'register': 'TEST_REG',
            'base_field': 'BASE',
            'fixed_address': 0xFED00000
        }
        result = config_command.mmio_details(regi)

        assert 'register: TEST_REG' in result
        assert 'base_field: BASE' in result
        assert 'size: None' in result
        assert 'fixed_address: 4273995776' in result

    @pytest.mark.unit
    def test_io_details_with_register(self, config_command, mock_cs):
        """Test io_details method with register information."""
        regi = mock_cs.Cfg.IO_BARS['TEST_IO_BAR']
        result = config_command.io_details(regi)

        assert 'register: TEST_IO_REG' in result
        assert 'base_field: IOBASE' in result
        assert 'size: 256' in result
        assert 'fixed_address: 4096' in result

    @pytest.mark.unit
    def test_io_details_with_bus(self, config_command, mock_cs):
        """Test io_details method with bus information."""
        regi = {
            'bus': 0x00,
            'dev': 0x1F,
            'fun': 0x00,
            'reg': 0x10,
            'mask': 0xFF00,
            'size': 0x100
        }
        result = config_command.io_details(regi)

        assert 'bus: 0' in result
        assert 'dev: 31' in result
        assert 'func: 0' in result
        assert 'reg: 16' in result
        assert 'mask: 65280' in result
        assert 'size: 256' in result

    @pytest.mark.unit
    def test_mem_details(self, config_command, mock_cs):
        """Test mem_details method."""
        regi = mock_cs.Cfg.MEMORY_RANGES['TEST_MEM_RANGE']
        result = config_command.mem_details(regi)

        assert 'access: read-write' in result
        assert 'address: 1048576' in result
        assert 'size: 4096' in result

    @pytest.mark.unit
    def test_control_details(self, config_command, mock_cs):
        """Test control_details method."""
        regi = mock_cs.Cfg.CONTROLS['TEST_CONTROL']
        result = config_command.control_details(regi)

        assert 'register: TEST_REG' in result
        assert 'field: TEST_FIELD' in result

    @pytest.mark.unit
    def test_lock_details(self, config_command, mock_cs):
        """Test lock_details method."""
        regi = mock_cs.Cfg.LOCKS['TEST_LOCK']
        result = config_command.lock_details(regi)

        assert 'register: TEST_REG' in result
        assert 'field: LOCK_FIELD' in result
        assert 'value: 1' in result

    @pytest.mark.unit
    def test_bus_details(self, config_command, mock_cs):
        """Test bus_details method."""
        regi = mock_cs.Cfg.BUS['TEST_BUS']
        result = config_command.bus_details(regi)

        assert 'bus: 0x00' in result


class TestCONFIGCommandIntegration:
    """Integration tests for CONFIG command with configuration data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for CONFIG testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock comprehensive configuration data
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.CONFIG_PCI = {
            'LPC': {'bus': 0x00, 'dev': 0x1F, 'fun': 0x00, 'vid': 0x8086, 'did': 0x1234},
            'VGA': {'bus': 0x00, 'dev': 0x02, 'fun': 0x00, 'vid': 0x10DE, 'did': 0xABCD}
        }

        cs_mock.Cfg.REGISTERS = {
            'BC': {
                'type': 'pcicfg',
                'bus': 0x00,
                'dev': 0x1F,
                'fun': 0x00,
                'offset': 0xDC,
                'size': 1,
                'FIELDS': {
                    'BIOSWE': {'bit': 0, 'size': 1},
                    'BLE': {'bit': 1, 'size': 1}
                }
            }
        }

        cs_mock.Cfg.MMIO_BARS = {
            'SPIBAR': {
                'bus': 0x00,
                'dev': 0x1F,
                'fun': 0x05,
                'mask': 0xFFFFF000,
                'width': 32,
                'size': 0x1000
            }
        }

        cs_mock.Cfg.CONTROLS = {
            'BiosWriteEnable': {'register': 'BC', 'field': 'BIOSWE'},
            'BiosLockEnable': {'register': 'BC', 'field': 'BLE'}
        }

        # Mock helper
        cs_mock.helper = Mock()
        cs_mock.helper.get_threads_count.return_value = 2

        return cs_mock

    @pytest.mark.integration
    def test_config_show_all_workflow(self, integrated_cs):
        """Test complete config show ALL workflow."""
        config_cmd = CONFIGCommand(['show', 'ALL'], cs=integrated_cs)
        config_cmd.parse_arguments()

        with patch.object(config_cmd.logger, 'log') as mock_log:
            config_cmd.run()

            # Should show all configuration categories
            expected_categories = ['CONFIG_PCI', 'REGISTERS', 'MMIO_BARS', 'IO_BARS', 'MEMORY_RANGES', 'CONTROLS', 'BUS', 'LOCKS']
            for category in expected_categories:
                mock_log.assert_any_call(category)

    @pytest.mark.integration
    def test_config_show_registers_workflow(self, integrated_cs):
        """Test config show REGISTERS workflow."""
        config_cmd = CONFIGCommand(['show', 'REGISTERS'], cs=integrated_cs)
        config_cmd.parse_arguments()

        with patch.object(config_cmd.logger, 'log') as mock_log:
            config_cmd.run()

            mock_log.assert_any_call('REGISTERS')
            # Should show register details with fields
            mock_log.assert_any_call('\tBC - bus: 0, dev: 31, func: 0, offset: 220, size: 1\n\t\tBIOSWE - bit 0:0\n\t\tBLE - bit 1:1')

    @pytest.mark.integration
    def test_config_show_pci_workflow(self, integrated_cs):
        """Test config show CONFIG_PCI workflow."""
        config_cmd = CONFIGCommand(['show', 'CONFIG_PCI'], cs=integrated_cs)
        config_cmd.parse_arguments()

        with patch.object(config_cmd.logger, 'log') as mock_log:
            config_cmd.run()

            mock_log.assert_any_call('CONFIG_PCI')
            # Should show PCI device details
            mock_log.assert_any_call('\tLPC - bus: 0, dev: 31, func: 0, vid: 32902, did: 4660')
            mock_log.assert_any_call('\tVGA - bus: 0, dev: 2, func: 0, vid: 4319, did: 43981')

    @pytest.mark.integration
    def test_config_show_mmio_workflow(self, integrated_cs):
        """Test config show MMIO_BARS workflow."""
        config_cmd = CONFIGCommand(['show', 'MMIO_BARS'], cs=integrated_cs)
        config_cmd.parse_arguments()

        with patch.object(config_cmd.logger, 'log') as mock_log:
            config_cmd.run()

            mock_log.assert_any_call('MMIO_BARS')
            # Should show MMIO BAR details
            mock_log.assert_any_call('\tSPIBAR - bus: 0, dev: 31, func: 5, mask: 4294963200, width: 32, size: 4096, fixed_address: None')

    @pytest.mark.integration
    def test_config_show_controls_workflow(self, integrated_cs):
        """Test config show CONTROLS workflow."""
        config_cmd = CONFIGCommand(['show', 'CONTROLS'], cs=integrated_cs)
        config_cmd.parse_arguments()

        with patch.object(config_cmd.logger, 'log') as mock_log:
            config_cmd.run()

            mock_log.assert_any_call('CONTROLS')
            # Should show control details
            mock_log.assert_any_call('\tBiosWriteEnable - register: BC, field: BIOSWE')
            mock_log.assert_any_call('\tBiosLockEnable - register: BC, field: BLE')


class TestCONFIGCommandEdgeCases:
    """Test edge cases and error conditions for CONFIG command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.CONFIG_PCI = {}
        cs_mock.Cfg.REGISTERS = {}
        cs_mock.Cfg.MMIO_BARS = {}
        cs_mock.Cfg.IO_BARS = {}
        cs_mock.Cfg.MEMORY_RANGES = {}
        cs_mock.Cfg.CONTROLS = {}
        cs_mock.Cfg.LOCKS = {}
        cs_mock.Cfg.BUS = {}
        return cs_mock

    @pytest.fixture
    def config_command(self, mock_cs):
        """Create CONFIGCommand instance for edge case testing."""
        return CONFIGCommand(['show', 'ALL'], cs=mock_cs)

    @pytest.mark.unit
    def test_empty_argv_handling(self, mock_cs):
        """Test handling of empty argv."""
        config_cmd = CONFIGCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            config_cmd.parse_arguments()

    @pytest.mark.unit
    def test_invalid_subcommand(self, mock_cs):
        """Test handling of invalid subcommand."""
        config_cmd = CONFIGCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            config_cmd.parse_arguments()

    @pytest.mark.unit
    def test_show_missing_config_type(self, mock_cs):
        """Test show command with missing config type."""
        config_cmd = CONFIGCommand(['show'], cs=mock_cs)

        # Should raise SystemExit due to missing required arguments
        with pytest.raises(SystemExit):
            config_cmd.parse_arguments()

    @pytest.mark.unit
    def test_show_empty_config(self, config_command, mock_cs):
        """Test show method with empty configuration."""
        config_command.config = 'CONFIG_PCI'
        config_command.name = []

        with patch.object(config_command.logger, 'log') as mock_log:
            config_command.show()

            mock_log.assert_any_call('CONFIG_PCI')
            # Should not log any specific items since config is empty

    @pytest.mark.unit
    def test_show_nonexistent_config_type(self, config_command, mock_cs):
        """Test show method with nonexistent config type."""
        config_command.config = 'NONEXISTENT'
        config_command.name = []

        with patch.object(config_command.logger, 'log') as mock_log:
            config_command.show()

            mock_log.assert_any_call('NONEXISTENT')
            # Should not log any specific items since config type doesn't exist

    @pytest.mark.unit
    def test_show_specific_nonexistent_name(self, config_command, mock_cs):
        """Test show method with specific nonexistent name."""
        config_command.config = 'CONFIG_PCI'
        config_command.name = ['NONEXISTENT_DEVICE']

        with patch.object(config_command.logger, 'log') as mock_log:
            config_command.show()

            mock_log.assert_any_call('CONFIG_PCI')
            # Should not log the nonexistent device

    @pytest.mark.unit
    def test_register_details_unknown_type(self, config_command, mock_cs):
        """Test register_details method with unknown type."""
        regi = {
            'type': 'unknown_type',
            'offset': 0x10,
            'size': 4
        }
        result = config_command.register_details(regi)

        # Should return empty string for unknown type
        assert result == ''

    @pytest.mark.unit
    def test_register_details_mmcfg_type(self, config_command, mock_cs):
        """Test register_details method for mmcfg type."""
        regi = {
            'type': 'mmcfg',
            'bus': 0x00,
            'dev': 0x1F,
            'fun': 0x00,
            'offset': 0x10,
            'size': 4
        }
        result = config_command.register_details(regi)

        assert 'bus: 0' in result
        assert 'dev: 31' in result
        assert 'func: 0' in result
        assert 'offset: 16' in result
        assert 'size: 4' in result

    @pytest.mark.unit
    def test_register_details_mmcfg_device_format(self, config_command, mock_cs):
        """Test register_details method for mmcfg with device format."""
        regi = {
            'type': 'mmcfg',
            'device': 'TEST_DEVICE',
            'offset': 0x20,
            'size': 8
        }
        result = config_command.register_details(regi)

        assert 'device: TEST_DEVICE' in result
        assert 'offset: 32' in result
        assert 'size: 8' in result

    @pytest.mark.unit
    def test_pci_details_minimal_info(self, config_command, mock_cs):
        """Test pci_details method with minimal information."""
        regi = {
            'bus': 0x00,
            'dev': 0x00,
            'fun': 0x00,
            'vid': 0x8086
        }
        result = config_command.pci_details(regi)

        assert 'bus: 0' in result
        assert 'dev: 0' in result
        assert 'func: 0' in result
        assert 'vid: 32902' in result
        assert 'did: None' in result

    @pytest.mark.unit
    def test_mmio_details_minimal_info(self, config_command, mock_cs):
        """Test mmio_details method with minimal information."""
        regi = {
            'bus': 0x00,
            'dev': 0x00,
            'fun': 0x00,
            'mask': 0xFFFFF000,
            'width': 32
        }
        result = config_command.mmio_details(regi)

        assert 'bus: 0' in result
        assert 'dev: 0' in result
        assert 'func: 0' in result
        assert 'mask: 4294963200' in result
        assert 'width: 32' in result
        assert 'size: None' in result
        assert 'fixed_address: None' in result

    @pytest.mark.unit
    def test_io_details_minimal_info(self, config_command, mock_cs):
        """Test io_details method with minimal information."""
        regi = {
            'bus': 0x00,
            'dev': 0x00,
            'fun': 0x00,
            'reg': 0x10,
            'mask': 0xFF00
        }
        result = config_command.io_details(regi)

        assert 'bus: 0' in result
        assert 'dev: 0' in result
        assert 'func: 0' in result
        assert 'reg: 16' in result
        assert 'mask: 65280' in result
        assert 'size: None' in result
        assert 'fixed_address: None' in result

    @pytest.mark.unit
    def test_config_show_multiple_categories(self, config_command, mock_cs):
        """Test show method processes multiple categories correctly."""
        config_command.config = 'ALL'
        config_command.name = []

        # Add some test data
        mock_cs.Cfg.CONFIG_PCI = {'TEST': {'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'vid': 0x8086}}
        mock_cs.Cfg.REGISTERS = {'TEST_REG': {'type': 'pcicfg', 'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'offset': 0x00, 'size': 4}}

        with patch.object(config_command.logger, 'log') as mock_log:
            config_command.show()

            # Should process all categories
            mock_log.assert_any_call('CONFIG_PCI')
            mock_log.assert_any_call('REGISTERS')
            mock_log.assert_any_call('\tTEST - bus: 0, dev: 0, func: 0, vid: 32902, did: None')
            mock_log.assert_any_call('\tTEST_REG - bus: 0, dev: 0, func: 0, offset: 0, size: 4')


class TestCONFIGCommandConfigurationValidation:
    """Test configuration validation aspects of CONFIG command."""

    @pytest.fixture
    def config_cs(self):
        """Create ChipsecCs with comprehensive configuration for validation."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock configuration with various data types
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.CONFIG_PCI = {
            'HOST_BRIDGE': {'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'vid': 0x8086, 'did': 0x1234},
            'LPC_BRIDGE': {'bus': 0x00, 'dev': 0x1F, 'fun': 0x00, 'vid': 0x8086, 'did': 0x5678},
            'VGA_CONTROLLER': {'bus': 0x01, 'dev': 0x00, 'fun': 0x00, 'vid': 0x10DE, 'did': 0xABCD}
        }

        cs_mock.Cfg.REGISTERS = {
            'VID': {'type': 'pcicfg', 'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'offset': 0x00, 'size': 2},
            'DID': {'type': 'pcicfg', 'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'offset': 0x02, 'size': 2},
            'CMD': {'type': 'pcicfg', 'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'offset': 0x04, 'size': 2},
            'STS': {'type': 'pcicfg', 'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'offset': 0x06, 'size': 2},
            'BC': {'type': 'pcicfg', 'bus': 0x00, 'dev': 0x1F, 'fun': 0x00, 'offset': 0xDC, 'size': 1}
        }

        cs_mock.Cfg.MMIO_BARS = {
            'MCHBAR': {'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'mask': 0xFFFFC000, 'width': 32, 'size': 0x4000},
            'DMIBAR': {'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'mask': 0xFFFFC000, 'width': 32, 'size': 0x4000},
            'EPBAR': {'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'mask': 0xFFFFC000, 'width': 32, 'size': 0x4000}
        }

        cs_mock.Cfg.CONTROLS = {
            'BiosWriteEnable': {'register': 'BC', 'field': 'BIOSWE'},
            'BiosLockEnable': {'register': 'BC', 'field': 'BLE'},
            'SpiBiosLockEnable': {'register': 'HSFC', 'field': 'FLOCKDN'}
        }

        return cs_mock

    @pytest.mark.unit
    def test_configuration_completeness(self, config_cs):
        """Test that configuration has all expected categories."""
        cfg = config_cs.Cfg

        # Test that all major configuration categories exist
        assert hasattr(cfg, 'CONFIG_PCI')
        assert hasattr(cfg, 'REGISTERS')
        assert hasattr(cfg, 'MMIO_BARS')
        assert hasattr(cfg, 'IO_BARS')
        assert hasattr(cfg, 'MEMORY_RANGES')
        assert hasattr(cfg, 'CONTROLS')
        assert hasattr(cfg, 'LOCKS')
        assert hasattr(cfg, 'BUS')

    @pytest.mark.unit
    def test_pci_configuration_structure(self, config_cs):
        """Test PCI configuration structure and content."""
        pci_config = config_cs.Cfg.CONFIG_PCI

        # Test that all devices have required fields
        for device_name, device_info in pci_config.items():
            assert 'bus' in device_info
            assert 'dev' in device_info
            assert 'fun' in device_info
            assert 'vid' in device_info

            # Test field value ranges
            assert 0 <= device_info['bus'] <= 0xFF
            assert 0 <= device_info['dev'] <= 0x1F
            assert 0 <= device_info['fun'] <= 0x7
            assert 0 <= device_info['vid'] <= 0xFFFF

            if 'did' in device_info:
                assert 0 <= device_info['did'] <= 0xFFFF

    @pytest.mark.unit
    def test_register_configuration_structure(self, config_cs):
        """Test register configuration structure and content."""
        registers = config_cs.Cfg.REGISTERS

        # Test that all registers have required fields
        for reg_name, reg_info in registers.items():
            assert 'type' in reg_info
            assert 'size' in reg_info

            # Test size is reasonable
            assert reg_info['size'] > 0
            assert reg_info['size'] <= 8  # Maximum reasonable register size

            # Test type-specific fields
            if reg_info['type'] in ['pcicfg', 'mmcfg']:
                if 'device' in reg_info:
                    assert 'offset' in reg_info
                else:
                    assert 'bus' in reg_info
                    assert 'dev' in reg_info
                    assert 'fun' in reg_info
                    assert 'offset' in reg_info

            elif reg_info['type'] == 'mmio':
                assert 'bar' in reg_info
                assert 'offset' in reg_info

            elif reg_info['type'] == 'io':
                assert 'port' in reg_info

            elif reg_info['type'] == 'msr':
                assert 'msr' in reg_info

    @pytest.mark.unit
    def test_mmio_bar_configuration_structure(self, config_cs):
        """Test MMIO BAR configuration structure and content."""
        mmio_bars = config_cs.Cfg.MMIO_BARS

        # Test that all MMIO BARs have required fields
        for bar_name, bar_info in mmio_bars.items():
            if 'register' in bar_info:
                assert 'base_field' in bar_info
            else:
                assert 'bus' in bar_info
                assert 'dev' in bar_info
                assert 'fun' in bar_info
                assert 'mask' in bar_info
                assert 'width' in bar_info

            # Test that size is reasonable if present
            if 'size' in bar_info:
                assert bar_info['size'] > 0
                assert bar_info['size'] <= 0x10000000  # Maximum reasonable BAR size (256MB)

    @pytest.mark.unit
    def test_control_configuration_structure(self, config_cs):
        """Test control configuration structure and content."""
        controls = config_cs.Cfg.CONTROLS

        # Test that all controls have required fields
        for control_name, control_info in controls.items():
            assert 'register' in control_info
            assert 'field' in control_info

            # Test that register and field are non-empty strings
            assert len(control_info['register']) > 0
            assert len(control_info['field']) > 0

    @pytest.mark.unit
    def test_configuration_cross_references(self, config_cs):
        """Test that configuration has valid cross-references."""
        registers = config_cs.Cfg.REGISTERS
        controls = config_cs.Cfg.CONTROLS

        # Test that controls reference valid registers
        for control_name, control_info in controls.items():
            reg_name = control_info['register']
            assert reg_name in registers, f"Control '{control_name}' references non-existent register '{reg_name}'"

            # Test that register has FIELDS if control references a field
            field_name = control_info['field']
            reg_info = registers[reg_name]
            if 'FIELDS' in reg_info:
                assert field_name in reg_info['FIELDS'], f"Control '{control_name}' references non-existent field '{field_name}' in register '{reg_name}'"


if __name__ == '__main__':
    pytest.main([__file__])
