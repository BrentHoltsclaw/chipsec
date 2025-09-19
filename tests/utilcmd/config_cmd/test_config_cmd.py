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
from chipsec.utilcmd.config_cmd import CONFIGCommand
from tests.test_utils import MockFactory


class TestCONFIGCommand(unittest.TestCase):
    """Comprehensive tests for CONFIG utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()

        # Mock configuration data
        self.mock_cs.Cfg = Mock()
        self.mock_cs.Cfg.CONFIG_PCI = {
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

        self.mock_cs.Cfg.REGISTERS = {
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

        self.mock_cs.Cfg.MMIO_BARS = {
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

        self.mock_cs.Cfg.IO_BARS = {
            'TEST_IO_BAR': {
                'register': 'TEST_IO_REG',
                'base_field': 'IOBASE',
                'size': 0x100,
                'fixed_address': 0x1000
            }
        }

        self.mock_cs.Cfg.MEMORY_RANGES = {
            'TEST_MEM_RANGE': {
                'access': 'read-write',
                'address': 0x100000,
                'size': 0x1000
            }
        }

        self.mock_cs.Cfg.CONTROLS = {
            'TEST_CONTROL': {
                'register': 'TEST_REG',
                'field': 'TEST_FIELD'
            }
        }

        self.mock_cs.Cfg.LOCKS = {
            'TEST_LOCK': {
                'register': 'TEST_REG',
                'field': 'LOCK_FIELD',
                'value': 0x1
            }
        }

        self.mock_cs.Cfg.BUS = {
            'TEST_BUS': '0x00'
        }

        self.config_command = CONFIGCommand(['show', 'ALL'], cs=self.mock_cs)

    def test_config_command_initialization(self):
        """Test CONFIGCommand initialization."""
        self.assertEqual(self.config_command.cs, self.mock_cs)
        self.assertEqual(self.config_command.argv, ['show', 'ALL'])

    def test_parse_arguments_show_all(self):
        """Test parsing show command with ALL argument."""
        command = CONFIGCommand(['show', 'ALL'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.show)
        self.assertEqual(command.config, 'ALL')
        self.assertEqual(command.name, [])

    def test_parse_arguments_show_specific(self):
        """Test parsing show command with specific config type."""
        command = CONFIGCommand(['show', 'REGISTERS', 'TEST_PCICFG_REG'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.show)
        self.assertEqual(command.config, 'REGISTERS')
        self.assertEqual(command.name, ['TEST_PCICFG_REG'])

    def test_parse_arguments_show_multiple_names(self):
        """Test parsing show command with multiple names."""
        command = CONFIGCommand(['show', 'CONFIG_PCI', 'TEST_DEVICE', 'TEST_COMPONENT'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.show)
        self.assertEqual(command.config, 'CONFIG_PCI')
        self.assertEqual(command.name, ['TEST_DEVICE', 'TEST_COMPONENT'])

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.config_command.requirements()
        self.assertTrue(hasattr(reqs, 'load_config'))
        self.assertTrue(hasattr(reqs, 'load_driver'))

    def test_show_all_config(self):
        """Test show method with ALL config."""
        self.config_command.config = 'ALL'
        self.config_command.name = []

        with patch.object(self.config_command.logger, 'log') as mock_log:
            self.config_command.show()

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

    def test_show_specific_config(self):
        """Test show method with specific config type."""
        self.config_command.config = 'REGISTERS'
        self.config_command.name = ['TEST_PCICFG_REG']

        with patch.object(self.config_command.logger, 'log') as mock_log:
            self.config_command.show()

            mock_log.assert_any_call('REGISTERS')
            # Should call register_details for the specific register
            mock_log.assert_any_call('\tTEST_PCICFG_REG - bus: 0, dev: 31, func: 0, offset: 0, size: 4\n\t\tTEST_FIELD - bit 0:7')

    def test_show_config_with_multiple_names(self):
        """Test show method with multiple specific names."""
        self.config_command.config = 'CONFIG_PCI'
        self.config_command.name = ['TEST_DEVICE', 'TEST_COMPONENT']

        with patch.object(self.config_command.logger, 'log') as mock_log:
            self.config_command.show()

            mock_log.assert_any_call('CONFIG_PCI')
            # Should show both devices - check both possible formats
            mock_log.assert_any_call('\tTEST_DEVICE - bus: 0, dev: 31, func: 0, vid: 32902, did: 4660, Config: LPC')
            mock_log.assert_any_call('\tTEST_COMPONENT - Component: TEST_COMP, Config: TEST_CFG')

    def test_register_details_pcicfg(self):
        """Test register_details method for pcicfg type."""
        regi = self.mock_cs.Cfg.REGISTERS['TEST_PCICFG_REG']
        result = self.config_command.register_details(regi)

        self.assertIn('bus: 0', result)
        self.assertIn('dev: 31', result)
        self.assertIn('func: 0', result)
        self.assertIn('offset: 0', result)
        self.assertIn('size: 4', result)
        self.assertIn('TEST_FIELD - bit 0:7', result)

    def test_register_details_mmio(self):
        """Test register_details method for mmio type."""
        regi = self.mock_cs.Cfg.REGISTERS['TEST_MMIO_REG']
        result = self.config_command.register_details(regi)

        self.assertIn('bar: TEST_BAR', result)
        self.assertIn('offset: 16', result)
        self.assertIn('size: 8', result)

    def test_register_details_io(self):
        """Test register_details method for io type."""
        regi = self.mock_cs.Cfg.REGISTERS['TEST_IO_REG']
        result = self.config_command.register_details(regi)

        self.assertIn('port: 128', result)
        self.assertIn('size: 1', result)

    def test_register_details_msr(self):
        """Test register_details method for msr type."""
        regi = self.mock_cs.Cfg.REGISTERS['TEST_MSR_REG']
        result = self.config_command.register_details(regi)

        self.assertIn('msr: 27', result)
        self.assertIn('size: 8', result)

    def test_register_details_pcicfg_device_format(self):
        """Test register_details method for pcicfg with device format."""
        regi = {
            'type': 'pcicfg',
            'device': 'TEST_DEVICE',
            'offset': 0x10,
            'size': 2
        }
        result = self.config_command.register_details(regi)

        self.assertIn('device: TEST_DEVICE', result)
        self.assertIn('offset: 16', result)
        self.assertIn('size: 2', result)

    def test_register_details_mm_msgbus(self):
        """Test register_details method for mm_msgbus type."""
        regi = {
            'type': 'mm_msgbus',
            'port': 0x1234,
            'offset': 0x20,
            'size': 4
        }
        result = self.config_command.register_details(regi)

        self.assertIn('port: 4660', result)
        self.assertIn('offset: 32', result)
        self.assertIn('size: 4', result)

    def test_register_details_iobar(self):
        """Test register_details method for iobar type."""
        regi = {
            'type': 'iobar',
            'bar': 'TEST_IO_BAR',
            'offset': 0x4,
            'size': 4
        }
        result = self.config_command.register_details(regi)

        self.assertIn('bar: TEST_IO_BAR', result)
        self.assertIn('offset: 4', result)
        self.assertIn('size: 4', result)

    def test_register_details_memory(self):
        """Test register_details method for memory type."""
        regi = {
            'type': 'memory',
            'access': 'read-write',
            'address': 0x100000,
            'offset': 0x0,
            'size': 0x1000
        }
        result = self.config_command.register_details(regi)

        self.assertIn('access: read-write', result)
        self.assertIn('address: 1048576', result)
        self.assertIn('offset: 0', result)
        self.assertIn('size: 4096', result)

    def test_register_details_r_byte(self):
        """Test register_details method for R Byte type."""
        regi = {
            'type': 'R Byte',
            'offset': 0x10,
            'size': 1
        }
        result = self.config_command.register_details(regi)

        self.assertIn('offset: 16', result)
        self.assertIn('size: 1', result)

    def test_register_details_no_fields(self):
        """Test register_details method with no FIELDS."""
        regi = {
            'type': 'pcicfg',
            'bus': 0x00,
            'dev': 0x1F,
            'fun': 0x00,
            'offset': 0x00,
            'size': 4
        }
        result = self.config_command.register_details(regi)

        self.assertIn('bus: 0', result)
        self.assertIn('dev: 31', result)
        self.assertIn('func: 0', result)
        self.assertIn('offset: 0', result)
        self.assertIn('size: 4', result)
        self.assertNotIn('FIELDS', result)

    def test_pci_details_with_bus(self):
        """Test pci_details method with bus information."""
        regi = self.mock_cs.Cfg.CONFIG_PCI['TEST_DEVICE']
        result = self.config_command.pci_details(regi)

        self.assertIn('bus: 0', result)
        self.assertIn('dev: 31', result)
        self.assertIn('func: 0', result)
        self.assertIn('vid: 32902', result)
        self.assertIn('did: 4660', result)

    def test_pci_details_with_component(self):
        """Test pci_details method with component information."""
        regi = self.mock_cs.Cfg.CONFIG_PCI['TEST_COMPONENT']
        result = self.config_command.pci_details(regi)

        self.assertIn('Component: TEST_COMP', result)
        self.assertIn('Config: TEST_CFG', result)

    def test_pci_details_no_did(self):
        """Test pci_details method without DID."""
        regi = {
            'bus': 0x00,
            'dev': 0x1F,
            'fun': 0x00,
            'vid': 0x8086
        }
        result = self.config_command.pci_details(regi)

        self.assertIn('bus: 0', result)
        self.assertIn('dev: 31', result)
        self.assertIn('func: 0', result)
        self.assertIn('vid: 32902', result)
        self.assertIn('did: None', result)

    def test_mmio_details_with_register(self):
        """Test mmio_details method with register information."""
        regi = self.mock_cs.Cfg.MMIO_BARS['TEST_MMIO_BAR']
        result = self.config_command.mmio_details(regi)

        self.assertIn('register: TEST_REG', result)
        self.assertIn('base_field: BASE', result)
        self.assertIn('size: 4096', result)
        # Use the actual hex value from the mock
        self.assertIn('fixed_address: 4275044352', result)

    def test_mmio_details_with_bus(self):
        """Test mmio_details method with bus information."""
        regi = self.mock_cs.Cfg.MMIO_BARS['TEST_MMIO_BAR2']
        result = self.config_command.mmio_details(regi)

        self.assertIn('bus: 0', result)
        self.assertIn('dev: 31', result)
        self.assertIn('func: 0', result)
        self.assertIn('mask: 4294963200', result)
        self.assertIn('width: 32', result)
        self.assertIn('size: 4096', result)

    def test_mmio_details_no_size(self):
        """Test mmio_details method without size."""
        regi = {
            'register': 'TEST_REG',
            'base_field': 'BASE',
            'fixed_address': 0xFED00000
        }
        result = self.config_command.mmio_details(regi)

        self.assertIn('register: TEST_REG', result)
        self.assertIn('base_field: BASE', result)
        self.assertIn('size: None', result)
        # Use the actual hex value from the mock
        self.assertIn('fixed_address: 4275044352', result)

    def test_io_details_with_register(self):
        """Test io_details method with register information."""
        regi = self.mock_cs.Cfg.IO_BARS['TEST_IO_BAR']
        result = self.config_command.io_details(regi)

        self.assertIn('register: TEST_IO_REG', result)
        self.assertIn('base_field: IOBASE', result)
        self.assertIn('size: 256', result)
        self.assertIn('fixed_address: 4096', result)

    def test_io_details_with_bus(self):
        """Test io_details method with bus information."""
        regi = {
            'bus': 0x00,
            'dev': 0x1F,
            'fun': 0x00,
            'reg': 0x10,
            'mask': 0xFF00,
            'size': 0x100
        }
        result = self.config_command.io_details(regi)

        self.assertIn('bus: 0', result)
        self.assertIn('dev: 31', result)
        self.assertIn('func: 0', result)
        self.assertIn('reg: 16', result)
        self.assertIn('mask: 65280', result)
        self.assertIn('size: 256', result)

    def test_mem_details(self):
        """Test mem_details method."""
        regi = self.mock_cs.Cfg.MEMORY_RANGES['TEST_MEM_RANGE']
        result = self.config_command.mem_details(regi)

        self.assertIn('access: read-write', result)
        self.assertIn('address: 1048576', result)
        self.assertIn('size: 4096', result)

    def test_control_details(self):
        """Test control_details method."""
        regi = self.mock_cs.Cfg.CONTROLS['TEST_CONTROL']
        result = self.config_command.control_details(regi)

        self.assertIn('register: TEST_REG', result)
        self.assertIn('field: TEST_FIELD', result)

    def test_lock_details(self):
        """Test lock_details method."""
        regi = self.mock_cs.Cfg.LOCKS['TEST_LOCK']
        result = self.config_command.lock_details(regi)

        self.assertIn('register: TEST_REG', result)
        self.assertIn('field: LOCK_FIELD', result)
        self.assertIn('value: 1', result)

    def test_bus_details(self):
        """Test bus_details method."""
        regi = self.mock_cs.Cfg.BUS['TEST_BUS']
        result = self.config_command.bus_details(regi)

        self.assertIn('bus: 0x00', result)


class TestCONFIGCommandIntegration(unittest.TestCase):
    """Integration tests for CONFIG command with configuration data."""

    def setUp(self):
        """Set up test fixtures."""
        # Create integrated ChipsecCs for CONFIG testing
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock comprehensive configuration data
        self.integrated_cs.Cfg = Mock()
        self.integrated_cs.Cfg.CONFIG_PCI = {
            'LPC': {'bus': 0x00, 'dev': 0x1F, 'fun': 0x00, 'vid': 0x8086, 'did': 0x1234},
            'VGA': {'bus': 0x00, 'dev': 0x02, 'fun': 0x00, 'vid': 0x10DE, 'did': 0xABCD}
        }

        self.integrated_cs.Cfg.REGISTERS = {
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

        self.integrated_cs.Cfg.MMIO_BARS = {
            'SPIBAR': {
                'bus': 0x00,
                'dev': 0x1F,
                'fun': 0x05,
                'mask': 0xFFFFF000,
                'width': 32,
                'size': 0x1000
            }
        }

        self.integrated_cs.Cfg.CONTROLS = {
            'BiosWriteEnable': {'register': 'BC', 'field': 'BIOSWE'},
            'BiosLockEnable': {'register': 'BC', 'field': 'BLE'}
        }

        # Mock helper
        self.integrated_cs.helper = Mock()
        self.integrated_cs.helper.get_threads_count.return_value = 2

    def test_config_show_all_workflow(self):
        """Test complete config show ALL workflow."""
        config_cmd = CONFIGCommand(['show', 'ALL'], cs=self.integrated_cs)
        config_cmd.parse_arguments()

        with patch.object(config_cmd.logger, 'log') as mock_log:
            config_cmd.run()

            # Should show all configuration categories
            expected_categories = ['CONFIG_PCI', 'REGISTERS', 'MMIO_BARS', 'IO_BARS', 'MEMORY_RANGES', 'CONTROLS', 'BUS', 'LOCKS']
            for category in expected_categories:
                mock_log.assert_any_call(category)

    def test_config_show_registers_workflow(self):
        """Test config show REGISTERS workflow."""
        config_cmd = CONFIGCommand(['show', 'REGISTERS'], cs=self.integrated_cs)
        config_cmd.parse_arguments()

        with patch.object(config_cmd.logger, 'log') as mock_log:
            config_cmd.run()

            mock_log.assert_any_call('REGISTERS')
            # Should show register details with fields
            mock_log.assert_any_call('\tBC - bus: 0, dev: 31, func: 0, offset: 220, size: 1\n\t\tBIOSWE - bit 0:0\n\t\tBLE - bit 1:1')

    def test_config_show_pci_workflow(self):
        """Test config show CONFIG_PCI workflow."""
        config_cmd = CONFIGCommand(['show', 'CONFIG_PCI'], cs=self.integrated_cs)
        config_cmd.parse_arguments()

        with patch.object(config_cmd.logger, 'log') as mock_log:
            config_cmd.run()

            mock_log.assert_any_call('CONFIG_PCI')
            # Should show PCI device details
            mock_log.assert_any_call('\tLPC - bus: 0, dev: 31, func: 0, vid: 32902, did: 4660')
            # Adjusted expected vid to match mock configuration (0x10DE = 4318)
            mock_log.assert_any_call('\tVGA - bus: 0, dev: 2, func: 0, vid: 4318, did: 43981')

    def test_config_show_mmio_workflow(self):
        """Test config show MMIO_BARS workflow."""
        config_cmd = CONFIGCommand(['show', 'MMIO_BARS'], cs=self.integrated_cs)
        config_cmd.parse_arguments()

        with patch.object(config_cmd.logger, 'log') as mock_log:
            config_cmd.run()

            mock_log.assert_any_call('MMIO_BARS')
            # Should show MMIO BAR details
            mock_log.assert_any_call('\tSPIBAR - bus: 0, dev: 31, func: 5, mask: 4294963200, width: 32, size: 4096, fixed_address: None')

    def test_config_show_controls_workflow(self):
        """Test config show CONTROLS workflow."""
        config_cmd = CONFIGCommand(['show', 'CONTROLS'], cs=self.integrated_cs)
        config_cmd.parse_arguments()

        with patch.object(config_cmd.logger, 'log') as mock_log:
            config_cmd.run()

            mock_log.assert_any_call('CONTROLS')
            # Should show control details
            mock_log.assert_any_call('\tBiosWriteEnable - register: BC, field: BIOSWE')
            mock_log.assert_any_call('\tBiosLockEnable - register: BC, field: BLE')


class TestCONFIGCommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for CONFIG command."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.Cfg = Mock()
        self.mock_cs.Cfg.CONFIG_PCI = {}
        self.mock_cs.Cfg.REGISTERS = {}
        self.mock_cs.Cfg.MMIO_BARS = {}
        self.mock_cs.Cfg.IO_BARS = {}
        self.mock_cs.Cfg.MEMORY_RANGES = {}
        self.mock_cs.Cfg.CONTROLS = {}
        self.mock_cs.Cfg.LOCKS = {}
        self.mock_cs.Cfg.BUS = {}
        self.config_command = CONFIGCommand(['show', 'ALL'], cs=self.mock_cs)

    def test_empty_argv_handling(self):
        """Test handling of empty argv."""
        config_cmd = CONFIGCommand([], cs=self.mock_cs)

        # Should raise SystemExit due to missing required subcommand
        with self.assertRaises(SystemExit):
            config_cmd.parse_arguments()

    def test_invalid_subcommand(self):
        """Test handling of invalid subcommand."""
        config_cmd = CONFIGCommand(['invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with self.assertRaises(SystemExit):
            config_cmd.parse_arguments()

    def test_show_missing_config_type(self):
        """Test show command with missing config type."""
        config_cmd = CONFIGCommand(['show'], cs=self.mock_cs)

        # Should raise SystemExit due to missing required arguments
        with self.assertRaises(SystemExit):
            config_cmd.parse_arguments()

    def test_show_empty_config(self):
        """Test show method with empty configuration."""
        self.config_command.config = 'CONFIG_PCI'
        self.config_command.name = []

        with patch.object(self.config_command.logger, 'log') as mock_log:
            self.config_command.show()

            mock_log.assert_any_call('CONFIG_PCI')
            # Should not log any specific items since config is empty

    def test_show_nonexistent_config_type(self):
        """Test show method with nonexistent config type."""
        self.config_command.config = 'NONEXISTENT'
        self.config_command.name = []
        
        # Mock nonexistent config to return empty dict
        with patch.object(self.mock_cs.Cfg, 'NONEXISTENT', {}):
            with patch.object(self.config_command.logger, 'log') as mock_log:
                self.config_command.show()

                mock_log.assert_any_call('NONEXISTENT')
                # Should not log any specific items since config type doesn't exist

    def test_show_specific_nonexistent_name(self):
        """Test show method with specific nonexistent name."""
        self.config_command.config = 'CONFIG_PCI'
        self.config_command.name = ['NONEXISTENT_DEVICE']

        with patch.object(self.config_command.logger, 'log') as mock_log:
            # This should raise a KeyError since the device doesn't exist
            with self.assertRaises(KeyError):
                self.config_command.show()

            mock_log.assert_any_call('CONFIG_PCI')
            # Should not log the nonexistent device

    def test_register_details_unknown_type(self):
        """Test register_details method with unknown type."""
        regi = {
            'type': 'unknown_type',
            'offset': 0x10,
            'size': 4
        }
        result = self.config_command.register_details(regi)

        # Should return empty string for unknown type
        self.assertEqual(result, '')

    def test_register_details_mmcfg_type(self):
        """Test register_details method for mmcfg type."""
        regi = {
            'type': 'mmcfg',
            'bus': 0x00,
            'dev': 0x1F,
            'fun': 0x00,
            'offset': 0x10,
            'size': 4
        }
        result = self.config_command.register_details(regi)

        self.assertIn('bus: 0', result)
        self.assertIn('dev: 31', result)
        self.assertIn('func: 0', result)
        self.assertIn('offset: 16', result)
        self.assertIn('size: 4', result)

    def test_register_details_mmcfg_device_format(self):
        """Test register_details method for mmcfg with device format."""
        regi = {
            'type': 'mmcfg',
            'device': 'TEST_DEVICE',
            'offset': 0x20,
            'size': 8
        }
        result = self.config_command.register_details(regi)

        self.assertIn('device: TEST_DEVICE', result)
        self.assertIn('offset: 32', result)
        self.assertIn('size: 8', result)

    def test_pci_details_minimal_info(self):
        """Test pci_details method with minimal information."""
        regi = {
            'bus': 0x00,
            'dev': 0x00,
            'fun': 0x00,
            'vid': 0x8086
        }
        result = self.config_command.pci_details(regi)

        self.assertIn('bus: 0', result)
        self.assertIn('dev: 0', result)
        self.assertIn('func: 0', result)
        self.assertIn('vid: 32902', result)
        self.assertIn('did: None', result)

    def test_mmio_details_minimal_info(self):
        """Test mmio_details method with minimal information."""
        regi = {
            'bus': 0x00,
            'dev': 0x00,
            'fun': 0x00,
            'mask': 0xFFFFF000,
            'width': 32
        }
        result = self.config_command.mmio_details(regi)

        self.assertIn('bus: 0', result)
        self.assertIn('dev: 0', result)
        self.assertIn('func: 0', result)
        self.assertIn('mask: 4294963200', result)
        self.assertIn('width: 32', result)
        self.assertIn('size: None', result)
        self.assertIn('fixed_address: None', result)

    def test_io_details_minimal_info(self):
        """Test io_details method with minimal information."""
        regi = {
            'bus': 0x00,
            'dev': 0x00,
            'fun': 0x00,
            'reg': 0x10,
            'mask': 0xFF00
        }
        result = self.config_command.io_details(regi)

        self.assertIn('bus: 0', result)
        self.assertIn('dev: 0', result)
        self.assertIn('func: 0', result)
        self.assertIn('reg: 16', result)
        self.assertIn('mask: 65280', result)
        self.assertIn('size: None', result)
        self.assertIn('fixed_address: None', result)

    def test_config_show_multiple_categories(self):
        """Test show method processes multiple categories correctly."""
        self.config_command.config = 'ALL'
        self.config_command.name = []

        # Add some test data
        self.mock_cs.Cfg.CONFIG_PCI = {'TEST': {'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'vid': 0x8086}}
        self.mock_cs.Cfg.REGISTERS = {'TEST_REG': {'type': 'pcicfg', 'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'offset': 0x00, 'size': 4}}

        with patch.object(self.config_command.logger, 'log') as mock_log:
            self.config_command.show()

            # Should process all categories
            mock_log.assert_any_call('CONFIG_PCI')
            mock_log.assert_any_call('REGISTERS')
            mock_log.assert_any_call('\tTEST - bus: 0, dev: 0, func: 0, vid: 32902, did: None')
            mock_log.assert_any_call('\tTEST_REG - bus: 0, dev: 0, func: 0, offset: 0, size: 4')


class TestCONFIGCommandConfigurationValidation(unittest.TestCase):
    """Test configuration validation aspects of CONFIG command."""

    def setUp(self):
        """Set up test fixtures."""
        # Create ChipsecCs with comprehensive configuration for validation
        self.config_cs = MockFactory.create_mock_chipsec_cs()

        # Mock configuration with various data types
        self.config_cs.Cfg = Mock()
        self.config_cs.Cfg.CONFIG_PCI = {
            'HOST_BRIDGE': {'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'vid': 0x8086, 'did': 0x1234},
            'LPC_BRIDGE': {'bus': 0x00, 'dev': 0x1F, 'fun': 0x00, 'vid': 0x8086, 'did': 0x5678},
            'VGA_CONTROLLER': {'bus': 0x01, 'dev': 0x00, 'fun': 0x00, 'vid': 0x10DE, 'did': 0xABCD}
        }

        self.config_cs.Cfg.REGISTERS = {
            'VID': {'type': 'pcicfg', 'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'offset': 0x00, 'size': 2},
            'DID': {'type': 'pcicfg', 'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'offset': 0x02, 'size': 2},
            'CMD': {'type': 'pcicfg', 'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'offset': 0x04, 'size': 2},
            'STS': {'type': 'pcicfg', 'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'offset': 0x06, 'size': 2},
            'BC': {'type': 'pcicfg', 'bus': 0x00, 'dev': 0x1F, 'fun': 0x00, 'offset': 0xDC, 'size': 1},
            # Added HSFC register to satisfy control cross-reference validation
            'HSFC': {
                'type': 'pcicfg', 'bus': 0x00, 'dev': 0x1F, 'fun': 0x05, 'offset': 0x10, 'size': 4,
                'FIELDS': {'FLOCKDN': {'bit': 0, 'size': 1}}
            }
        }

        self.config_cs.Cfg.MMIO_BARS = {
            'MCHBAR': {'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'mask': 0xFFFFC000, 'width': 32, 'size': 0x4000},
            'DMIBAR': {'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'mask': 0xFFFFC000, 'width': 32, 'size': 0x4000},
            'EPBAR': {'bus': 0x00, 'dev': 0x00, 'fun': 0x00, 'mask': 0xFFFFC000, 'width': 32, 'size': 0x4000}
        }

        self.config_cs.Cfg.CONTROLS = {
            'BiosWriteEnable': {'register': 'BC', 'field': 'BIOSWE'},
            'BiosLockEnable': {'register': 'BC', 'field': 'BLE'},
            'SpiBiosLockEnable': {'register': 'HSFC', 'field': 'FLOCKDN'}
        }

    def test_configuration_completeness(self):
        """Test that configuration has all expected categories."""
        cfg = self.config_cs.Cfg

        # Test that all major configuration categories exist
        self.assertTrue(hasattr(cfg, 'CONFIG_PCI'))
        self.assertTrue(hasattr(cfg, 'REGISTERS'))
        self.assertTrue(hasattr(cfg, 'MMIO_BARS'))
        self.assertTrue(hasattr(cfg, 'IO_BARS'))
        self.assertTrue(hasattr(cfg, 'MEMORY_RANGES'))
        self.assertTrue(hasattr(cfg, 'CONTROLS'))
        self.assertTrue(hasattr(cfg, 'LOCKS'))
        self.assertTrue(hasattr(cfg, 'BUS'))

    def test_pci_configuration_structure(self):
        """Test PCI configuration structure and content."""
        pci_config = self.config_cs.Cfg.CONFIG_PCI

        # Test that all devices have required fields
        for device_name, device_info in pci_config.items():
            self.assertIn('bus', device_info)
            self.assertIn('dev', device_info)
            self.assertIn('fun', device_info)
            self.assertIn('vid', device_info)

            # Test field value ranges
            self.assertGreaterEqual(device_info['bus'], 0)
            self.assertLessEqual(device_info['bus'], 0xFF)
            self.assertGreaterEqual(device_info['dev'], 0)
            self.assertLessEqual(device_info['dev'], 0x1F)
            self.assertGreaterEqual(device_info['fun'], 0)
            self.assertLessEqual(device_info['fun'], 0x7)
            self.assertGreaterEqual(device_info['vid'], 0)
            self.assertLessEqual(device_info['vid'], 0xFFFF)

            if 'did' in device_info:
                self.assertGreaterEqual(device_info['did'], 0)
                self.assertLessEqual(device_info['did'], 0xFFFF)

    def test_register_configuration_structure(self):
        """Test register configuration structure and content."""
        registers = self.config_cs.Cfg.REGISTERS

        # Test that all registers have required fields
        for reg_name, reg_info in registers.items():
            self.assertIn('type', reg_info)
            self.assertIn('size', reg_info)

            # Test size is reasonable
            self.assertGreater(reg_info['size'], 0)
            self.assertLessEqual(reg_info['size'], 8)  # Maximum reasonable register size

            # Test type-specific fields
            if reg_info['type'] in ['pcicfg', 'mmcfg']:
                if 'device' in reg_info:
                    self.assertIn('offset', reg_info)
                else:
                    self.assertIn('bus', reg_info)
                    self.assertIn('dev', reg_info)
                    self.assertIn('fun', reg_info)
                    self.assertIn('offset', reg_info)

            elif reg_info['type'] == 'mmio':
                self.assertIn('bar', reg_info)
                self.assertIn('offset', reg_info)

            elif reg_info['type'] == 'io':
                self.assertIn('port', reg_info)

            elif reg_info['type'] == 'msr':
                self.assertIn('msr', reg_info)

    def test_mmio_bar_configuration_structure(self):
        """Test MMIO BAR configuration structure and content."""
        mmio_bars = self.config_cs.Cfg.MMIO_BARS

        # Test that all MMIO BARs have required fields
        for bar_name, bar_info in mmio_bars.items():
            if 'register' in bar_info:
                self.assertIn('base_field', bar_info)
            else:
                self.assertIn('bus', bar_info)
                self.assertIn('dev', bar_info)
                self.assertIn('fun', bar_info)
                self.assertIn('mask', bar_info)
                self.assertIn('width', bar_info)

            # Test that size is reasonable if present
            if 'size' in bar_info:
                self.assertGreater(bar_info['size'], 0)
                self.assertLessEqual(bar_info['size'], 0x10000000)  # Maximum reasonable BAR size (256MB)

    def test_control_configuration_structure(self):
        """Test control configuration structure and content."""
        controls = self.config_cs.Cfg.CONTROLS

        # Test that all controls have required fields
        for control_name, control_info in controls.items():
            self.assertIn('register', control_info)
            self.assertIn('field', control_info)

            # Test that register and field are non-empty strings
            self.assertGreater(len(control_info['register']), 0)
            self.assertGreater(len(control_info['field']), 0)

    def test_configuration_cross_references(self):
        """Test that configuration has valid cross-references."""
        registers = self.config_cs.Cfg.REGISTERS
        controls = self.config_cs.Cfg.CONTROLS

        # Test that controls reference valid registers
        for control_name, control_info in controls.items():
            reg_name = control_info['register']
            self.assertIn(reg_name, registers, f"Control '{control_name}' references non-existent register '{reg_name}'")

            # Test that register has FIELDS if control references a field
            field_name = control_info['field']
            reg_info = registers[reg_name]
            if 'FIELDS' in reg_info:
                self.assertIn(field_name, reg_info['FIELDS'], f"Control '{control_name}' references non-existent field '{field_name}' in register '{reg_name}'")


if __name__ == '__main__':
    unittest.main()
