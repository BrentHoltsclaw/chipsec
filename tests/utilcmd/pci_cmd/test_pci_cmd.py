import unittest
from unittest.mock import Mock, patch, MagicMock
from chipsec.utilcmd.pci_cmd import PCICommand
from tests.test_utils import MockFactory


class TestPCICommand(unittest.TestCase):
    """Comprehensive tests for PCI utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.pci_command = PCICommand(['enumerate'], cs=self.mock_cs)

    def test_initialization(self):
        """Test PCI command initializes correctly."""
        self.assertIsNotNone(self.pci_command)

    def test_requirements(self):
        """Test PCI command requirements."""
        from chipsec.command import toLoad
        self.assertEqual(self.pci_command.requirements(), toLoad.Driver)

    def test_parse_arguments_enumerate(self):
        """Test parsing enumerate command arguments."""
        command = PCICommand(['enumerate'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.pci_enumerate)

    def test_parse_arguments_read(self):
        """Test parsing read command arguments."""
        command = PCICommand(['read', '0', '0', '0', '0x0'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.pci_read)
        self.assertEqual(command.bus, 0)
        self.assertEqual(command.device, 0)
        self.assertEqual(command.function, 0)
        self.assertEqual(command.offset, 0x0)

    def test_parse_arguments_read_with_size(self):
        """Test parsing read command with size argument."""
        command = PCICommand(['read', '0', '0', '0', '0x0', 'byte'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.size, 'byte')

    def test_parse_arguments_write(self):
        """Test parsing write command arguments."""
        command = PCICommand(['write', '0', '0', '0', '0x0', 'dword', '0x12345678'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.pci_write)
        self.assertEqual(command.bus, 0)
        self.assertEqual(command.device, 0)
        self.assertEqual(command.function, 0)
        self.assertEqual(command.offset, 0x0)
        self.assertEqual(command.size, 'dword')
        self.assertEqual(command.value, 0x12345678)

    def test_parse_arguments_dump_all(self):
        """Test parsing dump command with no arguments."""
        command = PCICommand(['dump'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.pci_dump)
        self.assertIsNone(command.bus)

    def test_parse_arguments_dump_specific(self):
        """Test parsing dump command for specific device."""
        command = PCICommand(['dump', '0', '0', '0'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.bus, 0)
        self.assertEqual(command.device, 0)
        self.assertEqual(command.function, 0)

    def test_parse_arguments_xrom(self):
        """Test parsing xrom command arguments."""
        command = PCICommand(['xrom'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.pci_xrom)

    def test_parse_arguments_cmd(self):
        """Test parsing cmd command arguments."""
        command = PCICommand(['cmd'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.pci_cmd)
        self.assertEqual(command.cmd_mask, 0xFFFF)

    def test_pci_enumerate(self):
        """Test PCI enumerate functionality."""
        # Mock PCI devices
        mock_devices = [(0, 0, 0, 0x8086, 0x1234, 0x00)]
        self.mock_cs.hals.Pci.enumerate_devices.return_value = mock_devices

        command = PCICommand(['enumerate'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch('chipsec.library.pci.print_pci_devices') as mock_print:
            with patch.object(command, 'logger'):
                command.run()
                mock_print.assert_called_once_with(mock_devices)

    def test_pci_cmd_default(self):
        """Test PCI cmd command with default parameters."""
        # Mock devices and required PCI reads
        mock_devices = [(0, 0, 0, 0x8086, 0x1234, 0x00)]
        self.mock_cs.hals.Pci.enumerate_devices.return_value = mock_devices
        self.mock_cs.hals.Pci.read_byte.return_value = 0x06  # Mock class code
        self.mock_cs.hals.Pci.read_word.return_value = 0x0007  # Mock command register

        command = PCICommand(['cmd'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            mock_logger.log.assert_any_call('BDF     | VID:DID   | CMD  | CLS | Sub CLS')
            mock_logger.log.assert_any_call('------------------------------------------')

    def test_pci_read_dword(self):
        """Test PCI read dword operation."""
        # Setup mock
        self.mock_cs.hals.Pci.read_dword.return_value = 0x12345678

        command = PCICommand(['read', '0', '0', '0', '0x0'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            self.mock_cs.hals.Pci.read_dword.assert_called_once_with(0, 0, 0, 0x0)
            mock_logger.log.assert_any_call("[CHIPSEC] PCI 00:00.0 + 0x00: 0x12345678")

    def test_pci_read_word(self):
        """Test PCI read word operation."""
        # Setup mock
        self.mock_cs.hals.Pci.read_word.return_value = 0x1234

        command = PCICommand(['read', '0', '0', '0', '0x0', 'word'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            self.mock_cs.hals.Pci.read_word.assert_called_once_with(0, 0, 0, 0x0)
            mock_logger.log.assert_any_call("[CHIPSEC] PCI 00:00.0 + 0x00: 0x1234")

    def test_pci_read_byte(self):
        """Test PCI read byte operation."""
        # Setup mock
        self.mock_cs.hals.Pci.read_byte.return_value = 0x12

        command = PCICommand(['read', '0', '0', '0', '0x0', 'byte'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            self.mock_cs.hals.Pci.read_byte.assert_called_once_with(0, 0, 0, 0x0)
            mock_logger.log.assert_any_call("[CHIPSEC] PCI 00:00.0 + 0x00: 0x12")

    def test_pci_write_dword(self):
        """Test PCI write dword operation."""
        command = PCICommand(['write', '0', '0', '0', '0x0', 'dword', '0x12345678'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            self.mock_cs.hals.Pci.write_dword.assert_called_once_with(0, 0, 0, 0x0, 0x12345678)
            mock_logger.log.assert_any_call("[CHIPSEC] Write 0x12345678 to PCI 00:00.0 + 0x00")

    def test_pci_write_word(self):
        """Test PCI write word operation."""
        command = PCICommand(['write', '0', '0', '0', '0x0', 'word', '0x1234'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            self.mock_cs.hals.Pci.write_word.assert_called_once_with(0, 0, 0, 0x0, 0x1234)
            mock_logger.log.assert_any_call("[CHIPSEC] Write 0x1234 to PCI 00:00.0 + 0x00")

    def test_pci_write_byte(self):
        """Test PCI write byte operation."""
        command = PCICommand(['write', '0', '0', '0', '0x0', 'byte', '0x12'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            self.mock_cs.hals.Pci.write_byte.assert_called_once_with(0, 0, 0, 0x0, 0x12)
            mock_logger.log.assert_any_call("[CHIPSEC] Write 0x12 to PCI 00:00.0 + 0x00")

    def test_pci_dump_specific_device(self):
        """Test PCI dump for specific device."""
        # Setup mock
        mock_config = bytearray(256)
        mock_config[0:4] = [0x86, 0x80, 0x34, 0x12]  # Mock VID/DID
        self.mock_cs.hals.Pci.dump_pci_config.return_value = mock_config

        command = PCICommand(['dump', '0', '0', '0'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch('chipsec.library.logger.pretty_print_hex_buffer') as mock_print:
            with patch.object(command, 'logger') as mock_logger:
                command.run()
                self.mock_cs.hals.Pci.dump_pci_config.assert_called_once_with(0, 0, 0)
                mock_print.assert_called_once_with(mock_config)
                mock_logger.log.assert_any_call("[CHIPSEC] PCI device 00:00.0 configuration:")

    def test_pci_dump_all_devices(self):
        """Test PCI dump for all devices."""
        # Setup mock for enumerate
        mock_devices = [(0, 0, 0, 0x8086, 0x1234, 0x00)]
        self.mock_cs.hals.Pci.enumerate_devices.return_value = mock_devices
        
        # Setup mock for config dump
        mock_config = bytearray(256)
        self.mock_cs.hals.Pci.dump_pci_config.return_value = mock_config

        command = PCICommand(['dump'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch('chipsec.library.logger.pretty_print_hex_buffer'):
            with patch.object(command, 'logger'):
                command.run()
                self.mock_cs.hals.Pci.enumerate_devices.assert_called_once()
                self.mock_cs.hals.Pci.dump_pci_config.assert_called_once_with(0, 0, 0)

    def test_pci_cmd_default(self):
        """Test PCI cmd command with default parameters."""
        command = PCICommand(['cmd'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            mock_logger.log.assert_any_call("[CHIPSEC] PCI devices with command register mask 0xFFFF:")

    def test_command_registration(self):
        """Test that PCI command is properly registered."""
        from chipsec.utilcmd.pci_cmd import commands
        self.assertIn('pci', commands)
        self.assertEqual(commands['pci'], PCICommand)


if __name__ == '__main__':
    unittest.main()
