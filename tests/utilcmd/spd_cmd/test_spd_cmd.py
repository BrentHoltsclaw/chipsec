import unittest
from unittest.mock import Mock, patch, MagicMock
from chipsec.utilcmd.spd_cmd import SPDCommand
from tests.test_utils import MockFactory


class TestSPDCommand(unittest.TestCase):
    """Comprehensive tests for SPD utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.spd_command = SPDCommand(['detect'], cs=self.mock_cs)

    def test_initialization(self):
        """Test SPD command initializes correctly."""
        self.assertIsNotNone(self.spd_command)

    def test_requirements(self):
        """Test SPD command requirements."""
        from chipsec.command import toLoad
        self.assertEqual(self.spd_command.requirements(), toLoad.All)

    def test_parse_arguments_detect(self):
        """Test parsing detect command arguments."""
        command = SPDCommand(['detect'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spd_detect)

    def test_parse_arguments_dump_no_device(self):
        """Test parsing dump command with no device specified."""
        command = SPDCommand(['dump'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spd_dump)
        self.assertIsNone(command.dev)

    def test_parse_arguments_dump_with_device(self):
        """Test parsing dump command with device specified."""
        command = SPDCommand(['dump', 'DIMM0'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spd_dump)
        self.assertEqual(command.dev, 'DIMM0')

    def test_parse_arguments_read(self):
        """Test parsing read command arguments."""
        command = SPDCommand(['read', '0xA0', '0x0'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spd_read)
        self.assertEqual(command.dev, '0xA0')
        self.assertEqual(command.off, 0x0)

    def test_parse_arguments_write(self):
        """Test parsing write command arguments."""
        command = SPDCommand(['write', '0xA0', '0x0', '0xAA'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.spd_write)
        self.assertEqual(command.dev, '0xA0')
        self.assertEqual(command.off, 0x0)
        self.assertEqual(command.val, 0xAA)

    @patch('chipsec.hal.common.smbus.SMBus')
    @patch('chipsec.hal.common.spd.SPD')
    def test_spd_detect_with_devices(self, mock_spd_class, mock_smbus_class):
        """Test SPD detect with devices found."""
        # Setup mocks
        mock_smbus = Mock()
        mock_smbus.is_SMBus_supported.return_value = True
        mock_smbus_class.return_value = mock_smbus

        mock_spd = Mock()
        mock_spd.detect.return_value = [0xA0, 0xA2]
        mock_spd_class.return_value = mock_spd

        # Create and run command
        command = SPDCommand(['detect'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            mock_logger.log.assert_any_call("[CHIPSEC] Searching for DIMMs with SPD...")
            mock_spd.detect.assert_called_once()

    @patch('chipsec.hal.common.smbus.SMBus')
    @patch('chipsec.hal.common.spd.SPD')
    def test_spd_detect_no_devices(self, mock_spd_class, mock_smbus_class):
        """Test SPD detect with no devices found."""
        # Setup mocks
        mock_smbus = Mock()
        mock_smbus.is_SMBus_supported.return_value = True
        mock_smbus_class.return_value = mock_smbus

        mock_spd = Mock()
        mock_spd.detect.return_value = None
        mock_spd_class.return_value = mock_spd

        # Create and run command
        command = SPDCommand(['detect'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            mock_logger.log.assert_any_call("Unable to detect SPD devices.")

    @patch('chipsec.hal.common.smbus.SMBus')
    @patch('chipsec.hal.common.spd.SPD')
    def test_spd_read_success(self, mock_spd_class, mock_smbus_class):
        """Test SPD read operation success."""
        # Setup mocks
        mock_smbus = Mock()
        mock_smbus.is_SMBus_supported.return_value = True
        mock_smbus_class.return_value = mock_smbus

        mock_spd = Mock()
        mock_spd.isSPDPresent.return_value = True
        mock_spd.read_byte.return_value = 0xAB
        mock_spd_class.return_value = mock_spd

        # Create and run command
        command = SPDCommand(['read', '0xA0', '0x0'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            mock_spd.isSPDPresent.assert_called_once_with(0xA0)
            mock_spd.read_byte.assert_called_once_with(0x0, 0xA0)
            mock_logger.log.assert_any_call("[CHIPSEC] SPD read: offset 0x0 = 0xAB")

    @patch('chipsec.hal.common.smbus.SMBus')
    @patch('chipsec.hal.common.spd.SPD')
    def test_spd_read_device_not_present(self, mock_spd_class, mock_smbus_class):
        """Test SPD read when device is not present."""
        # Setup mocks
        mock_smbus = Mock()
        mock_smbus.is_SMBus_supported.return_value = True
        mock_smbus_class.return_value = mock_smbus

        mock_spd = Mock()
        mock_spd.isSPDPresent.return_value = False
        mock_spd_class.return_value = mock_spd

        # Create and run command
        command = SPDCommand(['read', '0xA0', '0x0'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            mock_logger.log.assert_any_call("[CHIPSEC] SPD for DIMM 0xA0 is not found")

    @patch('chipsec.hal.common.smbus.SMBus')
    @patch('chipsec.hal.common.spd.SPD')
    def test_spd_write_success(self, mock_spd_class, mock_smbus_class):
        """Test SPD write operation success."""
        # Setup mocks
        mock_smbus = Mock()
        mock_smbus.is_SMBus_supported.return_value = True
        mock_smbus_class.return_value = mock_smbus

        mock_spd = Mock()
        mock_spd.isSPDPresent.return_value = True
        mock_spd_class.return_value = mock_spd

        # Create and run command
        command = SPDCommand(['write', '0xA0', '0x0', '0xAA'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            mock_spd.isSPDPresent.assert_called_once_with(0xA0)
            mock_spd.write_byte.assert_called_once_with(0x0, 0xAA, 0xA0)
            mock_logger.log.assert_any_call("[CHIPSEC] SPD write: offset 0x0 = 0xAA")

    @patch('chipsec.hal.common.smbus.SMBus')
    @patch('chipsec.hal.common.spd.SPD')
    def test_spd_dump_specific_device(self, mock_spd_class, mock_smbus_class):
        """Test SPD dump for specific device."""
        # Setup mocks
        mock_smbus = Mock()
        mock_smbus.is_SMBus_supported.return_value = True
        mock_smbus_class.return_value = mock_smbus

        mock_spd = Mock()
        mock_spd.isSPDPresent.return_value = True
        mock_spd_class.return_value = mock_spd

        # Create and run command
        command = SPDCommand(['dump', 'DIMM0'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch('chipsec.hal.common.spd.SPD_DIMM_ADDRESSES', {'DIMM0': 0xA0}):
            command.run()
            mock_spd.isSPDPresent.assert_called_once_with(0xA0)
            mock_spd.decode.assert_called_once_with(0xA0)

    @patch('chipsec.hal.common.smbus.SMBus')
    def test_smbus_not_supported(self, mock_smbus_class):
        """Test behavior when SMBus is not supported."""
        # Setup mock
        mock_smbus = Mock()
        mock_smbus.is_SMBus_supported.return_value = False
        mock_smbus_class.return_value = mock_smbus

        # Create and run command
        command = SPDCommand(['detect'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            mock_logger.log.assert_any_call("[CHIPSEC] SMBus controller is not supported")

    def test_command_registration(self):
        """Test that SPD command is properly registered."""
        from chipsec.utilcmd.spd_cmd import commands
        self.assertIn('spd', commands)
        self.assertEqual(commands['spd'], SPDCommand)


if __name__ == '__main__':
    unittest.main()
