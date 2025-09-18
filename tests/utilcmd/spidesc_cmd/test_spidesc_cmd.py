import unittest
from unittest.mock import Mock, patch
from chipsec.utilcmd.spidesc_cmd import SPIDescCommand
from tests.test_utils import MockFactory


class TestSPIDescCommand(unittest.TestCase):
    """Comprehensive tests for SPIDESC utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        # Add SpiDescriptor HAL mock
        self.mock_cs.hals.SpiDescriptor = Mock()
        self.mock_cs.hals.SpiDescriptor.parse_spi_flash_descriptor = Mock()
        self.spidesc_command = SPIDescCommand(['test.bin'], cs=self.mock_cs)

    def test_initialization(self):
        """Test SPIDESC command initializes correctly."""
        self.assertIsNotNone(self.spidesc_command)

    def test_requirements(self):
        """Test SPIDESC command requirements."""
        from chipsec.command import toLoad
        self.assertEqual(self.spidesc_command.requirements(), toLoad.Config)

    def test_parse_arguments_with_file(self):
        """Test parsing arguments with file parameter."""
        command = SPIDescCommand(['test.bin'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.fd_file, 'test.bin')

    def test_parse_arguments_missing_file(self):
        """Test parsing arguments without required file parameter raises SystemExit."""
        command = SPIDescCommand([], cs=self.mock_cs)
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    @patch('chipsec.utilcmd.spidesc_cmd.read_file')
    def test_run_with_valid_file(self, mock_read_file):
        """Test running SPIDESC command with a valid file."""
        mock_read_file.return_value = b'\x5A' * 4096
        
        command = SPIDescCommand(['test.bin'], cs=self.mock_cs)
        command.parse_arguments()
        command.set_up()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            mock_read_file.assert_called_once_with('test.bin')
            self.mock_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.assert_called_once_with(b'\x5A' * 4096)
            mock_logger.log.assert_called_with("[CHIPSEC] Parsing SPI Flash Descriptor from file 'test.bin'\n")

    @patch('chipsec.utilcmd.spidesc_cmd.read_file')
    def test_run_with_empty_file(self, mock_read_file):
        """Test running SPIDESC command with an empty file."""
        mock_read_file.return_value = None
        
        command = SPIDescCommand(['empty.bin'], cs=self.mock_cs)
        command.parse_arguments()
        command.set_up()
        
        command.run()
        mock_read_file.assert_called_once_with('empty.bin')
        self.mock_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.assert_not_called()

    @patch('chipsec.utilcmd.spidesc_cmd.read_file')
    def test_run_with_small_file(self, mock_read_file):
        """Test running SPIDESC command with a small file."""
        mock_read_file.return_value = b'\x5A' * 10  # Small content
        
        command = SPIDescCommand(['small.bin'], cs=self.mock_cs)
        command.parse_arguments()
        command.set_up()
        
        command.run()
        mock_read_file.assert_called_once_with('small.bin')
        self.mock_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.assert_called_once_with(b'\x5A' * 10)

    @patch('chipsec.utilcmd.spidesc_cmd.read_file')
    def test_run_file_read_exception(self, mock_read_file):
        """Test running SPIDESC command when file read raises exception."""
        mock_read_file.side_effect = Exception("File not found")
        
        command = SPIDescCommand(['nonexistent.bin'], cs=self.mock_cs)
        command.parse_arguments()
        command.set_up()
        
        with self.assertRaises(Exception):
            command.run()

    def test_run_with_binary_file(self):
        """Test running SPIDESC command with actual binary file content."""
        # Create a realistic SPI descriptor pattern
        spi_descriptor_data = b'\xFF\xFF\xFF\xFF' * 1024  # 4KB of flash descriptor pattern
        
        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=spi_descriptor_data):
            command = SPIDescCommand(['descriptor.bin'], cs=self.mock_cs)
            command.parse_arguments()
            command.set_up()
            
            command.run()
            self.mock_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.assert_called_once_with(spi_descriptor_data)

    def test_spi_descriptor_hal_integration(self):
        """Test that the SPI descriptor HAL is properly called."""
        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=b'test_data'):
            command = SPIDescCommand(['test.bin'], cs=self.mock_cs)
            command.parse_arguments()
            command.set_up()
            command.run()
            
            # Verify HAL method was called with correct data
            self.mock_cs.hals.SpiDescriptor.parse_spi_flash_descriptor.assert_called_once_with(b'test_data')

    def test_command_registration(self):
        """Test that SPIDESC command is properly registered."""
        from chipsec.utilcmd.spidesc_cmd import commands
        self.assertIn('spidesc', commands)
        self.assertEqual(commands['spidesc'], SPIDescCommand)

    def test_multiple_file_arguments(self):
        """Test parsing arguments with extra arguments (should raise SystemExit)."""
        command = SPIDescCommand(['first.bin', 'second.bin'], cs=self.mock_cs)
        # ArgumentParser will raise SystemExit for unrecognized arguments
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_logger_integration(self):
        """Test that logger is properly integrated and called."""
        with patch('chipsec.utilcmd.spidesc_cmd.read_file', return_value=b'test_data'):
            command = SPIDescCommand(['test.bin'], cs=self.mock_cs)
            command.parse_arguments()
            command.set_up()
            
            # Ensure logger exists
            self.assertIsNotNone(command.logger)
            
            with patch.object(command, 'logger') as mock_logger:
                command.run()
                mock_logger.log.assert_called_once()

    def test_hal_access(self):
        """Test that HAL access works correctly."""
        command = SPIDescCommand(['test.bin'], cs=self.mock_cs)
        
        # Verify HAL access
        self.assertIsNotNone(command.cs.hals.SpiDescriptor)
        self.assertTrue(hasattr(command.cs.hals.SpiDescriptor, 'parse_spi_flash_descriptor'))


if __name__ == '__main__':
    unittest.main()
