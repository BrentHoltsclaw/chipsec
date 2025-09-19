import unittest
from unittest.mock import patch, Mock, MagicMock
from tests.test_utils import MockFactory


class TestECCommand(unittest.TestCase):
    """Comprehensive tests for EC utility command functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        with patch('chipsec.chipset.cs', self.mock_cs):
            from chipsec.utilcmd.ec_cmd import ECCommand
            self._ec = ECCommand(['dump'])
    
    def test_ec_command_initialization(self):
        """Test EC command initializes correctly."""
        self.assertIsNotNone(self._ec)
        # Test that the command is properly registered
        from chipsec.utilcmd.ec_cmd import commands
        self.assertIn('ec', commands)
        self.assertEqual(commands['ec'], type(self._ec))

    def test_requirements_with_func(self):
        """Test EC command requirements when func is set."""
        from chipsec.command import toLoad
        from chipsec.utilcmd.ec_cmd import ECCommand
        
        command = ECCommand(['dump'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.requirements(), toLoad.Driver)

    def test_requirements_without_func(self):
        """Test EC command requirements when func is not set."""
        from chipsec.command import toLoad
        from chipsec.utilcmd.ec_cmd import ECCommand
        
        command = ECCommand(['dump'], cs=self.mock_cs)
        # Don't parse arguments so func is not set
        self.assertEqual(command.requirements(), toLoad.Nil)

    def test_parse_arguments_dump(self):
        """Test parsing dump command arguments."""
        from chipsec.utilcmd.ec_cmd import ECCommand
        command = ECCommand(['dump'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.dump)
        self.assertEqual(command.size, 0x160)  # Default size

    def test_parse_arguments_dump_with_size(self):
        """Test parsing dump command with custom size."""
        from chipsec.utilcmd.ec_cmd import ECCommand
        command = ECCommand(['dump', '0x100'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.size, 0x100)

    def test_parse_arguments_command(self):
        """Test parsing command arguments."""
        from chipsec.utilcmd.ec_cmd import ECCommand
        command = ECCommand(['command', '0x84'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.command)
        self.assertEqual(command.cmd, 0x84)

    def test_parse_arguments_read(self):
        """Test parsing read command arguments."""
        from chipsec.utilcmd.ec_cmd import ECCommand
        command = ECCommand(['read', '0x60'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.read)
        self.assertEqual(command.offset, 0x60)
        self.assertIsNone(command.size)

    def test_parse_arguments_read_with_size(self):
        """Test parsing read command with size."""
        from chipsec.utilcmd.ec_cmd import ECCommand
        command = ECCommand(['read', '0x60', '4'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.offset, 0x60)
        self.assertEqual(command.size, 4)

    def test_parse_arguments_write(self):
        """Test parsing write command arguments."""
        from chipsec.utilcmd.ec_cmd import ECCommand
        command = ECCommand(['write', '0x60', '0xAB'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.write)
        self.assertEqual(command.offset, 0x60)
        self.assertEqual(command.wval, 0xAB)

    def test_parse_arguments_index(self):
        """Test parsing index command arguments."""
        from chipsec.utilcmd.ec_cmd import ECCommand
        command = ECCommand(['index'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.index)
        self.assertEqual(command.offset, 0)  # Default offset

    def test_parse_arguments_index_with_offset(self):
        """Test parsing index command with offset."""
        from chipsec.utilcmd.ec_cmd import ECCommand
        command = ECCommand(['index', '0x12'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.offset, 0x12)

    @patch('chipsec.hal.common.ec.EC')
    def test_ec_dump(self, mock_ec_class):
        """Test EC dump functionality."""
        # Setup mocks
        mock_ec = Mock()
        mock_ec.read_range.return_value = bytearray([0x01, 0x02, 0x03, 0x04])
        mock_ec_class.return_value = mock_ec

        from chipsec.utilcmd.ec_cmd import ECCommand
        command = ECCommand(['dump'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch('chipsec.library.logger.print_buffer_bytes') as mock_print:
            with patch.object(command, 'logger') as mock_logger:
                command.run()
                mock_ec.read_range.assert_called_once_with(0, 0x160)
                mock_print.assert_called_once()
                mock_logger.log.assert_any_call("[CHIPSEC] EC dump")

    @patch('chipsec.hal.common.ec.EC')
    def test_ec_command(self, mock_ec_class):
        """Test EC command functionality."""
        # Setup mocks
        mock_ec = Mock()
        mock_ec_class.return_value = mock_ec

        from chipsec.utilcmd.ec_cmd import ECCommand
        command = ECCommand(['command', '0x84'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            mock_ec.write_command.assert_called_once_with(0x84)
            mock_logger.log.assert_any_call('[CHIPSEC] Sending EC command 0x84')

    @patch('chipsec.hal.common.ec.EC')
    def test_ec_read_single_byte(self, mock_ec_class):
        """Test EC read single byte."""
        # Setup mocks
        mock_ec = Mock()
        mock_ec.read_byte.return_value = 0xAB
        mock_ec_class.return_value = mock_ec

        from chipsec.utilcmd.ec_cmd import ECCommand
        command = ECCommand(['read', '0x60'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            mock_ec.read_byte.assert_called_once_with(0x60)
            mock_logger.log.assert_any_call('[CHIPSEC] EC offset 0x60: 0xAB')

    @patch('chipsec.hal.common.ec.EC')
    def test_ec_read_range(self, mock_ec_class):
        """Test EC read range."""
        # Setup mocks
        mock_ec = Mock()
        mock_ec.read_range.return_value = bytearray([0x01, 0x02, 0x03, 0x04])
        mock_ec_class.return_value = mock_ec

        from chipsec.utilcmd.ec_cmd import ECCommand
        command = ECCommand(['read', '0x60', '4'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch('chipsec.library.logger.print_buffer_bytes') as mock_print:
            with patch.object(command, 'logger') as mock_logger:
                command.run()
                mock_ec.read_range.assert_called_once_with(0x60, 4)
                mock_print.assert_called_once()
                mock_logger.log.assert_any_call('[CHIPSEC] EC memory range 0x60+0x4:')

    @patch('chipsec.hal.common.ec.EC')
    def test_ec_write(self, mock_ec_class):
        """Test EC write functionality."""
        # Setup mocks
        mock_ec = Mock()
        mock_ec_class.return_value = mock_ec

        from chipsec.utilcmd.ec_cmd import ECCommand
        command = ECCommand(['write', '0x60', '0xAB'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            mock_ec.write_byte.assert_called_once_with(0x60, 0xAB)
            mock_logger.log.assert_any_call('[CHIPSEC] Writing EC offset 0x60 = 0xAB')

    @patch('chipsec.hal.common.ec.EC')
    def test_ec_index_with_offset(self, mock_ec_class):
        """Test EC index with specific offset."""
        # Setup mocks
        mock_ec = Mock()
        mock_ec.read_idx.return_value = 0xCD
        mock_ec_class.return_value = mock_ec

        from chipsec.utilcmd.ec_cmd import ECCommand
        command = ECCommand(['index', '0x12'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch.object(command, 'logger') as mock_logger:
            command.run()
            mock_ec.read_idx.assert_called_once_with(0x12)
            mock_logger.log.assert_any_call('[CHIPSEC] EC index I/O: reading memory offset 0x12: 0xCD')

    @patch('chipsec.hal.common.ec.EC')
    def test_ec_index_dump_all(self, mock_ec_class):
        """Test EC index dump all memory."""
        # Setup mocks
        mock_ec = Mock()
        mock_ec.read_idx.return_value = 0x55
        mock_ec_class.return_value = mock_ec

        from chipsec.utilcmd.ec_cmd import ECCommand
        command = ECCommand(['index'], cs=self.mock_cs)
        command.parse_arguments()
        
        with patch('chipsec.library.logger.print_buffer_bytes') as mock_print:
            with patch.object(command, 'logger') as mock_logger:
                command.run()
                # Should read from 0x0 to 0xFFFF (65536 calls)
                self.assertEqual(mock_ec.read_idx.call_count, 65536)
                mock_print.assert_called_once()
                mock_logger.log.assert_any_call("[CHIPSEC] EC index I/O: dumping memory...")

    def test_run_exception_handling(self):
        """Test EC command exception handling."""
        from chipsec.utilcmd.ec_cmd import ECCommand
        command = ECCommand(['dump'], cs=self.mock_cs)
        command.parse_arguments()
        
        # Mock set_up to raise an exception
        with patch.object(command, 'set_up', side_effect=Exception("Test error")):
            with patch.object(command, 'logger') as mock_logger:
                command.run()
                mock_logger.log_error.assert_any_call('An error occured during the execution of the command!')
                mock_logger.log_error.assert_any_call('Please run with the debug option for further details')


if __name__ == '__main__':
    unittest.main()
    unittest.main()
