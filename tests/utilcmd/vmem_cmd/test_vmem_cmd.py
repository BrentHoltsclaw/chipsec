# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024, Intel Corporation
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

"""
Unit tests for VMem utility command functionality
"""

import os
import unittest
from unittest.mock import Mock, patch
from chipsec.utilcmd.vmem_cmd import VMemCommand
from chipsec.command import toLoad
from tests.test_utils import MockFactory


class TestVMemCommand(unittest.TestCase):
    """Test core functionality of VMem command."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock ChipsecCs object for VMem testing
        self.mock_cs = MockFactory.create_mock_chipsec_cs()

        # Mock VirtMemory component
        self.mock_cs.hals = Mock()
        self.mock_cs.hals.virtmem = Mock()

        # Create VMemCommand instance
        self.vmem_command = VMemCommand(['read', '0x1000', '0x100'], cs=self.mock_cs)

    def test_vmem_command_initialization(self):
        """Test VMemCommand initialization."""
        self.assertEqual(self.vmem_command.cs, self.mock_cs)
        self.assertEqual(self.vmem_command.argv, ['read', '0x1000', '0x100'])

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.vmem_command.requirements()
        self.assertEqual(reqs, toLoad.Driver)

    def test_parse_arguments_read(self):
        """Test parsing read command."""
        command = VMemCommand(['read', '0xFED40000', '0x20', 'buffer.bin'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.vmem_read)
        self.assertEqual(command.virt_address, 0xFED40000)
        self.assertEqual(command.size, 0x20)
        self.assertEqual(command.buf_file, 'buffer.bin')

    def test_parse_arguments_readval(self):
        """Test parsing readval command."""
        command = VMemCommand(['readval', '0xFED40000', 'dword'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.vmem_readval)
        self.assertEqual(command.virt_address, 0xFED40000)
        self.assertEqual(command.length, 'dword')

    def test_parse_arguments_write(self):
        """Test parsing write command."""
        command = VMemCommand(['write', '0x100000000', '0x1000', 'buffer.bin'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.vmem_write)
        self.assertEqual(command.virt_address, 0x100000000)
        self.assertEqual(command.size, 0x1000)
        self.assertEqual(command.buf_file, 'buffer.bin')

    def test_parse_arguments_writeval(self):
        """Test parsing writeval command."""
        command = VMemCommand(['writeval', '0xA0000', 'dword', '0x9090CCCC'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.vmem_writeval)
        self.assertEqual(command.virt_address, 0xA0000)
        self.assertEqual(command.length, 'dword')
        self.assertEqual(command.value, 0x9090CCCC)

    def test_parse_arguments_search(self):
        """Test parsing search command."""
        command = VMemCommand(['search', '0xF0000', '0x10000', '_SM_'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.vmem_search)
        self.assertEqual(command.virt_address, 0xF0000)
        self.assertEqual(command.size, 0x10000)
        self.assertEqual(command.value, '_SM_')

    def test_parse_arguments_allocate(self):
        """Test parsing allocate command."""
        command = VMemCommand(['allocate', '0x1000'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.vmem_allocate)
        self.assertEqual(command.size, 0x1000)

    def test_parse_arguments_getphys(self):
        """Test parsing getphys command."""
        command = VMemCommand(['getphys', '0xFED00000'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.func, command.vmem_getphys)
        self.assertEqual(command.virt_address, 0xFED00000)

    def test_parse_arguments_invalid(self):
        """Test parsing invalid command."""
        command = VMemCommand(['invalid'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_set_up(self):
        """Test set_up method."""
        self.vmem_command.set_up()
        # Should create VirtMemory instance
        self.assertTrue(hasattr(self.vmem_command, '_vmem'))

    def test_vmem_read_with_file(self):
        """Test vmem_read method with file output."""
        self.vmem_command.virt_address = 0xFED40000
        self.vmem_command.size = 0x20
        self.vmem_command.buf_file = 'buffer.bin'

        # Mock VirtMemory
        self.vmem_command._vmem = Mock()
        test_buffer = b'\x01\x02\x03\x04' * 8  # 32 bytes
        self.vmem_command._vmem.read_virtual_mem.return_value = test_buffer

        with patch('chipsec.utilcmd.vmem_cmd.write_file') as mock_write, \
             patch.object(self.vmem_command.logger, 'log') as mock_log:
            self.vmem_command.vmem_read()

            self.mock_cs.hals.virtmem.read_virtual_mem.assert_called_once_with(0xFED40000, 0x20)
            mock_write.assert_called_once_with('buffer.bin', test_buffer)
            mock_log.assert_any_call("[CHIPSEC] Written 0x20 bytes to 'buffer.bin'")

    def test_vmem_read_without_file(self):
        """Test vmem_read method without file output."""
        self.vmem_command.virt_address = 0xFED40000
        self.vmem_command.size = 0x10
        self.vmem_command.buf_file = ''

        # Mock VirtMemory
        self.vmem_command._vmem = Mock()
        test_buffer = b'\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11' * 2  # 16 bytes
        self.vmem_command._vmem.read_virtual_mem.return_value = test_buffer

        with patch('chipsec.utilcmd.vmem_cmd.print_buffer_bytes') as mock_print:
            self.vmem_command.vmem_read()

            self.vmem_command._vmem.read_virtual_mem.assert_called_once_with(0xFED40000, 0x10)
            mock_print.assert_called_once_with(test_buffer)

    def test_vmem_read_error(self):
        """Test vmem_read method with error."""
        self.vmem_command.virt_address = 0xFED40000
        self.vmem_command.size = 0x20
        self.vmem_command.buf_file = 'buffer.bin'

        # Mock VirtMemory to raise error
        self.vmem_command._vmem = Mock()
        self.vmem_command._vmem.read_virtual_mem.side_effect = OSError("Mapping failed")

        with patch.object(self.vmem_command.logger, 'log_error') as mock_log_error:
            self.vmem_command.vmem_read()

            mock_log_error.assert_called_with('Error mapping VA to PA.')

    def test_vmem_readval_byte(self):
        """Test vmem_readval method with byte length."""
        self.vmem_command.virt_address = 0xFED40000
        self.vmem_command.length = 'byte'

        # Mock VirtMemory
        self.vmem_command._vmem = Mock()
        self.vmem_command._vmem.read_virtual_mem_byte.return_value = 0xAB

        with patch.object(self.vmem_command.logger, 'log') as mock_log:
            self.vmem_command.vmem_readval()

            self.vmem_command._vmem.read_virtual_mem_byte.assert_called_once_with(0xFED40000)
            mock_log.assert_any_call('[CHIPSEC] value = 0xAB')

    def test_vmem_readval_word(self):
        """Test vmem_readval method with word length."""
        self.vmem_command.virt_address = 0xFED40000
        self.vmem_command.length = 'word'

        # Mock VirtMemory
        self.vmem_command._vmem = Mock()
        self.vmem_command._vmem.read_virtual_mem_word.return_value = 0xABCD

        with patch.object(self.vmem_command.logger, 'log') as mock_log:
            self.vmem_command.vmem_readval()

            self.vmem_command._vmem.read_virtual_mem_word.assert_called_once_with(0xFED40000)
            mock_log.assert_any_call('[CHIPSEC] value = 0xABCD')

    def test_vmem_readval_dword(self):
        """Test vmem_readval method with dword length."""
        self.vmem_command.virt_address = 0xFED40000
        self.vmem_command.length = 'dword'

        # Mock VirtMemory
        self.vmem_command._vmem = Mock()
        self.vmem_command._vmem.read_virtual_mem_dword.return_value = 0xABCD1234

        with patch.object(self.vmem_command.logger, 'log') as mock_log:
            self.vmem_command.vmem_readval()

            self.vmem_command._vmem.read_virtual_mem_dword.assert_called_once_with(0xFED40000)
            mock_log.assert_any_call('[CHIPSEC] value = 0xABCD1234')

    def test_vmem_readval_hex_length(self):
        """Test vmem_readval method with hex length."""
        self.vmem_command.virt_address = 0xFED40000
        self.vmem_command.length = '0x8'

        # Mock VirtMemory
        self.vmem_command._vmem = Mock()
        self.vmem_command._vmem.read_virtual_mem_dword.return_value = 0x12345678

        with patch.object(self.vmem_command.logger, 'log') as mock_log:
            self.vmem_command.vmem_readval()

            self.vmem_command._vmem.read_virtual_mem_dword.assert_called_once_with(0xFED40000)
            mock_log.assert_any_call('[CHIPSEC] value = 0x12345678')

    def test_vmem_readval_invalid_length(self):
        """Test vmem_readval method with invalid length."""
        self.vmem_command.virt_address = 0xFED40000
        self.vmem_command.length = 'invalid'

        # Mock VirtMemory
        self.vmem_command._vmem = Mock()
        self.vmem_command._vmem.CMD_OPTS_WIDTH = ['byte', 'word', 'dword']

        with patch.object(self.vmem_command.logger, 'log_error') as mock_log_error:
            self.vmem_command.vmem_readval()

            mock_log_error.assert_called_with("Must specify <length> argument in 'mem readval' as one of ['byte', 'word', 'dword']")

    def test_vmem_readval_error(self):
        """Test vmem_readval method with error."""
        self.vmem_command.virt_address = 0xFED40000
        self.vmem_command.length = 'dword'

        # Mock VirtMemory to raise error
        self.vmem_command._vmem = Mock()
        self.vmem_command._vmem.read_virtual_mem_dword.side_effect = OSError("Mapping failed")

        with patch.object(self.vmem_command.logger, 'log_error') as mock_log_error:
            self.vmem_command.vmem_readval()

            mock_log_error.assert_called_with('Error mapping VA to PA.')


class TestVMemCommandIntegration(unittest.TestCase):
    """Integration tests for VMem command with realistic data."""

    def setUp(self):
        """Set up test fixtures."""
        # Create integrated ChipsecCs for VMem testing
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

        # Mock VirtMemory components with realistic data
        self.integrated_cs.hals = Mock()
        self.integrated_cs.hals.virtmem = Mock()

    def test_vmem_read_write_workflow(self):
        """Test complete read-write workflow."""
        # Test write operation
        write_cmd = VMemCommand(['write', '0x100000000', '0x10', '000102030405060708090A0B0C0D0E0F'], cs=self.integrated_cs)
        write_cmd.parse_arguments()
        write_cmd.set_up()

        with patch('chipsec.utilcmd.vmem_cmd.os.path.exists') as mock_exists:
            mock_exists.return_value = False
            write_cmd.run()

            # Verify write operation
            self.assertTrue(write_cmd._vmem.write_virtual_mem.called)

        # Test read operation
        read_cmd = VMemCommand(['read', '0x100000000', '0x10'], cs=self.integrated_cs)
        read_cmd.parse_arguments()
        read_cmd.set_up()

        expected_buffer = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
        read_cmd._vmem.read_virtual_mem.return_value = expected_buffer

        with patch('chipsec.utilcmd.vmem_cmd.print_buffer_bytes') as mock_print:
            read_cmd.run()

            # Verify read operation
            read_cmd._vmem.read_virtual_mem.assert_called_once_with(0x100000000, 0x10)
            mock_print.assert_called_once_with(expected_buffer)

    def test_vmem_allocate_getphys_workflow(self):
        """Test allocate and getphys workflow."""
        # Test allocate operation
        alloc_cmd = VMemCommand(['allocate', '0x1000'], cs=self.integrated_cs)
        alloc_cmd.parse_arguments()
        alloc_cmd.set_up()

        alloc_cmd._vmem.alloc_virtual_mem.return_value = (0x100000, 0x200000)

        with patch.object(alloc_cmd.logger, 'log'):
            alloc_cmd.run()

            alloc_cmd._vmem.alloc_virtual_mem.assert_called_once_with(0x1000)

        # Test getphys operation
        getphys_cmd = VMemCommand(['getphys', '0x100000'], cs=self.integrated_cs)
        getphys_cmd.parse_arguments()
        getphys_cmd.set_up()

        getphys_cmd._vmem.va2pa.return_value = 0x200000

        with patch.object(getphys_cmd.logger, 'log'):
            getphys_cmd.run()

            getphys_cmd._vmem.va2pa.assert_called_once_with(0x100000)


class TestVMemCommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for VMem command."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock ChipsecCs for edge case testing
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.mock_cs.hals = Mock()
        self.mock_cs.hals.virtmem = Mock()

    def test_vmem_read_default_size(self):
        """Test vmem_read with default size."""
        command = VMemCommand(['read', '0x1000'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command.size, 0x100)  # Default size

        # Mock the VirtMemory creation
        mock_vmem = Mock()
        mock_vmem.read_virtual_mem.return_value = b'\x00' * 0x100

        with patch('chipsec.hal.common.virtmem.VirtMemory', return_value=mock_vmem), \
             patch('chipsec.utilcmd.vmem_cmd.print_buffer_bytes'):
            command.set_up()
            command.run()

            mock_vmem.read_virtual_mem.assert_called_once_with(0x1000, 0x100)

    def test_vmem_writeval_hex_parsing(self):
        """Test vmem_writeval with various hex formats."""
        test_cases = [
            ('0xAB', 0xAB),
            ('0xABCD', 0xABCD),
            ('0xABCD1234', 0xABCD1234),
            ('FF', 0xFF),
        ]

        for hex_str, expected_value in test_cases:
            command = VMemCommand(['writeval', '0x1000', 'byte', hex_str], cs=self.mock_cs)
            command.parse_arguments()
            self.assertEqual(command.value, expected_value)


if __name__ == '__main__':
    unittest.main()