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

import os
import uuid
import pytest
from unittest.mock import Mock, patch, mock_open, MagicMock
from chipsec.utilcmd.uefi_cmd import UEFICommand
from chipsec.library.uefi.common import EFI_STATUS_DICT
from chipsec.library.exceptions import HWAccessViolationError
from tests.test_utils import MockFactory


class TestUEFICommand:
    """Comprehensive tests for UEFI utility command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for UEFI testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock UEFI-related components
        cs_mock.hals = Mock()
        cs_mock.hals.Memory = Mock()

        # Mock UEFI HAL
        cs_mock.hals.UEFI = Mock()

        # Mock OS helper
        cs_mock.os_helper = Mock()
        cs_mock.os_helper.getcwd.return_value = "/tmp"

        return cs_mock

    @pytest.fixture
    def uefi_command(self, mock_cs):
        """Create UEFICommand instance."""
        return UEFICommand(['var-list'], cs=mock_cs)

    @pytest.mark.unit
    def test_uefi_command_initialization(self, uefi_command, mock_cs):
        """Test UEFICommand initialization."""
        assert uefi_command.cs == mock_cs
        assert uefi_command.argv == ['var-list']

    @pytest.mark.unit
    def test_requirements_decode(self, mock_cs):
        """Test requirements for decode command."""
        command = UEFICommand(['decode', 'test.rom'], cs=mock_cs)
        reqs = command.requirements()
        assert reqs == command.toLoad.Nil

    @pytest.mark.unit
    def test_requirements_var_list_spi(self, mock_cs):
        """Test requirements for var-list-spi command."""
        command = UEFICommand(['var-list-spi', 'test.rom'], cs=mock_cs)
        reqs = command.requirements()
        assert reqs == command.toLoad.All

    @pytest.mark.unit
    def test_requirements_other_commands(self, mock_cs):
        """Test requirements for other commands."""
        command = UEFICommand(['var-list'], cs=mock_cs)
        reqs = command.requirements()
        assert reqs == command.toLoad.Driver

    @pytest.mark.unit
    def test_parse_arguments_var_read(self, mock_cs):
        """Test parsing var-read command."""
        command = UEFICommand(['var-read', 'test_var', '12345678-1234-1234-1234-123456789ABC', 'output.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.var_read
        assert command.name == 'test_var'
        assert command.guid == '12345678-1234-1234-1234-123456789ABC'
        assert command.filename == 'output.bin'

    @pytest.mark.unit
    def test_parse_arguments_var_write(self, mock_cs):
        """Test parsing var-write command."""
        command = UEFICommand(['var-write', 'test_var', '12345678-1234-1234-1234-123456789ABC', 'input.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.var_write
        assert command.name == 'test_var'
        assert command.guid == '12345678-1234-1234-1234-123456789ABC'
        assert command.filename == 'input.bin'

    @pytest.mark.unit
    def test_parse_arguments_var_delete(self, mock_cs):
        """Test parsing var-delete command."""
        command = UEFICommand(['var-delete', 'test_var', '12345678-1234-1234-1234-123456789ABC'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.var_delete
        assert command.name == 'test_var'
        assert command.guid == '12345678-1234-1234-1234-123456789ABC'

    @pytest.mark.unit
    def test_parse_arguments_var_list(self, mock_cs):
        """Test parsing var-list command."""
        command = UEFICommand(['var-list'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.var_list

    @pytest.mark.unit
    def test_parse_arguments_var_list_spi(self, mock_cs):
        """Test parsing var-list-spi command."""
        command = UEFICommand(['var-list-spi', 'test.rom'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.var_list_spi
        assert command.filename == 'test.rom'

    @pytest.mark.unit
    def test_parse_arguments_var_find(self, mock_cs):
        """Test parsing var-find command."""
        command = UEFICommand(['var-find', 'test_var'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.var_find
        assert command.name_guid == 'test_var'

    @pytest.mark.unit
    def test_parse_arguments_nvram(self, mock_cs):
        """Test parsing nvram command."""
        command = UEFICommand(['nvram', 'test.rom', 'vss'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.nvram
        assert command.romfilename == 'test.rom'
        assert command.fwtype == 'vss'

    @pytest.mark.unit
    def test_parse_arguments_nvram_auth(self, mock_cs):
        """Test parsing nvram-auth command."""
        command = UEFICommand(['nvram-auth', 'test.rom'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.nvram_auth
        assert command.romfilename == 'test.rom'
        assert command.fwtype is None

    @pytest.mark.unit
    def test_parse_arguments_decode(self, mock_cs):
        """Test parsing decode command."""
        command = UEFICommand(['decode', 'test.rom', 'FV_MM'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.decode
        assert command.filename == 'test.rom'
        assert command.filetypes == ['FV_MM']

    @pytest.mark.unit
    def test_parse_arguments_keys(self, mock_cs):
        """Test parsing keys command."""
        command = UEFICommand(['keys', 'test.bin'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.keys
        assert command.filename == 'test.bin'

    @pytest.mark.unit
    def test_parse_arguments_tables(self, mock_cs):
        """Test parsing tables command."""
        command = UEFICommand(['tables'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.tables

    @pytest.mark.unit
    def test_parse_arguments_s3bootscript(self, mock_cs):
        """Test parsing s3bootscript command."""
        command = UEFICommand(['s3bootscript', '0x1000'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.s3bootscript
        assert command.bootscript_pa == 0x1000

    @pytest.mark.unit
    def test_parse_arguments_assemble(self, mock_cs):
        """Test parsing assemble command."""
        command = UEFICommand(['assemble', '12345678-1234-1234-1234-123456789ABC', 'freeform', 'lzma', 'input.raw', 'output.efi'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.assemble
        assert command.guid == '12345678-1234-1234-1234-123456789ABC'
        assert command.file_type == 'freeform'
        assert command.comp == 'lzma'
        assert command.raw_file == 'input.raw'
        assert command.efi_file == 'output.efi'

    @pytest.mark.unit
    def test_parse_arguments_invalid(self, mock_cs):
        """Test parsing invalid command."""
        command = UEFICommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_set_up(self, uefi_command, mock_cs):
        """Test set_up method."""
        uefi_command.set_up()
        # Should create UEFI instance
        assert hasattr(uefi_command, '_uefi')

    @pytest.mark.unit
    def test_var_read(self, uefi_command, mock_cs):
        """Test var_read method."""
        uefi_command.name = 'test_var'
        uefi_command.guid = '12345678-1234-1234-1234-123456789ABC'
        uefi_command.filename = 'output.bin'

        # Mock UEFI instance
        uefi_command._uefi = Mock()

        with patch.object(uefi_command.logger, 'log') as mock_log:
            uefi_command.var_read()

            mock_log.assert_called_with("[CHIPSEC] Reading EFI variable Name='test_var' GUID={12345678-1234-1234-1234-123456789ABC} to 'output.bin' via Variable API..")
            uefi_command._uefi.get_EFI_variable.assert_called_once_with('test_var', '12345678-1234-1234-1234-123456789ABC', 'output.bin')

    @pytest.mark.unit
    def test_var_write_success(self, uefi_command, mock_cs):
        """Test var_write method with success."""
        uefi_command.name = 'test_var'
        uefi_command.guid = '12345678-1234-1234-1234-123456789ABC'
        uefi_command.filename = 'input.bin'

        # Mock UEFI instance
        uefi_command._uefi = Mock()
        uefi_command._uefi.set_EFI_variable_from_file.return_value = 0  # Success

        with patch.object(uefi_command.logger, 'log') as mock_log:
            uefi_command.var_write()

            mock_log.assert_any_call("[CHIPSEC] writing EFI variable was successful")
            uefi_command._uefi.set_EFI_variable_from_file.assert_called_once_with('test_var', '12345678-1234-1234-1234-123456789ABC', 'input.bin')

    @pytest.mark.unit
    def test_var_write_failure(self, uefi_command, mock_cs):
        """Test var_write method with failure."""
        uefi_command.name = 'test_var'
        uefi_command.guid = '12345678-1234-1234-1234-123456789ABC'
        uefi_command.filename = 'input.bin'

        # Mock UEFI instance
        uefi_command._uefi = Mock()
        uefi_command._uefi.set_EFI_variable_from_file.return_value = 1  # Failure

        with patch.object(uefi_command.logger, 'log') as mock_log, \
             patch.object(uefi_command.logger, 'log_error') as mock_log_error:
            uefi_command.var_write()

            mock_log_error.assert_called_with("writing EFI variable failed")

    @pytest.mark.unit
    def test_var_delete_success(self, uefi_command, mock_cs):
        """Test var_delete method with success."""
        uefi_command.name = 'test_var'
        uefi_command.guid = '12345678-1234-1234-1234-123456789ABC'

        # Mock UEFI instance
        uefi_command._uefi = Mock()
        uefi_command._uefi.delete_EFI_variable.return_value = 0  # Success

        with patch.object(uefi_command.logger, 'log') as mock_log:
            uefi_command.var_delete()

            mock_log.assert_any_call("[CHIPSEC] deleting EFI variable was successful")

    @pytest.mark.unit
    def test_var_delete_failure(self, uefi_command, mock_cs):
        """Test var_delete method with failure."""
        uefi_command.name = 'test_var'
        uefi_command.guid = '12345678-1234-1234-1234-123456789ABC'

        # Mock UEFI instance
        uefi_command._uefi = Mock()
        uefi_command._uefi.delete_EFI_variable.return_value = 1  # Failure

        with patch.object(uefi_command.logger, 'log_error') as mock_log_error:
            uefi_command.var_delete()

            mock_log_error.assert_called_with("deleting EFI variable failed")

    @pytest.mark.unit
    def test_var_list_success(self, uefi_command, mock_cs):
        """Test var_list method with success."""
        # Mock UEFI instance
        uefi_command._uefi = Mock()
        uefi_command._uefi.list_EFI_variables.return_value = {'test_var': []}

        with patch.object(uefi_command.logger, 'log') as mock_log, \
             patch('chipsec.utilcmd.uefi_cmd.decode_EFI_variables') as mock_decode, \
             patch('chipsec.utilcmd.uefi_cmd.os.path.exists') as mock_exists, \
             patch('chipsec.utilcmd.uefi_cmd.os.makedirs') as mock_makedirs:
            mock_exists.return_value = False
            uefi_command.var_list()

            mock_log.assert_any_call("[CHIPSEC] Enumerating all EFI variables via OS specific EFI Variable API..")
            mock_log.assert_any_call("[CHIPSEC] Decoding EFI Variables..")
            mock_log.assert_any_call("[CHIPSEC] Variables are in efi_variables.lst log and efi_variables.dir directory")
            mock_decode.assert_called_once()
            mock_makedirs.assert_called_once_with('efi_variables.dir')

    @pytest.mark.unit
    def test_var_list_failure(self, uefi_command, mock_cs):
        """Test var_list method with failure."""
        # Mock UEFI instance
        uefi_command._uefi = Mock()
        uefi_command._uefi.list_EFI_variables.return_value = None

        with patch.object(uefi_command.logger, 'log_important') as mock_log_important:
            uefi_command.var_list()

            mock_log_important.assert_called_with("[CHIPSEC] Could not enumerate EFI Variables. You can try using the `var-list-spi` subcommand. Exit..")

    @pytest.mark.unit
    def test_var_list_spi_success(self, uefi_command, mock_cs):
        """Test var_list_spi method with success."""
        uefi_command.filename = 'test.rom'

        # Mock UEFI instance
        uefi_command._uefi = Mock()
        uefi_command._uefi.list_EFI_variables_spi.return_value = {'test_var': []}

        with patch.object(uefi_command.logger, 'log') as mock_log, \
             patch('chipsec.utilcmd.uefi_cmd.decode_EFI_variables') as mock_decode, \
             patch('chipsec.utilcmd.uefi_cmd.os.path.exists') as mock_exists, \
             patch('chipsec.utilcmd.uefi_cmd.os.makedirs') as mock_makedirs:
            mock_exists.return_value = False
            uefi_command.var_list_spi()

            mock_log.assert_any_call("[CHIPSEC] Variables are in efi_variables.lst log and efi_variables.dir directory")
            mock_decode.assert_called_once()
            mock_makedirs.assert_called_once_with('efi_variables.dir')

    @pytest.mark.unit
    def test_var_list_spi_failure(self, uefi_command, mock_cs):
        """Test var_list_spi method with failure."""
        uefi_command.filename = 'test.rom'

        # Mock UEFI instance
        uefi_command._uefi = Mock()
        uefi_command._uefi.list_EFI_variables_spi.return_value = None

        with patch.object(uefi_command.logger, 'log') as mock_log:
            uefi_command.var_list_spi()

            mock_log.assert_any_call("[CHIPSEC] Could not enumerate EFI Variables (Legacy OS?). Exit..")

    @pytest.mark.unit
    def test_var_find_by_name(self, uefi_command, mock_cs):
        """Test var_find method searching by name."""
        uefi_command.name_guid = 'test_var'

        # Mock UEFI instance
        uefi_command._uefi = Mock()
        uefi_command._uefi.list_EFI_variables.return_value = {
            'test_var': [(0, b'', b'', b'test_data', '12345678-1234-1234-1234-123456789ABC', 0x7)]
        }

        with patch.object(uefi_command.logger, 'log') as mock_log, \
             patch.object(uefi_command.logger, 'log_good') as mock_log_good, \
             patch('chipsec.utilcmd.uefi_cmd.write_file') as mock_write_file:
            uefi_command.var_find()

            mock_log.assert_any_call("[*] Searching for UEFI variable with name test_var..")
            mock_log_good.assert_called_with("Found UEFI variable 12345678-1234-1234-1234-123456789ABC:test_var. Dumped to 'test_var_12345678-1234-1234-1234-123456789ABC_RT+AT_0.bin'")
            mock_write_file.assert_called_once()

    @pytest.mark.unit
    def test_var_find_by_guid(self, uefi_command, mock_cs):
        """Test var_find method searching by GUID."""
        uefi_command.name_guid = '12345678-1234-1234-1234-123456789ABC'

        # Mock UEFI instance
        uefi_command._uefi = Mock()
        uefi_command._uefi.list_EFI_variables.return_value = {
            'test_var': [(0, b'', b'', b'test_data', '12345678-1234-1234-1234-123456789ABC', 0x7)]
        }

        with patch.object(uefi_command.logger, 'log') as mock_log, \
             patch.object(uefi_command.logger, 'log_good') as mock_log_good, \
             patch('chipsec.utilcmd.uefi_cmd.write_file') as mock_write_file:
            uefi_command.var_find()

            mock_log.assert_any_call("[*] Searching for UEFI variable with GUID {12345678-1234-1234-1234-123456789ABC}..")
            mock_log_good.assert_called_with("Found UEFI variable 12345678-1234-1234-1234-123456789ABC:test_var. Dumped to 'test_var_12345678-1234-1234-1234-123456789ABC_RT+AT_0.bin'")
            mock_write_file.assert_called_once()

    @pytest.mark.unit
    def test_var_find_no_variables(self, uefi_command, mock_cs):
        """Test var_find method when no variables can be enumerated."""
        uefi_command.name_guid = 'test_var'

        # Mock UEFI instance
        uefi_command._uefi = Mock()
        uefi_command._uefi.list_EFI_variables.return_value = None

        with patch.object(uefi_command.logger, 'log_warning') as mock_log_warning:
            uefi_command.var_find()

            mock_log_warning.assert_called_with('Could not enumerate UEFI variables (non-UEFI OS?)')

    @pytest.mark.unit
    def test_nvram_auto_detect_success(self, uefi_command, mock_cs):
        """Test nvram method with successful auto-detection."""
        uefi_command.romfilename = 'test.rom'
        uefi_command.fwtype = None

        with patch('chipsec.utilcmd.uefi_cmd.read_file') as mock_read, \
             patch('chipsec.utilcmd.uefi_cmd.identify_EFI_NVRAM') as mock_identify, \
             patch('chipsec.utilcmd.uefi_cmd.parse_EFI_variables') as mock_parse, \
             patch.object(uefi_command.logger, 'set_log_file') as mock_set_log:
            mock_read.return_value = b'test_rom_data'
            mock_identify.return_value = 'vss'
            uefi_command.nvram()

            mock_identify.assert_called_once_with(b'test_rom_data')
            mock_parse.assert_called_once_with('test.rom', b'test_rom_data', 0, 'vss')

    @pytest.mark.unit
    def test_nvram_auto_detect_failure(self, uefi_command, mock_cs):
        """Test nvram method with auto-detection failure."""
        uefi_command.romfilename = 'test.rom'
        uefi_command.fwtype = None

        with patch('chipsec.utilcmd.uefi_cmd.read_file') as mock_read, \
             patch('chipsec.utilcmd.uefi_cmd.identify_EFI_NVRAM') as mock_identify, \
             patch.object(uefi_command.logger, 'log_error') as mock_log_error:
            mock_read.return_value = b'test_rom_data'
            mock_identify.return_value = None
            uefi_command.nvram()

            mock_log_error.assert_called_with("Could not automatically identify EFI NVRAM type")

    @pytest.mark.unit
    def test_nvram_invalid_fwtype(self, uefi_command, mock_cs):
        """Test nvram method with invalid firmware type."""
        uefi_command.romfilename = 'test.rom'
        uefi_command.fwtype = 'invalid_type'

        with patch('chipsec.utilcmd.uefi_cmd.fw_types', ['vss', 'evsa']), \
             patch.object(uefi_command.logger, 'log_error') as mock_log_error:
            uefi_command.nvram()

            mock_log_error.assert_called_with("Unrecognized EFI NVRAM type 'invalid_type'")

    @pytest.mark.unit
    def test_decode_file_not_found(self, uefi_command, mock_cs):
        """Test decode method when file doesn't exist."""
        uefi_command.filename = 'nonexistent.rom'

        with patch('chipsec.utilcmd.uefi_cmd.os.path.exists') as mock_exists, \
             patch.object(uefi_command.logger, 'log_error') as mock_log_error:
            mock_exists.return_value = False
            uefi_command.decode()

            mock_log_error.assert_called_with("Could not find file 'nonexistent.rom'")

    @pytest.mark.unit
    def test_decode_success(self, uefi_command, mock_cs):
        """Test decode method with success."""
        uefi_command.filename = 'test.rom'
        uefi_command.fwtype = 'vss'
        uefi_command.filetypes = ['FV_MM']

        with patch('chipsec.utilcmd.uefi_cmd.os.path.exists') as mock_exists, \
             patch('chipsec.utilcmd.uefi_cmd.decode_uefi_region') as mock_decode, \
             patch.object(uefi_command.logger, 'log') as mock_log, \
             patch.object(uefi_command.logger, 'set_log_file') as mock_set_log:
            mock_exists.return_value = True
            uefi_command.decode()

            mock_log.assert_any_call("[CHIPSEC] Parsing EFI volumes from 'test.rom'..")
            mock_decode.assert_called_once()

    @pytest.mark.unit
    def test_keys_file_not_found(self, uefi_command, mock_cs):
        """Test keys method when file doesn't exist."""
        uefi_command.filename = 'nonexistent.bin'

        with patch('chipsec.utilcmd.uefi_cmd.os.path.exists') as mock_exists, \
             patch.object(uefi_command.logger, 'log_error') as mock_log_error:
            mock_exists.return_value = False
            uefi_command.keys()

            mock_log_error.assert_called_with("Could not find file 'nonexistent.bin'")

    @pytest.mark.unit
    def test_keys_success(self, uefi_command, mock_cs):
        """Test keys method with success."""
        uefi_command.filename = 'test.bin'

        with patch('chipsec.utilcmd.uefi_cmd.os.path.exists') as mock_exists, \
             patch('chipsec.utilcmd.uefi_cmd.parse_efivar_file') as mock_parse, \
             patch.object(uefi_command.logger, 'log') as mock_log:
            mock_exists.return_value = True
            uefi_command.keys()

            mock_log.assert_any_call("[CHIPSEC] Parsing EFI variable from 'test.bin'..")
            mock_parse.assert_called_once_with('test.bin')

    @pytest.mark.unit
    def test_tables(self, uefi_command, mock_cs):
        """Test tables method."""
        # Mock UEFI instance
        uefi_command._uefi = Mock()

        with patch.object(uefi_command.logger, 'log') as mock_log:
            uefi_command.tables()

            mock_log.assert_called_with("[CHIPSEC] Searching memory for and dumping EFI tables (this may take a minute)..\n")
            uefi_command._uefi.dump_EFI_tables.assert_called_once()

    @pytest.mark.unit
    def test_s3bootscript_with_address(self, uefi_command, mock_cs):
        """Test s3bootscript method with specific address."""
        uefi_command.bootscript_pa = 0x1000

        with patch.object(uefi_command.logger, 'log') as mock_log, \
             patch('chipsec.utilcmd.uefi_cmd.parse_script') as mock_parse:
            uefi_command.s3bootscript()

            mock_log.assert_any_call('[*] Reading S3 boot-script from memory at 0x0000000000001000..')
            mock_cs.hals.Memory.read_physical_mem.assert_called_once_with(0x1000, 0x100000)
            mock_parse.assert_called_once()

    @pytest.mark.unit
    def test_s3bootscript_without_address(self, uefi_command, mock_cs):
        """Test s3bootscript method without specific address."""
        uefi_command.bootscript_pa = None

        # Mock UEFI instance
        uefi_command._uefi = Mock()

        with patch.object(uefi_command.logger, 'log') as mock_log:
            uefi_command.s3bootscript()

            mock_log.assert_called_with("[CHIPSEC] Searching for and parsing S3 resume bootscripts..")
            uefi_command._uefi.get_s3_bootscript.assert_called_once_with(True)

    @pytest.mark.unit
    def test_insert_before_invalid_guid(self, uefi_command, mock_cs):
        """Test insert_before method with invalid GUID."""
        uefi_command.guid = 'invalid-guid'

        with patch('chipsec.utilcmd.uefi_cmd.get_guid_bin') as mock_get_guid, \
             patch.object(uefi_command.logger, 'log_bad') as mock_log_bad:
            mock_get_guid.return_value = ''
            uefi_command.insert_before()

            mock_log_bad.assert_called_with('*** Error *** Invalid GUID: invalid-guid')

    @pytest.mark.unit
    def test_insert_before_file_not_found(self, uefi_command, mock_cs):
        """Test insert_before method when ROM file doesn't exist."""
        uefi_command.guid = '12345678-1234-1234-1234-123456789ABC'
        uefi_command.rom_file = 'nonexistent.rom'

        with patch('chipsec.utilcmd.uefi_cmd.get_guid_bin') as mock_get_guid, \
             patch('chipsec.utilcmd.uefi_cmd.os.path.isfile') as mock_isfile, \
             patch.object(uefi_command.logger, 'log_bad') as mock_log_bad:
            mock_get_guid.return_value = b'guid_bytes'
            mock_isfile.return_value = False
            uefi_command.insert_before()

            mock_log_bad.assert_called_with("*** Error *** File doesn't exist: nonexistent.rom")

    @pytest.mark.unit
    def test_insert_before_success(self, uefi_command, mock_cs):
        """Test insert_before method with success."""
        uefi_command.guid = '12345678-1234-1234-1234-123456789ABC'
        uefi_command.rom_file = 'test.rom'
        uefi_command.efi_file = 'test.efi'
        uefi_command.new_file = 'new.rom'

        with patch('chipsec.utilcmd.uefi_cmd.get_guid_bin') as mock_get_guid, \
             patch('chipsec.utilcmd.uefi_cmd.os.path.isfile') as mock_isfile, \
             patch('chipsec.utilcmd.uefi_cmd.read_file') as mock_read, \
             patch('chipsec.utilcmd.uefi_cmd.modify_uefi_region') as mock_modify, \
             patch('chipsec.utilcmd.uefi_cmd.write_file') as mock_write:
            mock_get_guid.return_value = b'guid_bytes'
            mock_isfile.return_value = True
            mock_read.side_effect = [b'rom_data', b'efi_data']
            mock_modify.return_value = b'modified_data'

            uefi_command.insert_before()

            mock_modify.assert_called_once()
            mock_write.assert_called_once_with('new.rom', b'modified_data')

    @pytest.mark.unit
    def test_replace_success(self, uefi_command, mock_cs):
        """Test replace method with success."""
        uefi_command.guid = '12345678-1234-1234-1234-123456789ABC'
        uefi_command.rom_file = 'test.rom'
        uefi_command.efi_file = 'test.efi'
        uefi_command.new_file = 'new.rom'

        with patch('chipsec.utilcmd.uefi_cmd.get_guid_bin') as mock_get_guid, \
             patch('chipsec.utilcmd.uefi_cmd.os.path.isfile') as mock_isfile, \
             patch('chipsec.utilcmd.uefi_cmd.read_file') as mock_read, \
             patch('chipsec.utilcmd.uefi_cmd.modify_uefi_region') as mock_modify, \
             patch('chipsec.utilcmd.uefi_cmd.write_file') as mock_write:
            mock_get_guid.return_value = b'guid_bytes'
            mock_isfile.return_value = True
            mock_read.side_effect = [b'rom_data', b'efi_data']
            mock_modify.return_value = b'modified_data'

            uefi_command.replace()

            mock_modify.assert_called_once()
            mock_write.assert_called_once_with('new.rom', b'modified_data')

    @pytest.mark.unit
    def test_remove_success(self, uefi_command, mock_cs):
        """Test remove method with success."""
        uefi_command.guid = '12345678-1234-1234-1234-123456789ABC'
        uefi_command.rom_file = 'test.rom'
        uefi_command.new_file = 'new.rom'

        with patch('chipsec.utilcmd.uefi_cmd.get_guid_bin') as mock_get_guid, \
             patch('chipsec.utilcmd.uefi_cmd.os.path.isfile') as mock_isfile, \
             patch('chipsec.utilcmd.uefi_cmd.read_file') as mock_read, \
             patch('chipsec.utilcmd.uefi_cmd.modify_uefi_region') as mock_modify, \
             patch('chipsec.utilcmd.uefi_cmd.write_file') as mock_write:
            mock_get_guid.return_value = b'guid_bytes'
            mock_isfile.return_value = True
            mock_read.return_value = b'rom_data'
            mock_modify.return_value = b'modified_data'

            uefi_command.remove()

            mock_modify.assert_called_once()
            mock_write.assert_called_once_with('new.rom', b'modified_data')

    @pytest.mark.unit
    def test_assemble_invalid_guid(self, uefi_command, mock_cs):
        """Test assemble method with invalid GUID."""
        uefi_command.guid = 'invalid-guid'

        with patch('chipsec.utilcmd.uefi_cmd.get_guid_bin') as mock_get_guid, \
             patch.object(uefi_command.logger, 'log_bad') as mock_log_bad:
            mock_get_guid.return_value = ''
            uefi_command.assemble()

            mock_log_bad.assert_called_with('*** Error *** Invalid GUID: invalid-guid')

    @pytest.mark.unit
    def test_assemble_file_not_found(self, uefi_command, mock_cs):
        """Test assemble method when raw file doesn't exist."""
        uefi_command.guid = '12345678-1234-1234-1234-123456789ABC'
        uefi_command.raw_file = 'nonexistent.raw'

        with patch('chipsec.utilcmd.uefi_cmd.get_guid_bin') as mock_get_guid, \
             patch('chipsec.utilcmd.uefi_cmd.os.path.isfile') as mock_isfile, \
             patch.object(uefi_command.logger, 'log_bad') as mock_log_bad:
            mock_get_guid.return_value = b'guid_bytes'
            mock_isfile.return_value = False
            uefi_command.assemble()

            mock_log_bad.assert_called_with("*** Error *** File doesn't exist: nonexistent.raw")

    @pytest.mark.unit
    def test_assemble_invalid_compression(self, uefi_command, mock_cs):
        """Test assemble method with invalid compression."""
        uefi_command.guid = '12345678-1234-1234-1234-123456789ABC'
        uefi_command.raw_file = 'test.raw'
        uefi_command.comp = 'invalid_comp'

        with patch('chipsec.utilcmd.uefi_cmd.get_guid_bin') as mock_get_guid, \
             patch('chipsec.utilcmd.uefi_cmd.os.path.isfile') as mock_isfile, \
             patch.object(uefi_command.logger, 'log_bad') as mock_log_bad:
            mock_get_guid.return_value = b'guid_bytes'
            mock_isfile.return_value = True
            uefi_command.assemble()

            mock_log_bad.assert_called_with("*** Error *** Unknown compression: invalid_comp")

    @pytest.mark.unit
    def test_assemble_invalid_file_type(self, uefi_command, mock_cs):
        """Test assemble method with invalid file type."""
        uefi_command.guid = '12345678-1234-1234-1234-123456789ABC'
        uefi_command.raw_file = 'test.raw'
        uefi_command.comp = 'none'
        uefi_command.file_type = 'invalid_type'

        with patch('chipsec.utilcmd.uefi_cmd.get_guid_bin') as mock_get_guid, \
             patch('chipsec.utilcmd.uefi_cmd.os.path.isfile') as mock_isfile, \
             patch.object(uefi_command.logger, 'log_bad') as mock_log_bad:
            mock_get_guid.return_value = b'guid_bytes'
            mock_isfile.return_value = True
            uefi_command.assemble()

            mock_log_bad.assert_called_with("*** Error *** Unknow file type: invalid_type")

    @pytest.mark.unit
    def test_assemble_freeform_success(self, uefi_command, mock_cs):
        """Test assemble method with freeform file type success."""
        uefi_command.guid = '12345678-1234-1234-1234-123456789ABC'
        uefi_command.raw_file = 'test.raw'
        uefi_command.efi_file = 'test.efi'
        uefi_command.comp = 'none'
        uefi_command.file_type = 'freeform'

        with patch('chipsec.utilcmd.uefi_cmd.get_guid_bin') as mock_get_guid, \
             patch('chipsec.utilcmd.uefi_cmd.os.path.isfile') as mock_isfile, \
             patch('chipsec.utilcmd.uefi_cmd.read_file') as mock_read, \
             patch('chipsec.utilcmd.uefi_cmd.assemble_uefi_raw') as mock_assemble_raw, \
             patch('chipsec.utilcmd.uefi_cmd.assemble_uefi_file') as mock_assemble_file, \
             patch('chipsec.utilcmd.uefi_cmd.write_file') as mock_write, \
             patch.object(uefi_command.logger, 'log') as mock_log:
            mock_get_guid.return_value = b'guid_bytes'
            mock_isfile.return_value = True
            mock_read.return_value = b'raw_data'
            mock_assemble_raw.return_value = b'wrapped_data'
            mock_assemble_file.return_value = b'uefi_data'

            uefi_command.assemble()

            mock_log.assert_called_with("[CHIPSEC]  UEFI file was successfully assembled! Binary file size: 8, compressed UEFI file size: 9")

    @pytest.mark.unit
    def test_run_success(self, uefi_command, mock_cs):
        """Test run method with successful execution."""
        # Mock successful function execution
        uefi_command.func = Mock()

        uefi_command.run()

        # Should call the function and set exit code to OK
        uefi_command.func.assert_called_once()
        assert uefi_command.ExitCode.name == "OK"

    @pytest.mark.unit
    def test_run_exception(self, uefi_command, mock_cs):
        """Test run method with exception during execution."""
        # Mock function to raise exception
        uefi_command.func = Mock(side_effect=Exception("Test exception"))

        uefi_command.run()

        # Should call the function and set exit code to ERROR
        uefi_command.func.assert_called_once()
        assert uefi_command.ExitCode.name == "ERROR"


class TestUEFICommandIntegration:
    """Integration tests for UEFI command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for UEFI testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock UEFI-related components with realistic data
        cs_mock.hals = Mock()
        cs_mock.hals.Memory = Mock()
        cs_mock.hals.UEFI = Mock()

        # Mock OS helper
        cs_mock.os_helper = Mock()
        cs_mock.os_helper.getcwd.return_value = "/tmp"

        return cs_mock

    @pytest.mark.integration
    def test_var_operations_workflow(self, integrated_cs):
        """Test complete variable operations workflow."""
        # Test var-read
        read_cmd = UEFICommand(['var-read', 'SecureBoot', '8be4df61-93ca-11d2-aa0d-00e098032b8c', 'secureboot.bin'], cs=integrated_cs)
        read_cmd.parse_arguments()
        read_cmd.set_up()

        with patch.object(read_cmd.logger, 'log'):
            read_cmd.run()
            read_cmd._uefi.get_EFI_variable.assert_called_once_with('SecureBoot', '8be4df61-93ca-11d2-aa0d-00e098032b8c', 'secureboot.bin')

        # Test var-write
        write_cmd = UEFICommand(['var-write', 'TestVar', '12345678-1234-1234-1234-123456789ABC', 'test.bin'], cs=integrated_cs)
        write_cmd.parse_arguments()
        write_cmd.set_up()
        write_cmd._uefi.set_EFI_variable_from_file.return_value = 0

        with patch.object(write_cmd.logger, 'log'):
            write_cmd.run()
            write_cmd._uefi.set_EFI_variable_from_file.assert_called_once_with('TestVar', '12345678-1234-1234-1234-123456789ABC', 'test.bin')

    @pytest.mark.integration
    def test_nvram_operations_workflow(self, integrated_cs):
        """Test complete NVRAM operations workflow."""
        nvram_cmd = UEFICommand(['nvram', 'test.rom', 'vss'], cs=integrated_cs)
        nvram_cmd.parse_arguments()

        with patch('chipsec.utilcmd.uefi_cmd.read_file') as mock_read, \
             patch('chipsec.utilcmd.uefi_cmd.identify_EFI_NVRAM') as mock_identify, \
             patch('chipsec.utilcmd.uefi_cmd.parse_EFI_variables') as mock_parse, \
             patch.object(nvram_cmd.logger, 'set_log_file'):
            mock_read.return_value = b'test_rom_data'
            mock_identify.return_value = 'vss'

            nvram_cmd.run()

            mock_parse.assert_called_once_with('test.rom', b'test_rom_data', 0, 'vss')

    @pytest.mark.integration
    def test_decode_operations_workflow(self, integrated_cs):
        """Test complete decode operations workflow."""
        decode_cmd = UEFICommand(['decode', 'test.rom'], cs=integrated_cs)
        decode_cmd.parse_arguments()

        with patch('chipsec.utilcmd.uefi_cmd.os.path.exists') as mock_exists, \
             patch('chipsec.utilcmd.uefi_cmd.decode_uefi_region') as mock_decode, \
             patch.object(decode_cmd.logger, 'set_log_file'):
            mock_exists.return_value = True

            decode_cmd.run()

            mock_decode.assert_called_once()


class TestUEFICommandEdgeCases:
    """Test edge cases and error conditions for UEFI command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.hals = Mock()
        cs_mock.hals.Memory = Mock()
        cs_mock.hals.UEFI = Mock()
        cs_mock.os_helper = Mock()
        cs_mock.os_helper.getcwd.return_value = "/tmp"
        return cs_mock

    @pytest.mark.unit
    def test_var_find_invalid_uuid(self, mock_cs):
        """Test var_find with invalid UUID format."""
        command = UEFICommand(['var-find', 'invalid-uuid'], cs=mock_cs)
        command.parse_arguments()

        # Mock UEFI instance
        command._uefi = Mock()
        command._uefi.list_EFI_variables.return_value = None

        with patch.object(command.logger, 'log_warning'):
            command.var_find()
            # Should handle invalid UUID gracefully

    @pytest.mark.unit
    def test_nvram_auth_workflow(self, mock_cs):
        """Test nvram-auth method workflow."""
        command = UEFICommand(['nvram-auth', 'test.rom'], cs=mock_cs)
        command.parse_arguments()

        with patch('chipsec.utilcmd.uefi_cmd.read_file') as mock_read, \
             patch('chipsec.utilcmd.uefi_cmd.identify_EFI_NVRAM') as mock_identify, \
             patch('chipsec.utilcmd.uefi_cmd.parse_EFI_variables') as mock_parse, \
             patch.object(command.logger, 'set_log_file'):
            mock_read.return_value = b'test_rom_data'
            mock_identify.return_value = 'vss_auth'

            command.run()

            mock_parse.assert_called_once_with('test.rom', b'test_rom_data', 1, 'vss_auth')

    @pytest.mark.unit
    def test_assemble_with_compression(self, mock_cs):
        """Test assemble method with compression enabled."""
        command = UEFICommand(['assemble', '12345678-1234-1234-1234-123456789ABC', 'freeform', 'lzma', 'input.raw', 'output.efi'], cs=mock_cs)
        command.parse_arguments()

        with patch('chipsec.utilcmd.uefi_cmd.get_guid_bin') as mock_get_guid, \
             patch('chipsec.utilcmd.uefi_cmd.os.path.isfile') as mock_isfile, \
             patch('chipsec.utilcmd.uefi_cmd.read_file') as mock_read, \
             patch('chipsec.utilcmd.uefi_cmd.assemble_uefi_raw') as mock_assemble_raw, \
             patch('chipsec.utilcmd.uefi_cmd.compress_image') as mock_compress, \
             patch('chipsec.utilcmd.uefi_cmd.assemble_uefi_section') as mock_assemble_section, \
             patch('chipsec.utilcmd.uefi_cmd.assemble_uefi_file') as mock_assemble_file, \
             patch('chipsec.utilcmd.uefi_cmd.write_file') as mock_write:
            mock_get_guid.return_value = b'guid_bytes'
            mock_isfile.return_value = True
            mock_read.return_value = b'raw_data'
            mock_assemble_raw.return_value = b'wrapped_data'
            mock_compress.return_value = b'compressed_data'
            mock_assemble_section.return_value = b'section_data'
            mock_assemble_file.return_value = b'uefi_data'

            command.run()

            mock_compress.assert_called_once()
            mock_assemble_section.assert_called_once()


class TestUEFICommandConfigurationValidation:
    """Test configuration validation aspects of UEFI command."""

    @pytest.fixture
    def uefi_cs(self):
        """Create ChipsecCs with UEFI-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock UEFI configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.UEFI = {
            'UEFI_BASE': 0x100000,
            'UEFI_SIZE': 0x100000,
            'NVRAM_BASE': 0x200000,
            'NVRAM_SIZE': 0x10000
        }

        cs_mock.hals = Mock()
        cs_mock.hals.Memory = Mock()
        cs_mock.hals.UEFI = Mock()

        return cs_mock

    @pytest.mark.unit
    def test_uefi_configuration_structure(self, uefi_cs):
        """Test UEFI configuration structure."""
        uefi_config = uefi_cs.Cfg.UEFI

        # Test that required UEFI configuration exists
        assert 'UEFI_BASE' in uefi_config
        assert 'UEFI_SIZE' in uefi_config

        # Test configuration values are reasonable
        assert uefi_config['UEFI_BASE'] > 0
        assert uefi_config['UEFI_SIZE'] > 0

    @pytest.mark.unit
    def test_uefi_memory_regions(self, uefi_cs):
        """Test UEFI memory region configuration."""
        uefi_config = uefi_cs.Cfg.UEFI

        # Test memory regions don't overlap
        if 'NVRAM_BASE' in uefi_config and 'UEFI_BASE' in uefi_config:
            assert uefi_config['NVRAM_BASE'] != uefi_config['UEFI_BASE']


if __name__ == '__main__':
    pytest.main([__file__])
