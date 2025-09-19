# Tests for UEFICommand variable enumeration and search logic
# Focus: var_list (None path), var_find by GUID and name, attribute formatting,
# nvram type detection failures.

import pytest
from unittest.mock import Mock, patch

from chipsec.utilcmd.uefi_cmd import UEFICommand

class DummyCS:
    class DummyLogger:
        def __init__(self):
            self.records = []
            self.DEBUG = False
            self.LOG_FILE_NAME = 'log'
        def log(self, msg):
            self.records.append(('log', msg))
        def log_good(self, msg):
            self.records.append(('good', msg))
        def log_error(self, msg):
            self.records.append(('error', msg))
        def log_warning(self, msg):
            self.records.append(('warn', msg))
        def log_important(self, msg):
            self.records.append(('important', msg))
        def set_log_file(self, name, *_):
            self.LOG_FILE_NAME = name
    def __init__(self):
        self.os_helper = Mock(getcwd=lambda: '.')
        self.logger = self.DummyLogger()

@pytest.fixture
def cmd():
    cs = DummyCS()
    # UEFICommand expects argv list as first positional argument, chipsec context via kw 'cs'
    c = UEFICommand([], cs=cs)
    # Replace logger with dummy so we can inspect messages deterministically
    c.logger = cs.logger
    return c

# ---------------------------------------------------------------------------
# var_list: enumeration returns None
# ---------------------------------------------------------------------------
@pytest.mark.unit
def test_var_list_none(cmd):
    cmd._uefi = Mock(list_EFI_variables=Mock(return_value=None))
    cmd.var_list()
    # Records are tuples (level, message)
    assert any('Could not enumerate EFI Variables' in msg for level, msg in cmd.logger.records if level == 'important')

# ---------------------------------------------------------------------------
# var_find by GUID and name
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_vars():
    # Structure per var_list: mapping name -> list of tuples (off, buf, hdr, data, guid, attrs)
    return {
        'PK': [(0, b'', b'', b'PKDATA', 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE', 0x3)],
        'db': [(0, b'', b'', b'DBDATA', 'D719B2CB-3D3A-4596-A3BC-DAD00E67656F', 0x3)]
    }

@pytest.mark.unit
def test_var_find_guid(cmd, sample_vars, tmp_path):
    cmd._uefi = Mock(list_EFI_variables=Mock(return_value=sample_vars))
    cmd.name_guid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'  # lower-case input
    with patch('chipsec.utilcmd.uefi_cmd.write_file') as wf:
        cmd.var_find()
    # Ensure GUID path searched normalized to uppercase in log
    assert any('Searching for UEFI variable with GUID {AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}' in msg for _, msg in cmd.logger.records)
        # File written with expected name pattern (attrs 0x3 => RT+AT)
    wf.assert_called()
    args, _ = wf.call_args
    assert 'PK_AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE_RT+AT_0.bin' in args[0]

@pytest.mark.unit
def test_var_find_name(cmd, sample_vars, tmp_path):
    cmd._uefi = Mock(list_EFI_variables=Mock(return_value=sample_vars))
    cmd.name_guid = 'db'
    with patch('chipsec.utilcmd.uefi_cmd.write_file') as wf:
        cmd.var_find()
    wf.assert_called()
    args, _ = wf.call_args
    assert args[0].startswith('db_D719B2CB-3D3A-4596-A3BC-DAD00E67656F_RT+AT_0.bin')

# ---------------------------------------------------------------------------
# _format_attr_string deterministic ordering
# ---------------------------------------------------------------------------
@pytest.mark.unit
def test_format_attr_string(cmd):
    # Directly call helper through command instance
    result = cmd._format_attr_string(0x3)
    assert result == 'RT+AT'

# ---------------------------------------------------------------------------
# nvram type detection failures
# ---------------------------------------------------------------------------
@pytest.mark.unit
def test_nvram_unidentified_type(cmd, tmp_path):
    fake_rom = tmp_path / 'rom.bin'
    fake_rom.write_bytes(b'RANDOMDATA')
    cmd.romfilename = str(fake_rom)
    cmd.fwtype = None
    # identify_EFI_NVRAM returns None
    with patch('chipsec.utilcmd.uefi_cmd.read_file', return_value=b'RANDOMDATA'):
        with patch('chipsec.utilcmd.uefi_cmd.identify_EFI_NVRAM', return_value=None):
            cmd.nvram()
    assert any('Could not automatically identify EFI NVRAM type' in m for t, m in cmd.logger.records if t == 'error')

@pytest.mark.unit
def test_nvram_invalid_type(cmd, tmp_path):
    fake_rom = tmp_path / 'rom.bin'
    fake_rom.write_bytes(b'RANDOMDATA')
    cmd.romfilename = str(fake_rom)
    cmd.fwtype = 'bogus'
    with patch('chipsec.utilcmd.uefi_cmd.read_file', return_value=b'RANDOMDATA'):
        cmd.nvram()
    assert any("Unrecognized EFI NVRAM type 'bogus'" in m for t, m in cmd.logger.records if t == 'error')


# ---------------------------------------------------------------------------
# Additional coverage: nvram_auth auto-detect failure / invalid type, insert-after success,
# decode with unmatched filetype filter (no selected types appended)
# ---------------------------------------------------------------------------

 
@pytest.mark.unit
def test_nvram_auth_auto_detect_failure(cmd, tmp_path):
    fake_rom = tmp_path / 'rom.bin'
    fake_rom.write_bytes(b'RANDOMDATA')
    cmd.romfilename = str(fake_rom)
    cmd.fwtype = None
    with patch('chipsec.utilcmd.uefi_cmd.read_file', return_value=b'RANDOMDATA'):
        with patch('chipsec.utilcmd.uefi_cmd.identify_EFI_NVRAM', return_value=None):
            cmd.nvram_auth()
    assert any('Could not automatically identify EFI NVRAM type' in m for t, m in cmd.logger.records if t == 'error')

 
@pytest.mark.unit
def test_nvram_auth_invalid_type(cmd, tmp_path):
    fake_rom = tmp_path / 'rom.bin'
    fake_rom.write_bytes(b'RANDOMDATA')
    cmd.romfilename = str(fake_rom)
    cmd.fwtype = 'weird'
    with patch('chipsec.utilcmd.uefi_cmd.read_file', return_value=b'RANDOMDATA'):
        cmd.nvram_auth()
    assert any("Unrecognized EFI NVRAM type 'weird'" in m for t, m in cmd.logger.records if t == 'error')

 
@pytest.mark.unit
def test_insert_after_success(cmd, tmp_path):
    # Leverage existing logic in command file by constructing minimal state
    cmd.guid = '12345678-1234-1234-1234-123456789ABC'
    cmd.rom_file = str(tmp_path / 'rom.bin')
    cmd.efi_file = str(tmp_path / 'drv.efi')
    cmd.new_file = str(tmp_path / 'newrom.bin')
    (tmp_path / 'rom.bin').write_bytes(b'OLDROM')
    (tmp_path / 'drv.efi').write_bytes(b'DRV')
    with patch('chipsec.utilcmd.uefi_cmd.get_guid_bin', return_value=b'guidbytes'), \
         patch('chipsec.utilcmd.uefi_cmd.read_file', side_effect=[b'OLDROM', b'DRV']), \
         patch('chipsec.utilcmd.uefi_cmd.modify_uefi_region', return_value=b'NEWDATA') as mod_fn, \
         patch('chipsec.utilcmd.uefi_cmd.write_file') as wfn, \
         patch('chipsec.utilcmd.uefi_cmd.os.path.isfile', return_value=True):
        cmd.insert_after()
        mod_fn.assert_called_once()
        wfn.assert_called_once()

 
@pytest.mark.unit
def test_decode_unmatched_filetype_filter(cmd, tmp_path):
    # When a provided filetype isn't in FILE_TYPE_NAMES values, loop won't append
    rom = tmp_path / 'bios.rom'
    rom.write_bytes(b'FAKEBIOS')
    cmd.filename = str(rom)
    cmd.fwtype = None
    cmd.filetypes = ['NON_EXISTENT_TYPE']
    # Provide inv map via actual module (already imported). Just ensure decode_uefi_region still called with empty ftypes list.
    with patch('chipsec.utilcmd.uefi_cmd.os.path.exists', return_value=True), \
         patch('chipsec.utilcmd.uefi_cmd.decode_uefi_region') as dec, \
         patch.object(cmd.logger, 'set_log_file'):
        cmd.decode()
        # ftypes should be []
        # We can't directly inspect local ftypes; instead assert decode called with None fwtype and list []
        args, kwargs = dec.call_args
        assert args[3] == []
