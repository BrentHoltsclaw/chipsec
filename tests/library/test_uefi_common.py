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
from chipsec.library.uefi.common import (
    StatusCode, EFI_STATUS_DICT, EFI_MAX_BIT, EFI_ERROR_STR,
    EFI_GUID_STR, align, bit_set, get_3b_size,
    EFI_TABLE_HEADER, EFI_SYSTEM_TABLE, EFI_RUNTIME_SERVICES_TABLE,
    EFI_BOOT_SERVICES_TABLE, EFI_DXE_SERVICES_TABLE,
    EFI_VENDOR_TABLE, EFI_CONFIGURATION_TABLE,
    EFI_SYSTEM_TABLE_SIGNATURE, EFI_RUNTIME_SERVICES_SIGNATURE,
    EFI_BOOT_SERVICES_SIGNATURE, EFI_DXE_SERVICES_TABLE_SIGNATURE,
    EFI_SYSTEM_TABLE_REVISION, EFI_TABLES
)


class TestEFIStatusCodes:
    """Test EFI status code functionality."""

    @pytest.mark.unit
    def test_status_code_constants(self):
        """Test EFI status code constants are properly defined."""
        assert StatusCode.EFI_SUCCESS == 0
        assert StatusCode.EFI_NOT_FOUND == 14
        assert StatusCode.EFI_ACCESS_DENIED == 15
        assert StatusCode.EFI_SECURITY_VIOLATION == 26

    @pytest.mark.unit
    def test_efi_status_dict(self):
        """Test EFI_STATUS_DICT contains expected mappings."""
        assert len(EFI_STATUS_DICT) == 33
        assert EFI_STATUS_DICT[StatusCode.EFI_SUCCESS] == "EFI_SUCCESS"
        assert EFI_STATUS_DICT[StatusCode.EFI_NOT_FOUND] == "EFI_NOT_FOUND"
        assert EFI_STATUS_DICT[StatusCode.EFI_SECURITY_VIOLATION] == "EFI_SECURITY_VIOLATION"

    @pytest.mark.unit
    def test_efi_error_str_success(self):
        """Test EFI_ERROR_STR with success code."""
        result = EFI_ERROR_STR(StatusCode.EFI_SUCCESS)
        assert result == "EFI_SUCCESS"

    @pytest.mark.unit
    def test_efi_error_str_error_code(self):
        """Test EFI_ERROR_STR with error code."""
        error_code = StatusCode.EFI_NOT_FOUND | EFI_MAX_BIT
        result = EFI_ERROR_STR(error_code)
        assert result == "EFI_NOT_FOUND"

    @pytest.mark.unit
    def test_efi_error_str_unknown(self):
        """Test EFI_ERROR_STR with unknown error code."""
        result = EFI_ERROR_STR(999)
        assert result == "UNKNOWN"

    @pytest.mark.unit
    def test_efi_max_bit_constant(self):
        """Test EFI_MAX_BIT constant."""
        assert EFI_MAX_BIT == 0x8000000000000000


class TestEFIFunctions:
    """Test EFI utility functions."""

    @pytest.mark.unit
    def test_efi_guid_str(self):
        """Test EFI_GUID_STR function."""
        # Test with a known GUID (little-endian bytes)
        guid_bytes = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78\x9a\xbc\xde\xf0'
        result = EFI_GUID_STR(guid_bytes)
        # Should return uppercase string representation
        assert isinstance(result, str)
        assert len(result) == 36  # UUID string length
        assert result == result.upper()

    @pytest.mark.unit
    def test_align_function(self):
        """Test align function."""
        # Test various alignments
        assert align(0, 4) == 0
        assert align(1, 4) == 4
        assert align(3, 4) == 4
        assert align(4, 4) == 4
        assert align(5, 4) == 8
        assert align(10, 8) == 16

    @pytest.mark.unit
    def test_bit_set_function(self):
        """Test bit_set function."""
        value = 0b1010  # Binary: 1010

        # Test with polarity=False (normal)
        assert bit_set(value, 0b0010) is True   # Bit 1 is set
        assert bit_set(value, 0b0100) is False  # Bit 2 is not set
        assert bit_set(value, 0b1010) is True   # All bits match
        assert bit_set(value, 0b1111) is False  # Not all bits match

        # Test with polarity=True (inverted)
        assert bit_set(value, 0b0100, polarity=True) is True   # Inverted bit 2 is set
        assert bit_set(value, 0b0010, polarity=True) is False  # Inverted bit 1 is not set

    @pytest.mark.unit
    def test_get_3b_size(self):
        """Test get_3b_size function."""
        # Test with 3 bytes representing size 0x123456
        data = b'\x56\x34\x12'
        result = get_3b_size(data)
        assert result == 0x123456

        # Test with smaller values
        data = b'\x01\x00\x00'
        result = get_3b_size(data)
        assert result == 0x000001


class TestEFITableHeaders:
    """Test EFI table header structures."""

    @pytest.mark.unit
    def test_efi_table_header_creation(self):
        """Test EFI_TABLE_HEADER creation and string representation."""
        header = EFI_TABLE_HEADER(
            Signature=b'SYSTIBI',
            Revision=0x00020080,
            HeaderSize=0x5C,
            CRC32=0x12345678,
            Reserved=0x00000000
        )

        assert header.Signature == b'SYSTIBI'
        assert header.Revision == 0x00020080
        assert header.HeaderSize == 0x5C
        assert header.CRC32 == 0x12345678
        assert header.Reserved == 0x00000000

        # Test string representation contains key information
        header_str = str(header)
        assert 'SYSTIBI' in header_str
        assert '2.128' in header_str  # Revision formatting
        assert '0x0000005C' in header_str

    @pytest.mark.unit
    def test_efi_system_table_creation(self):
        """Test EFI_SYSTEM_TABLE creation."""
        table = EFI_SYSTEM_TABLE(
            FirmwareVendor=0x1000,
            FirmwareRevision=0x2000,
            ConsoleInHandle=0x3000,
            ConIn=0x4000,
            ConsoleOutHandle=0x5000,
            ConOut=0x6000,
            StandardErrorHandle=0x7000,
            StdErr=0x8000,
            RuntimeServices=0x9000,
            BootServices=0xA000,
            NumberOfTableEntries=0xB000,
            ConfigurationTable=0xC000
        )

        assert table.FirmwareVendor == 0x1000
        assert table.RuntimeServices == 0x9000
        assert table.BootServices == 0xA000

    @pytest.mark.unit
    def test_efi_runtime_services_table_creation(self):
        """Test EFI_RUNTIME_SERVICES_TABLE creation."""
        table = EFI_RUNTIME_SERVICES_TABLE(
            GetTime=0x1000, SetTime=0x2000, GetWakeupTime=0x3000,
            SetWakeupTime=0x4000, SetVirtualAddressMap=0x5000,
            ConvertPointer=0x6000, GetVariable=0x7000,
            GetNextVariableName=0x8000, SetVariable=0x9000,
            GetNextHighMonotonicCount=0xA000, ResetSystem=0xB000,
            UpdateCapsule=0xC000, QueryCapsuleCapabilities=0xD000,
            QueryVariableInfo=0xE000
        )

        assert table.GetVariable == 0x7000
        assert table.SetVariable == 0x9000
        assert table.ResetSystem == 0xB000

    @pytest.mark.unit
    def test_efi_boot_services_table_creation(self):
        """Test EFI_BOOT_SERVICES_TABLE creation."""
        # Create with minimal required fields for testing
        table = EFI_BOOT_SERVICES_TABLE(
            RaiseTPL=0x1000, RestoreTPL=0x2000, AllocatePages=0x3000,
            FreePages=0x4000, GetMemoryMap=0x5000, AllocatePool=0x6000,
            FreePool=0x7000, CreateEvent=0x8000, SetTimer=0x9000,
            WaitForEvent=0xA000, SignalEvent=0xB000, CloseEvent=0xC000,
            CheckEvent=0xD000, InstallProtocolInterface=0xE000,
            ReinstallProtocolInterface=0xF000, UninstallProtocolInterface=0x10000,
            HandleProtocol=0x11000, Reserved=0x12000,
            RegisterProtocolNotify=0x13000, LocateHandle=0x14000,
            LocateDevicePath=0x15000, InstallConfigurationTable=0x16000,
            LoadImage=0x17000, StartImage=0x18000, Exit=0x19000,
            UnloadImage=0x1A000, ExitBootServices=0x1B000,
            GetNextMonotonicCount=0x1C000, Stall=0x1D000,
            SetWatchdogTimer=0x1E000, ConnectController=0x1F000,
            DisconnectController=0x20000, OpenProtocol=0x21000,
            CloseProtocol=0x22000, OpenProtocolInformation=0x23000,
            ProtocolsPerHandle=0x24000, LocateHandleBuffer=0x25000,
            LocateProtocol=0x26000, InstallMultipleProtocolInterfaces=0x27000,
            UninstallMultipleProtocolInterfaces=0x28000, CalculateCrc32=0x29000,
            CopyMem=0x2A000, SetMem=0x2B000, CreateEventEx=0x2C000
        )

        assert table.AllocatePages == 0x3000
        assert table.ExitBootServices == 0x1B000
        assert table.LocateProtocol == 0x26000

    @pytest.mark.unit
    def test_efi_dxe_services_table_creation(self):
        """Test EFI_DXE_SERVICES_TABLE creation."""
        table = EFI_DXE_SERVICES_TABLE(
            AddMemorySpace=0x1000, AllocateMemorySpace=0x2000,
            FreeMemorySpace=0x3000, RemoveMemorySpace=0x4000,
            GetMemorySpaceDescriptor=0x5000, SetMemorySpaceAttributes=0x6000,
            GetMemorySpaceMap=0x7000, AddIoSpace=0x8000,
            AllocateIoSpace=0x9000, FreeIoSpace=0xA000,
            RemoveIoSpace=0xB000, GetIoSpaceDescriptor=0xC000,
            GetIoSpaceMap=0xD000, Dispatch=0xE000,
            Schedule=0xF000, Trust=0x10000, ProcessFirmwareVolume=0x11000
        )

        assert table.AddMemorySpace == 0x1000
        assert table.Dispatch == 0xE000
        assert table.ProcessFirmwareVolume == 0x11000


class TestEFIVendorTable:
    """Test EFI vendor table functionality."""

    @pytest.mark.unit
    def test_efi_vendor_table_creation(self):
        """Test EFI_VENDOR_TABLE creation."""
        guid_data = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78\x9a\xbc\xde\xf0'
        table = EFI_VENDOR_TABLE(
            VendorGuidData=guid_data,
            VendorTable=0x123456789ABCDEF0
        )

        assert table.VendorGuidData == guid_data
        assert table.VendorTable == 0x123456789ABCDEF0

        # Test VendorGuid method
        guid_str = table.VendorGuid()
        assert isinstance(guid_str, str)
        assert len(guid_str) == 36

    @pytest.mark.unit
    def test_efi_configuration_table(self):
        """Test EFI_CONFIGURATION_TABLE functionality."""
        config_table = EFI_CONFIGURATION_TABLE()
        assert config_table.VendorTables == {}

        # Test string representation with empty table
        config_str = str(config_table)
        assert 'Vendor Tables:' in config_str

        # Add some vendor tables
        config_table.VendorTables = {
            'vendor1': 0x1000,
            'vendor2': 0x2000
        }

        config_str = str(config_table)
        assert 'vendor1' in config_str
        assert 'vendor2' in config_str


class TestEFITableSignatures:
    """Test EFI table signature constants."""

    @pytest.mark.unit
    def test_table_signatures(self):
        """Test EFI table signature constants."""
        assert EFI_SYSTEM_TABLE_SIGNATURE == 'IBI SYST'
        assert EFI_RUNTIME_SERVICES_SIGNATURE == 'RUNTSERV'
        assert EFI_BOOT_SERVICES_SIGNATURE == 'BOOTSERV'
        assert EFI_DXE_SERVICES_TABLE_SIGNATURE == 'DXE_SERV'

    @pytest.mark.unit
    def test_efi_system_table_revision(self):
        """Test EFI_SYSTEM_TABLE_REVISION function."""
        # Test various revision values
        assert EFI_SYSTEM_TABLE_REVISION(0x00020080) == '2.128'
        assert EFI_SYSTEM_TABLE_REVISION(0x00010002) == '1.2'
        assert EFI_SYSTEM_TABLE_REVISION(0x00000000) == '0.0'

    @pytest.mark.unit
    def test_efi_tables_dictionary(self):
        """Test EFI_TABLES dictionary structure."""
        assert len(EFI_TABLES) == 4
        assert EFI_SYSTEM_TABLE_SIGNATURE in EFI_TABLES
        assert EFI_RUNTIME_SERVICES_SIGNATURE in EFI_TABLES
        assert EFI_BOOT_SERVICES_SIGNATURE in EFI_TABLES
        assert EFI_DXE_SERVICES_TABLE_SIGNATURE in EFI_TABLES

        # Test table entry structure
        system_table_entry = EFI_TABLES[EFI_SYSTEM_TABLE_SIGNATURE]
        assert 'name' in system_table_entry
        assert 'struct' in system_table_entry
        assert 'fmt' in system_table_entry
        assert system_table_entry['name'] == 'EFI System Table'


if __name__ == '__main__':
    pytest.main([__file__])
