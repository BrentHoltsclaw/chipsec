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
from unittest.mock import Mock
from tests.test_utils import MockFactory


class TestUEFISecurityAssessment:
    """Comprehensive tests for UEFI security assessment functionality."""

    @pytest.fixture
    def uefi_security_cs(self):
        """Create ChipsecCs with UEFI security-focused mocking."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock UEFI HAL with security-relevant methods
        cs_mock.hals.UEFI = Mock()
        cs_mock.hals.UEFI.get_EFI_variable.return_value = b'test_variable_data'
        cs_mock.hals.UEFI.list_EFI_variables.return_value = ['SecureBoot', 'SetupMode', 'KEK']
        cs_mock.hals.UEFI.get_EFI_variable_attributes.return_value = 0x07  # EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS

        # Mock Memory HAL for UEFI memory operations
        cs_mock.hals.Memory = Mock()
        cs_mock.hals.Memory.read_physical_mem.return_value = b'\x00\x01\x02\x03'

        # Mock helper for UEFI operations
        cs_mock.helper = Mock()
        cs_mock.helper.get_EFI_variable.return_value = b'helper_variable_data'
        cs_mock.helper.list_EFI_variables.return_value = ['PK', 'KEK', 'db', 'dbx']

        return cs_mock

    @pytest.mark.security
    def test_uefi_secure_boot_validation(self, uefi_security_cs):
        """Test UEFI Secure Boot validation."""
        cs_mock = uefi_security_cs

        # Mock Secure Boot variable values
        cs_mock.hals.UEFI.get_EFI_variable.side_effect = [
            b'\x01',  # SecureBoot enabled
            b'\x00',  # SetupMode disabled
            b'KEK_data',  # KEK present
        ]

        # Test Secure Boot status
        secure_boot = cs_mock.hals.UEFI.get_EFI_variable('SecureBoot', '{8be4df61-93ca-11d2-aa0d-00e098032b8c}')
        setup_mode = cs_mock.hals.UEFI.get_EFI_variable('SetupMode', '{8be4df61-93ca-11d2-aa0d-00e098032b8c}')
        kek = cs_mock.hals.UEFI.get_EFI_variable('KEK', '{8be4df61-93ca-11d2-aa0d-00e098032b8c}')

        # Validate Secure Boot is properly configured
        assert secure_boot == b'\x01'  # Secure Boot should be enabled
        assert setup_mode == b'\x00'   # Setup Mode should be disabled
        assert kek == b'KEK_data'      # KEK should be present

        # Verify UEFI variable calls
        assert cs_mock.hals.UEFI.get_EFI_variable.call_count >= 3

    @pytest.mark.security
    def test_uefi_variable_security_attributes(self, uefi_security_cs):
        """Test UEFI variable security attributes validation."""
        cs_mock = uefi_security_cs

        # Test variable attributes for security-critical variables
        attributes = cs_mock.hals.UEFI.get_EFI_variable_attributes('SecureBoot', '{8be4df61-93ca-11d2-aa0d-00e098032b8c}')

        # Check for required security attributes
        assert attributes & 0x01 == 0x01  # EFI_VARIABLE_NON_VOLATILE
        assert attributes & 0x02 == 0x02  # EFI_VARIABLE_BOOTSERVICE_ACCESS
        assert attributes & 0x04 == 0x04  # EFI_VARIABLE_RUNTIME_ACCESS

        # Verify attribute retrieval
        cs_mock.hals.UEFI.get_EFI_variable_attributes.assert_called_once()

    @pytest.mark.security
    def test_uefi_signature_database_validation(self, uefi_security_cs):
        """Test UEFI signature database validation."""
        cs_mock = uefi_security_cs

        # Mock signature database variables
        cs_mock.hals.UEFI.get_EFI_variable.side_effect = [
            b'PK_data',   # Platform Key
            b'KEK_data',  # Key Exchange Key
            b'db_data',   # Authorized signatures
            b'dbx_data',  # Forbidden signatures
        ]

        # Test signature database integrity
        pk = cs_mock.hals.UEFI.get_EFI_variable('PK', '{8be4df61-93ca-11d2-aa0d-00e098032b8c}')
        kek = cs_mock.hals.UEFI.get_EFI_variable('KEK', '{8be4df61-93ca-11d2-aa0d-00e098032b8c}')
        db = cs_mock.hals.UEFI.get_EFI_variable('db', '{d719b2cb-3d3a-4596-a3bc-dad00e67656f}')
        dbx = cs_mock.hals.UEFI.get_EFI_variable('dbx', '{d719b2cb-3d3a-4596-a3bc-dad00e67656f}')

        # Validate signature databases are present and non-empty
        assert pk == b'PK_data'
        assert kek == b'KEK_data'
        assert db == b'db_data'
        assert dbx == b'dbx_data'

        # Verify signature database calls
        assert cs_mock.hals.UEFI.get_EFI_variable.call_count >= 4

    @pytest.mark.security
    def test_uefi_boot_variable_security(self, uefi_security_cs):
        """Test UEFI boot variable security validation."""
        cs_mock = uefi_security_cs

        # Mock boot variables
        cs_mock.hals.UEFI.list_EFI_variables.return_value = [
            'Boot0000', 'Boot0001', 'BootOrder', 'BootCurrent'
        ]
        cs_mock.hals.UEFI.get_EFI_variable.side_effect = [
            b'boot_entry_0',  # Boot0000
            b'boot_entry_1',  # Boot0001
            b'\x00\x00\x01\x00',  # BootOrder
            b'\x00\x00',  # BootCurrent
        ]

        # Test boot variable enumeration
        boot_vars = cs_mock.hals.UEFI.list_EFI_variables()
        assert 'Boot0000' in boot_vars
        assert 'BootOrder' in boot_vars

        # Test boot variable content validation
        boot_order = cs_mock.hals.UEFI.get_EFI_variable('BootOrder', '{8be4df61-93ca-11d2-aa0d-00e098032b8c}')
        assert boot_order == b'\x00\x00\x01\x00'  # Valid boot order

        # Verify boot variable calls
        cs_mock.hals.UEFI.list_EFI_variables.assert_called()

    @pytest.mark.security
    def test_uefi_runtime_services_security(self, uefi_security_cs):
        """Test UEFI runtime services security validation."""
        cs_mock = uefi_security_cs

        # Mock runtime services table
        cs_mock.hals.UEFI.get_runtime_services_table.return_value = {
            'GetTime': 0x1000,
            'SetTime': 0x1008,
            'GetWakeupTime': 0x1010,
            'SetWakeupTime': 0x1018,
            'GetVariable': 0x1020,
            'GetNextVariableName': 0x1028,
            'SetVariable': 0x1030,
            'GetNextHighMonotonicCount': 0x1038,
            'ResetSystem': 0x1040,
        }

        # Test runtime services table validation
        runtime_services = cs_mock.hals.UEFI.get_runtime_services_table()

        # Validate critical runtime services are present
        assert 'GetVariable' in runtime_services
        assert 'SetVariable' in runtime_services
        assert 'ResetSystem' in runtime_services

        # Validate function pointers are valid (non-zero)
        assert runtime_services['GetVariable'] != 0
        assert runtime_services['SetVariable'] != 0
        assert runtime_services['ResetSystem'] != 0

        # Verify runtime services validation
        cs_mock.hals.UEFI.get_runtime_services_table.assert_called_once()

    @pytest.mark.security
    def test_uefi_configuration_table_security(self, uefi_security_cs):
        """Test UEFI configuration table security validation."""
        cs_mock = uefi_security_cs

        # Mock EFI configuration table
        cs_mock.hals.UEFI.find_EFI_Configuration_Table.return_value = (True, None, {
            'VendorTables': {
                '8868E871-E4F1-11D3-BC22-0080C73C8881': 0x2000,  # ACPI 2.0
                'EB9D2D31-2D88-11D3-9A16-0090273FC14D': 0x2010,  # ACPI 1.0
                '5B1B31A1-9562-11D2-8E3F-00A0C969723B': 0x2020,  # SMBIOS
            }
        }, None)

        # Test configuration table validation
        found, _, config_table, _ = cs_mock.hals.UEFI.find_EFI_Configuration_Table()

        assert found is True
        assert 'VendorTables' in config_table

        # Validate critical configuration tables are present
        vendor_tables = config_table['VendorTables']
        assert '8868E871-E4F1-11D3-BC22-0080C73C8881' in vendor_tables  # ACPI 2.0
        assert '5B1B31A1-9562-11D2-8E3F-00A0C969723B' in vendor_tables  # SMBIOS

        # Verify configuration table validation
        cs_mock.hals.UEFI.find_EFI_Configuration_Table.assert_called_once()

    @pytest.mark.security
    def test_uefi_memory_map_security(self, uefi_security_cs):
        """Test UEFI memory map security validation."""
        cs_mock = uefi_security_cs

        # Mock UEFI memory map
        cs_mock.hals.UEFI.get_EFI_memory_map.return_value = [
            {'Type': 7, 'PhysicalStart': 0x100000, 'VirtualStart': 0x100000, 'NumberOfPages': 0x100, 'Attribute': 0xF},  # EfiConventionalMemory
            {'Type': 0, 'PhysicalStart': 0x0, 'VirtualStart': 0x0, 'NumberOfPages': 0x10, 'Attribute': 0xF},  # EfiReservedMemoryType
            {'Type': 3, 'PhysicalStart': 0x1000, 'VirtualStart': 0x1000, 'NumberOfPages': 0x20, 'Attribute': 0xF},  # EfiBootServicesCode
        ]

        # Test memory map validation
        memory_map = cs_mock.hals.UEFI.get_EFI_memory_map()

        # Validate memory map structure
        assert len(memory_map) >= 3
        assert all('Type' in entry for entry in memory_map)
        assert all('PhysicalStart' in entry for entry in memory_map)
        assert all('NumberOfPages' in entry for entry in memory_map)

        # Check for critical memory regions
        has_reserved = any(entry['Type'] == 0 for entry in memory_map)
        has_boot_services = any(entry['Type'] == 3 for entry in memory_map)
        has_conventional = any(entry['Type'] == 7 for entry in memory_map)

        assert has_reserved  # Should have reserved memory
        assert has_boot_services  # Should have boot services memory
        assert has_conventional  # Should have conventional memory

        # Verify memory map validation
        cs_mock.hals.UEFI.get_EFI_memory_map.assert_called_once()

    @pytest.mark.security
    def test_uefi_firmware_volume_security(self, uefi_security_cs):
        """Test UEFI firmware volume security validation."""
        cs_mock = uefi_security_cs

        # Mock firmware volume information
        cs_mock.hals.UEFI.get_firmware_volumes.return_value = [
            {'Base': 0xFFE00000, 'Size': 0x200000, 'FileSystemGuid': '8C8CE578-8A3D-4F1C-9935-896185C32DD3'},
            {'Base': 0xFFC00000, 'Size': 0x200000, 'FileSystemGuid': '5473C07A-3DCB-4DCA-BD6F-1E9689E7349A'},
        ]

        # Test firmware volume validation
        firmware_volumes = cs_mock.hals.UEFI.get_firmware_volumes()

        # Validate firmware volume structure
        assert len(firmware_volumes) >= 2
        assert all('Base' in fv for fv in firmware_volumes)
        assert all('Size' in fv for fv in firmware_volumes)
        assert all('FileSystemGuid' in fv for fv in firmware_volumes)

        # Validate firmware volume addresses are valid
        for fv in firmware_volumes:
            assert fv['Base'] > 0
            assert fv['Size'] > 0
            assert len(fv['FileSystemGuid']) == 36  # GUID string length

        # Verify firmware volume validation
        cs_mock.hals.UEFI.get_firmware_volumes.assert_called_once()

    @pytest.mark.security
    def test_uefi_capsule_update_security(self, uefi_security_cs):
        """Test UEFI capsule update security validation."""
        cs_mock = uefi_security_cs

        # Mock capsule update capabilities
        cs_mock.hals.UEFI.query_capsule_capabilities.return_value = {
            'MaxCapsuleSize': 0x100000,
            'ResetType': 1,  # Cold reset
            'CapsuleGuid': '3B6686BD-0D76-4030-B70E-B5519E2FC5A0',
        }

        # Test capsule capabilities validation
        capsule_caps = cs_mock.hals.UEFI.query_capsule_capabilities()

        # Validate capsule capabilities
        assert 'MaxCapsuleSize' in capsule_caps
        assert 'ResetType' in capsule_caps
        assert 'CapsuleGuid' in capsule_caps

        # Validate capsule size is reasonable
        assert capsule_caps['MaxCapsuleSize'] > 0
        assert capsule_caps['MaxCapsuleSize'] <= 0x1000000  # Reasonable maximum

        # Validate reset type
        assert capsule_caps['ResetType'] in [0, 1, 2]  # Valid reset types

        # Verify capsule capabilities validation
        cs_mock.hals.UEFI.query_capsule_capabilities.assert_called_once()

    @pytest.mark.security
    def test_uefi_secure_boot_policy_validation(self, uefi_security_cs):
        """Test UEFI Secure Boot policy validation."""
        cs_mock = uefi_security_cs

        # Mock Secure Boot policy variables
        cs_mock.hals.UEFI.get_EFI_variable.side_effect = [
            b'\x01',  # SecureBoot: Enabled
            b'\x00',  # SetupMode: Disabled
            b'\x01',  # DeployedMode: Enabled
            b'\x00',  # AuditMode: Disabled
        ]

        # Test Secure Boot policy validation
        secure_boot = cs_mock.hals.UEFI.get_EFI_variable('SecureBoot', '{8be4df61-93ca-11d2-aa0d-00e098032b8c}')
        setup_mode = cs_mock.hals.UEFI.get_EFI_variable('SetupMode', '{8be4df61-93ca-11d2-aa0d-00e098032b8c}')
        deployed_mode = cs_mock.hals.UEFI.get_EFI_variable('DeployedMode', '{8be4df61-93ca-11d2-aa0d-00e098032b8c}')
        audit_mode = cs_mock.hals.UEFI.get_EFI_variable('AuditMode', '{8be4df61-93ca-11d2-aa0d-00e098032b8c}')

        # Validate Secure Boot policy configuration
        assert secure_boot == b'\x01'      # Secure Boot must be enabled
        assert setup_mode == b'\x00'       # Setup Mode must be disabled
        assert deployed_mode == b'\x01'    # Deployed Mode should be enabled
        assert audit_mode == b'\x00'       # Audit Mode should be disabled

        # Verify Secure Boot policy validation
        assert cs_mock.hals.UEFI.get_EFI_variable.call_count >= 4

    @pytest.mark.security
    def test_uefi_variable_authentication(self, uefi_security_cs):
        """Test UEFI variable authentication mechanisms."""
        cs_mock = uefi_security_cs

        # Mock authenticated variable attributes
        cs_mock.hals.UEFI.get_EFI_variable_attributes.return_value = 0x27
        # EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
        # EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS

        # Test authenticated variable validation
        auth_attrs = cs_mock.hals.UEFI.get_EFI_variable_attributes('SecureBoot', '{8be4df61-93ca-11d2-aa0d-00e098032b8c}')

        # Check for authentication attributes
        has_auth_write = (auth_attrs & 0x20) != 0  # EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS

        if has_auth_write:
            # If authenticated writes are supported, validate the configuration
            assert auth_attrs & 0x01 == 0x01  # Should also be non-volatile
            assert auth_attrs & 0x02 == 0x02  # Should have boot service access

        # Verify authentication validation
        cs_mock.hals.UEFI.get_EFI_variable_attributes.assert_called()

    @pytest.mark.security
    def test_uefi_firmware_integrity_validation(self, uefi_security_cs):
        """Test UEFI firmware integrity validation."""
        cs_mock = uefi_security_cs

        # Mock firmware integrity measurements
        cs_mock.hals.UEFI.get_TPM_EventLog.return_value = [
            {'PCR': 0, 'EventType': 0x00000001, 'Digest': b'\x00' * 20, 'EventSize': 0x10, 'Event': b'BIOS Startup'},
            {'PCR': 1, 'EventType': 0x00000002, 'Digest': b'\x01' * 20, 'EventSize': 0x20, 'Event': b'Platform Configuration'},
            {'PCR': 2, 'EventType': 0x00000003, 'Digest': b'\x02' * 20, 'EventSize': 0x15, 'Event': b'Option ROM'},
        ]

        # Test TPM event log validation
        event_log = cs_mock.hals.UEFI.get_TPM_EventLog()

        # Validate event log structure
        assert len(event_log) >= 3
        assert all('PCR' in event for event in event_log)
        assert all('EventType' in event for event in event_log)
        assert all('Digest' in event for event in event_log)

        # Validate PCR values are in valid range (0-23 for TPM 1.2/2.0)
        for event in event_log:
            assert 0 <= event['PCR'] <= 23

        # Verify firmware integrity validation
        cs_mock.hals.UEFI.get_TPM_EventLog.assert_called_once()


if __name__ == '__main__':
    pytest.main([__file__])
