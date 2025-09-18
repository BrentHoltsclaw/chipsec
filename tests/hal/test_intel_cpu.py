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
from unittest.mock import Mock, patch
from chipsec.hal.intel.cpu import CPU
from tests.test_utils import MockFactory


class TestIntelCPU:
    """Comprehensive tests for Intel CPU HAL functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for Intel."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        cs_mock.is_amd.return_value = False
        cs_mock.is_intel.return_value = True
        cs_mock.is_server.return_value = False
        return cs_mock

    @pytest.fixture
    def intel_cpu_instance(self, mock_cs):
        """Create Intel CPU instance with mocked dependencies."""
        return CPU(mock_cs)

    @pytest.mark.unit
    def test_intel_cpu_initialization(self, intel_cpu_instance):
        """Test Intel CPU class initialization."""
        assert hasattr(intel_cpu_instance, 'cs')
        assert hasattr(intel_cpu_instance, 'helper')
        assert hasattr(intel_cpu_instance, 'logger')

    @pytest.mark.unit
    def test_read_cr(self, intel_cpu_instance, mock_cs):
        """Test reading control register."""
        mock_cs.helper.read_cr.return_value = 0x12345678

        result = intel_cpu_instance.read_cr(0, 3)

        assert result == 0x12345678
        mock_cs.helper.read_cr.assert_called_once_with(0, 3)

    @pytest.mark.unit
    def test_write_cr(self, intel_cpu_instance, mock_cs):
        """Test writing control register."""
        mock_cs.helper.write_cr.return_value = 0

        result = intel_cpu_instance.write_cr(0, 3, 0x87654321)

        assert result == 0
        mock_cs.helper.write_cr.assert_called_once_with(0, 3, 0x87654321)

    @pytest.mark.unit
    def test_cpuid(self, intel_cpu_instance, mock_cs):
        """Test CPUID instruction."""
        mock_cs.helper.cpuid.return_value = (0x1234, 0x5678, 0x9ABC, 0xDEF0)

        result = intel_cpu_instance.cpuid(0x01, 0x00)

        assert result == (0x1234, 0x5678, 0x9ABC, 0xDEF0)
        mock_cs.helper.cpuid.assert_called_once_with(0x01, 0x00)

    @pytest.mark.unit
    def test_check_vmm_none(self, intel_cpu_instance, mock_cs):
        """Test VMM detection when no VMM is present."""
        mock_cs.helper.cpuid.side_effect = [
            (0x00000001, 0x00000000, 0x00000000, 0x00000000),  # No hypervisor bit
        ]

        result = intel_cpu_instance.check_vmm()

        assert result == 0  # VMM_NONE

    @pytest.mark.unit
    def test_check_vmm_xen(self, intel_cpu_instance, mock_cs):
        """Test VMM detection for Xen."""
        mock_cs.helper.cpuid.side_effect = [
            (0x00000001, 0x00000000, 0x80000000, 0x00000000),  # Hypervisor bit set
            (0x40000000, 0x566e6558, 0x65584d4d, 0x4d4d566e),  # Xen signature
        ]

        result = intel_cpu_instance.check_vmm()

        assert result == 1  # VMM_XEN

    @pytest.mark.unit
    def test_check_vmm_hyperv(self, intel_cpu_instance, mock_cs):
        """Test VMM detection for Hyper-V."""
        mock_cs.helper.cpuid.side_effect = [
            (0x00000001, 0x00000000, 0x80000000, 0x00000000),  # Hypervisor bit set
            (0x40000000, 0x7263694D, 0x666F736F, 0x76482074),  # Hyper-V signature
        ]

        result = intel_cpu_instance.check_vmm()

        assert result == 2  # VMM_HYPER_V

    @pytest.mark.unit
    def test_check_vmm_vmware(self, intel_cpu_instance, mock_cs):
        """Test VMM detection for VMware."""
        mock_cs.helper.cpuid.side_effect = [
            (0x00000001, 0x00000000, 0x80000000, 0x00000000),  # Hypervisor bit set
            (0x40000000, 0x61774d56, 0x4d566572, 0x65726177),  # VMware signature
        ]

        result = intel_cpu_instance.check_vmm()

        assert result == 3  # VMM_VMWARE

    @pytest.mark.unit
    def test_check_vmm_kvm(self, intel_cpu_instance, mock_cs):
        """Test VMM detection for KVM."""
        mock_cs.helper.cpuid.side_effect = [
            (0x00000001, 0x00000000, 0x80000000, 0x00000000),  # Hypervisor bit set
            (0x40000000, 0x4b4d564b, 0x564b4d56, 0x0000004d),  # KVM signature
        ]

        result = intel_cpu_instance.check_vmm()

        assert result == 4  # VMM_KVM

    @pytest.mark.unit
    def test_is_HT_active_true(self, intel_cpu_instance, mock_cs):
        """Test Hyper-Threading detection when active."""
        mock_cs.helper.cpuid.return_value = (0x0000000B, 0x00000002, 0x00000000, 0x00000000)

        result = intel_cpu_instance.is_HT_active()

        assert result is True

    @pytest.mark.unit
    def test_is_HT_active_false(self, intel_cpu_instance, mock_cs):
        """Test Hyper-Threading detection when inactive."""
        mock_cs.helper.cpuid.return_value = (0x0000000B, 0x00000001, 0x00000000, 0x00000000)

        result = intel_cpu_instance.is_HT_active()

        assert result is False

    @pytest.mark.unit
    def test_get_number_logical_processor_per_core(self, intel_cpu_instance, mock_cs):
        """Test getting logical processors per core."""
        mock_cs.helper.cpuid.return_value = (0x0000000B, 0x00000002, 0x00000000, 0x00000000)

        result = intel_cpu_instance.get_number_logical_processor_per_core()

        assert result == 0x00000002

    @pytest.mark.unit
    def test_get_number_logical_processor_per_package(self, intel_cpu_instance, mock_cs):
        """Test getting logical processors per package."""
        mock_cs.helper.cpuid.return_value = (0x0000000B, 0x00000004, 0x00000000, 0x00000000)

        result = intel_cpu_instance.get_number_logical_processor_per_package()

        assert result == 0x00000004

    @pytest.mark.unit
    def test_get_number_physical_processor_per_package(self, intel_cpu_instance, mock_cs):
        """Test getting physical processors per package."""
        mock_cs.helper.cpuid.side_effect = [
            (0x0000000B, 0x00000002, 0x00000000, 0x00000000),  # per core
            (0x0000000B, 0x00000008, 0x00000000, 0x00000000),  # per package
        ]

        result = intel_cpu_instance.get_number_physical_processor_per_package()

        assert result == 4  # 8 / 2

    @pytest.mark.unit
    def test_get_SMRR_intel(self, intel_cpu_instance, mock_cs):
        """Test getting SMRR for Intel."""
        mock_register_list = Mock()
        mock_register_list.read_field.return_value = [0x00000000FED00000]

        mock_cs.register.get_list_by_name.side_effect = [
            mock_register_list,  # IA32_SMRR_PHYSBASE
            mock_register_list,  # IA32_SMRR_PHYSMASK
        ]

        base, mask = intel_cpu_instance.get_SMRR()

        assert base == 0x00000000FED00000
        assert mask == 0x00000000FED00000
        assert mock_cs.register.get_list_by_name.call_count == 2

    @pytest.mark.unit
    def test_get_SMRR_SMRAM_intel(self, intel_cpu_instance, mock_cs):
        """Test getting SMRAM region for Intel."""
        mock_register_list = Mock()
        mock_register_list.read_field.return_value = [0x00000000FED00000]

        mock_cs.register.get_list_by_name.side_effect = [
            mock_register_list,  # IA32_SMRR_PHYSBASE
            mock_register_list,  # IA32_SMRR_PHYSMASK
        ]

        base, limit, size = intel_cpu_instance.get_SMRR_SMRAM()

        assert base == 0x00000000FED00000
        # For Intel: smram_size = ((~smrrmask) & 0xFFFFFFFF) + 1
        # ~0x00000000FED00000 & 0xFFFFFFFF = 0x012FFFFF, +1 = 0x01300000
        # limit = base + size - 1 = 0xFED00000 + 0x01300000 - 1 = 0xFFFFFFFF
        assert limit == 0x00000000FFFFFFFF
        assert size == 0x0000000001300000

    @pytest.mark.unit
    def test_get_TSEG_intel_client(self, intel_cpu_instance, mock_cs):
        """Test getting TSEG for Intel client system."""
        mock_register_list = Mock()
        mock_register_list.read_field.side_effect = [
            [0x00000000FED00000],  # TSEGMB - return as list
            [0x00000000FF000000],  # BGSM - return as list
        ]

        mock_cs.register.get_list_by_name.side_effect = [
            mock_register_list,  # TSEGMB
            mock_register_list,  # BGSM
        ]

        base, limit, size = intel_cpu_instance.get_TSEG()

        assert base == 0x00000000FED00000
        # For Intel client: tseg_limit = bgsm - 1 = 0xFF000000 - 1 = 0xFEFFFFFF
        assert limit == 0x00000000FEFFFFFF
        # tseg_size = tseg_limit - tseg_base + 1 = 0xFEFFFFFF - 0xFED00000 + 1 = 0x300000
        assert size == 0x0000000000300000

    @pytest.mark.unit
    def test_get_TSEG_intel_server(self, intel_cpu_instance, mock_cs):
        """Test getting TSEG for Intel server system."""
        mock_cs.is_server.return_value = True

        # Mock for TSEG base register
        mock_tseg_base_reg = Mock()
        mock_tseg_base_reg.read_field.return_value = [0x00000000FED00000]

        # Mock for TSEG limit register
        mock_tseg_limit_reg = Mock()
        mock_tseg_limit_reg.read_field.return_value = [0x00000000FEDFFFFF]

        def mock_get_list_by_name(name):
            if name == '8086.MEMMAP_VTD.TSEG':
                return mock_tseg_base_reg
            elif name == '8086.MEMMAP_VTD.TSEG_LIMIT':
                return mock_tseg_limit_reg
            return Mock()

        mock_cs.register.get_list_by_name.side_effect = mock_get_list_by_name

        base, limit, size = intel_cpu_instance.get_TSEG()

        assert base == 0x00000000FED00000
        # For Intel server: tseg_limit = tseg_limit + 0xFFFFF = 0xFEDFFFFF + 0xFFFFF = 0xFEFFFFFF
        # The actual calculation in the code: tseg_limit += 0xFFFFF
        expected_limit = 0x00000000FEDFFFFF + 0xFFFFF
        assert limit == expected_limit
        # tseg_size = tseg_limit - tseg_base + 1 = 0xFEFFFFFF - 0xFED00000 + 1 = 0x300000
        expected_size = expected_limit - 0x00000000FED00000 + 1
        assert size == expected_size

    @pytest.mark.unit
    def test_check_SMRR_supported_intel_true(self, intel_cpu_instance, mock_cs):
        """Test SMRR support check for Intel when supported."""
        mock_register_list = Mock()
        mock_register_list.read_and_hal_print.return_value = None
        mock_register_list.is_any_field_value.return_value = True

        mock_cs.register.get_list_by_name.return_value = mock_register_list

        result = intel_cpu_instance.check_SMRR_supported()

        assert result is True
        mock_register_list.read_and_hal_print.assert_called_once()
        mock_register_list.is_any_field_value.assert_called_once_with(1, 'SMRR')

    @pytest.mark.unit
    def test_check_SMRR_supported_intel_false(self, intel_cpu_instance, mock_cs):
        """Test SMRR support check for Intel when not supported."""
        mock_register_list = Mock()
        mock_register_list.read_and_hal_print.return_value = None
        mock_register_list.is_any_field_value.return_value = False

        mock_cs.register.get_list_by_name.return_value = mock_register_list

        result = intel_cpu_instance.check_SMRR_supported()

        assert result is False

    @pytest.mark.unit
    def test_dump_page_tables(self, intel_cpu_instance, mock_cs):
        """Test dumping page tables."""
        with patch('chipsec.library.paging.c_ia32e_page_tables') as mock_paging:
            mock_pt = Mock()
            mock_pt.read_pt_and_show_status.return_value = None
            mock_pt.failure = False
            mock_paging.return_value = mock_pt

            intel_cpu_instance.dump_page_tables(0x12345678, 'test_pt')

            mock_paging.assert_called_once_with(mock_cs)
            mock_pt.read_pt_and_show_status.assert_called_once_with('test_pt', 'PT', 0x12345678)

    @pytest.mark.unit
    def test_dump_page_tables_all(self, intel_cpu_instance, mock_cs):
        """Test dumping page tables for all threads."""
        mock_cs.hals.Msr.get_cpu_thread_count.return_value = 2
        mock_cs.helper.read_cr.side_effect = [0x11111111, 0x22222222]

        with patch.object(intel_cpu_instance, 'dump_page_tables') as mock_dump:
            intel_cpu_instance.dump_page_tables_all()

            assert mock_dump.call_count == 2
            mock_dump.assert_any_call(0x11111111)
            mock_dump.assert_any_call(0x22222222)

    @pytest.mark.unit
    def test_get_cpu_topology(self, intel_cpu_instance, mock_cs):
        """Test getting CPU topology."""
        mock_cs.helper.get_threads_count.return_value = 2
        mock_cs.helper.set_affinity.return_value = None
        mock_cs.helper.cpuid.side_effect = [
            # Thread 0: package 0, core 0
            (0x0000000B, 0x00000000, 0x00000000, 0x00000000),  # pkg_id
            (0x0000000B, 0x00000000, 0x00000000, 0x00000000),  # core_id
            # Thread 1: package 0, core 1
            (0x0000000B, 0x00000000, 0x00000000, 0x00000000),  # pkg_id
            (0x0000000B, 0x00000001, 0x00000000, 0x00000001),  # core_id
        ]

        result = intel_cpu_instance.get_cpu_topology()

        assert 'packages' in result
        assert 'cores' in result
        assert 'threads' in result
        assert result['threads'] == 2
        assert 0 in result['packages']
        assert len(result['packages'][0]) == 2

    @pytest.mark.unit
    def test_get_SMRAM_fallback_to_TSEG(self, intel_cpu_instance, mock_cs):
        """Test get_SMRAM falling back to TSEG when SMRR fails."""
        # Mock SMRR to fail
        mock_cs.register.get_list_by_name.side_effect = Exception("SMRR not available")

        # Mock TSEG registers
        mock_register_list = Mock()
        mock_register_list.read_field.side_effect = [
            [0x00000000FED00000],  # TSEGMB
            [0x00000000FF000000],  # BGSM
        ]

        mock_cs.register.get_list_by_name.side_effect = [
            Exception("SMRR failed"),  # First call fails
            mock_register_list,  # TSEGMB
            mock_register_list,  # BGSM
        ]

        base, limit, size = intel_cpu_instance.get_SMRAM()

        assert base == 0x00000000FED00000
        assert limit == 0x00000000FEFFFFFF  # BGSM - 1
        assert size == 0x0000000000300000  # limit - base + 1


if __name__ == '__main__':
    pytest.main([__file__])
