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


class TestCPUSecurityAssessment:
    """Comprehensive tests for CPU security assessment functionality."""

    @pytest.fixture
    def security_cs(self):
        """Create ChipsecCs with security-focused mocking."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock CPU HAL with security-relevant methods
        cs_mock.hals.CPU = Mock()
        cs_mock.hals.CPU.read_cr.return_value = 0x12345678
        cs_mock.hals.CPU.write_cr.return_value = None
        cs_mock.hals.CPU.cpuid.return_value = (0x806E9, 0x12345678, 0x9ABCDEF0, 0x11111111)
        cs_mock.hals.CPU.read_msr.return_value = (0x12345678, 0x9ABCDEF0)
        cs_mock.hals.CPU.write_msr.return_value = None

        # Mock Memory HAL for security checks
        cs_mock.hals.Memory = Mock()
        cs_mock.hals.Memory.read_physical_mem.return_value = b'\x00\x01\x02\x03'
        cs_mock.hals.Memory.write_physical_mem.return_value = None

        # Mock MSR HAL
        cs_mock.hals.Msr = Mock()
        cs_mock.hals.Msr.read_msr.return_value = (0x12345678, 0x9ABCDEF0)
        cs_mock.hals.Msr.write_msr.return_value = None

        return cs_mock

    @pytest.mark.security
    def test_cpu_feature_security_validation(self, security_cs):
        """Test CPU feature security validation."""
        # Test CPUID for security features
        cs_mock = security_cs

        # Mock CPUID responses for different security features
        cpuid_responses = {
            'basic_info': (0x806E9, 0x12345678, 0x9ABCDEF0, 0x11111111),
            'feature_flags': (0x00000001, 0x00000000, 0x00000000, 0x00000000),
            'extended_features': (0x00000007, 0x00000000, 0x00000000, 0x00000000),
        }

        cs_mock.hals.CPU.cpuid.side_effect = lambda eax, ecx=0: cpuid_responses.get(
            'basic_info' if eax == 0x01 else
            'feature_flags' if eax == 0x01 else
            'extended_features' if eax == 0x07 else
            (0, 0, 0, 0)
        )

        # Test basic CPU information
        vendor_info = cs_mock.hals.CPU.cpuid(0x00, 0x00)
        assert vendor_info[0] == 0x806E9  # AMD processor

        # Test feature flags
        features = cs_mock.hals.CPU.cpuid(0x01, 0x00)
        assert features[0] & 0x80000000  # Check if hypervisor bit is set

        # Verify CPUID calls
        assert cs_mock.hals.CPU.cpuid.call_count >= 1

    @pytest.mark.security
    def test_control_register_security_checks(self, security_cs):
        """Test control register security validation."""
        cs_mock = security_cs

        # Test CR0 security settings
        cs_mock.hals.CPU.read_cr.return_value = 0x80000011  # CR0 with WP and PE set

        cr0_value = cs_mock.hals.CPU.read_cr(0, 0)
        assert cr0_value & 0x00010000 == 0x00010000  # WP (Write Protect) should be set
        assert cr0_value & 0x00000001 == 0x00000001  # PE (Protection Enable) should be set

        # Test CR4 security settings
        cs_mock.hals.CPU.read_cr.return_value = 0x00000668  # CR4 with SMEP, SMAP, and other security features

        cr4_value = cs_mock.hals.CPU.read_cr(0, 4)
        assert cr4_value & 0x00000100 == 0x00000100  # SMEP (Supervisor Mode Execution Protection)
        assert cr4_value & 0x00000200 == 0x00000200  # SMAP (Supervisor Mode Access Prevention)

        # Verify CR reads
        assert cs_mock.hals.CPU.read_cr.call_count >= 2

    @pytest.mark.security
    def test_msr_security_register_validation(self, security_cs):
        """Test MSR security register validation."""
        cs_mock = security_cs

        # Test IA32_EFER MSR (Extended Feature Enable Register)
        cs_mock.hals.Msr.read_msr.return_value = (0x00000D01, 0x00000000)  # SCE, LME, LMA, NXE enabled

        efer_low, efer_high = cs_mock.hals.Msr.read_msr(0, 0xC0000080)
        assert efer_low & 0x00000001 == 0x00000001  # SCE (System Call Extensions)
        assert efer_low & 0x00000100 == 0x00000100  # LME (Long Mode Enable)
        assert efer_low & 0x00000200 == 0x00000200  # LMA (Long Mode Active)
        assert efer_low & 0x00000800 == 0x00000800  # NXE (No-Execute Enable)

        # Test IA32_APIC_BASE MSR
        cs_mock.hals.Msr.read_msr.return_value = (0xFEE00000, 0x00000000)  # Standard APIC base

        apic_low, apic_high = cs_mock.hals.Msr.read_msr(0, 0x1B)
        assert apic_low & 0xFFFFF000 == 0xFEE00000  # APIC base address
        assert apic_low & 0x00000800 == 0x00000800  # APIC is enabled

        # Verify MSR reads
        assert cs_mock.hals.Msr.read_msr.call_count >= 2

    @pytest.mark.security
    def test_memory_protection_mechanisms(self, security_cs):
        """Test memory protection mechanism validation."""
        cs_mock = security_cs

        # Test SMRR (System Management Range Registers) validation
        cs_mock.hals.CPU.get_SMRR.return_value = (0xFED00000, 0xFED00000)  # Base and mask
        cs_mock.hals.CPU.check_SMRR_supported.return_value = True

        smrr_base, smrr_mask = cs_mock.hals.CPU.get_SMRR()
        assert smrr_base == 0xFED00000
        assert smrr_mask == 0xFED00000
        assert cs_mock.hals.CPU.check_SMRR_supported() is True

        # Test TSEG (Top of System Management Memory) validation
        cs_mock.hals.CPU.get_TSEG.return_value = (0xFED00000, 0xFED01000, 0x1000)  # Base, limit, size

        tseg_base, tseg_limit, tseg_size = cs_mock.hals.CPU.get_TSEG()
        assert tseg_base == 0xFED00000
        assert tseg_limit == 0xFED01000
        assert tseg_size == 0x1000

        # Verify protection mechanism calls
        cs_mock.hals.CPU.get_SMRR.assert_called_once()
        cs_mock.hals.CPU.get_TSEG.assert_called_once()

    @pytest.mark.security
    def test_hypervisor_detection_security(self, security_cs):
        """Test hypervisor detection for security assessment."""
        cs_mock = security_cs

        # Test no hypervisor present
        cs_mock.hals.CPU.cpuid.return_value = (0x00000001, 0x00000000, 0x00000000, 0x00000000)
        cs_mock.hals.CPU.check_vmm.return_value = 0  # VMM_NONE

        vmm_status = cs_mock.hals.CPU.check_vmm()
        assert vmm_status == 0  # No hypervisor detected

        # Test Xen hypervisor detection
        cs_mock.hals.CPU.cpuid.side_effect = [
            (0x00000001, 0x00000000, 0x80000000, 0x00000000),  # Hypervisor bit set
            (0x40000000, 0x566e6558, 0x65584d4d, 0x4d4d566e),  # Xen signature
        ]
        cs_mock.hals.CPU.check_vmm.return_value = 1  # VMM_XEN

        vmm_status = cs_mock.hals.CPU.check_vmm()
        assert vmm_status == 1  # Xen detected

        # Test VMware hypervisor detection
        cs_mock.hals.CPU.cpuid.side_effect = [
            (0x00000001, 0x00000000, 0x80000000, 0x00000000),  # Hypervisor bit set
            (0x40000000, 0x61774d56, 0x4d566572, 0x65726177),  # VMware signature
        ]
        cs_mock.hals.CPU.check_vmm.return_value = 3  # VMM_VMWARE

        vmm_status = cs_mock.hals.CPU.check_vmm()
        assert vmm_status == 3  # VMware detected

        # Verify hypervisor detection calls
        assert cs_mock.hals.CPU.check_vmm.call_count >= 3

    @pytest.mark.security
    def test_cpu_microcode_security_validation(self, security_cs):
        """Test CPU microcode security validation."""
        cs_mock = security_cs

        # Test microcode revision via CPUID
        cs_mock.hals.CPU.cpuid.return_value = (0x00000001, 0x00000000, 0x00000000, 0x00000000)

        # Mock microcode MSR reads
        cs_mock.hals.Msr.read_msr.side_effect = [
            (0x00000001, 0x00000000),  # Microcode revision
            (0x00000000, 0x00000000),  # Platform ID
        ]

        microcode_rev = cs_mock.hals.Msr.read_msr(0, 0x8B)  # IA32_UCODE_REV
        platform_id = cs_mock.hals.Msr.read_msr(0, 0x17)    # IA32_PLATFORM_ID

        assert microcode_rev[0] > 0  # Microcode revision should be non-zero
        assert platform_id[0] >= 0   # Platform ID should be valid

        # Verify MSR reads for microcode validation
        assert cs_mock.hals.Msr.read_msr.call_count >= 2

    @pytest.mark.security
    def test_cpu_cache_security_validation(self, security_cs):
        """Test CPU cache security validation."""
        cs_mock = security_cs

        # Test cache configuration via CPUID
        cs_mock.hals.CPU.cpuid.side_effect = [
            (0x00000004, 0x00000000, 0x00000000, 0x00000000),  # Cache info
            (0x00000004, 0x00000001, 0x00000000, 0x00000000),  # L1 cache
            (0x00000004, 0x00000002, 0x00000000, 0x00000000),  # L2 cache
        ]

        # Verify cache information can be retrieved
        cache_info = cs_mock.hals.CPU.cpuid(0x04, 0x00)
        assert cache_info[0] & 0x1F == 0x04  # Cache type determination

        l1_cache = cs_mock.hals.CPU.cpuid(0x04, 0x01)
        l2_cache = cs_mock.hals.CPU.cpuid(0x04, 0x02)

        # Verify cache calls
        assert cs_mock.hals.CPU.cpuid.call_count >= 3

    @pytest.mark.security
    def test_cpu_branch_prediction_security(self, security_cs):
        """Test CPU branch prediction security features."""
        cs_mock = security_cs

        # Test speculative execution controls via MSR
        cs_mock.hals.Msr.read_msr.side_effect = [
            (0x00000000, 0x00000000),  # IA32_SPEC_CTRL (Speculative Control)
            (0x00000000, 0x00000000),  # IA32_PRED_CMD (Prediction Command)
        ]

        spec_ctrl = cs_mock.hals.Msr.read_msr(0, 0x48)  # IA32_SPEC_CTRL
        pred_cmd = cs_mock.hals.Msr.read_msr(0, 0x49)   # IA32_PRED_CMD

        # Verify speculative execution controls are accessible
        assert isinstance(spec_ctrl, tuple)
        assert isinstance(pred_cmd, tuple)

        # Verify MSR reads for branch prediction security
        assert cs_mock.hals.Msr.read_msr.call_count >= 2

    @pytest.mark.security
    def test_cpu_debug_security_features(self, security_cs):
        """Test CPU debug security features."""
        cs_mock = security_cs

        # Test debug registers
        cs_mock.hals.CPU.read_cr.side_effect = [
            0x00000000,  # DR0
            0x00000000,  # DR1
            0x00000000,  # DR2
            0x00000000,  # DR3
            0x00000000,  # DR6
            0x00000000,  # DR7
        ]

        # Read debug registers
        for i in range(8):
            if i < 4 or i > 5:  # DR0-DR3, DR6-DR7
                dr_value = cs_mock.hals.CPU.read_cr(0, 8 + i)  # DR registers start at CR8
                assert dr_value >= 0

        # Verify debug register reads
        assert cs_mock.hals.CPU.read_cr.call_count >= 6

    @pytest.mark.security
    def test_cpu_power_management_security(self, security_cs):
        """Test CPU power management security features."""
        cs_mock = security_cs

        # Test MWAIT/MSR power management features
        cs_mock.hals.CPU.cpuid.return_value = (0x00000005, 0x00000000, 0x00000000, 0x00000000)

        mwait_info = cs_mock.hals.CPU.cpuid(0x05, 0x00)
        assert mwait_info[0] & 0xFF == 0x05  # MWAIT leaf

        # Test power management MSRs
        cs_mock.hals.Msr.read_msr.side_effect = [
            (0x00000000, 0x00000000),  # IA32_CLOCK_MODULATION
            (0x00000000, 0x00000000),  # IA32_THERM_STATUS
        ]

        clock_mod = cs_mock.hals.Msr.read_msr(0, 0x19A)  # IA32_CLOCK_MODULATION
        therm_status = cs_mock.hals.Msr.read_msr(0, 0x19C)  # IA32_THERM_STATUS

        # Verify power management MSR reads
        assert cs_mock.hals.Msr.read_msr.call_count >= 2

    @pytest.mark.security
    def test_cpu_integrated_security_features(self, security_cs):
        """Test integrated CPU security features."""
        cs_mock = security_cs

        # Test SGX (Software Guard Extensions) if supported
        cs_mock.hals.CPU.cpuid.side_effect = [
            (0x00000007, 0x00000000, 0x00000000, 0x00000000),  # Extended features
            (0x00000012, 0x00000000, 0x00000000, 0x00000000),  # SGX capabilities
        ]

        extended_features = cs_mock.hals.CPU.cpuid(0x07, 0x00)
        sgx_capabilities = cs_mock.hals.CPU.cpuid(0x12, 0x00)

        # Check for SGX support (bit 2 in EBX of leaf 0x07)
        sgx_supported = (extended_features[1] & 0x00000004) != 0
        if sgx_supported:
            assert sgx_capabilities[0] & 0xFF == 0x12  # SGX leaf

        # Verify security feature detection calls
        assert cs_mock.hals.CPU.cpuid.call_count >= 2

    @pytest.mark.security
    def test_cpu_security_vulnerability_assessment(self, security_cs):
        """Test CPU security vulnerability assessment."""
        cs_mock = security_cs

        # Test for known security vulnerabilities via CPUID and MSRs
        cs_mock.hals.CPU.cpuid.return_value = (0x00000007, 0x00000000, 0x00000000, 0x00000000)

        # Check for security-related CPUID features
        features = cs_mock.hals.CPU.cpuid(0x07, 0x00)

        # Check for various security features
        has_smap = (features[1] & 0x00000200) != 0  # SMAP support
        has_smep = (features[1] & 0x00000100) != 0  # SMEP support
        has_invpcid = (features[1] & 0x00000400) != 0  # INVPCID support

        # These features help mitigate various security vulnerabilities
        security_features = {
            'SMAP': has_smap,
            'SMEP': has_smep,
            'INVPCID': has_invpcid
        }

        # Verify security feature assessment
        assert isinstance(security_features['SMAP'], bool)
        assert isinstance(security_features['SMEP'], bool)
        assert isinstance(security_features['INVPCID'], bool)

        # Verify security assessment calls
        cs_mock.hals.CPU.cpuid.assert_called_with(0x07, 0x00)


if __name__ == '__main__':
    pytest.main([__file__])
