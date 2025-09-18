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
from chipsec.library.bits import (
    BIT0, BIT1, BIT2, BIT3, BIT4, BIT5, BIT6, BIT7,
    BIT8, BIT9, BIT10, BIT11, BIT12, BIT13, BIT14, BIT15,
    BIT16, BIT17, BIT18, BIT19, BIT20, BIT21, BIT22, BIT23,
    BIT24, BIT25, BIT26, BIT27, BIT28, BIT29, BIT30, BIT31,
    BIT32, BIT33, BIT34, BIT35, BIT36, BIT37, BIT38, BIT39,
    BIT40, BIT41, BIT42, BIT43, BIT44, BIT45, BIT46, BIT47,
    BIT48, BIT49, BIT50, BIT51, BIT52, BIT53, BIT54, BIT55,
    BIT56, BIT57, BIT58, BIT59, BIT60, BIT61, BIT62, BIT63,
    make_mask, bit, is_set, scan_single_bit_mask, is_all_ones,
    ones_complement, get_bits, set_bits
)


class TestBitConstants:
    """Test bit constant definitions."""

    @pytest.mark.unit
    def test_bit_constants_values(self):
        """Test that bit constants have correct values."""
        # Test first 8 bits
        assert BIT0 == 0x0001
        assert BIT1 == 0x0002
        assert BIT2 == 0x0004
        assert BIT3 == 0x0008
        assert BIT4 == 0x0010
        assert BIT5 == 0x0020
        assert BIT6 == 0x0040
        assert BIT7 == 0x0080

        # Test 8-15 bits
        assert BIT8 == 0x0100
        assert BIT9 == 0x0200
        assert BIT10 == 0x0400
        assert BIT11 == 0x0800
        assert BIT12 == 0x1000
        assert BIT13 == 0x2000
        assert BIT14 == 0x4000
        assert BIT15 == 0x8000

        # Test 16-31 bits
        assert BIT16 == 0x00010000
        assert BIT17 == 0x00020000
        assert BIT18 == 0x00040000
        assert BIT19 == 0x00080000
        assert BIT20 == 0x00100000
        assert BIT21 == 0x00200000
        assert BIT22 == 0x00400000
        assert BIT23 == 0x00800000
        assert BIT24 == 0x01000000
        assert BIT25 == 0x02000000
        assert BIT26 == 0x04000000
        assert BIT27 == 0x08000000
        assert BIT28 == 0x10000000
        assert BIT29 == 0x20000000
        assert BIT30 == 0x40000000
        assert BIT31 == 0x80000000

        # Test 32-47 bits
        assert BIT32 == 0x100000000
        assert BIT33 == 0x200000000
        assert BIT34 == 0x400000000
        assert BIT35 == 0x800000000
        assert BIT36 == 0x1000000000
        assert BIT37 == 0x2000000000
        assert BIT38 == 0x4000000000
        assert BIT39 == 0x8000000000
        assert BIT40 == 0x10000000000
        assert BIT41 == 0x20000000000
        assert BIT42 == 0x40000000000
        assert BIT43 == 0x80000000000
        assert BIT44 == 0x100000000000
        assert BIT45 == 0x200000000000
        assert BIT46 == 0x400000000000
        assert BIT47 == 0x800000000000

        # Test 48-63 bits
        assert BIT48 == 0x1000000000000
        assert BIT49 == 0x2000000000000
        assert BIT50 == 0x4000000000000
        assert BIT51 == 0x8000000000000
        assert BIT52 == 0x10000000000000
        assert BIT53 == 0x20000000000000
        assert BIT54 == 0x40000000000000
        assert BIT55 == 0x80000000000000
        assert BIT56 == 0x100000000000000
        assert BIT57 == 0x200000000000000
        assert BIT58 == 0x400000000000000
        assert BIT59 == 0x800000000000000
        assert BIT60 == 0x1000000000000000
        assert BIT61 == 0x2000000000000000
        assert BIT62 == 0x4000000000000000
        assert BIT63 == 0x8000000000000000

    @pytest.mark.unit
    def test_bit_constants_relationships(self):
        """Test relationships between bit constants."""
        # Test that each bit is double the previous
        assert BIT1 == BIT0 * 2
        assert BIT2 == BIT1 * 2
        assert BIT3 == BIT2 * 2
        assert BIT4 == BIT3 * 2
        assert BIT5 == BIT4 * 2
        assert BIT6 == BIT5 * 2
        assert BIT7 == BIT6 * 2
        assert BIT8 == BIT7 * 2

        # Test that higher bits follow the same pattern
        assert BIT16 == BIT15 * 2
        assert BIT32 == BIT31 * 2


class TestMakeMaskFunction:
    """Test make_mask function."""

    @pytest.mark.unit
    def test_make_mask_basic(self):
        """Test basic mask creation."""
        # Test single bit masks
        assert make_mask(1) == 0x1
        assert make_mask(2) == 0x3
        assert make_mask(3) == 0x7
        assert make_mask(4) == 0xF
        assert make_mask(8) == 0xFF
        assert make_mask(16) == 0xFFFF
        assert make_mask(32) == 0xFFFFFFFF

    @pytest.mark.unit
    def test_make_mask_with_offset(self):
        """Test mask creation with offset."""
        # Test masks with starting position
        assert make_mask(4, 4) == 0xF0  # 4 bits starting at bit 4
        assert make_mask(8, 8) == 0xFF00  # 8 bits starting at bit 8
        assert make_mask(1, 31) == 0x80000000  # 1 bit at position 31

    @pytest.mark.unit
    def test_make_mask_edge_cases(self):
        """Test make_mask with edge cases."""
        # Test zero size
        assert make_mask(0) == 0

        # Test large sizes
        assert make_mask(64) == 0xFFFFFFFFFFFFFFFF

        # Test with large offset
        assert make_mask(1, 63) == 0x8000000000000000


class TestBitFunction:
    """Test bit function."""

    @pytest.mark.unit
    def test_bit_function_basic(self):
        """Test basic bit function operation."""
        assert bit(0) == 0x1
        assert bit(1) == 0x2
        assert bit(2) == 0x4
        assert bit(3) == 0x8
        assert bit(4) == 0x10
        assert bit(5) == 0x20
        assert bit(6) == 0x40
        assert bit(7) == 0x80

    @pytest.mark.unit
    def test_bit_function_large_values(self):
        """Test bit function with larger bit numbers."""
        assert bit(31) == 0x80000000
        assert bit(32) == 0x100000000
        assert bit(63) == 0x8000000000000000

    @pytest.mark.unit
    def test_bit_function_relationship_to_constants(self):
        """Test that bit function matches BIT constants."""
        assert bit(0) == BIT0
        assert bit(1) == BIT1
        assert bit(2) == BIT2
        assert bit(3) == BIT3
        assert bit(4) == BIT4
        assert bit(5) == BIT5
        assert bit(6) == BIT6
        assert bit(7) == BIT7


class TestIsSetFunction:
    """Test is_set function."""

    @pytest.mark.unit
    def test_is_set_basic(self):
        """Test basic is_set functionality."""
        # Test with single bits
        assert is_set(0x1, BIT0)
        assert is_set(0x2, BIT1)
        assert is_set(0x4, BIT2)
        assert is_set(0x8, BIT3)

        # Test bits that are not set
        assert not is_set(0x1, BIT1)
        assert not is_set(0x2, BIT0)
        assert not is_set(0x4, BIT1)

    @pytest.mark.unit
    def test_is_set_with_multiple_bits(self):
        """Test is_set with multiple bits set."""
        value = 0x0F  # Bits 0-3 set
        assert is_set(value, BIT0)
        assert is_set(value, BIT1)
        assert is_set(value, BIT2)
        assert is_set(value, BIT3)
        assert not is_set(value, BIT4)

    @pytest.mark.unit
    def test_is_set_with_zero_value(self):
        """Test is_set with zero value."""
        assert not is_set(0, BIT0)
        assert not is_set(0, BIT1)
        assert not is_set(0, 0xFF)

    @pytest.mark.unit
    def test_is_set_with_all_bits_set(self):
        """Test is_set with all bits set."""
        value = 0xFFFFFFFF
        for i in range(32):
            assert is_set(value, bit(i))


class TestScanSingleBitMaskFunction:
    """Test scan_single_bit_mask function."""

    @pytest.mark.unit
    def test_scan_single_bit_mask_basic(self):
        """Test basic scan_single_bit_mask functionality."""
        assert scan_single_bit_mask(0x01) == 0
        assert scan_single_bit_mask(0x02) == 1
        assert scan_single_bit_mask(0x04) == 2
        assert scan_single_bit_mask(0x08) == 3
        assert scan_single_bit_mask(0x10) == 4
        assert scan_single_bit_mask(0x20) == 5
        assert scan_single_bit_mask(0x40) == 6

    @pytest.mark.unit
    def test_scan_single_bit_mask_multiple_bits(self):
        """Test scan_single_bit_mask with multiple bits set."""
        # Should return the lowest set bit
        assert scan_single_bit_mask(0x03) == 0  # Bits 0 and 1 set, returns 0
        assert scan_single_bit_mask(0x06) == 1  # Bits 1 and 2 set, returns 1
        assert scan_single_bit_mask(0x0C) == 2  # Bits 2 and 3 set, returns 2

    @pytest.mark.unit
    def test_scan_single_bit_mask_no_bits_set(self):
        """Test scan_single_bit_mask with no bits set."""
        assert scan_single_bit_mask(0x00) == None

    @pytest.mark.unit
    def test_scan_single_bit_mask_out_of_range(self):
        """Test scan_single_bit_mask with bits outside 0-6 range."""
        # Bits 7 and higher should return None
        assert scan_single_bit_mask(0x80) == None
        assert scan_single_bit_mask(0x100) == None
        assert scan_single_bit_mask(0x80000000) == None


class TestIsAllOnesFunction:
    """Test is_all_ones function."""

    @pytest.mark.unit
    def test_is_all_ones_basic(self):
        """Test basic is_all_ones functionality."""
        # Test with 8-bit values
        assert is_all_ones(0xFF, 1) == True   # 8-bit all ones
        assert is_all_ones(0xFFFF, 2) == True # 16-bit all ones
        assert is_all_ones(0xFFFFFFFF, 4) == True # 32-bit all ones

        # Test with non-all-ones values
        assert is_all_ones(0xFE, 1) == False  # Missing bit 0
        assert is_all_ones(0xFFFE, 2) == False # Missing bit 0
        assert is_all_ones(0xFFFFFFFE, 4) == False # Missing bit 0

    @pytest.mark.unit
    def test_is_all_ones_with_different_widths(self):
        """Test is_all_ones with different bit widths."""
        # Test with 16-bit width
        assert is_all_ones(0xFFFF, 2, 8) == True
        assert is_all_ones(0xFFFE, 2, 8) == False

        # Test with 32-bit width
        assert is_all_ones(0xFFFFFFFF, 4, 8) == True
        assert is_all_ones(0xFFFFFFFE, 4, 8) == False

    @pytest.mark.unit
    def test_is_all_ones_edge_cases(self):
        """Test is_all_ones with edge cases."""
        # Test with zero size
        assert is_all_ones(0, 0) == True

        # Test with zero value
        assert is_all_ones(0, 1) == False
        assert is_all_ones(0, 4) == False

        # Test with maximum values
        assert is_all_ones(0xFFFFFFFFFFFFFFFF, 8) == True


class TestOnesComplementFunction:
    """Test ones_complement function."""

    @pytest.mark.unit
    def test_ones_complement_basic(self):
        """Test basic ones_complement functionality."""
        assert ones_complement(0x00, 8) == 0xFF
        assert ones_complement(0xFF, 8) == 0x00
        assert ones_complement(0xAA, 8) == 0x55
        assert ones_complement(0x55, 8) == 0xAA

    @pytest.mark.unit
    def test_ones_complement_16bit(self):
        """Test ones_complement with 16-bit values."""
        assert ones_complement(0x0000, 16) == 0xFFFF
        assert ones_complement(0xFFFF, 16) == 0x0000
        assert ones_complement(0xAAAA, 16) == 0x5555
        assert ones_complement(0x5555, 16) == 0xAAAA

    @pytest.mark.unit
    def test_ones_complement_32bit(self):
        """Test ones_complement with 32-bit values."""
        assert ones_complement(0x00000000, 32) == 0xFFFFFFFF
        assert ones_complement(0xFFFFFFFF, 32) == 0x00000000

    @pytest.mark.unit
    def test_ones_complement_64bit(self):
        """Test ones_complement with 64-bit values."""
        assert ones_complement(0x0000000000000000, 64) == 0xFFFFFFFFFFFFFFFF
        assert ones_complement(0xFFFFFFFFFFFFFFFF, 64) == 0x0000000000000000

    @pytest.mark.unit
    def test_ones_complement_default_bits(self):
        """Test ones_complement with default 64-bit."""
        assert ones_complement(0x00) == 0xFFFFFFFFFFFFFFFF
        assert ones_complement(0xFFFFFFFFFFFFFFFF) == 0x00


class TestGetBitsFunction:
    """Test get_bits function."""

    @pytest.mark.unit
    def test_get_bits_basic(self):
        """Test basic get_bits functionality."""
        value = 0x12345678

        # Extract individual bytes
        assert get_bits(value, 0, 8) == 0x78
        assert get_bits(value, 8, 8) == 0x56
        assert get_bits(value, 16, 8) == 0x34
        assert get_bits(value, 24, 8) == 0x12

    @pytest.mark.unit
    def test_get_bits_preserve_field_position_false(self):
        """Test get_bits with preserve_field_position=False."""
        value = 0xFF00FF00

        # Extract 8-bit fields, shifted to LSB
        assert get_bits(value, 0, 8) == 0x00
        assert get_bits(value, 8, 8) == 0xFF
        assert get_bits(value, 16, 8) == 0x00
        assert get_bits(value, 24, 8) == 0xFF

    @pytest.mark.unit
    def test_get_bits_preserve_field_position_true(self):
        """Test get_bits with preserve_field_position=True."""
        value = 0xFF00FF00

        # Extract 8-bit fields, preserving position
        assert get_bits(value, 0, 8, True) == 0x00
        assert get_bits(value, 8, 8, True) == 0xFF00
        assert get_bits(value, 16, 8, True) == 0x00
        assert get_bits(value, 24, 8, True) == 0xFF000000

    @pytest.mark.unit
    def test_get_bits_different_sizes(self):
        """Test get_bits with different field sizes."""
        value = 0x123456789ABCDEF0

        # Extract 4-bit fields
        assert get_bits(value, 0, 4) == 0x0
        assert get_bits(value, 4, 4) == 0xF
        assert get_bits(value, 8, 4) == 0xE
        assert get_bits(value, 12, 4) == 0xD

        # Extract 16-bit fields
        assert get_bits(value, 0, 16) == 0xDEF0
        assert get_bits(value, 16, 16) == 0x9ABC
        assert get_bits(value, 32, 16) == 0x5678
        assert get_bits(value, 48, 16) == 0x1234

    @pytest.mark.unit
    def test_get_bits_edge_cases(self):
        """Test get_bits with edge cases."""
        # Test with zero value
        assert get_bits(0, 0, 8) == 0
        assert get_bits(0, 16, 16) == 0

        # Test extracting from MSB
        value = 0x8000000000000000
        assert get_bits(value, 63, 1) == 1
        assert get_bits(value, 63, 1, True) == 0x8000000000000000


class TestSetBitsFunction:
    """Test set_bits function."""

    @pytest.mark.unit
    def test_set_bits_basic(self):
        """Test basic set_bits functionality."""
        # Start with zero, set individual bytes
        result = set_bits(0, 8, 0, 0x78)
        assert result == 0x78

        result = set_bits(8, 8, result, 0x56)
        assert result == 0x5678

        result = set_bits(16, 8, result, 0x34)
        assert result == 0x345678

        result = set_bits(24, 8, result, 0x12)
        assert result == 0x12345678

    @pytest.mark.unit
    def test_set_bits_overwrite(self):
        """Test set_bits overwriting existing values."""
        initial_value = 0xFFFFFFFF

        # Overwrite with zeros
        result = set_bits(0, 8, initial_value, 0x00)
        assert result == 0xFFFFFF00

        result = set_bits(8, 8, result, 0x00)
        assert result == 0xFFFF0000

        result = set_bits(16, 8, result, 0x00)
        assert result == 0xFF000000

        result = set_bits(24, 8, result, 0x00)
        assert result == 0x00000000

    @pytest.mark.unit
    def test_set_bits_different_sizes(self):
        """Test set_bits with different field sizes."""
        initial_value = 0x00000000

        # Set 4-bit fields
        result = set_bits(0, 4, initial_value, 0xF)
        assert result == 0xF

        result = set_bits(4, 4, result, 0xE)
        assert result == 0xEF  # 0xF | (0xE << 4) = 0xF | 0xE0 = 0xEF

        result = set_bits(8, 4, result, 0xD)
        assert result == 0xDEF  # 0xEF | (0xD << 8) = 0xEF | 0xD00 = 0xDEF

        result = set_bits(12, 4, result, 0xC)
        assert result == 0xCDEF  # 0xDEF | (0xC << 12) = 0xDEF | 0xC000 = 0xCDEF

    @pytest.mark.unit
    def test_set_bits_value_masking(self):
        """Test that set_bits properly masks the input value."""
        initial_value = 0x00000000

        # Try to set a value larger than the field size
        result = set_bits(0, 4, initial_value, 0xFF)  # Only bottom 4 bits should be used
        assert result == 0xF

        result = set_bits(4, 8, initial_value, 0xFFFF)  # Only bottom 8 bits should be used
        assert result == 0xFF0

    @pytest.mark.unit
    def test_set_bits_edge_cases(self):
        """Test set_bits with edge cases."""
        # Test with zero field size (should not change anything)
        result = set_bits(0, 0, 0xFF, 0xFF)
        assert result == 0xFF

        # Test setting at bit position 63
        result = set_bits(63, 1, 0x00, 0x1)
        assert result == 0x8000000000000000

        # Test setting at bit position 0
        result = set_bits(0, 1, 0x00, 0x1)
        assert result == 0x1


class TestBitManipulationIntegration:
    """Integration tests for bit manipulation functions."""

    @pytest.mark.integration
    def test_bit_manipulation_round_trip(self):
        """Test round-trip bit manipulation operations."""
        original_value = 0x123456789ABCDEF0

        # Extract and re-assemble bytes
        byte0 = get_bits(original_value, 0, 8)
        byte1 = get_bits(original_value, 8, 8)
        byte2 = get_bits(original_value, 16, 8)
        byte3 = get_bits(original_value, 24, 8)
        byte4 = get_bits(original_value, 32, 8)
        byte5 = get_bits(original_value, 40, 8)
        byte6 = get_bits(original_value, 48, 8)
        byte7 = get_bits(original_value, 56, 8)

        # Reassemble
        result = 0
        result = set_bits(0, 8, result, byte0)
        result = set_bits(8, 8, result, byte1)
        result = set_bits(16, 8, result, byte2)
        result = set_bits(24, 8, result, byte3)
        result = set_bits(32, 8, result, byte4)
        result = set_bits(40, 8, result, byte5)
        result = set_bits(48, 8, result, byte6)
        result = set_bits(56, 8, result, byte7)

        assert result == original_value

    @pytest.mark.integration
    def test_bit_operations_consistency(self):
        """Test consistency between different bit operations."""
        test_value = 0xAAAAAAAAAAAAAAAA

        # Test that bit() function is consistent with BIT constants
        for i in range(64):
            assert bit(i) == (1 << i)

        # Test that is_set works with bit() function
        for i in range(64):
            if (test_value & (1 << i)) != 0:
                assert is_set(test_value, bit(i)) == True
            else:
                assert is_set(test_value, bit(i)) == False

    @pytest.mark.integration
    def test_mask_operations(self):
        """Test mask creation and usage consistency."""
        # Test that make_mask creates proper masks for reasonable sizes
        for size in range(1, 21):  # Reduced from 33 to 21 to avoid exponential time complexity
            mask = make_mask(size)
            assert mask == (1 << size) - 1

            # Test mask operation with representative values instead of exhaustive testing
            # Test boundary values: 0, all bits set, and some random values
            test_values = [0, mask, mask // 2, mask // 4, (mask // 2) + 1]
            for test_val in test_values:
                assert (test_val & mask) == test_val

        # Test larger masks with minimal verification (avoid exponential time)
        for size in [24, 32, 64]:
            mask = make_mask(size)
            assert mask == (1 << size) - 1

            # Only test a few key values for large masks
            test_values = [0, 1, mask // 2, mask - 1, mask]
            for test_val in test_values:
                assert (test_val & mask) == test_val

    @pytest.mark.integration
    def test_complement_operations(self):
        """Test ones complement operations."""
        test_values = [0x00, 0xFF, 0xAAAA5555, 0xFFFFFFFFFFFFFFFF]

        for value in test_values:
            # Test that complementing twice returns original
            complemented = ones_complement(value, 64)
            double_complemented = ones_complement(complemented, 64)
            assert double_complemented == value

            # Test that complement of all ones is all zeros and vice versa
            if value == 0:
                assert complemented == 0xFFFFFFFFFFFFFFFF
            elif value == 0xFFFFFFFFFFFFFFFF:
                assert complemented == 0


if __name__ == '__main__':
    pytest.main([__file__])
