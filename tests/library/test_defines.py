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
import struct
import os
import platform
from unittest.mock import patch, mock_open
from chipsec.library.defines import (
    # Bit constants
    BIT0, BIT1, BIT2, BIT3, BIT4, BIT5, BIT6, BIT7,
    BIT8, BIT9, BIT10, BIT11, BIT12, BIT13, BIT14, BIT15,
    BIT16, BIT17, BIT18, BIT19, BIT20, BIT21, BIT22, BIT23,
    BIT24, BIT25, BIT26, BIT27, BIT28, BIT29, BIT30, BIT31,
    BIT32, BIT33, BIT34, BIT35, BIT36, BIT37, BIT38, BIT39,
    BIT40, BIT41, BIT42, BIT43, BIT44, BIT45, BIT46, BIT47,
    BIT48, BIT49, BIT50, BIT51, BIT52, BIT53, BIT54, BIT55,
    BIT56, BIT57, BIT58, BIT59, BIT60, BIT61, BIT62, BIT63,
    # Boundary constants
    BOUNDARY_1KB, BOUNDARY_2KB, BOUNDARY_4KB, BOUNDARY_1MB,
    BOUNDARY_2MB, BOUNDARY_4MB, BOUNDARY_8MB, BOUNDARY_16MB,
    BOUNDARY_32MB, BOUNDARY_64MB, BOUNDARY_128MB, BOUNDARY_256MB,
    BOUNDARY_512MB, BOUNDARY_1GB, BOUNDARY_2GB, BOUNDARY_4GB,
    # Alignment constants
    ALIGNED_4KB, ALIGNED_1MB, ALIGNED_8MB, ALIGNED_64MB,
    ALIGNED_128MB, ALIGNED_256MB,
    # Mask constants
    MASK_8b, MASK_16b, MASK_32b, MASK_64b,
    # Chipset constants
    CHIPSET_CODE_UNKNOWN, PCH_CODE_PREFIX, CHIPSET_ID_UNKNOWN,
    # Functions
    bit, is_set, scan_single_bit_mask, DB, DW, DD, DQ,
    SIZE2FORMAT, bytestostring, stringtobytes, pack1, unpack1,
    get_bits, get_version, os_version, is_printable, is_hex,
    is_all_ones, get_message, is_all_value, ARCH_VID
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


class TestBoundaryConstants:
    """Test boundary constant definitions."""

    @pytest.mark.unit
    def test_boundary_constants_values(self):
        """Test that boundary constants have correct values."""
        # Test KB boundaries
        assert BOUNDARY_1KB == 0x400
        assert BOUNDARY_2KB == 0x800
        assert BOUNDARY_4KB == 0x1000

        # Test MB boundaries
        assert BOUNDARY_1MB == 0x100000
        assert BOUNDARY_2MB == 0x200000
        assert BOUNDARY_4MB == 0x400000
        assert BOUNDARY_8MB == 0x800000
        assert BOUNDARY_16MB == 0x1000000
        assert BOUNDARY_32MB == 0x2000000
        assert BOUNDARY_64MB == 0x4000000
        assert BOUNDARY_128MB == 0x8000000
        assert BOUNDARY_256MB == 0x10000000
        assert BOUNDARY_512MB == 0x20000000

        # Test GB boundaries
        assert BOUNDARY_1GB == 0x40000000
        assert BOUNDARY_2GB == 0x80000000
        assert BOUNDARY_4GB == 0x100000000

    @pytest.mark.unit
    def test_boundary_constants_progression(self):
        """Test that boundary constants follow proper progression."""
        # Test KB progression
        assert BOUNDARY_2KB == BOUNDARY_1KB * 2
        assert BOUNDARY_4KB == BOUNDARY_2KB * 2

        # Test MB progression
        assert BOUNDARY_2MB == BOUNDARY_1MB * 2
        assert BOUNDARY_4MB == BOUNDARY_2MB * 2
        assert BOUNDARY_8MB == BOUNDARY_4MB * 2
        assert BOUNDARY_16MB == BOUNDARY_8MB * 2
        assert BOUNDARY_32MB == BOUNDARY_16MB * 2
        assert BOUNDARY_64MB == BOUNDARY_32MB * 2
        assert BOUNDARY_128MB == BOUNDARY_64MB * 2
        assert BOUNDARY_256MB == BOUNDARY_128MB * 2
        assert BOUNDARY_512MB == BOUNDARY_256MB * 2

        # Test GB progression
        assert BOUNDARY_2GB == BOUNDARY_1GB * 2
        assert BOUNDARY_4GB == BOUNDARY_2GB * 2


class TestAlignmentConstants:
    """Test alignment constant definitions."""

    @pytest.mark.unit
    def test_alignment_constants_values(self):
        """Test that alignment constants have correct values."""
        assert ALIGNED_4KB == 0xFFF
        assert ALIGNED_1MB == 0xFFFFF
        assert ALIGNED_8MB == 0x7FFFFF
        assert ALIGNED_64MB == 0x3FFFFFF
        assert ALIGNED_128MB == 0x7FFFFFF
        assert ALIGNED_256MB == 0xFFFFFFF

    @pytest.mark.unit
    def test_alignment_constants_relationships(self):
        """Test relationships between alignment constants."""
        # ALIGNED_4KB = 4KB - 1 = 0x1000 - 1 = 0xFFF
        assert ALIGNED_4KB == BOUNDARY_4KB - 1

        # ALIGNED_1MB = 1MB - 1 = 0x100000 - 1 = 0xFFFFF
        assert ALIGNED_1MB == BOUNDARY_1MB - 1

        # ALIGNED_8MB = 8MB - 1 = 0x800000 - 1 = 0x7FFFFF
        assert ALIGNED_8MB == BOUNDARY_8MB - 1


class TestMaskConstants:
    """Test mask constant definitions."""

    @pytest.mark.unit
    def test_mask_constants_values(self):
        """Test that mask constants have correct values."""
        assert MASK_8b == 0xFF
        assert MASK_16b == 0xFFFF
        assert MASK_32b == 0xFFFFFFFF
        assert MASK_64b == 0xFFFFFFFFFFFFFFFF

    @pytest.mark.unit
    def test_mask_constants_relationships(self):
        """Test relationships between mask constants."""
        # 8-bit mask
        assert MASK_8b == (1 << 8) - 1

        # 16-bit mask
        assert MASK_16b == (1 << 16) - 1

        # 32-bit mask
        assert MASK_32b == (1 << 32) - 1

        # 64-bit mask
        assert MASK_64b == (1 << 64) - 1

    @pytest.mark.unit
    def test_mask_constants_progression(self):
        """Test that mask constants follow proper progression."""
        # Test that each mask is composed of smaller masks
        assert MASK_16b == (MASK_8b << 8) | MASK_8b
        assert MASK_32b == (MASK_16b << 16) | MASK_16b
        assert MASK_64b == (MASK_32b << 32) | MASK_32b


class TestChipsetConstants:
    """Test chipset constant definitions."""

    @pytest.mark.unit
    def test_chipset_constants_values(self):
        """Test that chipset constants have correct values."""
        assert CHIPSET_CODE_UNKNOWN == ''
        assert PCH_CODE_PREFIX == 'PCH_'
        assert CHIPSET_ID_UNKNOWN == 0


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
        assert scan_single_bit_mask(0x00) is None

    @pytest.mark.unit
    def test_scan_single_bit_mask_out_of_range(self):
        """Test scan_single_bit_mask with bits outside 0-6 range."""
        # Bits 7 and higher should return None
        assert scan_single_bit_mask(0x80) is None
        assert scan_single_bit_mask(0x100) is None
        assert scan_single_bit_mask(0x80000000) is None


class TestDataPackingFunctions:
    """Test data packing functions (DB, DW, DD, DQ)."""

    @pytest.mark.unit
    def test_db_function(self):
        """Test DB function (pack byte)."""
        result = DB(0x42)
        assert result == b'\x42'
        assert len(result) == 1

        # Test with different values
        assert DB(0x00) == b'\x00'
        assert DB(0xFF) == b'\xFF'
        assert DB(0xAB) == b'\xAB'

    @pytest.mark.unit
    def test_dw_function(self):
        """Test DW function (pack word)."""
        result = DW(0x1234)
        assert result == b'\x34\x12'  # Little endian
        assert len(result) == 2

        # Test with different values
        assert DW(0x0000) == b'\x00\x00'
        assert DW(0xFFFF) == b'\xFF\xFF'
        assert DW(0xABCD) == b'\xCD\xAB'

    @pytest.mark.unit
    def test_dd_function(self):
        """Test DD function (pack double word)."""
        result = DD(0x12345678)
        assert result == b'\x78\x56\x34\x12'  # Little endian
        assert len(result) == 4

        # Test with different values
        assert DD(0x00000000) == b'\x00\x00\x00\x00'
        assert DD(0xFFFFFFFF) == b'\xFF\xFF\xFF\xFF'
        assert DD(0xABCDEF01) == b'\x01\xEF\xCD\xAB'

    @pytest.mark.unit
    def test_dq_function(self):
        """Test DQ function (pack quad word)."""
        result = DQ(0x123456789ABCDEF0)
        assert result == b'\xF0\xDE\xBC\x9A\x78\x56\x34\x12'  # Little endian
        assert len(result) == 8

        # Test with different values
        assert DQ(0x0000000000000000) == b'\x00\x00\x00\x00\x00\x00\x00\x00'
        assert DQ(0xFFFFFFFFFFFFFFFF) == b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'


class TestSize2FormatDictionary:
    """Test SIZE2FORMAT dictionary."""

    @pytest.mark.unit
    def test_size2format_values(self):
        """Test SIZE2FORMAT dictionary values."""
        assert SIZE2FORMAT[1] == 'B'  # 1 byte -> unsigned char
        assert SIZE2FORMAT[2] == 'H'  # 2 bytes -> unsigned short
        assert SIZE2FORMAT[4] == 'I'  # 4 bytes -> unsigned int
        assert SIZE2FORMAT[8] == 'Q'  # 8 bytes -> unsigned long long

    @pytest.mark.unit
    def test_size2format_keys(self):
        """Test SIZE2FORMAT dictionary keys."""
        expected_keys = {1, 2, 4, 8}
        assert set(SIZE2FORMAT.keys()) == expected_keys


class TestPackUnpackFunctions:
    """Test pack1 and unpack1 functions."""

    @pytest.mark.unit
    def test_pack1_function(self):
        """Test pack1 function."""
        # Test 1-byte packing
        result = pack1(0x42, 1)
        assert result == b'\x42'

        # Test 2-byte packing
        result = pack1(0x1234, 2)
        assert result == b'\x34\x12'

        # Test 4-byte packing
        result = pack1(0x12345678, 4)
        assert result == b'\x78\x56\x34\x12'

        # Test 8-byte packing
        result = pack1(0x123456789ABCDEF0, 8)
        assert result == b'\xF0\xDE\xBC\x9A\x78\x56\x34\x12'

    @pytest.mark.unit
    def test_unpack1_function(self):
        """Test unpack1 function."""
        # Test 1-byte unpacking
        result = unpack1(b'\x42', 1)
        assert result == 0x42

        # Test 2-byte unpacking
        result = unpack1(b'\x34\x12', 2)
        assert result == 0x1234

        # Test 4-byte unpacking
        result = unpack1(b'\x78\x56\x34\x12', 4)
        assert result == 0x12345678

        # Test 8-byte unpacking
        result = unpack1(b'\xF0\xDE\xBC\x9A\x78\x56\x34\x12', 8)
        assert result == 0x123456789ABCDEF0

    @pytest.mark.unit
    def test_pack_unpack_round_trip(self):
        """Test round-trip pack/unpack operations."""
        test_values = [0x42, 0x1234, 0x12345678, 0x123456789ABCDEF0]
        sizes = [1, 2, 4, 8]

        for value, size in zip(test_values, sizes):
            packed = pack1(value, size)
            unpacked = unpack1(packed, size)
            assert unpacked == value


class TestStringConversionFunctions:
    """Test string conversion functions."""

    @pytest.mark.unit
    def test_bytestostring_bytes(self):
        """Test bytestostring with bytes input."""
        result = bytestostring(b'hello')
        assert result == 'hello'
        assert isinstance(result, str)

    @pytest.mark.unit
    def test_bytestostring_bytearray(self):
        """Test bytestostring with bytearray input."""
        result = bytestostring(bytearray(b'world'))
        assert result == 'world'
        assert isinstance(result, str)

    @pytest.mark.unit
    def test_bytestostring_string(self):
        """Test bytestostring with string input."""
        result = bytestostring('test')
        assert result == 'test'
        assert isinstance(result, str)

    @pytest.mark.unit
    def test_stringtobytes_string(self):
        """Test stringtobytes with string input."""
        result = stringtobytes('hello')
        assert result == b'hello'
        assert isinstance(result, bytes)

    @pytest.mark.unit
    def test_stringtobytes_bytes(self):
        """Test stringtobytes with bytes input."""
        result = stringtobytes(b'world')
        assert result == b'world'
        assert isinstance(result, bytes)

    @pytest.mark.unit
    def test_string_conversion_round_trip(self):
        """Test round-trip string conversion."""
        original = 'Hello, World! 🌍'
        bytes_version = stringtobytes(original)
        string_version = bytestostring(bytes_version)
        assert string_version == original


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

        # Test extracting full value
        value = 0x12345678
        assert get_bits(value, 0, 32) == value


class TestSystemFunctions:
    """Test system-related functions."""

    @pytest.mark.unit
    def test_get_version(self):
        """Test get_version function."""
        with patch('os.listdir') as mock_listdir, \
             patch('os.path.join') as mock_join, \
             patch('builtins.open', mock_open(read_data='1.2.3')):

            mock_listdir.return_value = ['VERSION']
            mock_join.return_value = '/path/to/VERSION'

            result = get_version()
            assert result == '1.2.3'

    @pytest.mark.unit
    def test_get_version_multiple_files(self):
        """Test get_version with multiple version files."""
        with patch('os.listdir') as mock_listdir, \
             patch('os.path.join') as mock_join, \
             patch('builtins.open', mock_open()) as mock_file:

            mock_listdir.return_value = ['VERSION1', 'VERSION2', 'VERSION3']
            mock_join.return_value = '/path/to/VERSION'
            mock_file.return_value.read.side_effect = ['1.0', '2.0', '3.0']

            result = get_version()
            assert result == '1.0-2.0-3.0'

    @pytest.mark.unit
    def test_os_version(self):
        """Test os_version function."""
        with patch('platform.system', return_value='Linux'), \
             patch('platform.release', return_value='5.4.0'), \
             patch('platform.version', return_value='#1 SMP'), \
             patch('platform.machine', return_value='x86_64'):

            result = os_version()
            assert result == ('Linux', '5.4.0', '#1 SMP', 'x86_64')

    @pytest.mark.unit
    def test_get_message_existing_file(self):
        """Test get_message with existing message file."""
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data='Test message')):

            result = get_message()
            assert result == 'Test message'

    @pytest.mark.unit
    def test_get_message_no_file(self):
        """Test get_message with no message file."""
        with patch('os.path.exists', return_value=False):
            result = get_message()
            assert result == ''


class TestValidationFunctions:
    """Test validation functions."""

    @pytest.mark.unit
    def test_is_printable_printable_string(self):
        """Test is_printable with printable string."""
        assert is_printable('Hello World!')
        assert is_printable('123456')
        assert is_printable('!@#$%^&*()')

    @pytest.mark.unit
    def test_is_printable_non_printable(self):
        """Test is_printable with non-printable characters."""
        assert not is_printable('\x00\x01\x02')  # Null bytes
        assert not is_printable('Hello\x00World')  # Embedded null
        assert not is_printable('\x7F\x80\x81')  # DEL and high bytes

    @pytest.mark.unit
    def test_is_printable_bytes(self):
        """Test is_printable with bytes input."""
        assert is_printable(b'Hello World!')
        assert not is_printable(b'\x00\x01\x02')

    @pytest.mark.unit
    def test_is_hex_valid_hex(self):
        """Test is_hex with valid hexadecimal strings."""
        assert is_hex('123456789ABCDEF')
        assert is_hex('abcdef')
        assert is_hex('ABCDEF')
        assert is_hex('123ABC')
        assert is_hex('')  # Empty string

    @pytest.mark.unit
    def test_is_hex_invalid_hex(self):
        """Test is_hex with invalid hexadecimal strings."""
        assert not is_hex('123G')  # G is not hex
        assert not is_hex('Hello')  # Letters beyond F
        assert not is_hex('123-456')  # Hyphen not hex
        assert not is_hex('123 456')  # Space not hex

    @pytest.mark.unit
    def test_is_all_value_all_same(self):
        """Test is_all_value with all elements same."""
        assert is_all_value([1, 1, 1, 1], 1)
        assert is_all_value(['a', 'a', 'a'], 'a')
        assert is_all_value([True, True, True], True)

    @pytest.mark.unit
    def test_is_all_value_different_values(self):
        """Test is_all_value with different values."""
        assert not is_all_value([1, 2, 3], 1)
        assert not is_all_value(['a', 'b', 'c'], 'a')
        assert not is_all_value([True, False], True)

    @pytest.mark.unit
    def test_is_all_value_empty_list(self):
        """Test is_all_value with empty list."""
        assert is_all_value([], 42)  # Empty list vacuously true

    @pytest.mark.unit
    def test_is_all_value_single_element(self):
        """Test is_all_value with single element."""
        assert is_all_value([42], 42)
        assert not is_all_value([42], 43)


class TestIsAllOnesFunction:
    """Test is_all_ones function."""

    @pytest.mark.unit
    def test_is_all_ones_basic(self):
        """Test basic is_all_ones functionality."""
        # Test with 8-bit values
        assert is_all_ones(0xFF, 1)  # 8-bit all ones
        assert is_all_ones(0xFFFF, 2)  # 16-bit all ones
        assert is_all_ones(0xFFFFFFFF, 4)  # 32-bit all ones

        # Test with non-all-ones values
        assert not is_all_ones(0xFE, 1)  # Missing bit 0
        assert not is_all_ones(0xFFFE, 2)  # Missing bit 0
        assert not is_all_ones(0xFFFFFFFE, 4)  # Missing bit 0

    @pytest.mark.unit
    def test_is_all_ones_with_different_widths(self):
        """Test is_all_ones with different bit widths."""
        # Test with 16-bit width
        assert is_all_ones(0xFFFF, 2, 8)
        assert not is_all_ones(0xFFFE, 2, 8)

        # Test with 32-bit width
        assert is_all_ones(0xFFFFFFFF, 4, 8)
        assert not is_all_ones(0xFFFFFFFE, 4, 8)

    @pytest.mark.unit
    def test_is_all_ones_edge_cases(self):
        """Test is_all_ones with edge cases."""
        # Test with zero size
        assert is_all_ones(0, 0)

        # Test with zero value
        assert not is_all_ones(0, 1)
        assert not is_all_ones(0, 4)

        # Test with maximum values
        assert is_all_ones(0xFFFFFFFFFFFFFFFF, 8)


class TestArchitectureConstants:
    """Test architecture constant definitions."""

    @pytest.mark.unit
    def test_arch_vid_constants(self):
        """Test ARCH_VID constants."""
        assert ARCH_VID.INTEL == 0x8086
        assert ARCH_VID.AMD == 0x1022


class TestDefinesIntegration:
    """Integration tests for defines module."""

    @pytest.mark.integration
    def test_boundary_alignment_relationships(self):
        """Test relationships between boundary and alignment constants."""
        # Test that alignment constants are boundary - 1
        assert ALIGNED_4KB == BOUNDARY_4KB - 1
        assert ALIGNED_1MB == BOUNDARY_1MB - 1
        assert ALIGNED_8MB == BOUNDARY_8MB - 1
        assert ALIGNED_64MB == BOUNDARY_64MB - 1
        assert ALIGNED_128MB == BOUNDARY_128MB - 1
        assert ALIGNED_256MB == BOUNDARY_256MB - 1

    @pytest.mark.integration
    def test_mask_boundary_relationships(self):
        """Test relationships between masks and boundaries."""
        # Test that masks can be used for boundary checking
        assert (BOUNDARY_1KB & MASK_16b) == BOUNDARY_1KB
        assert (BOUNDARY_1MB & MASK_32b) == BOUNDARY_1MB
        assert (BOUNDARY_1GB & MASK_32b) == BOUNDARY_1GB

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
                assert is_set(test_value, bit(i))
            else:
                assert not is_set(test_value, bit(i))

    @pytest.mark.integration
    def test_data_packing_consistency(self):
        """Test consistency of data packing operations."""
        test_values = [0x42, 0x1234, 0x12345678, 0x123456789ABCDEF0]

        # Test that DB/DW/DD/DQ are consistent with pack1
        assert DB(test_values[0]) == pack1(test_values[0], 1)
        assert DW(test_values[1]) == pack1(test_values[1], 2)
        assert DD(test_values[2]) == pack1(test_values[2], 4)
        assert DQ(test_values[3]) == pack1(test_values[3], 8)

    @pytest.mark.integration
    def test_string_conversion_consistency(self):
        """Test consistency of string conversion operations."""
        test_strings = ['Hello', 'World', 'Test', 'CHIPSEC']

        for test_str in test_strings:
            # Test round-trip conversion
            bytes_version = stringtobytes(test_str)
            back_to_string = bytestostring(bytes_version)
            assert back_to_string == test_str

            # Test with bytes input
            bytes_input = test_str.encode('latin_1')
            string_version = bytestostring(bytes_input)
            assert string_version == test_str


if __name__ == '__main__':
    pytest.main([__file__])
