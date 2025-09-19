# Tests for DMAR ACPI table parsing (chipsec.library.acpi_tables.DMAR)
# Targets branches: empty content error, too short error, normal parse with
# multiple structures, premature termination on zero length, structure length
# overrun warnings.

import struct
import pytest
from unittest.mock import patch

from chipsec.library.acpi_tables import (
    DMAR,
    DMAR_TYPE_DRHD,
    DMAR_TYPE_RMRR,
    DMAR_TYPE_ATSR,
    DMAR_TYPE_RHSA,
    DMAR_TYPE_ANDD,
    ACPI_TABLE_FORMAT_DMAR,
    ACPI_TABLE_SIZE_DMAR,
)

# Helper builders for DMAR sub-structures ---------------------------------------------------------------

def build_device_scope(path_bytes=b"\x00\x01"):
    # Type=1 (PCI endpoint), Length = header(6) + path len
    ds_type = 0x01
    base_len = 6
    length = base_len + len(path_bytes)
    fmt = '=BBBBBB'  # Type, Length, Flags, Reserved, EnumerationID, StartBusNum
    header = struct.pack(fmt, ds_type, length, 0xAA, 0x00, 0x02, 0x00)
    return header + path_bytes


def build_drhd():
    # DRHD_FORMAT: '=HHBBHQ' -> Type, Length, Flags, Reserved, SegmentNumber, RegisterBaseAddr
    device_scope = build_device_scope()
    body_len = struct.calcsize('=HHBBHQ')
    length = body_len + len(device_scope)
    hdr = struct.pack('=HHBBHQ', DMAR_TYPE_DRHD, length, 0x01, 0x00, 0x0001, 0x12345678ABCDEF00)
    return hdr + device_scope


def build_rmrr():
    # RMRR_FORMAT '=HHHHQQ'
    device_scope = build_device_scope(b"\x00")
    body_len = struct.calcsize('=HHHHQQ')
    length = body_len + len(device_scope)
    hdr = struct.pack('=HHHHQQ', DMAR_TYPE_RMRR, length, 0x0000, 0x0001, 0x1000, 0x1FFF)
    return hdr + device_scope


def build_atsr():
    # ATRS_FORMAT '=HHBBH'
    device_scope = build_device_scope(b"\x00\x02")
    body_len = struct.calcsize('=HHBBH')
    length = body_len + len(device_scope)
    hdr = struct.pack('=HHBBH', DMAR_TYPE_ATSR, length, 0x01, 0x00, 0x0001)
    return hdr + device_scope


def build_rhsa():
    # RHSA_FORMAT '=HHIQI'
    body_len = struct.calcsize('=HHIQI')
    length = body_len
    hdr = struct.pack('=HHIQI', DMAR_TYPE_RHSA, length, 0x00000000, 0x0000000012345678, 0x00000042)
    return hdr


def build_andd():
    # ANDD_FORMAT 'HH3sB' + variable name bytes
    name = b'PCI0'
    base_fmt = 'HH3sB'
    base_len = struct.calcsize(base_fmt)
    length = base_len + len(name)
    hdr = struct.pack(base_fmt, DMAR_TYPE_ANDD, length, b'XYZ', 0x20)
    return hdr + name


# Build complete DMAR table content -------------------------------------------------------------------

def build_dmar_table(structs: list[bytes]):
    # DMAR header (HostAddrWidth, Flags, Reserved[10])
    header = struct.pack(ACPI_TABLE_FORMAT_DMAR, 0x28, 0x01, b'R'*10)
    return header + b''.join(structs)


# Tests ------------------------------------------------------------------------------------------------

@pytest.mark.unit
def test_dmar_parse_empty():
    dmar = DMAR()
    with pytest.raises(ValueError):
        dmar.parse(b'')


@pytest.mark.unit
def test_dmar_parse_too_short():
    dmar = DMAR()
    with pytest.raises(ValueError):
        dmar.parse(b'X' * (ACPI_TABLE_SIZE_DMAR - 1))


@pytest.mark.unit
def test_dmar_parse_single_structure_drhd():
    dmar = DMAR()
    t = build_dmar_table([build_drhd()])
    dmar.parse(t)
    assert len(dmar.dmar_structures) == 1
    # Validate captured header fields
    assert dmar.HostAddrWidth == 0x28
    assert dmar.Flags == 0x01


@pytest.mark.unit
def test_dmar_parse_multiple_structures():
    dmar = DMAR()
    t = build_dmar_table([build_drhd(), build_rmrr(), build_atsr(), build_rhsa(), build_andd()])
    dmar.parse(t)
    assert len(dmar.dmar_structures) == 5


@pytest.mark.unit
def test_dmar_parse_zero_length_break():
    dmar = DMAR()
    # Append a zero-length structure header to force early loop break
    drhd = build_drhd()
    zero_hdr = struct.pack('=HH', 0x1234, 0)  # type arbitrary, length=0 triggers break
    t = build_dmar_table([drhd + zero_hdr])
    dmar.parse(t)
    assert len(dmar.dmar_structures) == 1


@pytest.mark.unit
def test_dmar_parse_length_overrun_warning():
    dmar = DMAR()
    drhd = build_drhd()
    # Corrupt length to exceed remaining buffer
    malformed = bytearray(drhd)
    # length field is at offset 2 (after Type)
    bad_len = struct.pack('=H', len(drhd) + 50)
    malformed[2:4] = bad_len
    hdr = struct.pack(ACPI_TABLE_FORMAT_DMAR, 0x28, 0x01, b'R'*10)
    content = hdr + bytes(malformed)
    with patch('chipsec.library.acpi_tables.logger') as mock_logger_factory:
        mock_logger = mock_logger_factory.return_value
        dmar.parse(content)
        # Expect warning about structure length exceeding remaining data
        assert any('Structure length' in c[0][0] for c in mock_logger.log_warning.call_args_list)
        # Since overrun, parser should not append the malformed structure
        assert len(dmar.dmar_structures) == 0
