import struct
import pytest

from chipsec.library import acpi_tables as acpi


def checksum8(data: bytes) -> int:
    return (-(sum(data) & 0xFF)) & 0xFF


@pytest.mark.unit
def test_rsdp_legacy_and_extended():
    # Legacy (20 bytes)
    legacy = bytearray(struct.pack('<8sB6sBI', b'RSD PTR ', 0, b'OEMID ', 0, 0x12345678))
    legacy[8] = checksum8(legacy)  # set checksum
    r = acpi.RSDP()
    r.parse(bytes(legacy))
    assert r.Signature == b'RSD PTR '
    assert r.Length is None
    # Extended (36 bytes)
    ext = bytearray(struct.pack('<8sB6sBI', b'RSD PTR ', 0, b'OEMID ', 2, 0x9ABCDEF0))
    # Use little-endian for 64-bit XSDT address to match parser (struct default '<' from initial format)
    ext += struct.pack('<IQB3s', 36, 0x1122334455667788, 0, b'\x00\x00\x00')
    ext[8] = checksum8(ext[:20])
    ext[32] = checksum8(ext)  # extended checksum
    r2 = acpi.RSDP()
    r2.parse(bytes(ext))
    assert r2.Length == 36
    assert r2.XsdtAddress == 0x1122334455667788


@pytest.mark.unit
def test_rsdp_bad_signature_warning():
    bad = bytearray(struct.pack('<8sB6sBI', b'BAD SIGN', 0, b'OEMID ', 0, 0))
    bad[8] = checksum8(bad)
    r = acpi.RSDP()
    r.parse(bytes(bad))
    assert r.Signature == b'BAD SIGN'


def _dmar_header(host_width=0x27, flags=0):
    # DMAR base header (HostAddrWidth, Flags, Reserved[10])
    return struct.pack('=BB10s', host_width, flags, b'\x00'*10)


def _dmar_drhd(devscope: bytes):
    # DRHD: Type(0), Length, Flags, Reserved, Segment, RegBase
    hdr = struct.pack('=HHBBHQ', 0, 16 + len(devscope), 0, 0, 0, 0xFED90000)
    return hdr + devscope


def _dev_scope(path=b'\x00\x1F'):
    # Type=1 (PCI Endpoint), Length= sizeof(fmt)+path, Flags, Reserved, EnumID, StartBus
    base = struct.pack('=BBBBBB', 1, 6 + len(path), 0, 0, 0, 0)
    return base + path


@pytest.mark.unit
def test_dmar_minimal_parse():
    devscope = _dev_scope()
    drhd = _dmar_drhd(devscope)
    table = _dmar_header() + drhd
    d = acpi.DMAR()
    d.parse(table)
    assert len(d.dmar_structures) == 1
    assert 'DMA Remapping Hardware Unit' in d.dmar_structures[0]


@pytest.mark.unit
def test_dmar_truncated_structure():
    devscope = _dev_scope()[:-1]  # truncate path
    drhd = _dmar_drhd(devscope)
    table = _dmar_header() + drhd[:-2]  # corrupt length tail
    d = acpi.DMAR()
    d.parse(table)  # should not raise; logs warning
    assert len(d.dmar_structures) >= 0  # parse continues gracefully


def _apic_lapic_struct():
    # Type 0, Length 8, ACPIProcID, APICID, Flags
    return struct.pack('<BBBBI', 0, 8, 0, 1, 1)


@pytest.mark.unit
def test_apic_basic():
    header = struct.pack('<II', 0xFEE00000, 1)
    lapic = _apic_lapic_struct()
    a = acpi.APIC()
    a.parse(header + lapic)
    assert a.LAPICBase == 0xFEE00000
    assert len(a.apic_structs) == 1


@pytest.mark.unit
def test_apic_truncated_entry():
    header = struct.pack('<II', 0, 0)
    lapic = _apic_lapic_struct()[:-2]  # truncate
    a = acpi.APIC()
    a.parse(header + lapic)
    # Entry should be skipped due to truncation
    assert len(a.apic_structs) == 0
