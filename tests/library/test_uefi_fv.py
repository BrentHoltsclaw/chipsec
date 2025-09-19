import struct
import uuid

import pytest

from chipsec.library.uefi import fv as fvmod


def _guid_bytes_le(u: uuid.UUID) -> bytes:
    return u.bytes_le


@pytest.fixture(autouse=True)
def patch_bytestostring(monkeypatch):
    """Ensure checksum helpers treat each byte distinctly to avoid UTF-8 collapse during tests."""
    monkeypatch.setattr(fvmod, 'bytestostring', lambda b: b.decode('latin-1') if isinstance(b, (bytes, bytearray)) else b)
    yield


def build_fv(files: list[bytes], mutate_checksum: bool = False, oversize_len: bool = False):
    """Build a minimal firmware volume binary containing provided file byte blobs.

    files: list of already-assembled FFS file binaries
    mutate_checksum: if True, corrupt the header checksum
    oversize_len: if True, set FvLength larger than actual buffer to trigger rejection
    """
    # Concatenate file payloads
    file_blob = b''.join(files)
    zero_vec = b'\x00' * 16
    fsguid = _guid_bytes_le(fvmod.EFI_FIRMWARE_FILE_SYSTEM_GUID)
    signature = b'_FVH'
    attributes = 0x00000000
    block_entry_fmt = fvmod.EFI_FV_BLOCK_MAP_ENTRY
    block_entry_size = struct.calcsize(block_entry_fmt)
    header_struct_size = struct.calcsize(fvmod.EFI_FIRMWARE_VOLUME_HEADER)
    # Base header plus 2 block map entries (one real + one terminator). We include BOTH
    # entries in HeaderLength so that checksum logic in NextFwVolume (which reconstructs
    # the header up to HeaderLength) matches the test constructed checksum.
    header_len = header_struct_size + (2 * block_entry_size)
    terminator = struct.pack(block_entry_fmt, 0, 0)
    pad_len = (8 - (header_len % 8)) % 8
    if pad_len:
        file_blob = (b'\xFF' * pad_len) + file_blob
    # Full FV length counts entire header (already includes both block map entries) plus files
    fv_length_actual = header_len + len(file_blob)
    FvLength_field = fv_length_actual + (0x40 if oversize_len else 0)
    ext_hdr_off = 0
    reserved = 0
    revision = 2
    # Assemble zero-checksum header
    header_zero_ck = struct.pack(
        fvmod.EFI_FIRMWARE_VOLUME_HEADER,
        zero_vec,
        fsguid,
        FvLength_field,
        struct.unpack('<I', signature)[0],
        attributes,
        header_len,
        0,
        ext_hdr_off,
        reserved,
        revision,
    )
    first_block = struct.pack(block_entry_fmt, 1, FvLength_field)
    header_full_zero_ck = header_zero_ck + first_block + terminator
    calc_sum = fvmod.FvChecksum16(header_full_zero_ck)
    checksum_field = calc_sum ^ (0x1234 if mutate_checksum else 0)
    header_with_ck = struct.pack(
        fvmod.EFI_FIRMWARE_VOLUME_HEADER,
        zero_vec,
        fsguid,
        FvLength_field,
        struct.unpack('<I', signature)[0],
        attributes,
        header_len,
        checksum_field,
        ext_hdr_off,
        reserved,
        revision,
    ) + first_block + terminator
    image = header_with_ck + file_blob
    return image, calc_sum, checksum_field, fv_length_actual, header_len, attributes


def build_raw_file(payload: bytes) -> bytes:
    guid = uuid.uuid4()
    section = fvmod.assemble_uefi_raw(payload)
    return fvmod.assemble_uefi_file(guid, section)


@pytest.mark.unit
def test_next_fw_volume_valid():
    file_bytes = build_raw_file(b'PAYLOAD')
    image, calc_sum, checksum_field, fv_length, header_len, attrs = build_fv([file_bytes])
    vol = fvmod.NextFwVolume(image)
    assert vol is not None
    assert vol.Size == fv_length
    assert vol.HeaderSize == header_len
    assert vol.Attributes == attrs
    # Check that stored checksum matches calculated value
    assert vol.CalcSum == calc_sum
    assert vol.Checksum == checksum_field


@pytest.mark.unit
def test_next_fw_volume_checksum_mismatch():
    file_bytes = build_raw_file(b'DATA')
    image, calc_sum, checksum_field, *_ = build_fv([file_bytes], mutate_checksum=True)
    vol = fvmod.NextFwVolume(image)
    assert vol is not None
    # Should detect mismatch
    assert vol.CalcSum != vol.Checksum


@pytest.mark.unit
def test_next_fw_volume_truncated_rejected():
    file_bytes = build_raw_file(b'X')
    image, *_ = build_fv([file_bytes], oversize_len=True)
    vol = fvmod.NextFwVolume(image)
    # Oversized FvLength should invalidate volume
    assert vol is None


@pytest.mark.unit
def test_get_fv_header_roundtrip():
    file_bytes = build_raw_file(b'ABCDEFGH')
    image, _, _, fv_length, header_len, attrs = build_fv([file_bytes])
    size, header_len_ret, attrs_ret = fvmod.GetFvHeader(image)
    assert size == fv_length
    assert header_len_ret == header_len
    assert attrs_ret == attrs


@pytest.mark.unit
def test_next_fw_file_and_section():
    payload = b'HELLO_WORLD'
    file_bytes = build_raw_file(payload)
    image, *_ = build_fv([file_bytes])
    vol = fvmod.NextFwVolume(image)
    assert vol is not None
    # File starts after header; search using offset = vol.HeaderSize
    f = fvmod.NextFwFile(vol.Image, vol.Size, vol.HeaderSize, polarity=False)
    assert f is not None
    assert f.Type == fvmod.EFI_FV_FILETYPE_FREEFORM
    # Extract first (raw) section
    section_offset = f.HeaderSize
    sec = fvmod.NextFwFileSection(f.Image, f.Size, section_offset, polarity=False)
    assert sec is not None
    assert sec.Name == 'S_RAW'
    assert payload in sec.Image  # raw section contains payload


@pytest.mark.unit
def test_next_fw_file_section_unknown_type():
    # Manually craft a section with unknown type 0xEE
    unknown_type = 0xEE
    size = 0x10  # arbitrary > header size
    size_3b = (size & 0xFFFFFF).to_bytes(3, 'little')
    sec_header = size_3b + bytes([unknown_type])
    body = b'Z' * (size - 4)
    section_blob = sec_header + body
    # Wrap section in a file
    guid = uuid.uuid4()
    file_blob = fvmod.assemble_uefi_file(guid, fvmod.align_image(section_blob, 4))
    image, *_ = build_fv([file_blob])
    vol = fvmod.NextFwVolume(image)
    assert vol is not None
    f = fvmod.NextFwFile(vol.Image, vol.Size, vol.HeaderSize, polarity=False)
    sec = fvmod.NextFwFileSection(f.Image, f.Size, f.HeaderSize, polarity=False)
    assert sec is not None
    assert sec.Name.startswith('S_UNKNOWN_')


@pytest.mark.unit
def test_next_fw_file_section_truncated():
    # Provide a section whose declared size is non-zero but whose total bytes
    # stop at header only (no payload). Parser should treat Size == 0 after
    # attempting to read body and thus not return a section.
    declared_size = 0x20
    size_3b = (declared_size & 0xFFFFFF).to_bytes(3, 'little')
    sec_header = size_3b + bytes([fvmod.EFI_SECTION_RAW])
    truncated = sec_header  # no payload bytes
    guid = uuid.uuid4()
    file_blob = fvmod.assemble_uefi_file(guid, fvmod.align_image(truncated, 4))
    image, *_ = build_fv([file_blob])
    vol = fvmod.NextFwVolume(image)
    assert vol is not None
    f = fvmod.NextFwFile(vol.Image, vol.Size, vol.HeaderSize, polarity=False)
    sec = fvmod.NextFwFileSection(f.Image, f.Size, f.HeaderSize, polarity=False)
    # Parsing stops without valid section
    assert sec is None


@pytest.mark.unit
def test_next_fw_file_large_file_attribute():
    """Validate parser handles FFS large file attribute (extended size field)."""
    guid = uuid.uuid4()
    raw_sec = fvmod.assemble_uefi_raw(b'LARGE_FILE')
    # Manually build large-file header (EFI_FFS_FILE_HEADER2 format)
    # Fields: <16sHBB3sBQ>
    header2_fmt = fvmod.EFI_FFS_FILE_HEADER2
    full_hdr_size = struct.calcsize(header2_fmt)
    Type = fvmod.EFI_FV_FILETYPE_FREEFORM
    IntegrityCheck = 0x0000
    Attributes = fvmod.FFS_ATTRIB_LARGE_FILE  # only large file bit set
    Size3 = b'\xFF\xFF\xFF'  # per spec when extended size used
    State = 0xF8
    extended_size = full_hdr_size + len(raw_sec)
    header = struct.pack(header2_fmt, fvmod.get_guid_bin(guid), IntegrityCheck, Type, Attributes, Size3, State, extended_size)
    file_blob = header + raw_sec
    image, *_ = build_fv([file_blob])
    vol = fvmod.NextFwVolume(image)
    assert vol is not None
    f = fvmod.NextFwFile(vol.Image, vol.Size, vol.HeaderSize, polarity=False)
    assert f is not None
    assert f.HeaderSize == full_hdr_size
    assert f.Size == extended_size & 0xFFFFFFFF
    # Ensure raw section still parsed
    sec = fvmod.NextFwFileSection(f.Image, f.Size, f.HeaderSize, polarity=False)
    assert sec is not None and sec.Name == 'S_RAW'


# NOTE: Extended-size section (0xFFFFFF + 32-bit length) parsing isn't currently
# exercised because the helper NextFwFileSection only partially supports this
# path with additional constraints. Once library logic is enhanced, a focused
# test can be added here.


@pytest.mark.unit
def test_next_fw_file_section_compression():
    """Compression section parsing returns S_COMPRESSION name."""
    raw = fvmod.assemble_uefi_raw(b'COMP_DATA')
    comp_section = fvmod.assemble_uefi_section(raw, uncomressed_size=len(raw), compression_type=1)  # arbitrary algo id
    guid = uuid.uuid4()
    file_blob = fvmod.assemble_uefi_file(guid, fvmod.align_image(comp_section, 4))
    image, *_ = build_fv([file_blob])
    vol = fvmod.NextFwVolume(image)
    assert vol is not None
    f = fvmod.NextFwFile(vol.Image, vol.Size, vol.HeaderSize, polarity=False)
    sec = fvmod.NextFwFileSection(f.Image, f.Size, f.HeaderSize, polarity=False)
    assert sec is not None and sec.Name == 'S_COMPRESSION'
