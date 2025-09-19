# Unit tests for intel.spi_descriptor SpiDescriptor parsing logic
# Focus on pure parsing helpers without requiring real hardware access.

import struct
import pytest
from unittest.mock import Mock, patch

from chipsec.hal.intel.spi_descriptor import SpiDescriptor
from chipsec.library.intel.spi import (
    SPI_FLASH_DESCRIPTOR_SIGNATURE,
    SPI_FLASH_DESCRIPTOR_SIZE,
    SPI_REGION_NUMBER_IN_FD,
    FLASH_DESCRIPTOR,
)


class DummyRegister:
    def __init__(self, name):
        self.name = name
        self.value = 0
        self.fields = {}

    def get_field(self, fname):
        # Provide minimal fields used in parse_spi_flash_descriptor
        return self.fields.get(fname, 0)

    def has_field(self, fname):
        return fname in self.fields

    def print(self):
        pass


class DummyRegisterList(list):
    def filter_by_instance(self, instance):
        return self

    def read(self):
        return self


class DummyRegisterService:
    def __init__(self):
        # Pre-populate expected registers referenced in parse function
        self.regs = {
            '8086.SPI.FLMAP0': [DummyRegister('FLMAP0')],
            '8086.SPI.FLMAP1': [DummyRegister('FLMAP1')],
            '8086.SPI.FLMAP2': [DummyRegister('FLMAP2')],
            '8086.SPI.FLMSTR1': [DummyRegister('FLMSTR1')],
        }
        # Fields required for control flow and printed values
        self.regs['8086.SPI.FLMAP0'][0].fields.update({'FCBA': 0x02, 'FRBA': 0x04, 'NC': 0, 'NR': SPI_REGION_NUMBER_IN_FD - 1})
        self.regs['8086.SPI.FLMAP1'][0].fields.update({'FMBA': 0x06, 'NM': 1, 'FPSBA': 0x08, 'PSL': 0x10})
        self.regs['8086.SPI.FLMAP2'][0].fields.update({})
        self.regs['8086.SPI.FLMSTR1'][0].fields.update({'MRRA': 0, 'MRWA': 0})

    def get_list_by_name(self, name):
        # Wildcard names not exercised here; return stored list or empty list wrapper
        return DummyRegisterList(self.regs.get(name, []))


class DummyControlService:
    def get_instance_by_name(self, name, instance):
        return Mock()


class DummyHALs:
    MMIO = Mock()


class DummyDevice:
    def get_instance_by_name(self, name, idx):
        return Mock()


class DummyCS:
    def __init__(self):
        self.register = DummyRegisterService()
        self.control = DummyControlService()
        self.hals = DummyHALs()
        self.device = DummyDevice()


@pytest.fixture
def spi_desc():
    cs = DummyCS()
    # Patch logger to a mock to silence output
    with patch('chipsec.hal.intel.spi_descriptor.print_buffer_bytes'):
        sd = SpiDescriptor(cs)
        sd.logger = Mock()
        return sd


def build_descriptor_bytes():
    # Build a minimal synthetic descriptor satisfying structural expectations
    buf = bytearray(SPI_FLASH_DESCRIPTOR_SIZE)
    # Insert signature at offset 0x10 from fd base + 0x10 descriptor preamble
    sig_off = 0x10
    struct.pack_into('=I', buf, sig_off, struct.unpack('=I', SPI_FLASH_DESCRIPTOR_SIGNATURE)[0])
    return bytes(buf)


# ---------------------------------------------------------------------------------
# get_spi_flash_descriptor
# ---------------------------------------------------------------------------------
@pytest.mark.unit
def test_get_spi_flash_descriptor_found(spi_desc):
    rom = b'X' * 0x10 + SPI_FLASH_DESCRIPTOR_SIGNATURE + b'R' * (SPI_FLASH_DESCRIPTOR_SIZE)
    fd_off, fd = spi_desc.get_spi_flash_descriptor(rom)
    assert fd_off >= 0
    assert len(fd) == SPI_FLASH_DESCRIPTOR_SIZE


@pytest.mark.unit
def test_get_spi_flash_descriptor_not_found(spi_desc):
    rom = b'NO-DESC' * 100
    fd_off, fd = spi_desc.get_spi_flash_descriptor(rom)
    assert fd_off == -1
    assert fd == b''


# ---------------------------------------------------------------------------------
# get_spi_regions
# ---------------------------------------------------------------------------------
@pytest.mark.unit
def test_get_spi_regions_valid(spi_desc):
    rom = b'X' * 0x10 + SPI_FLASH_DESCRIPTOR_SIGNATURE + b'Y' * (SPI_FLASH_DESCRIPTOR_SIZE)
    fd_off, fd = spi_desc.get_spi_flash_descriptor(rom)
    regions = spi_desc.get_spi_regions(fd)
    # None means invalid; we expect a dict-like object
    assert regions is not None
    assert FLASH_DESCRIPTOR in regions


@pytest.mark.unit
def test_get_spi_regions_invalid_signature_pos(spi_desc):
    rom = b'B' * (SPI_FLASH_DESCRIPTOR_SIZE)
    regions = spi_desc.get_spi_regions(rom)
    assert regions is None


# ---------------------------------------------------------------------------------
# parse_spi_flash_descriptor high-level logging path & invalid type handling
# ---------------------------------------------------------------------------------
@pytest.mark.unit
def test_parse_spi_flash_descriptor_invalid_type(spi_desc):
    spi_desc.parse_spi_flash_descriptor(1234)  # non-bytes/str
    assert any('Invalid fd object type' in args[0] for args, _ in spi_desc.logger.log_error.call_args_list)


@pytest.mark.unit
def test_parse_spi_flash_descriptor_missing(spi_desc):
    spi_desc.parse_spi_flash_descriptor(b'A' * 64)
    assert any('Valid SPI flash descriptor is not found' in args[0] for args, _ in spi_desc.logger.log_error.call_args_list)


@pytest.mark.unit
def test_parse_spi_flash_descriptor_success(spi_desc):
    rom = b'X' * 0x10 + SPI_FLASH_DESCRIPTOR_SIGNATURE + b'Z' * (SPI_FLASH_DESCRIPTOR_SIZE)
    spi_desc.parse_spi_flash_descriptor(rom)
    # Ensure success path logs descriptor found line
    assert any('Valid SPI flash descriptor found' in args[0] for args, _ in spi_desc.logger.log.call_args_list)
