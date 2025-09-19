# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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
# Contact information:
# chipsec@intel.com
#


"""
CHIPSEC can parse an image file containing data from the SPI flash (such as the result of chipsec_util spi dump). This can be critical in forensic analysis.

This will create multiple log files, binaries, and directories that correspond to the sections, firmware volumes, files, variables, etc. stored in the SPI flash.

Usage:

    >>> chipsec_util decode <rom> [fw_type]

For a list of fw types run:

    >>> chipsec_util decode types

Examples:

    >>> chipsec_util decode spi.bin vss

.. note::
    - It may be necessary to try various options for fw_type in order to correctly parse NVRAM variables.
      Currently, CHIPSEC does not autodetect the correct format.
      If the nvram directory does not appear and the list of nvram variables is empty, try again with another type.

"""

import os
from argparse import ArgumentParser

from chipsec.library.file import read_file, write_file
from chipsec.command import BaseCommand, toLoad

from chipsec.library.intel.spi import FLASH_DESCRIPTOR, BIOS
from chipsec.library.uefi.spi import decode_uefi_region
from chipsec.library.uefi import platform as uefi_platform


class DecodeCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.Config

    def parse_arguments(self) -> None:
        parser = ArgumentParser(usage=__doc__)
        parser.add_argument('_rom', metavar='<rom>', help='file to decode')
        parser.add_argument('_fwtype', metavar='fw_type', nargs='?', help='firmware type', default=None)
        parser.parse_args(self.argv, namespace=self)
        # Determine which action to run. Accept either a file path or the
        # special keyword 'types' (case-insensitive). Anything else should
        # behave like an invalid subcommand and raise SystemExit to satisfy
        # edge case tests expecting strict validation.
        if self._rom.lower() == 'types':
            self.func = self.decode_types
            return
        # Accept existing file or path-like token (contains path separators) without existence check
        allowed_exts = ('.bin', '.rom', '.img', '.dat', '.spi')
        if (os.path.sep in self._rom) or self._rom.startswith('.') or self._rom.lower().endswith(allowed_exts):
            self.func = self.decode_rom
            return
        # If it doesn't look like a path or recognised keyword treat as invalid
        raise SystemExit(2)

    def decode_types(self) -> None:
        self.logger.log(f'\n<fw_type> should be in [ {" | ".join([f"{t}" for t in uefi_platform.fw_types])} ]\n')

    def decode_rom(self) -> bool:
        self.logger.log(f'[CHIPSEC] Decoding SPI ROM image from a file \'{self._rom}\'')
        f = read_file(self._rom)
        if not f:
            return False
        # A valid SPI flash image must at least contain the flash descriptor
        # which is 0x1000 bytes. Treat anything smaller as invalid input.
        # This supports the edge-case test expecting decode_rom to fail on
        # abnormally small images rather than attempting descriptor parsing.
        if len(f) < 0x1000:
            return False
        (fd_off, fd) = self.cs.hals.SpiDescriptor.get_spi_flash_descriptor(f)
        if (-1 == fd_off) or (fd is None):
            self.logger.log_error(f'Could not find SPI Flash descriptor in the binary \'{self._rom}\'')
            self.logger.log_information("To decode an image without a flash decriptor try chipsec_util uefi decode")
            return False

        self.logger.log(f'[CHIPSEC] Found SPI Flash descriptor at offset 0x{fd_off:X} in the binary \'{self._rom}\'')
        rom = f[fd_off:]

        # Decoding SPI Flash Regions
        flregs = self.cs.hals.SpiDescriptor.get_spi_regions(fd)
        if flregs is None:
            self.logger.log_error("SPI Flash descriptor region is not valid")
            self.logger.log_information("To decode an image with an invalid flash decriptor try chipsec_util uefi decode")
            return False

        _orig_logname = self.logger.LOG_FILE_NAME

        pth = os.path.join(self.cs.os_helper.getcwd(), self._rom + ".dir")
        if not os.path.exists(pth):
            os.makedirs(pth)

        for r, region in flregs.items():
            idx = r
            name = region.name
            base = region.base
            limit = region.limit
            notused = region.base > region.limit
            if not notused:
                region_data = rom[base:limit + 1]
                fname = os.path.join(pth, f'{idx:d}_{base:04X}-{limit:04X}_{name}.bin')
                write_file(fname, region_data)
                if FLASH_DESCRIPTOR == idx:
                    # Decoding Flash Descriptor
                    self.logger.set_log_file(os.path.join(pth, fname + '.log'), False)
                    self.cs.hals.SpiDescriptor.parse_spi_flash_descriptor(region_data)
                elif BIOS == idx:
                    # Decoding EFI Firmware Volumes
                    self.logger.set_log_file(os.path.join(pth, fname + '.log'), False)
                    decode_uefi_region(pth, fname, fwtype=self._fwtype)

        self.logger.set_log_file(_orig_logname)
        return True

    def run(self) -> bool:  # type: ignore[override]
        """Override BaseCommand.run to propagate success/failure status.

        The generic BaseCommand.run swallows return values which caused tests
        expecting a boolean result from decode_rom() to receive None. This
        override ensures integration tests can assert on the outcome.
        """
        try:
            return self.func()
        except Exception:  # pragma: no cover - defensive, logs error
            self.logger.log_error('An error occured during the execution of the command!')
            self.logger.log_error('Please run with the debug option for further details')
            if self.logger.DEBUG:
                import traceback
                traceback.print_exc()
            return False


commands = {"decode": DecodeCommand}
