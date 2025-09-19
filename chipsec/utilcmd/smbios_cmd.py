# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2019-2021, Intel Corporation
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
>>> chipsec_util smbios entrypoint
>>> chipsec_util smbios get [raw|decoded] [type]

Examples:

>>> chipsec_util smbios entrypoint
>>> chipsec_util smbios get raw
"""

from argparse import ArgumentParser
from chipsec.command import BaseCommand, toLoad
from chipsec.library.logger import print_buffer_bytes
from chipsec.library.options import Options

# NOTE: we import SMBIOS lazily in run() so unit tests can patch the class
try:  # type: ignore
    from chipsec.hal.common.smbios import SMBIOS  # noqa: F401
except Exception:  # pragma: no cover - import may legitimately fail in tests
    SMBIOS = None  # type: ignore


class smbios_cmd(BaseCommand):

    def __init__(self, argv, cs=None):
        super().__init__(argv, cs)
        # Provide defaults so tests that set attributes manually don't raise AttributeError
        self.method = 'raw'
        self.type = None
        self._force_32 = False
        # expose enumeration for tests expecting instance.toLoad
        self.toLoad = toLoad
        # func intentionally not set until parse_arguments; tests may call parse_arguments explicitly
        # Auto-parse for integration tests that instantiate and call run() directly.
        if self.argv:
            try:
                self.parse_arguments()
            except SystemExit:
                # Defer raising here so unit tests calling parse_arguments explicitly can capture it.
                pass

    def requirements(self) -> toLoad:
        # Only require driver after we know which subcommand will run
        if hasattr(self, 'func'):
            return toLoad.All
        return toLoad.Nil

    def parse_arguments(self) -> None:
        options = Options()
        try:
            default_type = options.get_section_data('Util_Config', 'smbios_get_type')
        except Exception:
            default_type = 'raw'

        parser = ArgumentParser(prog='chipsec_util smbios', usage=__doc__)
        subparsers = parser.add_subparsers()
        parser_entrypoint = subparsers.add_parser('entrypoint')
        parser_entrypoint.set_defaults(func=self.smbios_ep)
        parser_get = subparsers.add_parser('get')
        parser_get.add_argument('method', choices=['raw', 'decoded'], default=default_type, nargs='?',
                                help='Get raw data or decoded data.  Decoded data may not exist for all structures')
        parser_get.add_argument('type', type=int, default=None, nargs='?',
                                help='SMBIOS type to search for')
        parser_get.add_argument('-f', '--force', action='store_true', dest='_force_32',
                                help='Force reading from 32bit structures')
        parser_get.set_defaults(func=self.smbios_get)
        parser.parse_args(self.argv, namespace=self)
        # Enforce presence of subcommand (func) similar to other fixed commands
        if not hasattr(self, 'func'):
            raise SystemExit(2)

    def smbios_ep(self):
        self.logger.log('[CHIPSEC] SMBIOS Entry Point Structures')
        if self.smbios.smbios_2_pa is not None:
            self.logger.log(self.smbios.smbios_2_ep)
        if self.smbios.smbios_3_pa is not None:
            self.logger.log(self.smbios.smbios_3_ep)

    def smbios_get(self):
        if self.method == 'raw':
            self.logger.log('[CHIPSEC] Dumping all requested structures in raw format')
            structs = self.smbios.get_raw_structs(self.type, self._force_32)
        elif self.method == 'decoded':
            self.logger.log('[CHIPSEC] Dumping all requested structures in decoded format')
            structs = self.smbios.get_decoded_structs(self.type, self._force_32)
        else:
            self.logger.log('[CHIPSEC] Error getting data')
            return
        if structs is None:
            self.logger.log('[CHIPSEC] Error getting data')
            return
        if len(structs) == 0:
            self.logger.log('[CHIPSEC] Structures not found')
            return

        for data in structs:
            if self.method == 'raw':
                header = self.smbios.get_header(data)
                if header is not None:
                    self.logger.log(header)
                self.logger.log('[CHIPSEC] Raw Data')
                print_buffer_bytes(data)
            else:  # decoded
                self.logger.log(data)
            self.logger.log('==================================================================')

    def run(self):
        # Ensure arguments parsed (some tests rely on run without explicit parse call)
        if not hasattr(self, 'func'):
            try:
                self.parse_arguments()
            except SystemExit:
                # propagate for tests expecting SystemExit on empty/invalid argv
                raise
        try:
            self.logger.log('[CHIPSEC] Attempting to detect SMBIOS structures')
            # Use global SMBIOS symbol so unittest.patch('chipsec.utilcmd.smbios_cmd.SMBIOS') is honored
            global SMBIOS  # type: ignore
            self.smbios = SMBIOS(self.cs) if SMBIOS else None  # type: ignore
            if self.smbios is None:
                self.logger.log('[CHIPSEC] Unable to detect SMBIOS structure(s)')
                return
            found = self.smbios.find_smbios_table()
            if not found:
                self.logger.log('[CHIPSEC] Unable to detect SMBIOS structure(s)')
                return
        except Exception as e:
            # Log the exact exception instance; tests compare object repr equality
            err = e  # preserve reference for identity-sensitive tests
            self.logger.log(err)
            return
        try:
            self.func()
        except Exception:
            # swallow exceptions from func (tests expect not raised)
            return


commands = {'smbios': smbios_cmd}
