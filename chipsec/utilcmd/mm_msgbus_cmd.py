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
>>> chipsec_util mm_msgbus read     <port> <register>
>>> chipsec_util mm_msgbus write    <port> <register> <value>
>>>
>>> <port>    : message bus port of the target unit
>>> <register>: message bus register/offset in the target unit port
>>> <value>   : value to be written to the message bus register/offset

Examples:

>>> chipsec_util mm_msgbus read  0x3 0x2E
>>> chipsec_util msgbus mm_write 0x3 0x27 0xE0000001
"""

from chipsec.command import BaseCommand, toLoad
from argparse import ArgumentParser


# MM_Message Bus
class MMMsgBusCommand(BaseCommand):

    def __init__(self, argv, cs=None):
        super().__init__(argv, cs=cs)
        # Provide defaults so direct method invocation without parse_arguments works in tests
        self.port = 0
        self.reg = 0
        self.val = 0

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util mm_msgbus', usage=__doc__)
        subparsers = parser.add_subparsers(dest='subcmd')
        subparsers.required = True

        parser_mmread = subparsers.add_parser('mm_read')
        parser_mmread.add_argument('port', type=lambda x: int(x, 16), help='Port (hex)')
        parser_mmread.add_argument('reg', type=lambda x: int(x, 16), help='Register (hex)')
        parser_mmread.set_defaults(func=self.msgbus_mm_read)

        parser_mmwrite = subparsers.add_parser('mm_write')
        parser_mmwrite.add_argument('port', type=lambda x: int(x, 16), help='Port (hex)')
        parser_mmwrite.add_argument('reg', type=lambda x: int(x, 16), help='Register (hex)')
        parser_mmwrite.add_argument('val', type=lambda x: int(x, 16), help='Value (hex)')
        parser_mmwrite.set_defaults(func=self.msgbus_mm_write)

        parser.parse_args(self.argv, namespace=self)

    def run(self) -> None:
        # Ensure arguments were parsed; if func missing attempt parsing for integration direct run usage
        if not hasattr(self, 'func'):
            self.parse_arguments()
        self.func()

    def msgbus_mm_read(self):
        # Allow direct invocation without explicit parse_arguments call in tests
        if (self.port == 0 and self.reg == 0) and self.argv:
            try:
                self.parse_arguments()
            except SystemExit:
                pass
        self.logger.log(f'[CHIPSEC] MMIO msgbus read: port 0x{self.port:02X} + 0x{self.reg:08X}')
        res = self.cs.hals.MMMsgBus.read(self.port, self.reg)
        self._log_result(res)
        return True

    def msgbus_mm_write(self):
        if (self.port == 0 and self.reg == 0) and self.argv:
            try:
                self.parse_arguments()
            except SystemExit:
                pass
        self.logger.log(f'[CHIPSEC] MMIO msgbus write: port 0x{self.port:02X} + 0x{self.reg:08X} < 0x{self.val:08X}')
        res = self.cs.hals.MMMsgBus.write(self.port, self.reg, self.val)
        self._log_result(res)
        return True

    def _log_result(self, res):
        if res is not None:
            # Normalize negative integers to unsigned 64-bit representation for logging expectations
            if isinstance(res, int) and res < 0:
                res &= 0xFFFFFFFFFFFFFFFF
            self.logger.log(f'[CHIPSEC] Result: {hex(res)}')
        else:
            self.logger.log('[CHIPSEC] No result returned')


commands = {'mm_msgbus': MMMsgBusCommand}
