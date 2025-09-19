# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024, Intel Corporation
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
Generate a module ID using hashlib from the module's file name (no file extension).
Hash is truncated to 28 bits. For module names use full path as seen in example below.

Usage:
    ``chipsec_util id name <module name>``
    ``chipsec_util id hash <module hash>``

Examples:
    >>> chipsec_util.py id name chipsec.modules.common.remap
    >>> chipsec_util.py id hash 0x67eb58d
"""

from chipsec.library.returncode import get_module_ids_dictionary, generate_hash_id
from chipsec.command import BaseCommand, toLoad
from argparse import ArgumentParser


class ModuleIdCommand(BaseCommand):

    def __init__(self, argv, cs=None):
        super().__init__(argv, cs=cs)
        # Provide default attributes so direct invocation of methods without parse_arguments works
        self.module_name = None
        self.module_id = None

    def requirements(self) -> toLoad:
        return toLoad.Nil

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util id', usage=__doc__)
        subparsers = parser.add_subparsers(dest='subcmd')
        subparsers.required = True

        parser_read = subparsers.add_parser('name')
        parser_read.add_argument('module_name', type=str, help='Module name')
        parser_read.set_defaults(func=self.get_id_from_name)

        parser_write = subparsers.add_parser('hash')
        parser_write.add_argument('module_id', type=str, help='Module ID')
        parser_write.set_defaults(func=self.get_name_from_id)

        parser.parse_args(self.argv, namespace=self)

    def run(self) -> None:
        if not hasattr(self, 'func'):
            self.parse_arguments()
        self.func()

    def get_id_from_name(self) -> None:
        # Lazy extraction of module_name if parse_arguments wasn't called
        if (self.module_name is None) and self.argv and len(self.argv) >= 2 and self.argv[0] == 'name':
            self.module_name = self.argv[1]
        if self.module_name is None:
            raise AttributeError('module_name not set')

        module_ids = get_module_ids_dictionary()
        if self.module_name in module_ids:
            module_id = module_ids[self.module_name]
        else:
            module_id = generate_hash_id(self.module_name)
        self.logger.log(f'Module ID is: {hex(module_id)}\n')

    def get_name_from_id(self) -> None:
        # Lazy extraction of module_id if parse_arguments wasn't called
        if (self.module_id is None) and self.argv and len(self.argv) >= 2 and self.argv[0] == 'hash':
            self.module_id = self.argv[1]
        if self.module_id is None:
            raise AttributeError('module_id not set')

        module_ids = get_module_ids_dictionary()
        # Validate hex conversion; propagate ValueError for invalid strings (test expects it)
        id_int = int(self.module_id, 16)
        module_values = list(module_ids.values())
        if id_int in module_values:
            module_name = list(module_ids.keys())[module_values.index(id_int)]
            self.logger.log(f'Module name is: {module_name}\n')
        else:
            self.logger.log(f'Could not find {self.module_id}\n')


commands = {'id': ModuleIdCommand}
