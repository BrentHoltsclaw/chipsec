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

import os
from chipsec.library.logger import logger
from chipsec.library.file import get_module_dir
from typing import List


def enumerate_modules() -> List[str]:
    try:
        mod_path = get_module_dir()
        tools_path = os.path.join(mod_path)
        files = []
        for dirname, _, mod_fnames in os.walk(os.path.abspath(tools_path)):
            for modx in mod_fnames:
                # Only include Python files, exclude __init__.py files
                if modx.endswith('.py') and not modx.startswith('__init__'):
                    module_path = os.path.relpath(dirname, mod_path).replace('\\', '.').replace('/', '.')
                    if module_path and module_path != '.':
                        files.append(f'{module_path}.{modx[:-3]}')
                    else:
                        files.append(f'{modx[:-3]}')
        return files
    except (OSError, IOError):
        # Handle filesystem errors gracefully
        return []


def print_modules(module_list: List[str]) -> None:
    try:
        logger().log('Enumerating modules...')
        for module in module_list:
            logger().log(f'\t{module}')
    except Exception:
        # Handle logging errors gracefully
        pass
