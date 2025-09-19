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
usage as a standalone utility:
    >>> chipsec_util platform
"""

import argparse
from chipsec.command import BaseCommand, toLoad
from chipsec.library.exceptions import UnknownChipsetError

# ###################################################################
#
# Chipset/CPU Detection
#
# ###################################################################


class PlatformCommand(BaseCommand):
    """
    chipsec_util platform
    """

    def __init__(self, argv, cs=None):
        super().__init__(argv, cs)
        # Initialize argument parser
        self.parser = argparse.ArgumentParser(
            prog='chipsec_util platform',
            usage='%(prog)s',
            description='Show platform information'
        )

    def requirements(self) -> toLoad:
        return toLoad.All
    
    def parse_arguments(self) -> None:
        # When invoked via chipsec_util the argv list includes the command name itself
        # (e.g. ['platform']). Treat a single element (the command) as having no user
        # arguments. Only raise an error if additional unexpected parameters are present.
        if len(self.argv) > 1:
            self.parser.error('platform command does not accept any arguments')

    def run(self):
        if not hasattr(self.cs, 'Cfg'):
            raise AttributeError('Configuration not available (Cfg is None)')

        try:
            self.cs.Cfg.print_supported_chipsets()
            self.logger.log("")

            if not hasattr(self.cs.Cfg, 'print_platform_info'):
                raise AttributeError('print_platform_info method not available')
            self.cs.Cfg.print_platform_info()

            if not hasattr(self.cs.Cfg, 'print_pch_info'):
                raise AttributeError('print_pch_info method not available')
            self.cs.Cfg.print_pch_info()

        except UnknownChipsetError as msg:
            self.logger.log_error(msg)
        except AttributeError:
            # Let AttributeError propagate for configuration issues
            raise
        except Exception as e:
            self.logger.log_error(f"Error executing platform command: {e}")


commands = {'platform': PlatformCommand}
