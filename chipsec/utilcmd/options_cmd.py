from chipsec.command    import BaseCommand


# ###################################################################
#
# Chipset/CPU Detection
#
# ###################################################################
class OptionCommand(BaseCommand):
    """
    chipsec_util platform
    """

    def requires_driver(self):
        return False

    def run(self):
        sects = self.cs.options.get_sections()
        self.logger.log("Command found the following options")
        self.logger.log(sects)
        self.logger.log('Command can now use Login data')
        if "Login" in sects:
            self.logger.log(self.cs.options.get_section_data('Login'))


commands = {'options': OptionCommand}
