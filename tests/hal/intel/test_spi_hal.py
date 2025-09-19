import pytest

from chipsec.hal.intel import spi as spi_mod


class DummyField:
    def __init__(self, value):
        self._value = value
    def read(self):
        return self._value
    def get(self):
        return self._value


class DummyRegister:
    def __init__(self, name, value=0):
        self.name = name
        self.value = value
        self.offset = 0x10

    def read(self):
        return self.value

    def read_field(self, field):
        # Support minimal HSFS.FDV and BFPR fields
        if field == 'FDV':
            return 1  # hardware sequencing enabled
        if field == 'PRB':
            return (self.value >> 16) & 0xFFF
        return 0

    def get_field(self, field):
        if field == 'PRL':
            return self.value & 0xFFF
        if field == 'PRB':
            return (self.value >> 16) & 0xFFF
        if field == 'WPE':
            return (self.value >> 8) & 0x1
        if field == 'RPE':
            return (self.value >> 9) & 0x1
        if field in ('BRWA', 'BRRA', 'BMRAG', 'BMWAG'):
            return self.value & 0xFF
        return 0

    def write(self, v):
        self.value = v

    def print(self):
        pass


class DummyRegisterList(list):
    def filter_by_instance(self, instance):
        return self
    def read(self):
        return self


class DummyRegisterService:
    def __init__(self):
        # Pre-populate minimal registers accessed in test paths
        self.regs = {
            '8086.SPI.SPIBAR.HSFS': DummyRegister('HSFS', 0x1),
            '8086.SPI.SPIBAR.HSFC': DummyRegister('HSFC', 0x0),
            '8086.SPI.SPIBAR.FADDR': DummyRegister('FADDR', 0x0),
            '8086.SPI.SPIBAR.FDATA0': DummyRegister('FDATA0', 0x0),
            '8086.SPI.SPIBAR.FDATA1': DummyRegister('FDATA1', 0x0),
            '8086.SPI.SPIBAR.FDATA2': DummyRegister('FDATA2', 0x0),
            '8086.SPI.SPIBAR.FDATA3': DummyRegister('FDATA3', 0x0),
            '8086.SPI.SPIBAR.FDATA4': DummyRegister('FDATA4', 0x0),
            '8086.SPI.SPIBAR.FDATA5': DummyRegister('FDATA5', 0x0),
            '8086.SPI.SPIBAR.FDATA6': DummyRegister('FDATA6', 0x0),
            '8086.SPI.SPIBAR.FDATA7': DummyRegister('FDATA7', 0x0),
            '8086.SPI.SPIBAR.FDATA8': DummyRegister('FDATA8', 0x0),
            '8086.SPI.SPIBAR.FDATA9': DummyRegister('FDATA9', 0x0),
            '8086.SPI.SPIBAR.FDATA10': DummyRegister('FDATA10', 0x0),
            '8086.SPI.SPIBAR.FDATA11': DummyRegister('FDATA11', 0x0),
            '8086.SPI.SPIBAR.FDATA12': DummyRegister('FDATA12', 0x0),
            '8086.SPI.SPIBAR.FDATA13': DummyRegister('FDATA13', 0x0),
            '8086.SPI.SPIBAR.FDATA14': DummyRegister('FDATA14', 0x0),
            '8086.SPI.SPIBAR.FDATA15': DummyRegister('FDATA15', 0x0),
            '8086.SPI.SPIBAR.BIOS_PTINX': DummyRegister('BIOS_PTINX', 0x0),
            '8086.SPI.SPIBAR.BIOS_PTDATA': DummyRegister('BIOS_PTDATA', 0x0),
            '8086.SPI.SPIBAR.FDOC': DummyRegister('FDOC', 0x0),
            '8086.SPI.SPIBAR.FDOD': DummyRegister('FDOD', 0x0),
            '8086.SPI.SPIBAR.FRAP': DummyRegister('FRAP', 0x01010101),
            '8086.SPI.SPIBAR.BFPR': DummyRegister('BFPR', (0x100 << 16) | 0x101),  # base=0x100000, limit=0x101000 after shift
            # Set high bits to simulate WPE/RPE (exact positions abstracted in DummyRegister.get_field logic)
            '8086.SPI.SPIBAR.PR0': DummyRegister('PR0', (0x200 << 16) | 0x201 | (1 << 8) | (1 << 9)),
        }
    def is_defined(self, name):
        return any(k.endswith(name) or k == name for k in self.regs)

    def get_instance_by_name(self, name, instance):
        for k, v in self.regs.items():
            if k.endswith(name) or k == name:
                return v
        raise KeyError(name)

    def get_list_by_name(self, pattern):
        # pattern '8086.SPI.SPIBAR.PR*'
        lst = [v for k, v in self.regs.items() if 'PR' in k and 'PR0' in k]
        return DummyRegisterList(lst)

    def has_field(self, reg, field):
        return True


class DummyControlService:
    def __init__(self):
        self.ctrls = {
            'BiosLockEnable': DummyRegister('BLE', 0),
            'BiosWriteEnable': DummyRegister('BWE', 1),
            'SmmBiosWriteProtection': DummyRegister('SMMBWP', 0),
        }
    def get_instance_by_name(self, name, instance):
        return self.ctrls[name]

    def get_list_by_name(self, name):
        return DummyRegisterList([self.ctrls['BiosWriteEnable']])

    def is_defined(self, name):
        return name in self.ctrls


class DummyMMIO:
    def is_MMIO_BAR_defined(self, name):
        return True
    def get_MMIO_BAR_base_address(self, name):
        return (0xFE000000, 0x1000)
    def read_MMIO_reg(self, base, reg, size):
        return 0
    def write_MMIO_reg(self, base, reg, value, size):
        return value


class DummyDevice:
    def get_instance_by_name(self, name, idx):
        return object()


class DummyHALs:
    def __init__(self):
        self.MMIO = DummyMMIO()


class DummyCS:
    def __init__(self):
        self.device = DummyDevice()
        self.hals = DummyHALs()
        self.register = DummyRegisterService()
        self.control = DummyControlService()
        from chipsec.library.logger import logger
        self.logger = logger()


@pytest.fixture
def spi():
    cs = DummyCS()
    return spi_mod.SPI(cs)


@pytest.mark.unit
def test_spi_get_regions(spi):
    regions = spi.get_SPI_regions()
    # Expect at least the BIOS region descriptor structure (some may default to zero)
    assert isinstance(regions, dict)


@pytest.mark.unit
def test_spi_protected_ranges(spi):
    prs = spi.get_SPI_Protected_Ranges()
    # Dummy setup gives us one protected range entry
    assert len(prs) >= 1
    base, limit, wpe, rpe, *_ = prs[0]
    assert wpe and rpe


@pytest.mark.unit
def test_disable_bios_write_protection_noop(spi):
    # With BiosWriteEnable already set, function should early succeed
    result = spi.disable_BIOS_write_protection()
    assert result is True
