import pytest

from chipsec.cfg.parsers.ip.generic import GenericConfig
from chipsec.cfg.parsers.ip.memory import MemoryConfig
from chipsec.cfg.parsers.registers.memory import MEMORYRegisters
from chipsec.library.exceptions import GenericConfigError, MemoryConfigError, MemoryRegisterError


# ----------------- GenericConfig Tests -----------------

@pytest.mark.unit
def test_generic_missing_name():
    with pytest.raises(GenericConfigError):
        GenericConfig({})  # missing 'name'


@pytest.mark.unit
def test_generic_add_and_validate():
    gc = GenericConfig({'name': 'GEN1'})
    assert gc.validate_config() is True
    gc.add_config(['item1', 'item2'])
    assert gc.get_config_count() == 2
    assert gc.has_config('item2')
    gc.remove_config('item1')
    assert gc.get_config_count() == 1
    summary = gc.get_config_summary()
    assert summary['name'] == 'GEN1'
    assert summary['total_items'] == 1


@pytest.mark.unit
def test_generic_invalid_config_list():
    gc = GenericConfig({'name': 'GEN2'})
    with pytest.raises(GenericConfigError):
        gc.add_config('not-a-list')


# ----------------- MemoryConfig Tests -----------------

@pytest.mark.unit
def test_memory_config_missing_fields():
    # Missing address and limit
    with pytest.raises(MemoryConfigError):
        MemoryConfig({'name': 'MEMX', 'access': 'mmio'})


@pytest.mark.unit
def test_memory_config_invalid_access():
    # access empty string -> validate fails inside init and raises
    with pytest.raises(MemoryConfigError):
        MemoryConfig({'name': 'MEMX', 'access': '', 'address': 0x1000, 'limit': 0x2000})


@pytest.mark.unit
def test_memory_config_hex_string_fields():
    mc = MemoryConfig({'name': 'MEMY', 'access': 'dram', 'address': '0x1000', 'limit': '0x1800'})
    assert mc.get_address_int() == 0x1000
    assert mc.get_limit_int() == 0x1800
    assert mc.get_memory_range() == 0x800
    s = str(mc)
    assert 'MEMY' in s


@pytest.mark.unit
def test_memory_config_invalid_range():
    mc = MemoryConfig({'name': 'MEMZ', 'access': 'mmio', 'address': 0x3000, 'limit': 0x2000})
    with pytest.raises(MemoryConfigError):
        mc.get_memory_range()  # limit < address


# ----------------- MEMORYRegisters Tests -----------------

def valid_mem_reg(**overrides):
    base = {
        'name': 'REG_A',
        'desc': 'Test Register',
        'FIELDS': [],
        'offset': 0x10,
        'range': 0,
        'size': 4,
        'address': 0x10000000,
        'limit': 0x10001000,
        'access': 'mmio'
    }
    base.update(overrides)
    return base


@pytest.mark.unit
def test_memory_register_success():
    reg = MEMORYRegisters(valid_mem_reg())
    assert reg.get_physical_address() == 0x10000010
    assert reg.is_mmio_access() and not reg.is_dram_access()
    rep = repr(reg)
    assert 'REG_A' in rep


@pytest.mark.unit
@pytest.mark.parametrize('field,value', [
    ('offset', -1),
    ('address', -5),
    ('size', 3),
    ('access', 'io'),
    ('name', ''),
])
def test_memory_register_invalid_fields(field, value):
    cfg = valid_mem_reg()
    cfg[field] = value
    with pytest.raises(MemoryRegisterError):
        MEMORYRegisters(cfg)


@pytest.mark.unit
def test_memory_register_missing_required():
    cfg = valid_mem_reg()
    del cfg['offset']
    with pytest.raises(MemoryRegisterError):
        MEMORYRegisters(cfg)
