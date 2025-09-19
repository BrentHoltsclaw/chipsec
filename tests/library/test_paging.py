import pytest
from types import SimpleNamespace

from chipsec.library import paging

# Constants used from paging module
BIT0 = 0x1
BIT7 = 0x80
ADDR_4KB = paging.ADDR_4KB
ADDR_2MB = paging.ADDR_2MB
ADDR_1GB = paging.ADDR_1GB


class DummyMem:
    def __init__(self):
        self.reads = {}

    def read_physical_mem(self, addr, size):
        # Return 4KB of zeroes unless predefined; tests override via monkeypatching read_entries
        return b'\x00' * 4096


class DummyCS:
    def __init__(self):
        self.hals = SimpleNamespace(Memory=DummyMem())


@pytest.fixture
def cs():
    return DummyCS()


@pytest.fixture
def ia32e(cs):
    return paging.c_ia32e_page_tables(cs)


# Helper to build a present entry with base address and optional big page flag
def make_entry(base, present=True, big=False, rw=1, us=1):
    entry = (base & ADDR_4KB)
    if present:
        entry |= BIT0
    if big:
        entry |= BIT7
    if rw:
        entry |= (1 << 1)
    if us:
        entry |= (1 << 2)
    return entry

# We override read_entries to supply synthetic structures rather than raw memory


@pytest.mark.unit
def test_walk_4kb_page(ia32e, monkeypatch):
    # Structure: PML4 -> PDPT -> PD -> PT -> 4KB PTE
    pml4e = make_entry(0x1000)
    pdpte = make_entry(0x2000)  # not big
    pde = make_entry(0x3000)  # not big
    pte = make_entry(0x4000)  # final page frame

    def fake_read_entries(kind, addr, size=8):
        if kind == 'pml4':
            return [pml4e]
        if kind == 'pdpt':
            return [pdpte]
        if kind == 'pd':
            return [pde]
        if kind == 'pt':
            return [pte]
        raise AssertionError('Unexpected table kind ' + kind)

    monkeypatch.setattr(ia32e, 'read_entries', fake_read_entries)
    ia32e.read_page_tables(0x5000)  # CR3
    # Choose indices 0 so virt == composed offset for each level -> virt becomes 0
    info = ia32e.read_entry_by_virt_addr(0x0)
    assert info['size'] == '4KB'
    assert info['addr'] & ADDR_4KB == 0x4000


@pytest.mark.unit
def test_walk_2mb_page(ia32e, monkeypatch):
    pml4e = make_entry(0x1000)
    pdpte = make_entry(0x2000)  # not big
    # 2MB-aligned physical base for big page
    pde_big = make_entry(0x200000, big=True)  # 2MB page

    def fake_read_entries(kind, addr, size=8):
        if kind == 'pml4':
            return [pml4e]
        if kind == 'pdpt':
            return [pdpte]
        if kind == 'pd':
            return [pde_big]
        raise AssertionError('Unexpected table kind ' + kind)

    monkeypatch.setattr(ia32e, 'read_entries', fake_read_entries)
    ia32e.read_page_tables(0x6000)
    info = ia32e.read_entry_by_virt_addr(0x0)
    assert info['size'] == '2MB'
    assert info['addr'] & ADDR_2MB == 0x200000


@pytest.mark.unit
def test_walk_1gb_page(ia32e, monkeypatch):
    pml4e = make_entry(0x1000)
    # 1GB-aligned physical base for big page
    pdpte_big = make_entry(0x40000000, big=True)  # 1GB page

    def fake_read_entries(kind, addr, size=8):
        if kind == 'pml4':
            return [pml4e]
        if kind == 'pdpt':
            return [pdpte_big]
        raise AssertionError('Unexpected table kind ' + kind)

    monkeypatch.setattr(ia32e, 'read_entries', fake_read_entries)
    ia32e.read_page_tables(0x7000)
    info = ia32e.read_entry_by_virt_addr(0x0)
    assert info['size'] == '1GB'
    assert info['addr'] & ADDR_1GB == 0x40000000


@pytest.mark.unit
def test_non_present_entry_returns_empty(ia32e, monkeypatch):
    pml4e = make_entry(0x1000, present=False)
    
    def fake_read_entries(kind, addr, size=8):
        if kind == 'pml4':
            return [pml4e]
        raise AssertionError('Unexpected table kind ' + kind)
    monkeypatch.setattr(ia32e, 'read_entries', fake_read_entries)
    ia32e.read_page_tables(0x8000)
    info = ia32e.read_entry_by_virt_addr(0x0)
    assert info == {'addr': 0, 'attr': '', 'size': ''}


@pytest.mark.unit
def test_get_attr_variants(ia32e):
    # RW + US bits variations (bits 1 and 2)
    base = 0x9000 | BIT0
    read_super = base  # RW=0, US=0 => R S
    write_user = base | (1 << 1) | (1 << 2)  # W U
    assert ia32e.get_attr(read_super) == 'R S'
    assert ia32e.get_attr(write_user) == 'W U'


@pytest.mark.unit
def test_pointer_undefined_exception(cs):
    ia32e = paging.c_ia32e_page_tables(cs)
    with pytest.raises(Exception):
        ia32e.read_entry_by_virt_addr(0x0)


@pytest.mark.unit
def test_malformed_pdpt_size(ia32e, monkeypatch):
    # Provide PDPT list shorter than 512 entries but non-uniform; ensure walk stops gracefully
    pml4e = make_entry(0x1000)
    pdpte_entries = [make_entry(0x2000), make_entry(0x3000, present=False)]
    
    def fake_read_entries(kind, addr, size=8):
        if kind == 'pml4':
            return [pml4e]
        if kind == 'pdpt':
            return pdpte_entries
        if kind == 'pd':
            # Return empty PD; traversal shouldn't fail
            return []
        raise AssertionError('Unexpected table kind ' + kind)
    monkeypatch.setattr(ia32e, 'read_entries', fake_read_entries)
    ia32e.read_page_tables(0xA000)
    # Only first present pdpte should create a pd entry in pt mapping
    assert any(v == 'pd' for v in ia32e.pt.values())
