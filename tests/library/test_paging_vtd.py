import pytest

from chipsec.library import paging

# Reuse bit definitions
BIT0 = 0x1
BIT7 = 0x80

ADDR_4KB = paging.ADDR_4KB
ADDR_1GB = paging.ADDR_1GB


def make_root_entry(context_addr: int, present: bool = True):
    """Construct a VT-d Root Entry (low, high)."""
    ree_lo = (context_addr & ADDR_4KB)
    if present:
        ree_lo |= BIT0  # Present
    ree_hi = 0  # Not used in current logic
    return (ree_lo, ree_hi)


def make_context_entry(slptptr: int, present: bool = True, t: int = 0, fpd: int = 0, domain_id: int = 0x5A, aw: int = 0x3):
    """Construct a VT-d Context Entry (low, high).

    cee_lo fields:
      bit0: P
      bit1: FPD
      bits2-3: T (translation type)
      bits12+: SLPTPTR base (masked by MAXPHYADDR in code)
    cee_hi fields:
      bits0-2: AW
      bits8-15: DID (Domain ID)
    """
    cee_lo = (slptptr & paging.MAXPHYADDR)
    if present:
        cee_lo |= BIT0
    if fpd:
        cee_lo |= (1 << 1)
    cee_lo |= ((t & 0x3) << 2)

    cee_hi = 0
    cee_hi |= ((aw & 0x7) << 0)
    cee_hi |= ((domain_id & 0xFF) << 8)
    return (cee_lo, cee_hi)


@pytest.fixture
def vtd(cs_fixture=None):  # cs_fixture placeholder if shared fixture exists; create minimal mock inline
    class DummyMem:
        def read_physical_mem(self, addr, size):
            return b'\x00' * size

    class DummyCS:
        def __init__(self):
            self.hals = type('H', (), {'Memory': DummyMem()})()
    return paging.c_vtd_page_tables(DummyCS())


@pytest.mark.unit
def test_vtd_no_root_entries(vtd, monkeypatch, tmp_path):
    # read_entries returns root table of one entry not present
    def fake_read_entries(kind, addr, size=8):
        if kind == 're':
            return [(0, 0)]  # single non-present (low, high)
        raise AssertionError('Unexpected kind ' + kind)

    monkeypatch.setattr(vtd, 'read_entries', fake_read_entries)
    vtd.read_vtd_context(str(tmp_path / 'ctx.txt'), 0x1000)
    assert vtd.context == {}
    assert vtd.domains == {}
    assert any(v == 'root' for v in vtd.cpt.values())


@pytest.mark.unit
def test_vtd_single_context_and_domain(vtd, monkeypatch, tmp_path):
    domain_ptr = 0x4000  # 4KB aligned
    ctx_ptr = 0x2000
    root_entries = [make_root_entry(ctx_ptr, present=True)]
    context_entries = [make_context_entry(domain_ptr, present=True, t=0, domain_id=0x42)]

    def fake_read_entries(kind, addr, size=8):
        if kind == 're':
            return root_entries
        if kind == 'ce':
            return context_entries
        # During this test we don't traverse page tables yet
        if kind in ('pml4', 'pdpt', 'pd', 'pt'):
            return [0]
        raise AssertionError('Unexpected kind ' + kind)

    monkeypatch.setattr(vtd, 'read_entries', fake_read_entries)
    vtd.read_vtd_context(str(tmp_path / 'ctx2.txt'), 0x1000)
    # One context keyed by source_id 0x0000 (ree_index=0, cee_index=0)
    assert 0 in vtd.context
    # Domain pointer captured
    assert domain_ptr in vtd.domains


@pytest.mark.unit
def test_vtd_invalid_context_not_present(vtd, monkeypatch, tmp_path):
    ctx_ptr = 0x3000
    root_entries = [make_root_entry(ctx_ptr, present=True)]
    # Context entry not present (no BIT0)
    context_entries = [make_context_entry(0x5000, present=False)]

    def fake_read_entries(kind, addr, size=8):
        if kind == 're':
            return root_entries
        if kind == 'ce':
            return context_entries
        return [0]

    monkeypatch.setattr(vtd, 'read_entries', fake_read_entries)
    vtd.read_vtd_context(str(tmp_path / 'ctx3.txt'), 0x1000)
    assert vtd.context == {}
    assert vtd.domains == {}


@pytest.mark.unit
def test_vtd_bigpage_1g_translation(vtd, monkeypatch, tmp_path):
    # Setup a domain with a single 1GB big page mapping
    domain_ptr = 0x8000
    ctx_ptr = 0x6000
    root_entries = [make_root_entry(ctx_ptr, present=True)]
    context_entries = [make_context_entry(domain_ptr, present=True, t=0)]

    pml4_base = 0x9000
    pdpt_bigpage_phys = 0x40000000  # 1GB aligned

    pml4e = (pml4_base & ADDR_4KB) | 0x7  # XWR bits set -> present for extended tables
    pdpte_big = (pdpt_bigpage_phys & ADDR_1GB) | BIT7 | 0x7  # big page + perms

    def fake_read_entries(kind, addr, size=8):
        if kind == 're':
            return root_entries
        if kind == 'ce':
            return context_entries
        if kind == 'pml4':
            return [pml4e]
        if kind == 'pdpt':
            return [pdpte_big]
        raise AssertionError('Unexpected kind ' + kind)

    monkeypatch.setattr(vtd, 'read_entries', fake_read_entries)
    # First read context to populate domain list
    vtd.read_vtd_context(str(tmp_path / 'ctx4.txt'), 0x1000)
    assert domain_ptr in vtd.domains

    # Now emulate that the domain root pointer (SLPTPTR) actually points to pml4_base
    # For simplicity, we call read_page_tables with pml4_base to trigger traversal
    vtd.read_page_tables(pml4_base)
    # After traversal, translation mapping should include a 1GB page (size field stored as '1GB')
    assert any(page['size'] == '1GB' for page in vtd.translation.values())


@pytest.mark.unit
def test_vtd_device_id_extraction(vtd, monkeypatch, tmp_path):
    # Choose ree_index (bus) and cee_index encoding dev.fun
    ree_index = 0x34  # bus
    dev = 0x12
    fun = 0x3
    cee_index = (dev << 3) | fun

    ctx_ptr = 0xA000
    domain_ptr = 0xC000
    # Construct arrays sized to include indices we need (pad with non-present entries)
    root_entries = [(0, 0)] * (ree_index + 1)
    root_entries[ree_index] = make_root_entry(ctx_ptr, present=True)
    context_entries = [(0, 0)] * (cee_index + 1)
    context_entries[cee_index] = make_context_entry(domain_ptr, present=True, t=0, domain_id=0x77)

    def fake_read_entries(kind, addr, size=8):
        if kind == 're':
            return root_entries
        if kind == 'ce':
            return context_entries
        return [0]

    monkeypatch.setattr(vtd, 'read_entries', fake_read_entries)
    vtd.read_vtd_context(str(tmp_path / 'ctx5.txt'), 0x1000)
    # Source ID reconstructed
    source_id = (ree_index << 8) | cee_index
    assert source_id in vtd.context
    # Bus/Dev/Fun fields derivable from source_id via descriptors
    assert vtd.get_field(source_id, vtd.DID_BUS) == ree_index
    assert vtd.get_field(source_id, vtd.DID_DEV) == dev
    assert vtd.get_field(source_id, vtd.DID_FUN) == fun
