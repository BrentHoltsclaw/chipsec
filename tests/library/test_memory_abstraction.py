import pytest
from types import SimpleNamespace

from chipsec.library import memory as mem_consts
from chipsec.hal.common import physmem


class DummyHelper:
    """Helper mock that records operations and returns synthetic data."""
    def __init__(self):
        self.reads = {}
        self.writes = []
        self.allocs = []
        self.frees = []
        self.mapped = []
        self.cpuid_calls = []
        self.msrs = {0: 0}  # thread -> msr value

    # Memory primitives
    def read_phys_mem(self, pa, length):
        # Return pattern bytes or zeroes
        data = self.reads.get((pa, length))
        if data is None:
            # default incremental pattern limited to length
            data = bytes((i & 0xFF) for i in range(length))
        return data

    def write_phys_mem(self, pa, length, buf):
        assert len(buf) == length
        self.writes.append((pa, length, buf))
        return length

    def alloc_phys_mem(self, length, max_pa):
        pa = 0x100000  # fixed base
        va = 0x200000
        self.allocs.append((length, max_pa, pa, va))
        return (va, pa)

    def free_phys_mem(self, pa):
        self.frees.append(pa)
        return 1

    def map_io_space(self, pa, length, cache_type):
        self.mapped.append((pa, length, cache_type))
        return pa + 0x1000  # pseudo VA

    # CPU/CPUID / MSR
    def cpuid(self, leaf, subleaf):
        self.cpuid_calls.append((leaf, subleaf))
        # Simulate max functions available and 48-bit phys address capability
        if leaf == 0x80000000:
            return (0x80000008, 0, 0, 0)
        if leaf == 0x80000008:
            # eax low 8 bits = phys address bits (e.g., 48)
            return (48, 0, 0, 0)
        if leaf == 0x0:
            return (0x7, 0, 0, 0)
        if leaf == 0x7:
            # Indicate TME (bit13) not set to simplify path
            return (0, 0, 0, 0)
        return (0, 0, 0, 0)

    def read_msr(self, thread, msr):
        return self.msrs.get(thread, 0)


class DummyCS:
    def __init__(self):
        self.helper = DummyHelper()
        # Provide minimal config interface for get_def path (unused in current tests)
        self.Cfg = SimpleNamespace(get_objlist=lambda name: [])
        self.logger = SimpleNamespace(log=lambda *a, **k: None, log_hal=lambda *a, **k: None, HAL=False)


@pytest.fixture
def mem():
    return physmem.Memory(DummyCS())


# --- Constant / alignment tests ---

@pytest.mark.unit
def test_alignment_masks_basic():
    # Verify 4KB alignment mask strips lower 12 bits
    addr = 0x12345
    assert (addr & ~mem_consts.ALIGNED_4KB) % mem_consts.BOUNDARY_4KB == 0
    # Sanity: 1MB alignment mask corresponds to boundary
    assert mem_consts.ALIGNED_1MB == (mem_consts.BOUNDARY_1MB - 1)


@pytest.mark.unit
def test_size_constants_monotonic():
    ordered = [mem_consts.SIZE_64B, mem_consts.SIZE_4KB, mem_consts.SIZE_8KB, mem_consts.SIZE_16KB, mem_consts.SIZE_32KB]
    assert ordered == sorted(ordered)


# --- HAL read/write primitives ---

@pytest.mark.unit
def test_read_write_byte_word_dword_qword(mem):
    # Preload deterministic buffers for different sizes
    helper = mem.helper
    helper.reads[(0x1000, 1)] = b'\xAA'
    helper.reads[(0x1004, 2)] = b'\x55\xCC'
    helper.reads[(0x2000, 4)] = b'\x11\x22\x33\x44'
    helper.reads[(0x3000, 8)] = b'\x01\x02\x03\x04\x05\x06\x07\x08'

    assert mem.read_physical_mem_byte(0x1000) == 0xAA
    assert mem.read_physical_mem_word(0x1004) == 0xCC55  # little endian
    assert mem.read_physical_mem_dword(0x2000) == 0x44332211
    assert mem.read_physical_mem_qword(0x3000) == 0x0807060504030201

    # Writes
    mem.write_physical_mem_byte(0x4000, 0x5E)
    mem.write_physical_mem_word(0x4002, 0xBEEF)
    mem.write_physical_mem_dword(0x4004, 0xDEADBEEF)
    assert (0x4000, 1, b'\x5E') in helper.writes
    # Word stored little endian
    assert any(pa == 0x4002 and data == b'\xEF\xBE' for pa, _, data in helper.writes)
    assert any(pa == 0x4004 and data == b'\xEF\xBE\xAD\xDE' for pa, _, data in helper.writes)


@pytest.mark.unit
def test_alloc_and_free(mem):
    va, pa = mem.alloc_physical_mem(0x200)
    assert pa == 0x100000
    assert va == 0x200000
    assert mem.free_physical_mem(pa) is True


@pytest.mark.unit
def test_map_io_space(mem):
    va = mem.map_io_space(0xABC000, 0x100, cache_type=0)
    assert va == 0xABC000 + 0x1000


@pytest.mark.unit
def test_set_mem_bit(mem):
    # Prepare 1 byte at address 0x5000 => initial 0x00
    helper = mem.helper
    helper.reads[(0x5000, 1)] = b'\x00'
    mem.set_mem_bit(0x5000, 3)  # sets bit3 => 0x08
    # Expect a write with value 0x08
    assert any(pa == 0x5000 and buf == b'\x08' for pa, _, buf in helper.writes)


@pytest.mark.unit
def test_get_max_memory_bit_size(mem, monkeypatch):
    # Already returns 48 from DummyHelper path -> ensure mask matches 48-bit
    bits = mem.get_max_memory_bit_size()
    assert bits == 48
    mask = mem.get_max_memory_mask()
    # 48 bits => high bits clear beyond 48
    assert mask == (1 << 48) - 1
