# CHIPSEC: Platform Security Assessment Framework
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

import pytest
from unittest.mock import patch
from chipsec.library.intel.spi import (
    SPI_REGION, SPI_REGION_NAMES, SPI_MASTER_NAMES,
    SPI_FREGx_LIMIT_MASK, SPI_FREGx_BASE_MASK,
    SPI_FLA_SHIFT, SPI_FLA_PAGE_MASK,
    FLASH_DESCRIPTOR, BIOS, ME, GBE, PLATFORM_DATA,
    MASTER_HOST_CPU_BIOS, MASTER_ME, MASTER_GBE, MASTER_EC,
    print_SPI_Flash_Regions, SPI_REGION_tuple
)


class TestSPIConstants:
    """Test SPI constants and data structures."""

    @pytest.mark.unit
    def test_spi_region_constants(self):
        """Test SPI region constants are properly defined."""
        assert FLASH_DESCRIPTOR == 0
        assert BIOS == 1
        assert ME == 2
        assert GBE == 3
        assert PLATFORM_DATA == 4

    @pytest.mark.unit
    def test_spi_master_constants(self):
        """Test SPI master constants are properly defined."""
        assert MASTER_HOST_CPU_BIOS == 0
        assert MASTER_ME == 1
        assert MASTER_GBE == 2
        assert MASTER_EC == 3

    @pytest.mark.unit
    def test_spi_region_dictionary(self):
        """Test SPI_REGION dictionary contains expected entries."""
        assert len(SPI_REGION) == 16
        assert SPI_REGION[FLASH_DESCRIPTOR] == '8086.SPI.SPIBAR.FREG0_FLASHD'
        assert SPI_REGION[BIOS] == '8086.SPI.SPIBAR.FREG1_BIOS'
        assert SPI_REGION[ME] == '8086.SPI.SPIBAR.FREG2_ME'
        assert SPI_REGION[GBE] == '8086.SPI.SPIBAR.FREG3_GBE'
        assert SPI_REGION[PLATFORM_DATA] == '8086.SPI.SPIBAR.FREG4_PD'

    @pytest.mark.unit
    def test_spi_region_names_dictionary(self):
        """Test SPI_REGION_NAMES dictionary contains expected entries."""
        assert len(SPI_REGION_NAMES) == 16
        assert SPI_REGION_NAMES[FLASH_DESCRIPTOR] == 'Flash Descriptor'
        assert SPI_REGION_NAMES[BIOS] == 'BIOS'
        assert SPI_REGION_NAMES[ME] == 'Intel ME'
        assert SPI_REGION_NAMES[GBE] == 'GBe'
        assert SPI_REGION_NAMES[PLATFORM_DATA] == 'Platform Data'

    @pytest.mark.unit
    def test_spi_master_names_dictionary(self):
        """Test SPI_MASTER_NAMES dictionary contains expected entries."""
        assert len(SPI_MASTER_NAMES) == 4
        assert SPI_MASTER_NAMES[MASTER_HOST_CPU_BIOS] == 'CPU'
        assert SPI_MASTER_NAMES[MASTER_ME] == 'ME'
        assert SPI_MASTER_NAMES[MASTER_GBE] == 'GBe'
        assert SPI_MASTER_NAMES[MASTER_EC] == 'EC'

    @pytest.mark.unit
    def test_spi_mask_constants(self):
        """Test SPI mask constants."""
        assert SPI_FREGx_LIMIT_MASK == 0x7FFF0000
        assert SPI_FREGx_BASE_MASK == 0x00007FFF
        assert SPI_FLA_SHIFT == 12
        assert SPI_FLA_PAGE_MASK == 0xFFF  # ALIGNED_4KB - 1

    @pytest.mark.unit
    def test_spi_region_tuple(self):
        """Test SPI_REGION_tuple namedtuple structure."""
        region = SPI_REGION_tuple(name='Test Region', value=0x12345678, base=0x1000, limit=0x2000)
        assert region.name == 'Test Region'
        assert region.value == 0x12345678
        assert region.base == 0x1000
        assert region.limit == 0x2000


class TestSPIFunctions:
    """Test SPI utility functions."""

    @pytest.mark.unit
    def test_print_SPI_Flash_Regions(self):
        """Test print_SPI_Flash_Regions function."""
        regions = {
            0: SPI_REGION_tuple(name='Flash Descriptor', value=0x00000000, base=0x00000000, limit=0x00000FFF),
            1: SPI_REGION_tuple(name='BIOS', value=0x00100000, base=0x00100000, limit=0x007FFFFF),
            2: SPI_REGION_tuple(name='ME', value=0x00800000, base=0x00800000, limit=0x00FFFFFF),
        }

        with patch('chipsec.library.intel.spi.logger') as mock_logger:
            print_SPI_Flash_Regions(regions)

            # Verify logger.log was called multiple times
            assert mock_logger.return_value.log.call_count > 3  # Header + separator + regions

    @pytest.mark.unit
    def test_print_SPI_Flash_Regions_unused_region(self):
        """Test print_SPI_Flash_Regions with unused region (base > limit)."""
        regions = {
            0: SPI_REGION_tuple(name='Unused Region', value=0x00000000, base=0x00200000, limit=0x00100000),
        }

        with patch('chipsec.library.intel.spi.logger') as mock_logger:
            print_SPI_Flash_Regions(regions)

            # Check that '(not used)' appears in the log output
            log_calls = mock_logger.return_value.log.call_args_list
            unused_found = any('(not used)' in str(call) for call in log_calls)
            assert unused_found

    @pytest.mark.unit
    def test_print_SPI_Flash_Regions_empty(self):
        """Test print_SPI_Flash_Regions with empty regions dictionary."""
        regions = {}

        with patch('chipsec.library.intel.spi.logger') as mock_logger:
            print_SPI_Flash_Regions(regions)

            # Should still print header even with no regions
            assert mock_logger.return_value.log.call_count >= 3  # Header + separator lines


if __name__ == '__main__':
    pytest.main([__file__])
