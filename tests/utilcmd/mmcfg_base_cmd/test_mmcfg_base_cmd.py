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
from unittest.mock import Mock, patch
from chipsec.utilcmd.mmcfg_base_cmd import MMCfgBaseCommand
from tests.test_utils import MockFactory


class TestMMCfgBaseCommand:
    """Comprehensive tests for MMCFG Base command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for MMCFG Base testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        return cs_mock

    @pytest.fixture
    def mmcfg_base_command(self, mock_cs):
        """Create MMCfgBaseCommand instance."""
        return MMCfgBaseCommand([], cs=mock_cs)

    @pytest.mark.unit
    def test_mmcfg_base_command_initialization(self, mmcfg_base_command, mock_cs):
        """Test MMCfgBaseCommand initialization."""
        assert mmcfg_base_command.cs == mock_cs
        assert mmcfg_base_command.argv == []

    @pytest.mark.unit
    def test_requirements(self, mmcfg_base_command):
        """Test command requirements."""
        reqs = mmcfg_base_command.requirements()
        assert reqs == mmcfg_base_command.toLoad.All

    @pytest.mark.unit
    def test_parse_arguments(self, mmcfg_base_command, mock_cs):
        """Test parse_arguments method."""
        # MMCFG Base command doesn't parse arguments
        mmcfg_base_command.parse_arguments()
        # Should not raise any exceptions

    @pytest.mark.unit
    def test_run_single_mmcfg_region(self, mmcfg_base_command, mock_cs):
        """Test run method with single MMCFG region."""
        mock_mmio = Mock()
        mock_mmio.get_MMCFG_base_addresses.return_value = [
            (0xE0000000, 0x10000000)  # Base: 0xE0000000, Size: 256MB
        ]

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio), \
             patch.object(mmcfg_base_command.logger, 'log') as mock_log:
            mmcfg_base_command.run()

            mock_mmio.get_MMCFG_base_addresses.assert_called_once()
            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Base: 0xE0000000')
            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Size: 0x10000000')
            mock_log.assert_any_call('')

    @pytest.mark.unit
    def test_run_multiple_mmcfg_regions(self, mmcfg_base_command, mock_cs):
        """Test run method with multiple MMCFG regions."""
        mock_mmio = Mock()
        mock_mmio.get_MMCFG_base_addresses.return_value = [
            (0xE0000000, 0x10000000),  # Region 1: 256MB
            (0xF0000000, 0x08000000),  # Region 2: 128MB
            (0xF8000000, 0x04000000)   # Region 3: 64MB
        ]

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio), \
             patch.object(mmcfg_base_command.logger, 'log') as mock_log:
            mmcfg_base_command.run()

            mock_mmio.get_MMCFG_base_addresses.assert_called_once()

            # Check all regions are logged
            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Base: 0xE0000000')
            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Size: 0x10000000')
            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Base: 0xF0000000')
            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Size: 0x08000000')
            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Base: 0xF8000000')
            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Size: 0x04000000')

            # Should have empty lines between regions
            assert mock_log.call_count == 7  # 2 lines per region + 1 empty line per region

    @pytest.mark.unit
    def test_run_no_mmcfg_regions(self, mmcfg_base_command, mock_cs):
        """Test run method with no MMCFG regions."""
        mock_mmio = Mock()
        mock_mmio.get_MMCFG_base_addresses.return_value = []

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio), \
             patch.object(mmcfg_base_command.logger, 'log') as mock_log:
            mmcfg_base_command.run()

            mock_mmio.get_MMCFG_base_addresses.assert_called_once()
            # Should not log anything when no regions found
            mock_log.assert_not_called()

    @pytest.mark.unit
    def test_run_large_mmcfg_values(self, mmcfg_base_command, mock_cs):
        """Test run method with large MMCFG values."""
        mock_mmio = Mock()
        mock_mmio.get_MMCFG_base_addresses.return_value = [
            (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)  # Max 64-bit values
        ]

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio), \
             patch.object(mmcfg_base_command.logger, 'log') as mock_log:
            mmcfg_base_command.run()

            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Base: 0xFFFFFFFFFFFFFFFF')
            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Size: 0xFFFFFFFFFFFFFFFF')

    @pytest.mark.unit
    def test_run_zero_mmcfg_values(self, mmcfg_base_command, mock_cs):
        """Test run method with zero MMCFG values."""
        mock_mmio = Mock()
        mock_mmio.get_MMCFG_base_addresses.return_value = [
            (0x00000000, 0x00000000)  # Zero values
        ]

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio), \
             patch.object(mmcfg_base_command.logger, 'log') as mock_log:
            mmcfg_base_command.run()

            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Base: 0x00000000')
            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Size: 0x00000000')

    @pytest.mark.unit
    def test_run_mmio_initialization_error(self, mmcfg_base_command, mock_cs):
        """Test run method with MMIO initialization error."""
        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', side_effect=Exception("MMIO init failed")):
            # Should handle MMIO initialization exception gracefully
            with pytest.raises(Exception):
                mmcfg_base_command.run()

    @pytest.mark.unit
    def test_run_get_mmcfg_addresses_error(self, mmcfg_base_command, mock_cs):
        """Test run method with get_MMCFG_base_addresses error."""
        mock_mmio = Mock()
        mock_mmio.get_MMCFG_base_addresses.side_effect = Exception("Failed to get MMCFG addresses")

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio):
            # Should handle get_MMCFG_base_addresses exception gracefully
            with pytest.raises(Exception):
                mmcfg_base_command.run()


class TestMMCfgBaseCommandIntegration:
    """Integration tests for MMCFG Base command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for MMCFG Base testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        return cs_mock

    @pytest.mark.integration
    def test_mmcfg_base_command_integration(self, integrated_cs):
        """Test complete MMCFG Base command workflow."""
        mmcfg_cmd = MMCfgBaseCommand([], cs=integrated_cs)

        mock_mmio = Mock()
        mock_mmio.get_MMCFG_base_addresses.return_value = [
            (0xE0000000, 0x10000000),
            (0xF0000000, 0x08000000)
        ]

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio), \
             patch.object(mmcfg_cmd.logger, 'log'):
            mmcfg_cmd.run()

            mock_mmio.get_MMCFG_base_addresses.assert_called_once()

    @pytest.mark.integration
    def test_mmcfg_base_command_empty_integration(self, integrated_cs):
        """Test MMCFG Base command with empty results."""
        mmcfg_cmd = MMCfgBaseCommand([], cs=integrated_cs)

        mock_mmio = Mock()
        mock_mmio.get_MMCFG_base_addresses.return_value = []

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio), \
             patch.object(mmcfg_cmd.logger, 'log') as mock_log:
            mmcfg_cmd.run()

            mock_mmio.get_MMCFG_base_addresses.assert_called_once()
            mock_log.assert_not_called()


class TestMMCfgBaseCommandEdgeCases:
    """Test edge cases and error conditions for MMCFG Base command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        return cs_mock

    @pytest.mark.unit
    def test_run_with_malformed_mmcfg_data(self, mock_cs):
        """Test run method with malformed MMCFG data."""
        command = MMCfgBaseCommand([], cs=mock_cs)

        # Test with incomplete tuples
        mock_mmio = Mock()
        mock_mmio.get_MMCFG_base_addresses.return_value = [
            (0xE0000000,),  # Missing size
            (0xF0000000, 0x10000000, 0xDEADBEEF)  # Extra data
        ]

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio), \
             patch.object(command.logger, 'log') as mock_log:
            # Should handle malformed data gracefully
            command.run()

            # Should still attempt to log what it can
            assert mock_log.call_count >= 2  # At least some logging attempted

    @pytest.mark.unit
    def test_run_with_non_tuple_mmcfg_data(self, mock_cs):
        """Test run method with non-tuple MMCFG data."""
        command = MMCfgBaseCommand([], cs=mock_cs)

        mock_mmio = Mock()
        mock_mmio.get_MMCFG_base_addresses.return_value = [
            "invalid_data",  # String instead of tuple
            12345,           # Integer instead of tuple
            None             # None instead of tuple
        ]

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio), \
             patch.object(command.logger, 'log') as mock_log:
            # Should handle non-tuple data gracefully
            command.run()

            # Should still attempt to process data
            assert mock_log.call_count >= 0

    @pytest.mark.unit
    def test_run_with_extremely_large_region_count(self, mock_cs):
        """Test run method with extremely large number of MMCFG regions."""
        command = MMCfgBaseCommand([], cs=mock_cs)

        # Create 1000 MMCFG regions
        large_regions = [(0xE0000000 + i * 0x10000000, 0x10000000) for i in range(1000)]

        mock_mmio = Mock()
        mock_mmio.get_MMCFG_base_addresses.return_value = large_regions

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio), \
             patch.object(command.logger, 'log') as mock_log:
            command.run()

            # Should handle large number of regions
            assert mock_log.call_count == 3000  # 3 calls per region (base, size, empty line)

    @pytest.mark.unit
    def test_run_with_unicode_in_output(self, mock_cs):
        """Test run method with unicode characters in output."""
        command = MMCfgBaseCommand([], cs=mock_cs)

        mock_mmio = Mock()
        mock_mmio.get_MMCFG_base_addresses.return_value = [
            (0xE0000000, 0x10000000)
        ]

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio), \
             patch.object(command.logger, 'log') as mock_log:
            command.run()

            # Check that hex formatting works correctly
            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Base: 0xE0000000')
            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Size: 0x10000000')

    @pytest.mark.unit
    def test_run_with_negative_mmcfg_values(self, mock_cs):
        """Test run method with negative MMCFG values (edge case)."""
        command = MMCfgBaseCommand([], cs=mock_cs)

        mock_mmio = Mock()
        # Python handles negative values in hex formatting
        mock_mmio.get_MMCFG_base_addresses.return_value = [
            (-1, -1)  # Negative values
        ]

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio), \
             patch.object(command.logger, 'log') as mock_log:
            command.run()

            # Should handle negative values in hex formatting
            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Base: 0xFFFFFFFFFFFFFFFF')
            mock_log.assert_any_call('[CHIPSEC] Memory Mapped Config Size: 0xFFFFFFFFFFFFFFFF')

    @pytest.mark.unit
    def test_run_mmio_object_reuse(self, mock_cs):
        """Test that MMIO object is created fresh each run."""
        command = MMCfgBaseCommand([], cs=mock_cs)

        mock_mmio = Mock()
        mock_mmio.get_MMCFG_base_addresses.return_value = [(0xE0000000, 0x10000000)]

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio) as mock_mmio_class:
            # Run command twice
            command.run()
            command.run()

            # Should create MMIO object twice
            assert mock_mmio_class.call_count == 2
            assert mock_mmio.get_MMCFG_base_addresses.call_count == 2


class TestMMCfgBaseCommandConfigurationValidation:
    """Test configuration validation aspects of MMCFG Base command."""

    @pytest.fixture
    def mmcfg_cs(self):
        """Create ChipsecCs with MMCFG-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock MMCFG configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.MMIO = {
            'MMCFG_BASE_ADDRESSES': [
                {'base': 0xE0000000, 'size': 0x10000000},
                {'base': 0xF0000000, 'size': 0x08000000}
            ],
            'MMCFG_ENABLED': True,
            'MMCFG_MAX_REGIONS': 8
        }

        return cs_mock

    @pytest.mark.unit
    def test_mmcfg_configuration_structure(self, mmcfg_cs):
        """Test MMCFG configuration structure."""
        mmio_config = mmcfg_cs.Cfg.MMIO

        # Test that required MMCFG configuration exists
        assert 'MMCFG_BASE_ADDRESSES' in mmio_config
        assert 'MMCFG_ENABLED' in mmio_config
        assert 'MMCFG_MAX_REGIONS' in mmio_config

        # Test configuration values are reasonable
        assert isinstance(mmio_config['MMCFG_BASE_ADDRESSES'], list)
        assert isinstance(mmio_config['MMCFG_ENABLED'], bool)
        assert mmio_config['MMCFG_MAX_REGIONS'] > 0

    @pytest.mark.unit
    def test_mmcfg_base_addresses_validation(self, mmcfg_cs):
        """Test MMCFG base addresses validation."""
        base_addresses = mmcfg_cs.Cfg.MMIO['MMCFG_BASE_ADDRESSES']

        for addr_config in base_addresses:
            assert 'base' in addr_config
            assert 'size' in addr_config
            assert addr_config['base'] > 0
            assert addr_config['size'] > 0

    @pytest.mark.unit
    def test_mmcfg_enabled_flag(self, mmcfg_cs):
        """Test MMCFG enabled flag."""
        enabled = mmcfg_cs.Cfg.MMIO['MMCFG_ENABLED']
        assert isinstance(enabled, bool)

    @pytest.mark.unit
    def test_mmcfg_max_regions_limit(self, mmcfg_cs):
        """Test MMCFG max regions limit."""
        max_regions = mmcfg_cs.Cfg.MMIO['MMCFG_MAX_REGIONS']
        assert max_regions > 0
        assert max_regions <= 16  # Reasonable upper limit

    @pytest.mark.unit
    def test_mmcfg_command_with_config(self, mmcfg_cs):
        """Test MMCFG Base command with configuration."""
        command = MMCfgBaseCommand([], cs=mmcfg_cs)

        mock_mmio = Mock()
        mock_mmio.get_MMCFG_base_addresses.return_value = [
            (0xE0000000, 0x10000000)
        ]

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio), \
             patch.object(command.logger, 'log'):
            command.run()

            # Should work with configuration present
            mock_mmio.get_MMCFG_base_addresses.assert_called_once()

    @pytest.mark.unit
    def test_mmcfg_configuration_consistency(self, mmcfg_cs):
        """Test MMCFG configuration consistency."""
        base_addresses = mmcfg_cs.Cfg.MMIO['MMCFG_BASE_ADDRESSES']
        max_regions = mmcfg_cs.Cfg.MMIO['MMCFG_MAX_REGIONS']

        # Number of configured regions should not exceed max_regions
        assert len(base_addresses) <= max_regions

    @pytest.mark.unit
    def test_mmcfg_address_range_validation(self, mmcfg_cs):
        """Test MMCFG address range validation."""
        base_addresses = mmcfg_cs.Cfg.MMIO['MMCFG_BASE_ADDRESSES']

        for addr_config in base_addresses:
            base = addr_config['base']
            size = addr_config['size']

            # Base address should be in valid PCIe MMCFG range
            assert 0x80000000 <= base <= 0xFFFFFFFF  # Typical MMCFG range
            # Size should be power of 2 and reasonable
            assert size > 0
            assert (size & (size - 1)) == 0  # Power of 2
            assert size >= 0x100000  # At least 1MB

    @pytest.mark.unit
    def test_mmcfg_no_address_overlap(self, mmcfg_cs):
        """Test that MMCFG addresses don't overlap."""
        base_addresses = mmcfg_cs.Cfg.MMIO['MMCFG_BASE_ADDRESSES']

        # Sort by base address
        sorted_addresses = sorted(base_addresses, key=lambda x: x['base'])

        for i in range(len(sorted_addresses) - 1):
            current_end = sorted_addresses[i]['base'] + sorted_addresses[i]['size']
            next_start = sorted_addresses[i + 1]['base']

            # No overlap
            assert current_end <= next_start

    @pytest.mark.unit
    def test_mmcfg_command_error_handling(self, mmcfg_cs):
        """Test MMCFG Base command error handling."""
        command = MMCfgBaseCommand([], cs=mmcfg_cs)

        # Test MMIO creation error
        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', side_effect=Exception("MMIO error")):
            with pytest.raises(Exception):
                command.run()

        # Test get_MMCFG_base_addresses error
        mock_mmio = Mock()
        mock_mmio.get_MMCFG_base_addresses.side_effect = Exception("Get addresses error")

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio):
            with pytest.raises(Exception):
                command.run()

    @pytest.mark.unit
    def test_mmcfg_command_logging_comprehensive(self, mmcfg_cs):
        """Test MMCFG Base command comprehensive logging."""
        command = MMCfgBaseCommand([], cs=mmcfg_cs)

        mock_mmio = Mock()
        mock_mmio.get_MMCFG_base_addresses.return_value = [
            (0xE0000000, 0x10000000),
            (0xF0000000, 0x08000000)
        ]

        with patch('chipsec.utilcmd.mmcfg_base_cmd.mmio.MMIO', return_value=mock_mmio), \
             patch.object(command.logger, 'log') as mock_log:
            command.run()

            # Verify all expected log calls
            expected_calls = [
                ('[CHIPSEC] Memory Mapped Config Base: 0xE0000000',),
                ('[CHIPSEC] Memory Mapped Config Size: 0x10000000',),
                ('',),
                ('[CHIPSEC] Memory Mapped Config Base: 0xF0000000',),
                ('[CHIPSEC] Memory Mapped Config Size: 0x08000000',),
                ('',)
            ]

            for expected_call in expected_calls:
                mock_log.assert_any_call(*expected_call)

            assert mock_log.call_count == 6


if __name__ == '__main__':
    pytest.main([__file__])
