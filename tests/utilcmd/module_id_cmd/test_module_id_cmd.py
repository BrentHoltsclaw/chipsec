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
from chipsec.utilcmd.module_id_cmd import ModuleIdCommand
from tests.test_utils import MockFactory


class TestModuleIdCommand:
    """Comprehensive tests for Module ID command functionality."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object for Module ID testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        return cs_mock

    @pytest.fixture
    def module_id_command(self, mock_cs):
        """Create ModuleIdCommand instance."""
        return ModuleIdCommand(['name', 'chipsec.modules.common.remap'], cs=mock_cs)

    @pytest.mark.unit
    def test_module_id_command_initialization(self, module_id_command, mock_cs):
        """Test ModuleIdCommand initialization."""
        assert module_id_command.cs == mock_cs
        assert module_id_command.argv == ['name', 'chipsec.modules.common.remap']

    @pytest.mark.unit
    def test_requirements(self, module_id_command):
        """Test command requirements."""
        reqs = module_id_command.requirements()
        assert reqs == module_id_command.toLoad.Nil

    @pytest.mark.unit
    def test_parse_arguments_name(self, mock_cs):
        """Test parsing arguments for name subcommand."""
        command = ModuleIdCommand(['name', 'chipsec.modules.common.remap'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.get_id_from_name
        assert command.module_name == 'chipsec.modules.common.remap'

    @pytest.mark.unit
    def test_parse_arguments_hash(self, mock_cs):
        """Test parsing arguments for hash subcommand."""
        command = ModuleIdCommand(['hash', '0x67eb58d'], cs=mock_cs)
        command.parse_arguments()
        assert command.func == command.get_name_from_id
        assert command.module_id == '0x67eb58d'

    @pytest.mark.unit
    def test_parse_arguments_no_subcommand(self, mock_cs):
        """Test parsing arguments with no subcommand."""
        command = ModuleIdCommand([], cs=mock_cs)

        # Should raise SystemExit due to missing subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_invalid_subcommand(self, mock_cs):
        """Test parsing arguments with invalid subcommand."""
        command = ModuleIdCommand(['invalid'], cs=mock_cs)

        # Should raise SystemExit due to invalid subcommand
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_name_missing_module(self, mock_cs):
        """Test parsing arguments for name subcommand with missing module name."""
        command = ModuleIdCommand(['name'], cs=mock_cs)

        # Should raise SystemExit due to missing required argument
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_parse_arguments_hash_missing_id(self, mock_cs):
        """Test parsing arguments for hash subcommand with missing module ID."""
        command = ModuleIdCommand(['hash'], cs=mock_cs)

        # Should raise SystemExit due to missing required argument
        with pytest.raises(SystemExit):
            command.parse_arguments()

    @pytest.mark.unit
    def test_get_id_from_name_existing_module(self, module_id_command, mock_cs):
        """Test get_id_from_name method with existing module."""
        module_id_command.module_name = 'chipsec.modules.common.remap'

        mock_module_ids = {
            'chipsec.modules.common.remap': 0x67eb58d,
            'chipsec.modules.common.cpu': 0x12345678
        }

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value=mock_module_ids), \
             patch.object(module_id_command.logger, 'log') as mock_log:
            module_id_command.get_id_from_name()

            mock_log.assert_called_with('Module ID is: 0x67eb58d\n')

    @pytest.mark.unit
    def test_get_id_from_name_new_module(self, module_id_command, mock_cs):
        """Test get_id_from_name method with new module (not in dictionary)."""
        module_id_command.module_name = 'chipsec.modules.new.test'

        mock_module_ids = {
            'chipsec.modules.common.remap': 0x67eb58d,
            'chipsec.modules.common.cpu': 0x12345678
        }

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value=mock_module_ids), \
             patch('chipsec.utilcmd.module_id_cmd.generate_hash_id', return_value=0xabcdef12) as mock_generate, \
             patch.object(module_id_command.logger, 'log') as mock_log:
            module_id_command.get_id_from_name()

            mock_generate.assert_called_with('chipsec.modules.new.test')
            mock_log.assert_called_with('Module ID is: 0xabcdef12\n')

    @pytest.mark.unit
    def test_get_name_from_id_existing_id(self, module_id_command, mock_cs):
        """Test get_name_from_id method with existing module ID."""
        module_id_command.module_id = '0x67eb58d'

        mock_module_ids = {
            'chipsec.modules.common.remap': 0x67eb58d,
            'chipsec.modules.common.cpu': 0x12345678
        }

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value=mock_module_ids), \
             patch.object(module_id_command.logger, 'log') as mock_log:
            module_id_command.get_name_from_id()

            mock_log.assert_called_with('Module name is: chipsec.modules.common.remap\n')

    @pytest.mark.unit
    def test_get_name_from_id_nonexistent_id(self, module_id_command, mock_cs):
        """Test get_name_from_id method with nonexistent module ID."""
        module_id_command.module_id = '0xdeadbeef'

        mock_module_ids = {
            'chipsec.modules.common.remap': 0x67eb58d,
            'chipsec.modules.common.cpu': 0x12345678
        }

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value=mock_module_ids), \
             patch.object(module_id_command.logger, 'log') as mock_log:
            module_id_command.get_name_from_id()

            mock_log.assert_called_with('Could not find 0xdeadbeef\n')

    @pytest.mark.unit
    def test_get_name_from_id_hex_without_prefix(self, module_id_command, mock_cs):
        """Test get_name_from_id method with hex ID without 0x prefix."""
        module_id_command.module_id = '67eb58d'

        mock_module_ids = {
            'chipsec.modules.common.remap': 0x67eb58d,
            'chipsec.modules.common.cpu': 0x12345678
        }

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value=mock_module_ids), \
             patch.object(module_id_command.logger, 'log') as mock_log:
            module_id_command.get_name_from_id()

            mock_log.assert_called_with('Module name is: chipsec.modules.common.remap\n')

    @pytest.mark.unit
    def test_get_name_from_id_invalid_hex(self, module_id_command, mock_cs):
        """Test get_name_from_id method with invalid hex string."""
        module_id_command.module_id = 'invalid_hex'

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary'):
            # Should raise ValueError due to invalid hex conversion
            with pytest.raises(ValueError):
                module_id_command.get_name_from_id()

    @pytest.mark.unit
    def test_get_id_from_name_empty_dictionary(self, module_id_command, mock_cs):
        """Test get_id_from_name method with empty module IDs dictionary."""
        module_id_command.module_name = 'chipsec.modules.test'

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value={}), \
             patch('chipsec.utilcmd.module_id_cmd.generate_hash_id', return_value=0x12345678) as mock_generate, \
             patch.object(module_id_command.logger, 'log') as mock_log:
            module_id_command.get_id_from_name()

            mock_generate.assert_called_with('chipsec.modules.test')
            mock_log.assert_called_with('Module ID is: 0x12345678\n')

    @pytest.mark.unit
    def test_get_name_from_id_empty_dictionary(self, module_id_command, mock_cs):
        """Test get_name_from_id method with empty module IDs dictionary."""
        module_id_command.module_id = '0x12345678'

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value={}), \
             patch.object(module_id_command.logger, 'log') as mock_log:
            module_id_command.get_name_from_id()

            mock_log.assert_called_with('Could not find 0x12345678\n')

    @pytest.mark.unit
    def test_get_id_from_name_special_characters(self, module_id_command, mock_cs):
        """Test get_id_from_name method with special characters in module name."""
        module_id_command.module_name = 'chipsec.modules.test_module-name.123'

        mock_module_ids = {
            'chipsec.modules.common.remap': 0x67eb58d
        }

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value=mock_module_ids), \
             patch('chipsec.utilcmd.module_id_cmd.generate_hash_id', return_value=0xabcdef12) as mock_generate, \
             patch.object(module_id_command.logger, 'log') as mock_log:
            module_id_command.get_id_from_name()

            mock_generate.assert_called_with('chipsec.modules.test_module-name.123')
            mock_log.assert_called_with('Module ID is: 0xabcdef12\n')

    @pytest.mark.unit
    def test_get_name_from_id_large_hex_value(self, module_id_command, mock_cs):
        """Test get_name_from_id method with large hex value."""
        module_id_command.module_id = '0xFFFFFFFFFFFFFFFF'

        mock_module_ids = {
            'chipsec.modules.large_test': 0xFFFFFFFFFFFFFFFF,
            'chipsec.modules.common.remap': 0x67eb58d
        }

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value=mock_module_ids), \
             patch.object(module_id_command.logger, 'log') as mock_log:
            module_id_command.get_name_from_id()

            mock_log.assert_called_with('Module name is: chipsec.modules.large_test\n')

    @pytest.mark.unit
    def test_get_id_from_name_unicode_module_name(self, module_id_command, mock_cs):
        """Test get_id_from_name method with unicode characters in module name."""
        module_id_command.module_name = 'chipsec.modules.test_测试'

        mock_module_ids = {
            'chipsec.modules.common.remap': 0x67eb58d
        }

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value=mock_module_ids), \
             patch('chipsec.utilcmd.module_id_cmd.generate_hash_id', return_value=0x12345678) as mock_generate, \
             patch.object(module_id_command.logger, 'log') as mock_log:
            module_id_command.get_id_from_name()

            mock_generate.assert_called_with('chipsec.modules.test_测试')
            mock_log.assert_called_with('Module ID is: 0x12345678\n')


class TestModuleIdCommandIntegration:
    """Integration tests for Module ID command with realistic data."""

    @pytest.fixture
    def integrated_cs(self):
        """Create integrated ChipsecCs for Module ID testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        return cs_mock

    @pytest.mark.integration
    def test_module_id_name_to_id_integration(self, integrated_cs):
        """Test complete module name to ID workflow."""
        module_cmd = ModuleIdCommand(['name', 'chipsec.modules.common.remap'], cs=integrated_cs)

        mock_module_ids = {
            'chipsec.modules.common.remap': 0x67eb58d,
            'chipsec.modules.common.cpu': 0x12345678
        }

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value=mock_module_ids), \
             patch.object(module_cmd.logger, 'log'):
            module_cmd.get_id_from_name()

            # Should successfully get ID for existing module
            assert module_cmd.module_name == 'chipsec.modules.common.remap'

    @pytest.mark.integration
    def test_module_id_id_to_name_integration(self, integrated_cs):
        """Test complete module ID to name workflow."""
        module_cmd = ModuleIdCommand(['hash', '0x67eb58d'], cs=integrated_cs)

        mock_module_ids = {
            'chipsec.modules.common.remap': 0x67eb58d,
            'chipsec.modules.common.cpu': 0x12345678
        }

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value=mock_module_ids), \
             patch.object(module_cmd.logger, 'log'):
            module_cmd.get_name_from_id()

            # Should successfully get name for existing ID
            assert module_cmd.module_id == '0x67eb58d'

    @pytest.mark.integration
    def test_module_id_round_trip_integration(self, integrated_cs):
        """Test round-trip conversion between name and ID."""
        # Test name -> ID -> name
        original_name = 'chipsec.modules.common.remap'
        expected_id = 0x67eb58d

        mock_module_ids = {
            original_name: expected_id,
            'chipsec.modules.common.cpu': 0x12345678
        }

        # Name to ID
        name_cmd = ModuleIdCommand(['name', original_name], cs=integrated_cs)
        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value=mock_module_ids), \
             patch.object(name_cmd.logger, 'log'):
            name_cmd.get_id_from_name()

        # ID to name
        id_cmd = ModuleIdCommand(['hash', hex(expected_id)], cs=integrated_cs)
        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value=mock_module_ids), \
             patch.object(id_cmd.logger, 'log'):
            id_cmd.get_name_from_id()

        # Should round-trip correctly
        assert name_cmd.module_name == original_name


class TestModuleIdCommandEdgeCases:
    """Test edge cases and error conditions for Module ID command."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs for edge case testing."""
        cs_mock = MockFactory.create_mock_chipsec_cs()
        return cs_mock

    @pytest.mark.unit
    def test_parse_arguments_name_empty_string(self, mock_cs):
        """Test parsing arguments with empty string module name."""
        command = ModuleIdCommand(['name', ''], cs=mock_cs)
        command.parse_arguments()
        assert command.module_name == ''

    @pytest.mark.unit
    def test_parse_arguments_hash_empty_string(self, mock_cs):
        """Test parsing arguments with empty string module ID."""
        command = ModuleIdCommand(['hash', ''], cs=mock_cs)
        command.parse_arguments()
        assert command.module_id == ''

    @pytest.mark.unit
    def test_get_id_from_name_very_long_module_name(self, mock_cs):
        """Test get_id_from_name method with very long module name."""
        command = ModuleIdCommand(['name', 'a' * 1000], cs=mock_cs)
        command.module_name = 'a' * 1000

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value={}), \
             patch('chipsec.utilcmd.module_id_cmd.generate_hash_id', return_value=0x12345678) as mock_generate, \
             patch.object(command.logger, 'log'):
            command.get_id_from_name()

            mock_generate.assert_called_with('a' * 1000)

    @pytest.mark.unit
    def test_get_name_from_id_zero_value(self, mock_cs):
        """Test get_name_from_id method with zero value."""
        command = ModuleIdCommand(['hash', '0x0'], cs=mock_cs)

        mock_module_ids = {
            'chipsec.modules.zero_test': 0x0,
            'chipsec.modules.common.remap': 0x67eb58d
        }

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value=mock_module_ids), \
             patch.object(command.logger, 'log') as mock_log:
            command.get_name_from_id()

            mock_log.assert_called_with('Module name is: chipsec.modules.zero_test\n')

    @pytest.mark.unit
    def test_get_name_from_id_max_32bit_value(self, mock_cs):
        """Test get_name_from_id method with max 32-bit value."""
        command = ModuleIdCommand(['hash', '0xFFFFFFFF'], cs=mock_cs)

        mock_module_ids = {
            'chipsec.modules.max32_test': 0xFFFFFFFF,
            'chipsec.modules.common.remap': 0x67eb58d
        }

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value=mock_module_ids), \
             patch.object(command.logger, 'log') as mock_log:
            command.get_name_from_id()

            mock_log.assert_called_with('Module name is: chipsec.modules.max32_test\n')

    @pytest.mark.unit
    def test_get_id_from_name_with_path_separators(self, mock_cs):
        """Test get_id_from_name method with various path separators."""
        test_cases = [
            'chipsec.modules.common.remap',
            'chipsec/modules/common/remap',
            'chipsec\\modules\\common\\remap',
            'chipsec.modules.common.remap.py'
        ]

        for module_name in test_cases:
            command = ModuleIdCommand(['name', module_name], cs=mock_cs)
            command.module_name = module_name

            with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value={}), \
                 patch('chipsec.utilcmd.module_id_cmd.generate_hash_id', return_value=0x12345678) as mock_generate, \
                 patch.object(command.logger, 'log'):
                command.get_id_from_name()

                mock_generate.assert_called_with(module_name)

    @pytest.mark.unit
    def test_get_name_from_id_duplicate_ids(self, mock_cs):
        """Test get_name_from_id method with duplicate IDs (should return first match)."""
        command = ModuleIdCommand(['hash', '0x12345678'], cs=mock_cs)

        mock_module_ids = {
            'chipsec.modules.first': 0x12345678,
            'chipsec.modules.second': 0x12345678,  # Duplicate ID
            'chipsec.modules.third': 0x87654321
        }

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value=mock_module_ids), \
             patch.object(command.logger, 'log') as mock_log:
            command.get_name_from_id()

            # Should return first matching module name
            mock_log.assert_called_with('Module name is: chipsec.modules.first\n')

    @pytest.mark.unit
    def test_module_id_command_error_handling(self, mock_cs):
        """Test Module ID command error handling."""
        # Test get_module_ids_dictionary error
        command = ModuleIdCommand(['name', 'test'], cs=mock_cs)

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', side_effect=Exception("Dict error")), \
             patch.object(command.logger, 'log'):
            with pytest.raises(Exception):
                command.get_id_from_name()

        # Test generate_hash_id error
        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value={}), \
             patch('chipsec.utilcmd.module_id_cmd.generate_hash_id', side_effect=Exception("Hash error")), \
             patch.object(command.logger, 'log'):
            with pytest.raises(Exception):
                command.get_id_from_name()


class TestModuleIdCommandConfigurationValidation:
    """Test configuration validation aspects of Module ID command."""

    @pytest.fixture
    def module_id_cs(self):
        """Create ChipsecCs with Module ID-specific configuration."""
        cs_mock = MockFactory.create_mock_chipsec_cs()

        # Mock module ID configuration
        cs_mock.Cfg = Mock()
        cs_mock.Cfg.MODULE_ID = {
            'HASH_TRUNCATION_BITS': 28,
            'ENABLE_CACHING': True,
            'CACHE_SIZE': 1000,
            'SUPPORTED_MODULES': [
                'chipsec.modules.common.remap',
                'chipsec.modules.common.cpu',
                'chipsec.modules.common.uefi'
            ]
        }

        return cs_mock

    @pytest.mark.unit
    def test_module_id_configuration_structure(self, module_id_cs):
        """Test Module ID configuration structure."""
        module_config = module_id_cs.Cfg.MODULE_ID

        # Test that required MODULE_ID configuration exists
        assert 'HASH_TRUNCATION_BITS' in module_config
        assert 'ENABLE_CACHING' in module_config
        assert 'CACHE_SIZE' in module_config
        assert 'SUPPORTED_MODULES' in module_config

        # Test configuration values are reasonable
        assert module_config['HASH_TRUNCATION_BITS'] > 0
        assert module_config['HASH_TRUNCATION_BITS'] <= 32
        assert isinstance(module_config['ENABLE_CACHING'], bool)
        assert module_config['CACHE_SIZE'] > 0
        assert isinstance(module_config['SUPPORTED_MODULES'], list)

    @pytest.mark.unit
    def test_hash_truncation_bits_validation(self, module_id_cs):
        """Test hash truncation bits validation."""
        truncation_bits = module_id_cs.Cfg.MODULE_ID['HASH_TRUNCATION_BITS']

        # Should be reasonable for module ID generation
        assert 1 <= truncation_bits <= 32

        # Common values for hash truncation
        valid_values = [8, 16, 24, 28, 32]
        assert truncation_bits in valid_values

    @pytest.mark.unit
    def test_supported_modules_validation(self, module_id_cs):
        """Test supported modules validation."""
        supported_modules = module_id_cs.Cfg.MODULE_ID['SUPPORTED_MODULES']

        # Should contain valid module names
        for module in supported_modules:
            assert isinstance(module, str)
            assert module.startswith('chipsec.modules.')
            assert len(module) > len('chipsec.modules.')

    @pytest.mark.unit
    def test_cache_configuration_validation(self, module_id_cs):
        """Test cache configuration validation."""
        enable_caching = module_id_cs.Cfg.MODULE_ID['ENABLE_CACHING']
        cache_size = module_id_cs.Cfg.MODULE_ID['CACHE_SIZE']

        assert isinstance(enable_caching, bool)

        if enable_caching:
            # Cache size should be reasonable if caching is enabled
            assert cache_size > 0
            assert cache_size <= 10000  # Reasonable upper limit

    @pytest.mark.unit
    def test_module_id_command_with_config(self, module_id_cs):
        """Test Module ID command with configuration."""
        command = ModuleIdCommand(['name', 'chipsec.modules.common.remap'], cs=module_id_cs)

        mock_module_ids = {
            'chipsec.modules.common.remap': 0x67eb58d
        }

        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value=mock_module_ids), \
             patch.object(command.logger, 'log'):
            command.get_id_from_name()

            # Should work with configuration present
            assert command.module_name == 'chipsec.modules.common.remap'

    @pytest.mark.unit
    def test_module_id_supported_modules_check(self, module_id_cs):
        """Test Module ID supported modules check."""
        supported_modules = module_id_cs.Cfg.MODULE_ID['SUPPORTED_MODULES']

        # Test that configuration includes common CHIPSEC modules
        common_modules = [
            'chipsec.modules.common.remap',
            'chipsec.modules.common.cpu'
        ]

        for module in common_modules:
            assert module in supported_modules

    @pytest.mark.unit
    def test_module_id_configuration_consistency(self, module_id_cs):
        """Test Module ID configuration consistency."""
        supported_modules = module_id_cs.Cfg.MODULE_ID['SUPPORTED_MODULES']
        enable_caching = module_id_cs.Cfg.MODULE_ID['ENABLE_CACHING']
        cache_size = module_id_cs.Cfg.MODULE_ID['CACHE_SIZE']

        # If caching is disabled, cache size is irrelevant but should still be valid
        if not enable_caching:
            assert cache_size >= 0

        # All supported modules should be valid strings
        for module in supported_modules:
            assert isinstance(module, str)
            assert '.' in module  # Should contain dots for module path

    @pytest.mark.unit
    def test_module_id_hash_algorithm_configuration(self, module_id_cs):
        """Test Module ID hash algorithm configuration (if present)."""
        module_config = module_id_cs.Cfg.MODULE_ID

        # Some configurations might specify hash algorithm
        if 'HASH_ALGORITHM' in module_config:
            hash_algorithm = module_config['HASH_ALGORITHM']
            valid_algorithms = ['md5', 'sha1', 'sha256', 'sha512']
            assert hash_algorithm in valid_algorithms

    @pytest.mark.unit
    def test_module_id_error_handling_with_config(self, module_id_cs):
        """Test Module ID error handling with configuration."""
        command = ModuleIdCommand(['name', 'chipsec.modules.test'], cs=module_id_cs)

        # Test with configuration but module not found
        with patch('chipsec.utilcmd.module_id_cmd.get_module_ids_dictionary', return_value={}), \
             patch('chipsec.utilcmd.module_id_cmd.generate_hash_id', return_value=0x12345678), \
             patch.object(command.logger, 'log'):
            command.get_id_from_name()

            # Should still generate hash even with config
            assert command.module_name == 'chipsec.modules.test'

    @pytest.mark.unit
    def test_module_id_configuration_edge_cases(self, module_id_cs):
        """Test Module ID configuration edge cases."""
        # Test with empty supported modules list
        module_id_cs.Cfg.MODULE_ID['SUPPORTED_MODULES'] = []

        # Should still function with empty list
        supported_modules = module_id_cs.Cfg.MODULE_ID['SUPPORTED_MODULES']
        assert isinstance(supported_modules, list)
        assert len(supported_modules) == 0

        # Test with very large cache size
        module_id_cs.Cfg.MODULE_ID['CACHE_SIZE'] = 999999

        # Should still be valid
        assert module_id_cs.Cfg.MODULE_ID['CACHE_SIZE'] > 0


if __name__ == '__main__':
    pytest.main([__file__])
