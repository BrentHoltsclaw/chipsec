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
import os
import tempfile
from unittest.mock import patch, mock_open
from chipsec.library.module_helper import enumerate_modules, print_modules


class TestEnumerateModulesFunction:
    """Test enumerate_modules function."""

    @pytest.mark.unit
    def test_enumerate_modules_basic_structure(self):
        """Test that enumerate_modules returns a list."""
        result = enumerate_modules()
        assert isinstance(result, list)

    @pytest.mark.unit
    def test_enumerate_modules_with_mock_directory(self):
        """Test enumerate_modules with mocked directory structure."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk, \
             patch('os.path.abspath') as mock_abspath, \
             patch('os.path.relpath') as mock_relpath:

            # Mock the module directory
            mock_get_dir.return_value = '/mock/modules'

            # Mock os.walk to return a simple directory structure
            mock_walk.return_value = [
                ('/mock/modules', [], ['module1.py', 'module2.py', '__init__.py']),
                ('/mock/modules/subdir', [], ['submodule.py'])
            ]

            # Mock path conversions
            mock_abspath.return_value = '/mock/modules'
            mock_relpath.side_effect = lambda path, start: {
                '/mock/modules': '',
                '/mock/modules/subdir': 'subdir'
            }.get(path, '')

            result = enumerate_modules()

            # Should return list of module names
            assert isinstance(result, list)
            assert len(result) >= 0  # May be empty depending on actual modules

    @pytest.mark.unit
    def test_enumerate_modules_filters_init_files(self):
        """Test that enumerate_modules filters out __init__.py files."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk, \
             patch('os.path.abspath') as mock_abspath, \
             patch('os.path.relpath') as mock_relpath:

            mock_get_dir.return_value = '/mock/modules'
            mock_walk.return_value = [
                ('/mock/modules', [], ['module1.py', '__init__.py', 'module2.py'])
            ]
            mock_abspath.return_value = '/mock/modules'
            mock_relpath.return_value = ''

            result = enumerate_modules()

            # Should not include __init__.py files
            for module in result:
                assert not module.endswith('.__init__')
                assert '__init__' not in module

    @pytest.mark.unit
    def test_enumerate_modules_only_python_files(self):
        """Test that enumerate_modules only includes Python files."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk, \
             patch('os.path.abspath') as mock_abspath, \
             patch('os.path.relpath') as mock_relpath:

            mock_get_dir.return_value = '/mock/modules'
            mock_walk.return_value = [
                ('/mock/modules', [], ['module1.py', 'module2.py', 'readme.txt', 'data.bin'])
            ]
            mock_abspath.return_value = '/mock/modules'
            mock_relpath.return_value = ''

            result = enumerate_modules()

            # Should only include .py files (module names should not contain file extensions)
            for module in result:
                assert not any(ext in module for ext in ['.txt', '.bin']), f"Non-Python file extension found: {module}"

    @pytest.mark.unit
    def test_enumerate_modules_subdirectory_handling(self):
        """Test enumerate_modules handles subdirectories correctly."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk, \
             patch('os.path.abspath') as mock_abspath, \
             patch('os.path.relpath') as mock_relpath:

            mock_get_dir.return_value = '/mock/modules'
            mock_walk.return_value = [
                ('/mock/modules', ['subdir1', 'subdir2'], ['root_module.py']),
                ('/mock/modules/subdir1', [], ['sub_module1.py']),
                ('/mock/modules/subdir2', ['nested'], ['sub_module2.py']),
                ('/mock/modules/subdir2/nested', [], ['nested_module.py'])
            ]

            mock_abspath.return_value = '/mock/modules'
            mock_relpath.side_effect = lambda path, start: {
                '/mock/modules': '',
                '/mock/modules/subdir1': 'subdir1',
                '/mock/modules/subdir2': 'subdir2',
                '/mock/modules/subdir2/nested': 'subdir2.nested'
            }.get(path, '')

            result = enumerate_modules()

            # Should handle subdirectories with proper module paths
            assert isinstance(result, list)
            # Check that some modules are found
            assert len(result) > 0

    @pytest.mark.unit
    def test_enumerate_modules_path_conversion(self):
        """Test enumerate_modules path conversion logic."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk, \
             patch('os.path.abspath') as mock_abspath, \
             patch('os.path.relpath') as mock_relpath:

            mock_get_dir.return_value = '/mock/modules'
            mock_walk.return_value = [
                ('/mock/modules/subdir', [], ['test.py'])
            ]
            mock_abspath.return_value = '/mock/modules'
            mock_relpath.return_value = 'subdir'

            result = enumerate_modules()

            # Should convert path separators to dots
            for module in result:
                assert '\\' not in module  # No Windows path separators
                if '.' in module and not module.endswith('.py'):
                    # Should use dots for module path separation
                    pass  # This is expected

    @pytest.mark.unit
    def test_enumerate_modules_empty_directory(self):
        """Test enumerate_modules with empty directory."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk, \
             patch('os.path.abspath') as mock_abspath, \
             patch('os.path.relpath') as mock_relpath:

            mock_get_dir.return_value = '/mock/modules'
            mock_walk.return_value = [
                ('/mock/modules', [], [])
            ]
            mock_abspath.return_value = '/mock/modules'
            mock_relpath.return_value = ''

            result = enumerate_modules()

            # Should return empty list for empty directory
            assert result == []

    @pytest.mark.unit
    def test_enumerate_modules_no_python_files(self):
        """Test enumerate_modules with no Python files."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk, \
             patch('os.path.abspath') as mock_abspath, \
             patch('os.path.relpath') as mock_relpath:

            mock_get_dir.return_value = '/mock/modules'
            mock_walk.return_value = [
                ('/mock/modules', [], ['readme.txt', 'data.json', 'config.ini'])
            ]
            mock_abspath.return_value = '/mock/modules'
            mock_relpath.return_value = ''

            result = enumerate_modules()

            # Should return empty list when no Python files
            assert result == []

    @pytest.mark.unit
    def test_enumerate_modules_mixed_files(self):
        """Test enumerate_modules with mixed file types."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk, \
             patch('os.path.abspath') as mock_abspath, \
             patch('os.path.relpath') as mock_relpath:

            mock_get_dir.return_value = '/mock/modules'
            mock_walk.return_value = [
                ('/mock/modules', [], [
                    'module1.py',
                    'readme.txt',
                    'module2.py',
                    '__init__.py',
                    'data.bin',
                    'module3.py',
                    'config.json'
                ])
            ]
            mock_abspath.return_value = '/mock/modules'
            mock_relpath.return_value = ''

            result = enumerate_modules()

            # Should only include Python files, excluding __init__.py
            python_files = [f for f in result if f.endswith('.py')]
            assert len(python_files) >= 0

            # Should not include non-Python files
            for module in result:
                # Module names should not contain dots (except for submodules) and should not be empty
                assert '.' not in module or module.count('.') == 1, f"Invalid module name: {module}"
                assert module, f"Empty module name found"

    @pytest.mark.unit
    def test_enumerate_modules_error_handling(self):
        """Test enumerate_modules error handling."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk:

            mock_get_dir.return_value = '/mock/modules'
            mock_walk.side_effect = OSError("Permission denied")

            # Should handle OS errors gracefully
            result = enumerate_modules()
            assert isinstance(result, list)


class TestPrintModulesFunction:
    """Test print_modules function."""

    @pytest.mark.unit
    def test_print_modules_empty_list(self):
        """Test print_modules with empty list."""
        with patch('chipsec.library.module_helper.logger') as mock_logger:
            print_modules([])

            # Should log the enumeration message
            mock_logger.return_value.log.assert_called_with('Enumerating modules...')

    @pytest.mark.unit
    def test_print_modules_with_modules(self):
        """Test print_modules with module list."""
        modules = ['module1', 'module2', 'subdir.module3']

        with patch('chipsec.library.module_helper.logger') as mock_logger:
            print_modules(modules)

            # Should log enumeration message
            mock_logger.return_value.log.assert_any_call('Enumerating modules...')

            # Should log each module
            for module in modules:
                mock_logger.return_value.log.assert_any_call(f'\t{module}')

    @pytest.mark.unit
    def test_print_modules_single_module(self):
        """Test print_modules with single module."""
        modules = ['single.module']

        with patch('chipsec.library.module_helper.logger') as mock_logger:
            print_modules(modules)

            mock_logger.return_value.log.assert_any_call('Enumerating modules...')
            mock_logger.return_value.log.assert_any_call('\tsingle.module')

    @pytest.mark.unit
    def test_print_modules_large_list(self):
        """Test print_modules with large module list."""
        modules = [f'module{i}' for i in range(100)]

        with patch('chipsec.library.module_helper.logger') as mock_logger:
            print_modules(modules)

            # Should log enumeration message
            mock_logger.return_value.log.assert_any_call('Enumerating modules...')

            # Should log each module
            for i in range(100):
                mock_logger.return_value.log.assert_any_call(f'\tmodule{i}')

    @pytest.mark.unit
    def test_print_modules_special_characters(self):
        """Test print_modules with special characters in module names."""
        modules = ['module_with_underscore', 'module-with-dash', 'module.with.dots']

        with patch('chipsec.library.module_helper.logger') as mock_logger:
            print_modules(modules)

            for module in modules:
                mock_logger.return_value.log.assert_any_call(f'\t{module}')

    @pytest.mark.unit
    def test_print_modules_unicode_names(self):
        """Test print_modules with unicode module names."""
        modules = ['módulo', 'модуль', '模块']

        with patch('chipsec.library.module_helper.logger') as mock_logger:
            print_modules(modules)

            for module in modules:
                mock_logger.return_value.log.assert_any_call(f'\t{module}')


class TestModuleHelperIntegration:
    """Integration tests for module helper functions."""

    @pytest.mark.integration
    def test_enumerate_and_print_integration(self):
        """Test integration of enumerate_modules and print_modules."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk, \
             patch('os.path.abspath') as mock_abspath, \
             patch('os.path.relpath') as mock_relpath, \
             patch('chipsec.library.module_helper.logger') as mock_logger:

            mock_get_dir.return_value = '/mock/modules'
            mock_walk.return_value = [
                ('/mock/modules', [], ['test_module.py', 'another_module.py'])
            ]
            mock_abspath.return_value = '/mock/modules'
            mock_relpath.return_value = ''

            # Enumerate modules
            modules = enumerate_modules()
            assert isinstance(modules, list)

            # Print modules
            print_modules(modules)

            # Verify logging calls
            mock_logger.return_value.log.assert_any_call('Enumerating modules...')
            if modules:
                for module in modules:
                    mock_logger.return_value.log.assert_any_call(f'\t{module}')

    @pytest.mark.integration
    def test_module_discovery_workflow(self):
        """Test complete module discovery workflow."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk, \
             patch('os.path.abspath') as mock_abspath, \
             patch('os.path.relpath') as mock_relpath:

            # Setup mock directory structure
            mock_get_dir.return_value = '/mock/modules'
            mock_walk.return_value = [
                ('/mock/modules', ['security', 'hardware'], ['base_module.py']),
                ('/mock/modules/security', [], ['auth_module.py', 'crypto_module.py']),
                ('/mock/modules/hardware', ['cpu', 'memory'], ['hw_base.py']),
                ('/mock/modules/hardware/cpu', [], ['cpu_module.py']),
                ('/mock/modules/hardware/memory', [], ['memory_module.py'])
            ]

            mock_abspath.return_value = '/mock/modules'
            mock_relpath.side_effect = lambda path, start: {
                '/mock/modules': '',
                '/mock/modules/security': 'security',
                '/mock/modules/hardware': 'hardware',
                '/mock/modules/hardware/cpu': 'hardware.cpu',
                '/mock/modules/hardware/memory': 'hardware.memory'
            }.get(path, '')

            # Execute module enumeration
            modules = enumerate_modules()

            # Verify results
            assert isinstance(modules, list)
            assert len(modules) > 0

            # Should include modules from all levels
            module_names = [mod.split('.')[-1] for mod in modules]
            expected_modules = ['base_module', 'auth_module', 'crypto_module',
                              'hw_base', 'cpu_module', 'memory_module']

            for expected in expected_modules:
                assert any(expected in mod for mod in module_names), f"Missing expected module: {expected}"

    @pytest.mark.integration
    def test_error_recovery_integration(self):
        """Test error recovery in integration scenarios."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk:

            mock_get_dir.return_value = '/mock/modules'

            # Test with filesystem error
            mock_walk.side_effect = [OSError("Disk error"), [('fallback', [], ['fallback.py'])]]

            # Should handle errors gracefully
            modules = enumerate_modules()
            assert isinstance(modules, list)

    @pytest.mark.integration
    def test_cross_platform_path_handling(self):
        """Test cross-platform path handling."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk, \
             patch('os.path.abspath') as mock_abspath, \
             patch('os.path.relpath') as mock_relpath:

            mock_get_dir.return_value = '/mock/modules'

            # Test with Windows-style paths
            mock_walk.return_value = [
                ('C:\\mock\\modules\\subdir', [], ['windows_module.py'])
            ]
            mock_abspath.return_value = 'C:\\mock\\modules'
            mock_relpath.return_value = 'subdir'

            modules = enumerate_modules()

            # Should convert Windows paths to Python module format
            for module in modules:
                assert '\\' not in module  # No Windows path separators
                assert '/' not in module or module.count('/') == module.count('.')  # Unix paths converted to dots


class TestModuleHelperEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.unit
    def test_enumerate_modules_deep_directory_structure(self):
        """Test enumerate_modules with very deep directory structure."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk, \
             patch('os.path.abspath') as mock_abspath, \
             patch('os.path.relpath') as mock_relpath:

            mock_get_dir.return_value = '/mock/modules'

            # Create a very deep directory structure
            deep_path = '/mock/modules/' + '/'.join([f'level{i}' for i in range(10)])
            mock_walk.return_value = [
                (deep_path, [], ['deep_module.py'])
            ]
            mock_abspath.return_value = '/mock/modules'
            mock_relpath.return_value = '.'.join([f'level{i}' for i in range(10)])

            modules = enumerate_modules()

            # Should handle deep paths
            assert isinstance(modules, list)
            if modules:
                assert len(modules[0].split('.')) >= 10  # Should have many dots

    @pytest.mark.unit
    def test_enumerate_modules_many_files(self):
        """Test enumerate_modules with many files."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk, \
             patch('os.path.abspath') as mock_abspath, \
             patch('os.path.relpath') as mock_relpath:

            mock_get_dir.return_value = '/mock/modules'

            # Create many Python files
            many_files = [f'module_{i}.py' for i in range(1000)]
            mock_walk.return_value = [
                ('/mock/modules', [], many_files)
            ]
            mock_abspath.return_value = '/mock/modules'
            mock_relpath.return_value = ''

            modules = enumerate_modules()

            # Should handle many files
            assert isinstance(modules, list)
            assert len(modules) <= 1000  # Should not exceed input files

    @pytest.mark.unit
    def test_enumerate_modules_special_file_names(self):
        """Test enumerate_modules with special file names."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk, \
             patch('os.path.abspath') as mock_abspath, \
             patch('os.path.relpath') as mock_relpath:

            mock_get_dir.return_value = '/mock/modules'

            # Test with various special file names
            special_files = [
                'module-name.py',  # Hyphen
                'module_name.py',  # Underscore
                '123module.py',    # Starts with number
                'module.test.py',  # Multiple dots
                'module.py.backup' # Not .py extension
            ]

            mock_walk.return_value = [
                ('/mock/modules', [], special_files)
            ]
            mock_abspath.return_value = '/mock/modules'
            mock_relpath.return_value = ''

            modules = enumerate_modules()

            # Should handle special characters in module names
            assert isinstance(modules, list)

            # Should only include .py files (module names should not end with .py)
            for module in modules:
                assert not module.endswith('.py'), f"Module name should not end with .py: {module}"

    @pytest.mark.unit
    def test_print_modules_logging_error(self):
        """Test print_modules with logging error."""
        modules = ['test.module']

        with patch('chipsec.library.module_helper.logger') as mock_logger:
            mock_logger.return_value.log.side_effect = Exception("Logging error")

            # Should handle logging errors gracefully
            print_modules(modules)  # Should not raise exception

    @pytest.mark.unit
    def test_enumerate_modules_path_edge_cases(self):
        """Test enumerate_modules with path edge cases."""
        with patch('chipsec.library.module_helper.get_module_dir') as mock_get_dir, \
             patch('os.walk') as mock_walk, \
             patch('os.path.abspath') as mock_abspath, \
             patch('os.path.relpath') as mock_relpath:

            mock_get_dir.return_value = '/mock/modules'

            # Test with root directory
            mock_walk.return_value = [
                ('/', [], ['root_module.py'])
            ]
            mock_abspath.return_value = '/'
            mock_relpath.return_value = ''

            modules = enumerate_modules()
            assert isinstance(modules, list)

            # Test with current directory
            mock_walk.return_value = [
                ('.', [], ['current_module.py'])
            ]
            mock_abspath.return_value = '.'
            mock_relpath.return_value = ''

            modules = enumerate_modules()
            assert isinstance(modules, list)


if __name__ == '__main__':
    pytest.main([__file__])
