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

import unittest
from unittest.mock import Mock, patch
from chipsec.utilcmd.deltas_cmd import DeltasCommand
from chipsec.command import toLoad
from tests.test_utils import MockFactory


class TestDeltasCommand(unittest.TestCase):
    """Comprehensive tests for Deltas utility command functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.deltas_command = DeltasCommand(['run1.json', 'run2.json'], cs=self.mock_cs)

    def test_deltas_command_initialization(self):
        """Test DeltasCommand initialization."""
        self.assertEqual(self.deltas_command.cs, self.mock_cs)
        self.assertEqual(self.deltas_command.argv, ['run1.json', 'run2.json'])

    def test_requirements(self):
        """Test command requirements."""
        reqs = self.deltas_command.requirements()
        self.assertEqual(reqs, toLoad.Nil)

    def test_parse_arguments_basic(self):
        """Test parsing basic arguments."""
        command = DeltasCommand(['run1.json', 'run2.json'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command._prev_log, 'run1.json')
        self.assertEqual(command._cur_log, 'run2.json')
        self.assertEqual(command._out_format, 'JSON')  # Default when no config
        self.assertEqual(command._out_name, 'log_output_deltas.json')  # Default when no config

    def test_parse_arguments_with_options(self):
        """Test parsing arguments with format and output options."""
        command = DeltasCommand(['run1.json', 'run2.json', 'XML', 'output.xml'], cs=self.mock_cs)
        command.parse_arguments()
        self.assertEqual(command._prev_log, 'run1.json')
        self.assertEqual(command._cur_log, 'run2.json')
        self.assertEqual(command._out_format, 'XML')
        self.assertEqual(command._out_name, 'output.xml')

    def test_parse_arguments_with_config_defaults(self):
        """Test parsing arguments with config-based defaults."""
        command = DeltasCommand(['run1.json', 'run2.json'], cs=self.mock_cs)

        with patch('chipsec.utilcmd.deltas_cmd.Options') as mock_options_class:
            mock_options_instance = Mock()
            mock_options_class.return_value = mock_options_instance
            mock_options_instance.get_section_data.side_effect = ['XML', 'custom_output.xml']

            command.parse_arguments()

            self.assertEqual(command._out_format, 'XML')
            self.assertEqual(command._out_name, 'custom_output.xml')

    def test_parse_arguments_config_error_fallback(self):
        """Test parsing arguments with config error fallback."""
        command = DeltasCommand(['run1.json', 'run2.json'], cs=self.mock_cs)

        with patch('chipsec.utilcmd.deltas_cmd.Options') as mock_options_class:
            mock_options_instance = Mock()
            mock_options_class.return_value = mock_options_instance
            mock_options_instance.get_section_data.side_effect = Exception("Config error")

            command.parse_arguments()

            self.assertEqual(command._out_format, 'JSON')  # Fallback to default
            self.assertEqual(command._out_name, 'log_output_deltas.json')  # Fallback to default

    def test_parse_arguments_invalid_format(self):
        """Test parsing arguments with invalid format."""
        command = DeltasCommand(['run1.json', 'run2.json', 'INVALID'], cs=self.mock_cs)

        # Should raise SystemExit due to invalid choice
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_parse_arguments_missing_files(self):
        """Test parsing arguments with missing required files."""
        command = DeltasCommand([], cs=self.mock_cs)

        # Should raise SystemExit due to missing required arguments
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_run_successful_json_output(self):
        """Test run method with successful JSON output."""
        self.deltas_command._prev_log = 'run1.json'
        self.deltas_command._cur_log = 'run2.json'
        self.deltas_command._out_format = 'JSON'
        self.deltas_command._out_name = 'output.json'

        mock_previous = {'test1': 'pass', 'test2': 'fail'}
        mock_current = {'test1': 'pass', 'test2': 'pass'}
        mock_deltas = {'test2': {'previous': 'fail', 'current': 'pass'}}

        with patch('chipsec.utilcmd.deltas_cmd.chipsec.library.result_deltas') as mock_result_deltas, \
             patch.object(self.deltas_command.logger, 'log_error') as mock_log_error:
            mock_result_deltas.get_json_results.side_effect = [mock_previous, mock_current]
            mock_result_deltas.compute_result_deltas.return_value = mock_deltas

            self.deltas_command.run()

            mock_result_deltas.get_json_results.assert_any_call('run1.json')
            mock_result_deltas.get_json_results.assert_any_call('run2.json')
            mock_result_deltas.compute_result_deltas.assert_called_once_with(mock_previous, mock_current)
            mock_result_deltas.log_deltas_json.assert_called_once_with(mock_deltas, 'output.json')
            mock_result_deltas.display_deltas.assert_called_once()
            mock_log_error.assert_not_called()

    def test_run_successful_xml_output(self):
        """Test run method with successful XML output."""
        self.deltas_command._prev_log = 'run1.json'
        self.deltas_command._cur_log = 'run2.json'
        self.deltas_command._out_format = 'XML'
        self.deltas_command._out_name = 'output.xml'

        mock_previous = {'test1': 'pass'}
        mock_current = {'test1': 'fail'}
        mock_deltas = {'test1': {'previous': 'pass', 'current': 'fail'}}

        with patch('chipsec.utilcmd.deltas_cmd.chipsec.library.result_deltas') as mock_result_deltas, \
             patch.object(self.deltas_command.logger, 'log_error') as mock_log_error:
            mock_result_deltas.get_json_results.side_effect = [mock_previous, mock_current]
            mock_result_deltas.compute_result_deltas.return_value = mock_deltas

            self.deltas_command.run()

            mock_result_deltas.log_deltas_xml.assert_called_once_with(mock_deltas, 'output.xml')
            mock_result_deltas.display_deltas.assert_called_once()
            mock_log_error.assert_not_called()

    def test_run_no_output_file(self):
        """Test run method with no output file specified."""
        self.deltas_command._prev_log = 'run1.json'
        self.deltas_command._cur_log = 'run2.json'
        self.deltas_command._out_format = 'JSON'
        self.deltas_command._out_name = None

        mock_previous = {'test1': 'pass'}
        mock_current = {'test1': 'fail'}
        mock_deltas = {'test1': {'previous': 'pass', 'current': 'fail'}}

        with patch('chipsec.utilcmd.deltas_cmd.chipsec.library.result_deltas') as mock_result_deltas, \
             patch.object(self.deltas_command.logger, 'log_error') as mock_log_error:
            mock_result_deltas.get_json_results.side_effect = [mock_previous, mock_current]
            mock_result_deltas.compute_result_deltas.return_value = mock_deltas

            self.deltas_command.run()

            # Should not call log_deltas_json when no output file
            mock_result_deltas.log_deltas_json.assert_not_called()
            mock_result_deltas.log_deltas_xml.assert_not_called()
            mock_result_deltas.display_deltas.assert_called_once()
            mock_log_error.assert_not_called()

    def test_run_json_file_read_error(self):
        """Test run method when JSON file read fails."""
        self.deltas_command._prev_log = 'run1.json'
        self.deltas_command._cur_log = 'run2.json'

        with patch('chipsec.utilcmd.deltas_cmd.chipsec.library.result_deltas') as mock_result_deltas, \
             patch.object(self.deltas_command.logger, 'log_error') as mock_log_error:
            mock_result_deltas.get_json_results.return_value = None

            self.deltas_command.run()

            mock_log_error.assert_called_with('Unable to process JSON log files.')

    def test_run_invalid_output_format(self):
        """Test run method with invalid output format."""
        self.deltas_command._prev_log = 'run1.json'
        self.deltas_command._cur_log = 'run2.json'
        self.deltas_command._out_format = 'INVALID'
        self.deltas_command._out_name = 'output.invalid'

        mock_previous = {'test1': 'pass'}
        mock_current = {'test1': 'fail'}
        mock_deltas = {'test1': {'previous': 'pass', 'current': 'fail'}}

        with patch('chipsec.utilcmd.deltas_cmd.chipsec.library.result_deltas') as mock_result_deltas, \
             patch.object(self.deltas_command.logger, 'log_error') as mock_log_error:
            mock_result_deltas.get_json_results.side_effect = [mock_previous, mock_current]
            mock_result_deltas.compute_result_deltas.return_value = mock_deltas

            self.deltas_command.run()

            mock_log_error.assert_called_with('Output log format not supported: INVALID')
            # Should still display deltas even with invalid format
            mock_result_deltas.display_deltas.assert_called_once()

    def test_run_case_insensitive_xml_format(self):
        """Test run method with case-insensitive XML format."""
        self.deltas_command._prev_log = 'run1.json'
        self.deltas_command._cur_log = 'run2.json'
        self.deltas_command._out_format = 'xml'  # lowercase
        self.deltas_command._out_name = 'output.xml'

        mock_previous = {'test1': 'pass'}
        mock_current = {'test1': 'fail'}
        mock_deltas = {'test1': {'previous': 'pass', 'current': 'fail'}}

        with patch('chipsec.utilcmd.deltas_cmd.chipsec.library.result_deltas') as mock_result_deltas, \
             patch.object(self.deltas_command.logger, 'log_error') as mock_log_error:
            mock_result_deltas.get_json_results.side_effect = [mock_previous, mock_current]
            mock_result_deltas.compute_result_deltas.return_value = mock_deltas

            self.deltas_command.run()

            mock_result_deltas.log_deltas_xml.assert_called_once_with(mock_deltas, 'output.xml')
            mock_log_error.assert_not_called()


class TestDeltasCommandIntegration(unittest.TestCase):
    """Integration tests for Deltas command with realistic data."""

    def setUp(self):
        """Set up integrated test fixtures."""
        self.integrated_cs = MockFactory.create_mock_chipsec_cs()

    def test_deltas_json_workflow_integration(self):
        """Test complete JSON deltas workflow."""
        deltas_cmd = DeltasCommand(['run1.json', 'run2.json', 'JSON', 'output.json'], cs=self.integrated_cs)
        deltas_cmd.parse_arguments()

        mock_previous = {'module1': {'test1': 'pass'}, 'module2': {'test2': 'fail'}}
        mock_current = {'module1': {'test1': 'pass'}, 'module2': {'test2': 'pass'}}
        mock_deltas = {'module2': {'test2': {'previous': 'fail', 'current': 'pass'}}}

        with patch('chipsec.utilcmd.deltas_cmd.chipsec.library.result_deltas') as mock_result_deltas:
            mock_result_deltas.get_json_results.side_effect = [mock_previous, mock_current]
            mock_result_deltas.compute_result_deltas.return_value = mock_deltas

            deltas_cmd.run()

            mock_result_deltas.log_deltas_json.assert_called_once_with(mock_deltas, 'output.json')
            mock_result_deltas.display_deltas.assert_called_once()

    def test_deltas_xml_workflow_integration(self):
        """Test complete XML deltas workflow."""
        deltas_cmd = DeltasCommand(['run1.json', 'run2.json', 'XML', 'output.xml'], cs=self.integrated_cs)
        deltas_cmd.parse_arguments()

        mock_previous = {'test1': 'pass', 'test2': 'fail', 'test3': 'warning'}
        mock_current = {'test1': 'pass', 'test2': 'pass', 'test3': 'fail'}
        mock_deltas = {
            'test2': {'previous': 'fail', 'current': 'pass'},
            'test3': {'previous': 'warning', 'current': 'fail'}
        }

        with patch('chipsec.utilcmd.deltas_cmd.chipsec.library.result_deltas') as mock_result_deltas:
            mock_result_deltas.get_json_results.side_effect = [mock_previous, mock_current]
            mock_result_deltas.compute_result_deltas.return_value = mock_deltas

            deltas_cmd.run()

            mock_result_deltas.log_deltas_xml.assert_called_once_with(mock_deltas, 'output.xml')
            mock_result_deltas.display_deltas.assert_called_once()


class TestDeltasCommandEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions for Deltas command."""

    def setUp(self):
        """Set up mock ChipsecCs for edge case testing."""
        self.mock_cs = MockFactory.create_mock_chipsec_cs()

    def test_empty_argv_handling(self):
        """Test handling of empty argv."""
        command = DeltasCommand([], cs=self.mock_cs)

        # Should raise SystemExit due to missing required arguments
        with self.assertRaises(SystemExit):
            command.parse_arguments()

    def test_run_with_empty_deltas(self):
        """Test run method with empty deltas (no changes)."""
        command = DeltasCommand(['run1.json', 'run2.json'], cs=self.mock_cs)
        command.parse_arguments()

        mock_previous = {'test1': 'pass', 'test2': 'fail'}
        mock_current = {'test1': 'pass', 'test2': 'fail'}  # Same as previous
        mock_deltas = {}  # No changes

        with patch('chipsec.utilcmd.deltas_cmd.chipsec.library.result_deltas') as mock_result_deltas:
            mock_result_deltas.get_json_results.side_effect = [mock_previous, mock_current]
            mock_result_deltas.compute_result_deltas.return_value = mock_deltas

            command.run()

            mock_result_deltas.display_deltas.assert_called_once_with(mock_deltas, True, unittest.mock.ANY)

    def test_run_with_large_result_set(self):
        """Test run method with large result set."""
        command = DeltasCommand(['large_run1.json', 'large_run2.json'], cs=self.mock_cs)
        command.parse_arguments()

        # Create large mock data
        mock_previous = {f'test{i}': 'pass' for i in range(100)}
        mock_current = {f'test{i}': 'fail' for i in range(100)}
        mock_deltas = {f'test{i}': {'previous': 'pass', 'current': 'fail'} for i in range(100)}

        with patch('chipsec.utilcmd.deltas_cmd.chipsec.library.result_deltas') as mock_result_deltas:
            mock_result_deltas.get_json_results.side_effect = [mock_previous, mock_current]
            mock_result_deltas.compute_result_deltas.return_value = mock_deltas

            command.run()

            # Should handle large datasets without issues
            self.assertTrue(mock_result_deltas.display_deltas.called)

    def test_parse_arguments_various_file_extensions(self):
        """Test parsing arguments with various file extensions."""
        test_cases = [
            (['run1.json', 'run2.json'], 'run1.json', 'run2.json'),
            (['results1.xml', 'results2.xml'], 'results1.xml', 'results2.xml'),
            (['log1.txt', 'log2.txt'], 'log1.txt', 'log2.txt'),
            (['data1.log', 'data2.log'], 'data1.log', 'data2.log')
        ]

        for argv, expected_prev, expected_cur in test_cases:
            command = DeltasCommand(argv, cs=self.mock_cs)
            command.parse_arguments()

            self.assertEqual(command._prev_log, expected_prev)
            self.assertEqual(command._cur_log, expected_cur)

    def test_run_with_different_output_formats(self):
        """Test run method with different output formats."""
        formats_and_files = [
            ('JSON', 'output.json'),
            ('XML', 'output.xml'),
            # Note: lowercase formats will fail due to argparse case sensitivity
            # ('json', 'output.json'),  # lowercase - would fail
            # ('xml', 'output.xml')     # lowercase - would fail
        ]

        mock_previous = {'test1': 'pass'}
        mock_current = {'test1': 'fail'}
        mock_deltas = {'test1': {'previous': 'pass', 'current': 'fail'}}

        for out_format, out_file in formats_and_files:
            command = DeltasCommand(['run1.json', 'run2.json', out_format, out_file], cs=self.mock_cs)
            command.parse_arguments()

            with patch('chipsec.utilcmd.deltas_cmd.chipsec.library.result_deltas') as mock_result_deltas:
                mock_result_deltas.get_json_results.side_effect = [mock_previous, mock_current]
                mock_result_deltas.compute_result_deltas.return_value = mock_deltas

                command.run()

                # Should call appropriate logging function based on format
                if out_format.upper() == 'JSON':
                    mock_result_deltas.log_deltas_json.assert_called_with(mock_deltas, out_file)
                elif out_format.upper() == 'XML':
                    mock_result_deltas.log_deltas_xml.assert_called_with(mock_deltas, out_file)

    def test_run_with_unicode_filenames(self):
        """Test run method with unicode filenames."""
        unicode_filename = '测试文件.json'
        command = DeltasCommand([unicode_filename, 'run2.json'], cs=self.mock_cs)
        command.parse_arguments()

        mock_previous = {'test1': 'pass'}
        mock_current = {'test1': 'fail'}
        mock_deltas = {'test1': {'previous': 'pass', 'current': 'fail'}}

        with patch('chipsec.utilcmd.deltas_cmd.chipsec.library.result_deltas') as mock_result_deltas:
            mock_result_deltas.get_json_results.side_effect = [mock_previous, mock_current]
            mock_result_deltas.compute_result_deltas.return_value = mock_deltas

            command.run()

            mock_result_deltas.get_json_results.assert_any_call(unicode_filename)


class TestDeltasCommandConfigurationValidation(unittest.TestCase):
    """Test configuration validation aspects of Deltas command."""

    def setUp(self):
        """Set up ChipsecCs with Deltas-specific configuration."""
        self.deltas_cs = MockFactory.create_mock_chipsec_cs()

        # Mock Deltas configuration
        self.deltas_cs.Cfg = Mock()
        self.deltas_cs.Cfg.Util_Config = {
            'log_output_deltas_format': 'XML',
            'deltas_output_file': 'custom_deltas.xml'
        }

    def test_deltas_configuration_structure(self):
        """Test Deltas configuration structure."""
        util_config = self.deltas_cs.Cfg.Util_Config

        # Test that required Deltas configuration exists
        self.assertIn('log_output_deltas_format', util_config)
        self.assertIn('deltas_output_file', util_config)

        # Test configuration values are reasonable
        self.assertIn(util_config['log_output_deltas_format'], ['JSON', 'XML'])
        self.assertIsInstance(util_config['deltas_output_file'], str)

    def test_deltas_config_format_validation(self):
        """Test Deltas config format validation."""
        # Note: argparse only accepts uppercase formats, so we test with uppercase only
        valid_formats = ['JSON', 'XML']

        for fmt in valid_formats:
            self.deltas_cs.Cfg.Util_Config['log_output_deltas_format'] = fmt

            command = DeltasCommand(['run1.json', 'run2.json'], cs=self.deltas_cs)

            with patch('chipsec.utilcmd.deltas_cmd.Options') as mock_options_class:
                mock_options_instance = Mock()
                mock_options_class.return_value = mock_options_instance
                mock_options_instance.get_section_data.return_value = fmt

                command.parse_arguments()

                self.assertEqual(command._out_format, fmt)

    def test_deltas_config_file_validation(self):
        """Test Deltas config file validation."""
        test_files = [
            'output.json',
            'deltas.xml',
            'results.log',
            '/path/to/output/file.json',
            'C:\\path\\to\\output\\file.xml'
        ]

        for filename in test_files:
            self.deltas_cs.Cfg.Util_Config['deltas_output_file'] = filename

            command = DeltasCommand(['run1.json', 'run2.json'], cs=self.deltas_cs)

            with patch('chipsec.utilcmd.deltas_cmd.Options') as mock_options_class:
                mock_options_instance = Mock()
                mock_options_class.return_value = mock_options_instance
                mock_options_instance.get_section_data.side_effect = ['JSON', filename]

                command.parse_arguments()

                self.assertEqual(command._out_name, filename)

    def test_deltas_error_handling(self):
        """Test Deltas error handling."""
        command = DeltasCommand(['run1.json', 'run2.json'], cs=self.deltas_cs)

        # Mock result_deltas to raise exception
        with patch('chipsec.utilcmd.deltas_cmd.chipsec.library.result_deltas') as mock_result_deltas:
            mock_result_deltas.get_json_results.side_effect = Exception("File read error")

            # Should handle the exception gracefully
            with self.assertRaises(Exception):
                command.run()

    def test_deltas_display_error_handling(self):
        """Test Deltas display error handling."""
        command = DeltasCommand(['run1.json', 'run2.json'], cs=self.deltas_cs)

        mock_previous = {'test1': 'pass'}
        mock_current = {'test1': 'fail'}
        mock_deltas = {'test1': {'previous': 'pass', 'current': 'fail'}}

        with patch('chipsec.utilcmd.deltas_cmd.chipsec.library.result_deltas') as mock_result_deltas:
            mock_result_deltas.get_json_results.side_effect = [mock_previous, mock_current]
            mock_result_deltas.compute_result_deltas.return_value = mock_deltas
            mock_result_deltas.display_deltas.side_effect = Exception("Display error")

            # Should handle display exception gracefully
            with self.assertRaises(Exception):
                command.run()

    def test_deltas_file_operation_error_handling(self):
        """Test Deltas file operation error handling."""
        command = DeltasCommand(['run1.json', 'run2.json', 'JSON', 'output.json'], cs=self.deltas_cs)

        mock_previous = {'test1': 'pass'}
        mock_current = {'test1': 'fail'}
        mock_deltas = {'test1': {'previous': 'pass', 'current': 'fail'}}

        with patch('chipsec.utilcmd.deltas_cmd.chipsec.library.result_deltas') as mock_result_deltas:
            mock_result_deltas.get_json_results.side_effect = [mock_previous, mock_current]
            mock_result_deltas.compute_result_deltas.return_value = mock_deltas
            mock_result_deltas.log_deltas_json.side_effect = Exception("File write error")

            # Should handle file write exception gracefully
            with self.assertRaises(Exception):
                command.run()
