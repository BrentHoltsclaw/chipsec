#!/usr/bin/env python3
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

"""
CHIPSEC Test Runner

Comprehensive test execution framework for CHIPSEC components.
Supports unit tests, integration tests, and performance benchmarks.
"""

import sys
import os
import time
import argparse
import unittest
from typing import Dict, List, Any
import importlib.util


class TestRunner:
    """CHIPSEC Test Runner for comprehensive test execution."""

    def discover_tests(self, test_path: str = "tests") -> List[str]:
        """Discover all test files in the test directory."""
        test_files = []

        if not os.path.exists(test_path):
            print(f"Test path {test_path} does not exist")
            return test_files

        for root, dirs, files in os.walk(test_path):
            for file in files:
                if file.startswith("test_") and file.endswith(".py"):
                    # Convert path to module format
                    rel_path = os.path.relpath(os.path.join(root, file), test_path)
                    module_path = rel_path.replace(os.sep, ".").replace(".py", "")
                    test_files.append(f"{test_path}.{module_path}")

        return sorted(test_files)

    def run_test_module(self, module_name: str) -> Dict[str, Any]:
        """Run a specific test module and return results."""
        try:
            # Import the test module
            spec = importlib.util.find_spec(module_name)
            if spec is None:
                return {"status": "error", "message": f"Module {module_name} not found"}

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Discover test classes and methods
            test_classes = []
            for name in dir(module):
                obj = getattr(module, name)
                if isinstance(obj, type) and name.startswith("Test"):
                    test_classes.append(obj)

            if not test_classes:
                return {"status": "error", "message": f"No test classes found in {module_name}"}

            # Run tests using unittest with proper test discovery
            loader = unittest.TestLoader()
            suite = unittest.TestSuite()

            for test_class in test_classes:
                try:
                    suite.addTests(loader.loadTestsFromTestCase(test_class))
                except Exception:
                    # If unittest fails, try to run pytest-style tests
                    return self.run_pytest_module(module_name)

            if suite.countTestCases() == 0:
                # No unittest tests found, try pytest
                return self.run_pytest_module(module_name)

            runner = unittest.TextTestRunner(verbosity=0, stream=open(os.devnull, 'w'))
            result = runner.run(suite)

            return {
                "status": "success",
                "tests_run": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skipped": len(result.skipped),
                "time": 0.0
            }

        except Exception as e:
            return {"status": "error", "message": str(e)}

    def run_pytest_module(self, module_name: str) -> Dict[str, Any]:
        """Run a test module using pytest if unittest fails."""
        try:
            import subprocess
            import sys

            # Convert module name to file path
            file_path = module_name.replace(".", "/") + ".py"

            # Run pytest on the specific file
            result = subprocess.run([
                sys.executable, "-m", "pytest", file_path,
                "-v", "--tb=short", "--disable-warnings"
            ], capture_output=True, text=True, cwd=os.getcwd())

            # Parse pytest output
            tests_run = 0
            failures = 0
            errors = 0
            passed = 0

            for line in result.stdout.split('\n'):
                if '::' in line and 'PASSED' in line:
                    passed += 1
                    tests_run += 1
                elif '::' in line and 'FAILED' in line:
                    failures += 1
                    tests_run += 1
                elif '::' in line and 'ERROR' in line:
                    errors += 1
                    tests_run += 1

            return {
                "status": "success",
                "tests_run": tests_run,
                "failures": failures,
                "errors": errors,
                "skipped": 0,
                "time": 0.0
            }

        except Exception as e:
            return {"status": "error", "message": f"Pytest execution failed: {str(e)}"}

    def run_all_tests(self, test_path: str = "tests") -> Dict[str, Any]:
        """Run all discovered tests and return comprehensive results."""
        self.start_time = time.time()

        test_modules = self.discover_tests(test_path)
        results = {}

        print(f"Discovered {len(test_modules)} test modules")
        print("=" * 60)

        total_tests = 0
        total_failures = 0
        total_errors = 0
        total_skipped = 0

        for i, module_name in enumerate(test_modules, 1):
            print(f"[{i:2d}/{len(test_modules):2d}] Running {module_name}...")
            result = self.run_test_module(module_name)
            results[module_name] = result

            if result["status"] == "success":
                tests = result["tests_run"]
                failures = result["failures"]
                errors = result["errors"]
                skipped = result["skipped"]

                total_tests += tests
                total_failures += failures
                total_errors += errors
                total_skipped += skipped

                status = "✓" if failures == 0 and errors == 0 else "✗"
                print(f"[{i:2d}/{len(test_modules):2d}] {status} {tests:3d} tests, {failures:2d} failures, {errors:2d} errors")
            else:
                print(f"[{i:2d}/{len(test_modules):2d}] ✗ Error: {result['message']}")

        self.end_time = time.time()
        execution_time = self.end_time - self.start_time

        # Summary
        print("\n" + "=" * 60)
        print("TEST EXECUTION SUMMARY")
        print("=" * 60)
        print(f"Total Test Modules: {len(test_modules)}")
        print(f"Total Tests Run: {total_tests}")
        print(f"Total Failures: {total_failures}")
        print(f"Total Errors: {total_errors}")
        print(f"Total Skipped: {total_skipped}")
        print(f"Execution Time: {execution_time:.2f}s")
        print(f"Success Rate: {((total_tests - total_failures - total_errors) / max(total_tests, 1)) * 100:.1f}%")

        return {
            "summary": {
                "modules": len(test_modules),
                "tests": total_tests,
                "failures": total_failures,
                "errors": total_errors,
                "skipped": total_skipped,
                "execution_time": execution_time,
                "success_rate": ((total_tests - total_failures - total_errors) / max(total_tests, 1)) * 100
            },
            "results": results
        }

    def run_specific_tests(self, test_names: List[str]) -> Dict[str, Any]:
        """Run specific test modules by name."""
        results = {}

        for test_name in test_names:
            print(f"Running {test_name}...")
            result = self.run_test_module(test_name)
            results[test_name] = result

            if result["status"] == "success":
                print(f"  ✓ {result['tests_run']} tests, {result['failures']} failures, {result['errors']} errors")
            else:
                print(f"  ✗ {result['message']}")

        return results

    def generate_report(self, results: Dict[str, Any], output_file: str = "test_report.html"):
        """Generate HTML report of test results."""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CHIPSEC Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .summary {{ background: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .module {{ margin-bottom: 10px; padding: 10px; border: 1px solid #ddd; border-radius: 3px; }}
        .success {{ background: #d4edda; border-color: #c3e6cb; }}
        .failure {{ background: #f8d7da; border-color: #f5c6cb; }}
        .error {{ background: #fff3cd; border-color: #ffeaa7; }}
        h1, h2 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>CHIPSEC Test Execution Report</h1>

    <div class="summary">
        <h2>Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Test Modules</td><td>{results['summary']['modules']}</td></tr>
            <tr><td>Total Tests</td><td>{results['summary']['tests']}</td></tr>
            <tr><td>Failures</td><td>{results['summary']['failures']}</td></tr>
            <tr><td>Errors</td><td>{results['summary']['errors']}</td></tr>
            <tr><td>Skipped</td><td>{results['summary']['skipped']}</td></tr>
            <tr><td>Execution Time</td><td>{results['summary']['execution_time']:.2f}s</td></tr>
            <tr><td>Success Rate</td><td>{results['summary']['success_rate']:.1f}%</td></tr>
        </table>
    </div>

    <h2>Detailed Results</h2>
"""

        for module_name, result in results["results"].items():
            css_class = "success"
            if result["status"] != "success":
                css_class = "error"
            elif result.get("failures", 0) > 0 or result.get("errors", 0) > 0:
                css_class = "failure"

            html_content += f"""
    <div class="module {css_class}">
        <h3>{module_name}</h3>
        <p>Status: {result['status']}</p>
"""

            if result["status"] == "success":
                html_content += f"""
        <ul>
            <li>Tests Run: {result['tests_run']}</li>
            <li>Failures: {result['failures']}</li>
            <li>Errors: {result['errors']}</li>
            <li>Skipped: {result['skipped']}</li>
        </ul>
"""
            else:
                html_content += f"<p>Error: {result['message']}</p>"

            html_content += "</div>"

        html_content += """
</body>
</html>
"""

        with open(output_file, 'w') as f:
            f.write(html_content)

        print(f"Report generated: {output_file}")


def main():
    """Main entry point for the test runner."""
    parser = argparse.ArgumentParser(description="CHIPSEC Test Runner")
    parser.add_argument("--test-path", default="tests", help="Path to test directory")
    parser.add_argument("--specific", nargs="*", help="Run specific test modules")
    parser.add_argument("--report", help="Generate HTML report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Add current directory to Python path
    sys.path.insert(0, os.getcwd())

    runner = TestRunner()

    if args.specific:
        results = runner.run_specific_tests(args.specific)
    else:
        results = runner.run_all_tests(args.test_path)

    if args.report:
        runner.generate_report(results, args.report)

    # Exit with appropriate code
    if "summary" in results:
        summary = results["summary"]
        if summary["failures"] > 0 or summary["errors"] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
    else:
        # For specific tests, check if any test had failures/errors
        has_failures = any(
            result.get("failures", 0) > 0 or result.get("errors", 0) > 0
            for result in results.values()
            if isinstance(result, dict) and result.get("status") == "success"
        )
        sys.exit(1 if has_failures else 0)


if __name__ == "__main__":
    main()
