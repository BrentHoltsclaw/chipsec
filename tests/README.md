# CHIPSEC Testing Framework

This directory contains the comprehensive testing framework for CHIPSEC (Platform Security Assessment Framework). The framework has been significantly improved to provide better test coverage, maintainability, and CI/CD integration.

## Overview

The testing framework includes:
- **Unit Tests**: Comprehensive unit test coverage for all CHIPSEC components
- **Integration Tests**: End-to-end testing of CHIPSEC functionality
- **Performance Tests**: Benchmarking and performance regression detection
- **Security Tests**: Automated security vulnerability scanning
- **CI/CD Pipeline**: Automated testing on multiple Python versions and platforms

## Directory Structure

```
tests/
├── __init__.py                 # Test package initialization
├── conftest.py                 # Pytest configuration and fixtures
├── test_utils.py               # Test utilities and helper functions
├── README.md                   # This documentation
├── library/                    # Library component tests
│   ├── test_acpi_tables.py     # ACPI table parsing tests
│   └── test_register_improved.py # Improved register interface tests
├── helpers/                    # Helper component tests
│   ├── test_linuxhelper.py     # Linux helper tests
│   ├── test_windowshelper.py   # Windows helper tests
│   └── test_replayhelper.py    # Replay helper tests
├── modules/                    # Module tests
│   ├── test_cpu_info.py        # CPU information module tests
│   └── test_sgx_check.py       # SGX check module tests
├── utilcmd/                    # Utility command tests
│   ├── cpu_cmd/
│   ├── spi_cmd/
│   └── ...
├── hardware/                   # Hardware-specific tests
│   ├── test_generic.py         # Generic hardware tests
│   └── test_x1_carbon_ubuntu.py # Platform-specific tests
├── software/                   # Software component tests
│   ├── test_cs.py              # Core CHIPSEC tests
│   └── test_main.py            # Main entry point tests
└── hal/                        # Hardware abstraction layer tests
    ├── test_cpu.py             # CPU HAL tests
    ├── test_pci.py             # PCI HAL tests
    └── test_acpi.py            # ACPI HAL tests
```

## Key Improvements

### 1. Modern Testing Framework

- **Pytest**: Replaced unittest with pytest for better fixtures, parametrization, and plugins
- **Comprehensive Fixtures**: Pre-configured mock objects and test data
- **Custom Markers**: Support for different test types (unit, integration, slow, hardware)
- **Parallel Execution**: Support for running tests in parallel with pytest-xdist

### 2. Enhanced Test Utilities

The `test_utils.py` module provides:

- **TestDataGenerator**: Generate realistic test data for PCI configs, UEFI volumes, registers
- **MockFactory**: Create comprehensive mock objects for testing
- **FileTestHelper**: Utilities for temporary file/directory management
- **AssertionHelpers**: CHIPSEC-specific assertion functions
- **PerformanceTestHelper**: Benchmarking utilities

### 3. Improved Test Coverage

- **Register Interface**: Comprehensive testing of register read/write operations
- **Platform Detection**: Testing of platform identification and configuration
- **Helper Components**: Cross-platform testing with mocked system calls
- **Module Testing**: Testing of security assessment modules
- **Error Handling**: Testing of error conditions and edge cases

### 4. CI/CD Integration

- **GitHub Actions**: Automated testing on multiple Python versions (3.8-3.11)
- **Code Coverage**: Coverage reporting with minimum thresholds (80%)
- **Security Scanning**: Automated vulnerability detection with Bandit and Safety
- **Performance Monitoring**: Benchmark tracking and regression detection
- **Documentation**: Automated documentation building and deployment

## Running Tests

### Basic Test Execution

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/library/test_register_improved.py

# Run tests with coverage
pytest --cov=chipsec --cov-report=html
```

### Test Categories

```bash
# Run only unit tests
pytest -m "unit"

# Run integration tests
pytest -m "integration"

# Run slow/performance tests
pytest -m "slow"

# Run hardware-dependent tests (requires hardware)
pytest -m "hardware"

# Skip slow tests
pytest -m "not slow"
```

### Parallel Execution

```bash
# Run tests in parallel (4 workers)
pytest -n 4

# Auto-detect number of workers
pytest -n auto
```

### Coverage Reporting

```bash
# Generate HTML coverage report
pytest --cov=chipsec --cov-report=html

# Generate XML report for CI
pytest --cov=chipsec --cov-report=xml

# Show coverage in terminal
pytest --cov=chipsec --cov-report=term-missing
```

## Writing Tests

### Basic Test Structure

```python
import pytest
from chipsec.library.register import Register
from tests.test_utils import MockFactory

class TestMyComponent:
    """Test class for MyComponent."""

    @pytest.fixture
    def mock_cs(self):
        """Create mock ChipsecCs object."""
        return MockFactory.create_mock_chipsec_cs()

    @pytest.fixture
    def register_instance(self, mock_cs):
        """Create Register instance with mocked dependencies."""
        return Register(mock_cs)

    @pytest.mark.unit
    def test_my_function(self, register_instance):
        """Test my_function behavior."""
        # Arrange
        expected_value = 0x1234

        # Act
        result = register_instance.my_function()

        # Assert
        assert result == expected_value
```

### Using Test Utilities

```python
from tests.test_utils import TestDataGenerator, AssertionHelpers

def test_pci_config_parsing():
    """Test PCI configuration parsing."""
    # Generate test data
    pci_data = TestDataGenerator.generate_pci_config_data(
        vendor_id=0x8086,
        device_id=0x1234
    )

    # Test parsing logic
    # ... test implementation ...

    # Use custom assertions
    AssertionHelpers.assert_pci_config_equal(
        pci_data, 0x8086, 0x1234
    )
```

### Mocking Best Practices

```python
from unittest.mock import Mock, patch
from tests.test_utils import MockFactory

def test_with_mocking():
    """Example of proper mocking."""
    # Use MockFactory for consistent mock objects
    mock_helper = MockFactory.create_mock_helper()

    # Patch external dependencies
    with patch('chipsec.helper.linux.os') as mock_os:
        mock_os.path.exists.return_value = True

        # Test implementation
        result = my_function(mock_helper)
        assert result is True
```

## Test Configuration

### pytest.ini

The `pytest.ini` file configures pytest behavior:

```ini
[tool:pytest]
testpaths = tests
python_files = test_*.py *_test.py
python_classes = Test*
python_functions = test_*
addopts =
    --strict-markers
    --strict-config
    --disable-warnings
    --tb=short
    -v
    --cov=chipsec
    --cov-report=html:htmlcov
    --cov-report=term-missing
    --cov-fail-under=80
```

### conftest.py

The `conftest.py` file provides shared fixtures and configuration:

- **mock_modules**: Mocks Windows-specific modules for cross-platform testing
- **mock_chipsec_cs**: Mock ChipsecCs object
- **sample_register_data**: Sample register configuration data
- **mock_helper**: Mock helper object
- **temp_test_file**: Temporary file fixture

## Performance Testing

### Running Performance Tests

```bash
# Run performance benchmarks
pytest -m "slow" --benchmark-only

# Compare against previous runs
pytest --benchmark-compare

# Save benchmark results
pytest --benchmark-json=benchmark.json
```

### Writing Performance Tests

```python
import pytest
from tests.test_utils import PerformanceTestHelper

@pytest.mark.slow
def test_register_read_performance(register_instance):
    """Test register read performance."""
    # Benchmark the function
    benchmark_result = PerformanceTestHelper.benchmark_function(
        register_instance.read,
        iterations=1000
    )

    # Assert performance requirements
    assert benchmark_result['mean'] < 0.001  # Less than 1ms average
```

## Security Testing

### Automated Security Scanning

```bash
# Run Bandit security linter
bandit -r chipsec/ -f json -o bandit-report.json

# Run Safety vulnerability check
safety check --output json
```

### Security Test Integration

```python
@pytest.mark.security
def test_no_hardcoded_secrets():
    """Test that no hardcoded secrets exist in code."""
    import os
    from pathlib import Path

    # Scan for potential secrets
    secret_patterns = [
        r'password\s*=\s*["\'][^"\']*["\']',
        r'secret\s*=\s*["\'][^"\']*["\']',
        r'key\s*=\s*["\'][^"\']*["\']'
    ]

    # Implementation to scan codebase
    # ... security scanning logic ...
```

## Best Practices

### 1. Test Organization
- Group related tests in classes
- Use descriptive test method names
- Follow `test_*` naming convention
- Use fixtures for common setup/teardown

### 2. Mocking Strategy
- Mock external dependencies (file I/O, network, hardware)
- Use `MockFactory` for consistent mock objects
- Avoid over-mocking - test real behavior when possible
- Use `patch` for temporary mocking

### 3. Test Data Management
- Use `TestDataGenerator` for realistic test data
- Avoid hardcoded test data
- Clean up temporary files and resources
- Use fixtures for shared test data

### 4. Assertion Best Practices
- Use descriptive assertion messages
- Prefer specific assertions over generic `assert`
- Use `AssertionHelpers` for CHIPSEC-specific checks
- Test both positive and negative cases

### 5. Performance Considerations
- Mark slow tests with `@pytest.mark.slow`
- Use appropriate fixtures to avoid redundant setup
- Consider test parallelization for large test suites
- Monitor test execution time

## Contributing

### Adding New Tests

1. **Choose appropriate location**: Place tests in the appropriate subdirectory
2. **Follow naming conventions**: Use `test_*.py` for test files
3. **Add proper markers**: Use `@pytest.mark.unit`, `@pytest.mark.integration`, etc.
4. **Include documentation**: Add docstrings explaining test purpose
5. **Update fixtures**: Add new fixtures to `conftest.py` if needed

### Test Maintenance

1. **Keep tests updated**: Update tests when code changes
2. **Remove obsolete tests**: Delete tests for removed functionality
3. **Fix flaky tests**: Investigate and fix intermittent test failures
4. **Improve coverage**: Add tests for uncovered code paths

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure proper Python path setup in `conftest.py`
2. **Mock Issues**: Check that mocks are properly configured
3. **Platform Differences**: Use appropriate mocking for cross-platform tests
4. **Performance Issues**: Profile slow tests and optimize as needed

### Debugging Tests

```bash
# Run tests with debugging output
pytest -v -s --pdb

# Run specific test with detailed output
pytest tests/library/test_register_improved.py::TestRegister::test_register_initialization -v -s

# Run tests with coverage details
pytest --cov=chipsec --cov-report=html --cov-report=term-missing
```

## Future Improvements

### Planned Enhancements

1. **Property-based Testing**: Use Hypothesis for generating test cases
2. **Mutation Testing**: Implement mutation testing with Cosmic Ray
3. **Fuzz Testing**: Add fuzz testing for input validation
4. **Load Testing**: Performance testing under load conditions
5. **Integration Testing**: More comprehensive end-to-end tests
6. **Test Data Management**: Centralized test data repository
7. **CI/CD Enhancements**: Support for more platforms and configurations

### Metrics and Monitoring

1. **Coverage Tracking**: Monitor test coverage over time
2. **Performance Monitoring**: Track test execution performance
3. **Flakiness Detection**: Identify and fix flaky tests
4. **Test Health Dashboard**: Visual dashboard for test metrics

This testing framework provides a solid foundation for maintaining code quality and catching regressions in the CHIPSEC project. Regular updates and improvements ensure that the framework evolves with the codebase.
