# CHIPSEC: Platform Security Assessment Framework

## Overview

CHIPSEC is a comprehensive framework for analyzing the security of PC platforms including hardware, system firmware (BIOS/UEFI), and platform components. It provides a security test suite, tools for accessing various low-level interfaces, and forensic capabilities. The framework runs on Windows, Linux, and UEFI shell.

**⚠️ IMPORTANT WARNING**: This software is for security testing purposes only. Use at your own risk. CHIPSEC should only be used on test systems and never deployed on production end-user systems.

## Project Architecture

### Core Structure

- **Entry Points**:
  - `chipsec_main.py` - Main security assessment framework for running modules
  - `chipsec_util.py` - Standalone utility for low-level hardware access
  
- **Core Framework** (`chipsec/`):
  - `config.py` - Platform detection, configuration management, and XML parsing
  - `chipset.py` - Main chipset abstraction and platform initialization
  - `module_common.py` - Base classes for security assessment modules
  - `testcase.py` - Test execution framework and result handling

### Hardware Abstraction Layer (HAL)

Located in `chipsec/hal/`, provides vendor-specific hardware abstraction:

- `intel/` - Intel-specific hardware implementations
- `amd/` - AMD-specific hardware implementations  
- `common/` - Common hardware functionality
- `hals.py` - HAL registration and management
- `hal_base.py` - Base HAL interface

### Configuration System

- **XML Configurations** (`chipsec/cfg/`):
  - `8086/` - Intel chipset configurations (vendor ID 0x8086)
  - `1022/` - AMD chipset configurations (vendor ID 0x1022)
  - `parsers/` - Configuration file parsing logic
  - `chipsec_cfg.xsd` - XML schema definition

- **Platform Detection**: Automatic detection via PCI enumeration and device matching
- **Register Definitions**: XML-based register and control definitions per platform

### Security Modules

Located in `chipsec/modules/`, organized by platform:

- `common/` - Cross-platform security tests (BIOS write protection, SMM, etc.)
- `bdw/` - Broadwell-specific tests
- `byt/` - Bay Trail-specific tests
- `tools/` - Additional security tools

#### Module Structure
All modules inherit from `BaseModule` and implement:
- `is_supported()` - Platform compatibility check
- `run()` - Main test execution
- `TAGS` - Module categorization for filtering
- `METADATA_TAGS` - Additional metadata for classification

### Utility Commands

Located in `chipsec/utilcmd/`, provides low-level access tools:

- `pci_cmd.py` - PCI configuration space access
- `mem_cmd.py` - Physical memory access
- `msr_cmd.py` - Model-specific register access
- `spi_cmd.py` - SPI flash access
- `uefi_cmd.py` - UEFI firmware analysis
- `acpi_cmd.py` - ACPI table access
- And many more specialized tools

### Library Components

Core functionality in `chipsec/library/`:

- `defines.py` - Constants and definitions
- `logger.py` - Logging infrastructure
- `register.py` - Register access abstraction
- `pci.py` - PCI/PCIe functionality
- `cpu.py` - CPU-specific operations
- `memory.py` - Memory management
- `file.py` - File operations
- `exceptions.py` - Custom exception classes

## Development Guidelines

### Module Development

1. **Inherit from BaseModule**:
   ```python
   from chipsec.module_common import BaseModule, BIOS
   from chipsec.library.returncode import ModuleResult
   
   class my_test(BaseModule):
       def __init__(self):
           BaseModule.__init__(self)
       
       def is_supported(self) -> bool:
           return self.cs.control.is_defined('RequiredControl')
       
       def run(self, module_argv) -> int:
           # Test implementation
           return ModuleResult.PASSED
   ```

2. **Use Proper Tags**:
   ```python
   TAGS = [BIOS]  # or [SMM], [UEFI], etc.
   METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'TEST_NAME']
   ```

3. **Error Handling**:
   - Use try/catch for hardware access
   - Return appropriate ModuleResult codes
   - Log meaningful messages

### Utility Command Development

1. **Inherit from BaseCommand**:
   ```python
   from chipsec.command import BaseCommand, toLoad
   
   class MyCommand(BaseCommand):
       def requirements(self) -> toLoad:
           return toLoad.Driver  # or toLoad.All
       
       def parse_arguments(self) -> None:
           # Argument parsing logic
       
       def run(self) -> None:
           # Command implementation
   ```

2. **Register Commands**:
   ```python
   commands = {'my_cmd': MyCommand}
   ```

### Configuration Guidelines

1. **XML Register Definitions**:
   - Follow `chipsec_cfg.xsd` schema
   - Include proper field definitions with bit ranges
   - Add descriptions for registers and fields

2. **Platform Detection**:
   - Use PCI device ID matching
   - Include proper detect strings
   - Support multiple device configurations

### Coding Standards

1. **Type Hints**: Use type annotations for all functions
2. **Documentation**: Include comprehensive docstrings
3. **Error Handling**: Use specific exception types from `chipsec.library.exceptions`
4. **Logging**: Use the framework logger, not print statements
5. **Constants**: Define in `chipsec.library.defines` or module-level

### HAL Development

1. **Vendor-Specific**: Place in appropriate vendor directory (`intel/`, `amd/`)
2. **Common Functionality**: Use `common/` for shared implementations
3. **Registration**: Register HALs in `hals.py`
4. **Interface**: Follow `hal_base.py` interface patterns

## Key Workflows

### Running Security Tests
```bash
# Run all tests
python chipsec_main.py

# Run specific module
python chipsec_main.py -m common.bios_wp

# Run with platform override
python chipsec_main.py -p BDW
```

### Using Utility Commands
```bash
# Enumerate PCI devices
python chipsec_util.py pci enumerate

# Read memory
python chipsec_util.py mem read 0xFED00000 0x100

# Access MSRs
python chipsec_util.py msr read 0x1A0
```

### Platform Development
1. Add platform configuration in `chipsec/cfg/XXXX/`
2. Define register maps and controls
3. Add platform detection logic
4. Test with target hardware

## Testing and Validation

- Modules should include comprehensive self-tests
- Use mock objects for unit testing hardware access
- Validate on multiple platforms when possible
- Test error conditions and edge cases

## Important Notes

- **Driver Requirements**: Most functionality requires kernel drivers
- **Platform Support**: Check platform compatibility before running tests
- **Security Context**: Many operations require administrative privileges
- **Hardware Access**: Direct hardware access can cause system instability

## File Locations

- **Main Scripts**: Root directory (`chipsec_main.py`, `chipsec_util.py`)
- **Core Framework**: `chipsec/` directory
- **HAL Components**: `chipsec/hal/`
- **Security Modules**: `chipsec/modules/`
- **Utility Commands**: `chipsec/utilcmd/`
- **Configurations**: `chipsec/cfg/`
- **Library Functions**: `chipsec/library/`

This framework provides comprehensive platform security assessment capabilities while maintaining modularity and extensibility for new platforms and test cases.