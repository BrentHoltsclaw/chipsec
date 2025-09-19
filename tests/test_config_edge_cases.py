# Additional edge case tests for chipsec.config
# Focus: enhanced platform detection fallbacks, configuration validation errors,
# SKU selection ambiguity, scope aggregation, and loader error handling.

import os
import pytest
from unittest.mock import Mock, patch

from chipsec.config import Cfg, PlatformDetector
from chipsec.library.exceptions import ParserLoadError


@pytest.fixture
def cfg(mock_logger):
    with patch('chipsec.config.logger', return_value=mock_logger):
        return Cfg()


@pytest.fixture
def mock_logger():
    return Mock()


# ---------------------------------------------------------------------------
# validate_and_load_config edge cases
# ---------------------------------------------------------------------------
@pytest.mark.unit
def test_validate_and_load_config_missing_path(cfg, tmp_path):
    missing = tmp_path / 'does_not_exist'
    with pytest.raises(ParserLoadError):
        cfg.validate_and_load_config(str(missing))
    # Ensure error logged
    assert any('Configuration loading failed' in str(c[0][0]) for c in cfg.logger.log_error.call_args_list)


@pytest.mark.unit
def test_validate_and_load_config_success_minimal(cfg, tmp_path):
    # Existing directory triggers _load_config_files (currently a stub/pass)
    cfg.CONFIG_PCI_RAW = {}
    cfg.CONFIG_PCI = {}
    cfg.validate_and_load_config(str(tmp_path))
    # Validation passed debug message should appear
    assert any('Configuration validation passed' in str(c[0][0]) for c in cfg.logger.log_debug.call_args_list)


# ---------------------------------------------------------------------------
# enhanced_platform_detection fallback (no matching SKU -> unknown platform)
# ---------------------------------------------------------------------------
@pytest.mark.unit
def test_enhanced_platform_detection_fallback_unknown(cfg):
    # No proc_dictionary / pch_dictionary entries so fallback path is used
    cfg.enhanced_platform_detection(proc_code=None, pch_code=None, cpuid=0x1234)
    # Detection state flag set
    assert cfg.get_config_state().platform_detected is True
    # But platform still unknown so is_platform_detected() should be False
    assert cfg.is_platform_detected() is False
    # CPUID should be updated
    assert cfg.get_cpu_info().cpuid == 0x1234


# ---------------------------------------------------------------------------
# _find_sku_data ambiguity resolution (multiple vendor matches)
# ---------------------------------------------------------------------------
@pytest.mark.unit
def test_find_sku_data_multiple_vendors_generic(cfg):
    detect_val = '8086:abcd'
    # Craft artificial dictionary with two vendors each having a matching SKU
    sku1 = {'vid': 0x8086, 'did': 0x1111, 'code': 'AAA', 'longname': 'AAA Orig', 'req_pch': None, 'detect': [detect_val]}
    sku2 = {'vid': 0x1022, 'did': 0x2222, 'code': 'BBB', 'longname': 'BBB Orig', 'req_pch': None, 'detect': [detect_val]}
    dict_ref = {
        '8086': {'1111': [sku1]},
        '1022': {'2222': [sku2]},
    }
    # Call internal helper
    result = cfg._find_sku_data(dict_ref, code=None, detect_val=detect_val)
    assert result is not None
    # Returned longname should have been modified to indicate generic when multiple vendors
    assert result['longname'].endswith('Generic')
    # sku code preserved
    assert result['code'] in {'AAA', 'BBB'}


# ---------------------------------------------------------------------------
# get_objlist_from_scope wildcard aggregation
# ---------------------------------------------------------------------------
@pytest.mark.unit
def test_get_objlist_from_scope_wildcard_aggregation(cfg):
    # Build synthetic object dictionary similar in shape to REGISTERS but simpler values
    objdict = {
        '8086': {
            'devA': {
                'REG1': [1],
                'REG2': [2]
            },
            'devB': {
                'REG3': [3]
            }
        },
        '1022': {
            'devX': {
                'REG4': [4]
            }
        }
    }
    # Scope for all names under vendor 8086 (any parent / any register name)
    scope_namedtuple = cfg.convert_internal_scope('8086.*', '*')
    reg_def = cfg.get_objlist_from_scope(objdict, scope_namedtuple)
    # Flatten ObjList contents to primitive ints
    collected = []
    for item in reg_def:
        if isinstance(item, list):
            collected.extend(item)
        else:
            collected.append(item)
    assert set(collected) == {1, 2, 3}


# ---------------------------------------------------------------------------
# PlatformDetector detect_platform: vendor mismatch -> unknown platform
# ---------------------------------------------------------------------------
@pytest.mark.unit
def test_platform_detector_unknown_on_vendor_mismatch(mock_logger):
    detector = PlatformDetector(mock_logger)
    # pci_enum must have '0000:00:00.0'
    pci_enum = {
        '0000:00:00.0': {'vid': 0x1234, 'did': 0x5678, 'rid': 0x01}
    }
    config_pci_raw = {'DEAD': {}}  # Deliberately mismatched vendor space
    result = detector.detect_platform(pci_enum, config_pci_raw)
    assert result['name'] == 'Unknown'
    assert result['code'] == ''
    assert result['did'] == [0x5678]


# ---------------------------------------------------------------------------
# Defensive: ensure get_objlist_from_scope handles non-existing wildcards gracefully
# ---------------------------------------------------------------------------
@pytest.mark.unit
def test_get_objlist_from_scope_no_matches(cfg):
    objdict = {'9999': {}}
    scope_namedtuple = cfg.convert_internal_scope('8086.*', 'REGX')
    reg_def = cfg.get_objlist_from_scope(objdict, scope_namedtuple)
    assert len(list(reg_def)) == 0
