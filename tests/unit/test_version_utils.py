import pytest
from epcras.utils.version import parse_version, compare_versions, is_version_in_range, is_version_vulnerable

def test_equal_versions():
    assert compare_versions("1.2.3", "1.2.3") == 0
    assert compare_versions("v2.17.1", "2.17.1") == 0
    assert compare_versions("5.6.0.0", "5.6.0") == 0

def test_older_versions():
    assert compare_versions("1.2.2", "1.2.3") == -1
    assert compare_versions("2.0.1", "2.14.1") == -1
    assert compare_versions("5.5.99", "5.6.0") == -1

def test_newer_versions():
    assert compare_versions("1.2.4", "1.2.3") == 1
    assert compare_versions("2.17.2", "2.17.1") == 1
    assert compare_versions("5.6.2", "5.6.0") == 1

def test_multipart_versions():
    assert compare_versions("5.6.0.1", "5.6.0.0") == 1
    assert compare_versions("1.2.3.4.5", "1.2.3.4.6") == -1
    assert is_version_in_range("5.6.0.1", ">= 5.6.0, < 5.6.2") is True

def test_invalid_versions():
    assert parse_version("invalid_version") is None
    assert parse_version("") is None
    assert parse_version(None) is None
    assert compare_versions("1.0.0", "invalid") is None
    assert is_version_in_range("invalid", "< 1.0.0") is None
    assert is_version_in_range("1.0.0", "invalid_range_syntax!!!") is None

def test_range_specifiers():
    # Less than
    assert is_version_in_range("1.3.1", "< 1.3.2") is True
    assert is_version_in_range("1.3.2", "< 1.3.2") is False

    # Less than or equal
    assert is_version_in_range("2.14.1", "<= 2.14.1") is True
    assert is_version_in_range("2.14.2", "<= 2.14.1") is False

    # Range with comma
    assert is_version_in_range("2.10.0", ">= 2.0, <= 2.14.1") is True
    assert is_version_in_range("1.9.9", ">= 2.0, <= 2.14.1") is False
    assert is_version_in_range("2.15.0", ">= 2.0, <= 2.14.1") is False

    # Range with 'to' and '-'
    assert is_version_in_range("5.3.10", "5.3.0 to 5.3.17") is True
    assert is_version_in_range("5.3.18", "5.3.0 to 5.3.17") is False
    assert is_version_in_range("5.6.1", "5.6.0 - 5.6.1") is True

    # Space separated range '5.6.0 <= 5.6.1'
    assert is_version_in_range("5.6.0", "5.6.0 <= 5.6.1") is True
    assert is_version_in_range("5.6.2", "5.6.0 <= 5.6.1") is False

def test_is_version_vulnerable():
    # Vulnerable because in affected range and below fixed version
    assert is_version_vulnerable("2.14.0", "2.0 <= 2.14.1", "2.17.1") is True

    # Not vulnerable because installed version >= fixed version
    assert is_version_vulnerable("2.17.1", "2.0 <= 2.14.1", "2.17.1") is False
    assert is_version_vulnerable("2.18.0", "2.0 <= 2.14.1", "2.17.1") is False

    # UNKNOWN because installed version is invalid
    assert is_version_vulnerable("unparseable_v1", "2.0 <= 2.14.1", "2.17.1") is None

    # UNKNOWN because affected range is missing and no fixed version
    assert is_version_vulnerable("1.0.0", None, None) is None
