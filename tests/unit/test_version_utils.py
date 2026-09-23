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

def test_openssl_letter_versions():
    # Trailing letter patch levels (e.g. OpenSSL 1.1.1f -> 1.1.1.6)
    assert compare_versions("1.1.1a", "1.1.1b") == -1
    assert compare_versions("1.1.1f", "1.1.1l") == -1
    assert compare_versions("1.1.1n", "1.1.1f") == 1
    assert compare_versions("1.1.1", "1.1.1a") == -1
    assert compare_versions("1.1.1f", "1.1.1f") == 0

    # Range comparison with letter versions
    assert is_version_in_range("1.1.1f", "< 1.1.1l") is True
    assert is_version_in_range("1.1.1l", "< 1.1.1l") is False
    assert is_version_in_range("1.1.1m", "< 1.1.1l") is False

def test_discrete_version_list_matching():
    # Comma-separated discrete versions should match if ANY match
    assert is_version_in_range("5.6.0", "5.6.0, 5.6.1") is True
    assert is_version_in_range("5.6.1", "5.6.0, 5.6.1") is True
    assert is_version_in_range("5.6.2", "5.6.0, 5.6.1") is False

    # Three discrete versions
    assert is_version_in_range("2.0.1", "2.0.0, 2.0.1, 2.0.2") is True
    assert is_version_in_range("2.0.3", "2.0.0, 2.0.1, 2.0.2") is False

def test_or_and_pipe_clauses():
    # 'or' keyword
    assert is_version_in_range("1.1.0", "< 1.2 or > 2.0") is True
    assert is_version_in_range("2.1.0", "< 1.2 or > 2.0") is True
    assert is_version_in_range("1.5.0", "< 1.2 or > 2.0") is False

    # Pipe '|' notation
    assert is_version_in_range("1.0.0", "1.0.0 | 2.0.0") is True
    assert is_version_in_range("2.0.0", "1.0.0 | 2.0.0") is True
    assert is_version_in_range("1.5.0", "1.0.0 | 2.0.0") is False

def test_additional_operators():
    # != operator
    assert is_version_in_range("1.0.0", "!= 1.0.0") is False
    assert is_version_in_range("1.0.1", "!= 1.0.0") is True

    # ~= compatible release
    assert is_version_in_range("1.2.3", "~= 1.2.0") is True
    assert is_version_in_range("1.3.0", "~= 1.2.0") is True
    assert is_version_in_range("2.0.0", "~= 1.2.0") is False

    # == and = operators
    assert is_version_in_range("1.0.0", "== 1.0.0") is True
    assert is_version_in_range("1.0.0", "= 1.0.0") is True
    assert is_version_in_range("1.0.1", "== 1.0.0") is False

def test_whitespace_and_formatting():
    assert compare_versions("  1.2.3  ", "1.2.3") == 0
    assert compare_versions("V1.2.3", "v1.2.3") == 0
    assert is_version_in_range(" 2.10.0 ", " >= 2.0 , <= 2.14.1 ") is True
    assert parse_version("   ") is None
    assert parse_version(12345) is None
    assert parse_version([]) is None

def test_is_version_vulnerable_priority_and_edges():
    # Fixed version present without affected_versions
    assert is_version_vulnerable("1.0.0", None, "2.0.0") is True
    assert is_version_vulnerable("2.0.0", None, "2.0.0") is False
    assert is_version_vulnerable("2.0.1", None, "2.0.0") is False

    # Affected versions without fixed version
    assert is_version_vulnerable("1.5.0", "< 2.0.0", None) is True
    assert is_version_vulnerable("2.5.0", "< 2.0.0", None) is False

    # Invalid fixed version fallback
    assert is_version_vulnerable("1.0.0", "< 2.0.0", "invalid_fixed") is True
    assert is_version_vulnerable("3.0.0", "< 2.0.0", "invalid_fixed") is False

    # Both unparseable
    assert is_version_vulnerable("invalid_installed", "< 2.0.0", "2.0.0") is None
    assert is_version_vulnerable("1.0.0", "invalid_range_!!!", None) is None

