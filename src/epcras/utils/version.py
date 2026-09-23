import re
from typing import Optional, Union, Tuple
from packaging.version import parse as packaging_parse, InvalidVersion, Version

def parse_version(version_str: Optional[str]) -> Optional[Version]:
    """
    Safely parse a version string into a packaging.version.Version object.
    Returns None if the version string is empty, invalid, or cannot be reliably parsed.
    Never uses lexicographical string comparison.
    """
    if not version_str or not isinstance(version_str, str):
        return None

    clean_str = version_str.strip()
    if not clean_str:
        return None

    # Strip leading 'v' or 'V' if present (e.g., 'v1.2.3' -> '1.2.3')
    if clean_str.lower().startswith('v') and len(clean_str) > 1 and clean_str[1].isdigit():
        clean_str = clean_str[1:]

    # OpenSSL-style trailing letter patch levels (e.g. '1.1.1a' -> '1.1.1.1', '1.1.1f' -> '1.1.1.6')
    letter_patch_match = re.match(r'^(\d+(?:\.\d+)*)([a-z])$', clean_str, re.IGNORECASE)
    if letter_patch_match:
        base, letter = letter_patch_match.groups()
        letter_num = ord(letter.lower()) - ord('a') + 1
        try:
            ver = packaging_parse(f"{base}.{letter_num}")
            if isinstance(ver, Version):
                return ver
        except Exception:
            pass

    try:
        ver = packaging_parse(clean_str)
        if isinstance(ver, Version):
            return ver
    except (InvalidVersion, TypeError, Exception):
        pass

    return None


def compare_versions(ver1_str: str, ver2_str: str) -> Optional[int]:
    """
    Compare two version strings.
    Returns:
      -1 if ver1 < ver2
       0 if ver1 == ver2
       1 if ver1 > ver2
    Returns None if either version string cannot be reliably parsed.
    """
    v1 = parse_version(ver1_str)
    v2 = parse_version(ver2_str)

    if v1 is None or v2 is None:
        return None

    if v1 < v2:
        return -1
    elif v1 > v2:
        return 1
    else:
        return 0

def _parse_single_clause(clause_str: str, installed_ver: Version) -> Optional[bool]:
    """
    Evaluates a single range clause (e.g. '< 1.3.2', '>= 2.0', '5.6.0', '<= 5.6.1') against installed_ver.
    Returns True if matches, False if does not match, None if clause is invalid/unparseable.
    """
    clause = clause_str.strip()
    if not clause:
        return None

    # Check operator prefix
    match = re.match(r'^(<=|>=|<|>|==|!=|=|~=)?\s*(.+)$', clause)
    if not match:
        return None

    op, target_str = match.groups()
    op = op or '=='
    if op == '=':
        op = '=='

    target_ver = parse_version(target_str)
    if target_ver is None:
        return None

    if op == '==':
        return installed_ver == target_ver
    elif op == '!=':
        return installed_ver != target_ver
    elif op == '<':
        return installed_ver < target_ver
    elif op == '<=':
        return installed_ver <= target_ver
    elif op == '>':
        return installed_ver > target_ver
    elif op == '>=':
        return installed_ver >= target_ver
    elif op == '~=':
        return installed_ver >= target_ver and installed_ver.major == target_ver.major

    return None

def is_version_in_range(installed_version_str: str, affected_range_str: str) -> Optional[bool]:
    """
    Determine if an installed version string falls within an affected version range string.
    Supports formats:
      - Specifiers: '>= 2.0, <= 2.14.1', '< 1.3.2', '== 1.0.0'
      - Ranges with 'to' or '-': '5.3.0 to 5.3.17', '5.6.0 - 5.6.1'
      - Space separated ranges: '5.6.0 <= 5.6.1'
      - Exact versions: '1.0.0'
    Returns:
      True: installed version is in affected range (vulnerable)
      False: installed version is NOT in affected range
      None: UNKNOWN (unparseable installed version or affected range)
    """
    installed_ver = parse_version(installed_version_str)
    if installed_ver is None:
        return None

    if not affected_range_str or not isinstance(affected_range_str, str):
        return None

    range_clean = affected_range_str.strip()
    if not range_clean:
        return None

    # Handle 'to' or '-' range notation (e.g. '5.3.0 to 5.3.17' or '5.3.0 - 5.3.17')
    to_match = re.match(r'^([^\s,]+)\s*(?:to|-)\s*([^\s,]+)$', range_clean, re.IGNORECASE)
    if to_match:
        start_str, end_str = to_match.groups()
        start_ver = parse_version(start_str)
        end_ver = parse_version(end_str)
        if start_ver is None or end_ver is None:
            return None
        return start_ver <= installed_ver <= end_ver

    # Handle space-separated bounds e.g. '5.6.0 <= 5.6.1'
    space_range_match = re.match(r'^([^\s,]+)\s*(<=|<)\s*([^\s,]+)$', range_clean)
    if space_range_match:
        start_str, op, end_str = space_range_match.groups()
        start_ver = parse_version(start_str)
        end_ver = parse_version(end_str)
        if start_ver is None or end_ver is None:
            return None
        if op == '<=':
            return start_ver <= installed_ver <= end_ver
        else:
            return start_ver <= installed_ver < end_ver

    # Check if expression uses explicit OR ('or' / '|') or is a comma-separated list of exact versions
    is_or_expr = bool(re.search(r'\s+or\s+|\|', range_clean, re.IGNORECASE))
    clauses = [c.strip() for c in re.split(r'[,|]|(?:\s+or\s+)', range_clean) if c.strip()]
    if not clauses:
        return None

    has_relational_op = any(re.match(r'^(<=|>=|<|>|~=)', c) for c in clauses)
    use_any = is_or_expr or not has_relational_op

    clause_results = []
    for clause in clauses:
        res = _parse_single_clause(clause, installed_ver)
        if res is None:
            return None  # Unparseable clause -> UNKNOWN
        clause_results.append(res)

    return any(clause_results) if use_any else all(clause_results)

def is_version_vulnerable(installed_version_str: str, affected_versions_str: Optional[str], fixed_version_str: Optional[str] = None) -> Optional[bool]:
    """
    Check if installed version is affected by a vulnerability.
    Priority logic:
    1. If fixed_version_str is present, check if installed_version >= fixed_version.
       If so, returns False (patched).
    2. If affected_versions_str is present, check is_version_in_range(installed_version_str, affected_versions_str).
       If True -> returns True.
       If False -> returns False.
    3. If neither or unparseable -> returns None (UNKNOWN).
    """
    installed_ver = parse_version(installed_version_str)
    if installed_ver is None:
        return None

    # Check fixed version first if available
    fixed_ver = parse_version(fixed_version_str) if fixed_version_str else None
    if fixed_ver is not None:
        if installed_ver >= fixed_ver:
            return False  # Patched!

    # Check affected version range
    if affected_versions_str:
        in_range = is_version_in_range(installed_version_str, affected_versions_str)
        if in_range is not None:
            return in_range

    # If installed version is less than fixed version and no affected range specified:
    if fixed_ver is not None and installed_ver < fixed_ver:
        return True

    return None
