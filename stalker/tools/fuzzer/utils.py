"""
Utility functions for fuzzer engine.
"""
import re
from typing import Optional, Tuple
from utils.parsers import check_sanitizer_error as check_asan_error_in_output


def extract_base_type_for_const_cast(var_type: str) -> str:
    """
    Extract the base type from a const reference type to use in const_cast.
    Example: 'const uint32_t &' -> 'uint32_t&'
    """
    # Remove 'const' keyword (case insensitive)
    base_type = re.sub(r'\bconst\b', '', var_type, flags=re.IGNORECASE)
    # Remove extra whitespace
    base_type = re.sub(r'\s+', ' ', base_type).strip()
    # Ensure '&' is attached to the type (no space before &)
    base_type = re.sub(r'\s*&\s*', '&', base_type)
    return base_type


def parse_address(address_str: str) -> Optional[str]:
    """Parses a hex address string from a raw debugger output."""
    if not isinstance(address_str, str):
        return None
    match = re.search(r'(0x[0-9a-fA-F]+)', address_str)
    if not match:
        return None
    return match.group(1)
