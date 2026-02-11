# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

import sys
import types
from pathlib import Path

from paths import REPO_ROOT, UNIT_TESTS_DIR


def read_file_safe(file_path: Path) -> str:
    """Read file with proper error handling. Exits immediately on error."""
    if not file_path.exists():
        print(f"ERROR: Input file not found: {file_path}")
        sys.exit(1)

    try:
        return file_path.read_text(encoding='utf-8')
    except PermissionError as exc:
        print(f"ERROR: Permission denied reading {file_path}: {exc}")
        sys.exit(1)
    except UnicodeDecodeError as exc:
        print(f"ERROR: File encoding error in {file_path}: {exc}")
        sys.exit(1)
    except OSError as exc:
        print(f"ERROR: Failed to read file {file_path}: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: Unexpected error reading {file_path}: {exc}")
        sys.exit(1)


def write_file_safe(file_path: Path, content: str) -> None:
    """Write file with proper error handling. Exits immediately on error."""
    try:
        # Create parent directories if needed
        file_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        print(f"ERROR: Failed to create directory {file_path.parent}: {exc}")
        sys.exit(1)

    try:
        file_path.write_text(content, encoding='utf-8')
    except PermissionError as exc:
        print(f"ERROR: Permission denied writing to {file_path}: {exc}")
        sys.exit(1)
    except OSError as exc:
        print(f"ERROR: Failed to write file {file_path}: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: Unexpected error writing {file_path}: {exc}")
        sys.exit(1)


def sanitize_c_identifier(name: str, uppercase: bool = True, handle_leading_digit: bool = False) -> str:
    """
    Convert arbitrary string to valid C identifier.

    Replaces non-alphanumeric characters with underscores, collapses consecutive
    underscores, and optionally converts to uppercase.

    Args:
        name: Input string to sanitize
        uppercase: If True, convert to UPPER_SNAKE_CASE; if False, use lower_snake_case
        handle_leading_digit: If True, prefix with "num_" if name starts with digit

    Returns:
        Valid C identifier string

    Examples:
        >>> sanitize_c_identifier("path too short")
        'PATH_TOO_SHORT'
        >>> sanitize_c_identifier("base key/key with wrong path")
        'BASE_KEY_KEY_WITH_WRONG_PATH'
        >>> sanitize_c_identifier("test-case #1", uppercase=False)
        'test_case_1'
        >>> sanitize_c_identifier("123_test", handle_leading_digit=True)
        'NUM_123_TEST'
    """
    # Replace non-alphanumeric characters with underscores
    sanitized = "".join(c if c.isalnum() else "_" for c in name)

    # Collapse multiple consecutive underscores
    while "__" in sanitized:
        sanitized = sanitized.replace("__", "_")

    # Strip leading/trailing underscores
    sanitized = sanitized.strip("_")

    # Handle leading digit if requested
    if handle_leading_digit and sanitized and sanitized[0].isdigit():
        sanitized = f"num_{sanitized}"

    # Handle empty string case
    if not sanitized:
        sanitized = "unnamed"

    # Convert case
    return sanitized.upper() if uppercase else sanitized.lower()


def extract_apdu_payload(apdu: bytes) -> bytes:
    """
    Extract payload from APDU command.

    APDU format: [CLA: 1][INS: 1][P1: 1][P2: 1][LC: 1][DATA: LC bytes]

    Args:
        apdu: Complete APDU command with 5-byte header

    Returns:
        Payload bytes (DATA portion only, starting at offset 5)

    Raises:
        ValueError: If APDU is too short or payload length mismatch

    Examples:
        >>> apdu = b'\\x00\\x01\\x02\\x03\\x05\\xAA\\xBB\\xCC\\xDD\\xEE'
        >>> extract_apdu_payload(apdu)
        b'\\xAA\\xBB\\xCC\\xDD\\xEE'
    """
    MIN_HEADER_LENGTH = 5

    if len(apdu) < MIN_HEADER_LENGTH:
        raise ValueError(
            f"APDU command too short: {len(apdu)} bytes "
            f"(expected at least {MIN_HEADER_LENGTH})"
        )

    lc = apdu[4]
    payload_start = 5

    payload_length = lc

    payload_end = payload_start + payload_length
    payload_bytes = apdu[payload_start:payload_end]

    if len(payload_bytes) != payload_length:
        raise ValueError(
            f"Payload length mismatch: Lc field says {payload_length} bytes, "
            f"but got {len(payload_bytes)} bytes"
        )

    return payload_bytes


def format_bytes_as_c_array(
    data: bytes,
    name: str,
    bytes_per_line: int = 16,
    return_as_list: bool = False
) -> str | list[str]:
    """
    Generate C code for a byte array declaration.

    Args:
        data: Byte data to format
        name: C identifier for the array
        bytes_per_line: Number of bytes per line for readability (default: 16)
        return_as_list: If True, return list of lines; if False, return single string

    Returns:
        C code as string or list of strings

    Examples:
        >>> format_bytes_as_c_array(b'\\xAA\\xBB\\xCC', "TEST_DATA")
        'static const uint8_t TEST_DATA[] = {\\n    0xAA, 0xBB, 0xCC,\\n};'
        >>> format_bytes_as_c_array(b'\\xAA\\xBB\\xCC', "TEST_DATA", return_as_list=True)
        ['static const uint8_t TEST_DATA[] = {', '    0xAA, 0xBB, 0xCC,', '};']
    """
    lines = []
    lines.append(f"static const uint8_t {name}[] = {{")

    for i in range(0, len(data), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        hex_bytes = ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append(f"    {hex_bytes},")

    lines.append("};")

    if return_as_list:
        return lines
    else:
        return "\n".join(lines)


def _add_tests_to_sys_path() -> None:
    sys.path.insert(0, str(REPO_ROOT / "tests"))
    sys.path.insert(0, str(REPO_ROOT / "tests" / "application_client"))
    sys.path.insert(0, str(REPO_ROOT / "tests" / "standalone"))

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ALPHABET_INDEX = {char: index for index, char in enumerate(ALPHABET)}

def _ensure_base58_module() -> None:
    if "base58" in sys.modules:
        return

    def b58encode(data: bytes) -> bytes:
        if not data:
            return b""

        zero_prefix = 0
        for byte in data:
            if byte == 0:
                zero_prefix += 1
            else:
                break
        num = int.from_bytes(data, "big")
        encoded_bytes = bytearray()
        while num > 0:
            num, remainder = divmod(num, 58)
            encoded_bytes.append(ord(ALPHABET[remainder]))
        encoded_bytes.reverse()
        result = bytearray(b"1" * zero_prefix)
        if encoded_bytes:
            result.extend(encoded_bytes)
        elif zero_prefix == 0:
            result.extend(b"1")
        return bytes(result)

    def b58decode(value: bytes | str) -> bytes:
        if isinstance(value, bytes):
            value = value.decode("ascii")
        if value == "":
            return b""
        num = 0
        for char in value:
            num = num * 58 + ALPHABET_INDEX[char]
        decoded = num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""
        zero_prefix = len(value) - len(value.lstrip("1"))
        return b"\x00" * zero_prefix + decoded

    module = types.ModuleType("base58")
    module.b58encode = b58encode
    module.b58decode = b58decode
    sys.modules["base58"] = module
