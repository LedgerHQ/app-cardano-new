# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from typing import Any
import re

from common import (
    write_file_safe,
    sanitize_c_identifier,
    _add_tests_to_sys_path,
    format_bytes_as_c_array,
)
from paths import UNIT_TESTS_DIR

FIXTURES_FILE = UNIT_TESTS_DIR / "test_pubkey_fixtures.h"
MOCK_DATA_FILE = UNIT_TESTS_DIR / "mock_crypto" / "crypto_mock_data.h"


@dataclass(frozen=True)
class PubKeyTestGroup:
    test_cases: list[Any]
    silent_export_enabled: bool
    expected_policy: str


# ==============================================================================
# Step 1: Load Test Cases from Ragger Tests
# ==============================================================================

def _load_pubkey_test_cases() -> dict[str, PubKeyTestGroup]:
    """
    Load public key export test cases from ragger standalone tests.

    Returns:
        Dictionary mapping category names to PubKeyTestGroup metadata
    """
    _add_tests_to_sys_path()

    from standalone.input_files.pubkey import (  # type: ignore
        testsByron,
        testsShelleyUsual,
        testsShelleyUnusual,
        testsMultisig,
        testsColdKeys,
        testsCVoteKeysUsual,
        testsCVoteKeysUnusual,
        testsDRepKeys,
        testsCommitteeColdKeys,
        testsCommitteeHotKeys,
        testsMintKeys,
        testsSilentExport,
    )

    confirm_tests = (
        testsByron
        + testsShelleyUsual
        + testsShelleyUnusual
        + testsMultisig
        + testsColdKeys
        + testsCVoteKeysUsual
        + testsCVoteKeysUnusual
        + testsDRepKeys
        + testsCommitteeColdKeys
        + testsCommitteeHotKeys
        + testsMintKeys
    )

    categorized_test_cases: dict[str, PubKeyTestGroup] = {
        "test_pubkey_confirm": PubKeyTestGroup(
            test_cases=confirm_tests,
            silent_export_enabled=False,
            expected_policy="POLICY_SHOW",
        ),
        "test_pubkey_without_confirmation": PubKeyTestGroup(
            test_cases=testsSilentExport,
            silent_export_enabled=True,
            expected_policy="POLICY_HIDE",
        ),
    }

    return categorized_test_cases


# ==============================================================================
# Step 2: Serialize Test Case to APDU Command
# ==============================================================================


def _serialize_pubkey_test_case_to_apdu(test_case: Any) -> bytes:
    """
    Serialize a pubkey test case into APDU payload bytes.

    The payload is a packed BIP44 path:
      [path_len (1B)] [index_0 (4B)] ... [index_n (4B)]

    Args:
        test_case: PubKeyTestCase object from ragger tests

    Returns:
        APDU payload bytes (no header)
    """
    path = test_case.path
    parts = path.split("/")[1:]
    data = bytearray()
    data.append(len(parts))
    for part in parts:
        hardened = part.endswith("'")
        value_str = part[:-1] if hardened else part
        value = int(value_str)
        if hardened:
            value |= 0x80000000
        data.extend(value.to_bytes(4, "big"))
    return bytes(data)


# ==============================================================================
# Step 3: Derive Expected Pubkey + Chaincode
# ==============================================================================


def _resolve_mnemonic() -> str:
    default_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    try:
        from ragger.conftest import configuration as ragger_configuration  # type: ignore
    except ImportError:
        return default_mnemonic

    if ragger_configuration is not None:
        optional_seed = getattr(ragger_configuration.OPTIONAL, "CUSTOM_SEED", "")
        if optional_seed:
            return optional_seed

    return default_mnemonic


def _derive_expected_response_bytes(test_case: Any, mnemonic: str) -> bytes:
    """
    Derive expected extended public key bytes for a test case.

    Returns:
        Bytes: pubkey (32) + chaincode (32)
    """
    try:
        from ragger.bip import calculate_public_key_and_chaincode, CurveChoice  # type: ignore
    except ImportError:
        return _derive_expected_response_from_mock_data(test_case.path)

    pubkey_hex, chaincode_hex = calculate_public_key_and_chaincode(
        CurveChoice.Ed25519Kholaw,
        test_case.path,
        mnemonic=mnemonic,
    )

    public_key = bytes.fromhex(pubkey_hex[2:])
    chain_code = bytes.fromhex(chaincode_hex)
    return public_key + chain_code


_MOCK_PATH_MAP: dict[str, bytes] | None = None


def _derive_expected_response_from_mock_data(path: str) -> bytes:
    global _MOCK_PATH_MAP

    if _MOCK_PATH_MAP is None:
        _MOCK_PATH_MAP = _build_mock_path_map()

    if path not in _MOCK_PATH_MAP:
        raise ValueError(f"Mock data missing for path: {path}")

    return _MOCK_PATH_MAP[path]


def _build_mock_path_map() -> dict[str, bytes]:
    if not MOCK_DATA_FILE.exists():
        raise FileNotFoundError(f"Mock data file not found: {MOCK_DATA_FILE}")

    content = MOCK_DATA_FILE.read_text(encoding="utf-8")

    mock_paths_match = re.search(
        r'(static\s+const\s+mock_path_data_t\s+MOCK_PATHS\[\]\s*=\s*\{)(.*?)(\};)',
        content,
        flags=re.DOTALL,
    )
    if not mock_paths_match:
        raise ValueError("MOCK_PATHS definition not found in crypto_mock_data.h")

    body = mock_paths_match.group(2)
    entry_start_pattern = re.compile(r"\{\s*\.path\s*=")

    def extract_entries(text: str) -> list[str]:
        entries: list[str] = []
        search_pos = 0
        while True:
            match = entry_start_pattern.search(text, search_pos)
            if not match:
                break
            start = match.start()
            depth = 0
            idx = start
            while idx < len(text):
                char = text[idx]
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        end_idx = idx + 1
                        break
                idx += 1
            else:
                raise ValueError("Unbalanced braces while parsing mock entries")
            while end_idx < len(text) and text[end_idx] in " \t\r\n,":
                end_idx += 1
            entries.append(text[start:end_idx])
            search_pos = end_idx
        return entries

    def parse_bip32_path(path_array_str: str, path_len: int) -> str:
        hex_values = re.findall(r"0x[0-9a-fA-F]+", path_array_str)
        hex_values = hex_values[:path_len]
        path_parts = ["m"]
        for hex_val in hex_values:
            val = int(hex_val, 16)
            if val & 0x80000000:
                path_parts.append(f"{val & 0x7FFFFFFF}'")
            else:
                path_parts.append(str(val))
        return "/".join(path_parts)

    def parse_c_byte_array(array_str: str) -> bytes:
        hex_values = re.findall(r"0x[0-9a-fA-F]+", array_str)
        return bytes(int(val, 16) for val in hex_values)

    path_map: dict[str, bytes] = {}
    for entry in extract_entries(body):
        path_match = re.search(r"\.path\s*=\s*(\{[^}]+\})", entry)
        path_len_match = re.search(r"\.path_len\s*=\s*(\d+)", entry)
        pubkey_match = re.search(r"\.public_key\s*=\s*\{(.*?)\}", entry, re.DOTALL)
        chaincode_match = re.search(r"\.chain_code\s*=\s*\{(.*?)\}", entry, re.DOTALL)

        if not path_match or not path_len_match or not pubkey_match or not chaincode_match:
            raise ValueError("Failed to parse mock path entry")

        path_array = path_match.group(1)
        path_len = int(path_len_match.group(1))
        path_desc = parse_bip32_path(path_array, path_len)

        public_key = parse_c_byte_array(pubkey_match.group(1))
        chain_code = parse_c_byte_array(chaincode_match.group(1))

        path_map[path_desc] = public_key + chain_code

    return path_map

# ==============================================================================
# Step 4: Generate C Code for Fixtures
# ==============================================================================


def _generate_fixture_code_for_test_case(
    group_name: str,
    test_case: Any,
    test_number: int,
    expected_response: bytes,
) -> list[str]:
    """
    Generate C code for a single pubkey export test fixture.

    Args:
        group_name: Category name (e.g., test_pubkey_confirm)
        test_case: PubKeyTestCase from ragger tests
        test_number: Sequential test number (1-based)
        expected_response: Expected pubkey+chaincode bytes

    Returns:
        List of C code lines defining the test fixture
    """
    code_lines: list[str] = []

    code_lines.append("// ----------------------------------------------------------------------")
    code_lines.append(f"// Test group: {group_name}")
    code_lines.append(f"// Test {test_number}: {test_case.name}")
    code_lines.append(f"// Path: {test_case.path}")
    code_lines.append("// ----------------------------------------------------------------------")
    code_lines.append("")

    payload_bytes = _serialize_pubkey_test_case_to_apdu(test_case)

    safe_test_name = sanitize_c_identifier(test_case.name)

    code_lines.append(f"// Source: tests/standalone/input_files/pubkey.py > {test_case.name}")

    payload_array_name = (
        f"PUBKEY_{group_name}_{test_number:03d}_{safe_test_name}_APDU"
    )
    payload_array_code = format_bytes_as_c_array(
        payload_bytes,
        payload_array_name,
        bytes_per_line=16,
        return_as_list=True,
    )
    code_lines.extend(payload_array_code)
    code_lines.append("")

    public_key = expected_response[:32]
    chain_code = expected_response[32:]

    code_lines.append(f"// Public key (hex): {public_key.hex()}")
    code_lines.append(f"// Chain code (hex): {chain_code.hex()}")

    expected_array_name = (
        f"PUBKEY_{group_name}_{test_number:03d}_{safe_test_name}_EXPECTED_RESPONSE"
    )
    expected_array_code = format_bytes_as_c_array(
        expected_response,
        expected_array_name,
        bytes_per_line=16,
        return_as_list=True,
    )
    code_lines.extend(expected_array_code)
    code_lines.append("")

    return code_lines


# ==============================================================================
# Step 5: Build Complete C Header File
# ==============================================================================


def _build_fixtures() -> str:
    categorized_test_cases = _load_pubkey_test_cases()
    mnemonic = _resolve_mnemonic()

    header_lines: list[str] = [
        "// Auto-generated file - DO NOT EDIT",
        "//",
        "// Generated by: unit-tests/generators/generate_unit_tests_from_ragger.py",
        "// Generator: fixture_generators/pubkey_generators.py",
        "// Source: tests/standalone/input_files/pubkey.py",
        "//",
        "// To regenerate:",
        "//   cd unit-tests",
        "//   python3 generators/generate_unit_tests_from_ragger.py",
        "//",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <stdbool.h>",
        "#include \"cardano_swo.h\"",
        "#include \"securityPolicy/securityPolicyType.h\"",
        "#include \"test_fixture_types.h\"",
        "",
        "// ======================================================================",
        "// Public Key Export Test Fixtures",
        "// ======================================================================",
        "",
    ]

    fixture_arrays: dict[str, list[str]] = {}

    for group_name, group in categorized_test_cases.items():
        group_lines: list[str] = []
        for idx, test_case in enumerate(group.test_cases):
            expected_response = _derive_expected_response_bytes(test_case, mnemonic)
            group_lines.extend(
                _generate_fixture_code_for_test_case(
                    group_name,
                    test_case,
                    idx,
                    expected_response,
                )
            )
        fixture_arrays[group_name] = group_lines

    for group_name, lines in fixture_arrays.items():
        header_lines.extend(lines)

    for group_name, group in categorized_test_cases.items():
        array_name = f"PUBKEY_FIXTURES_{group_name.upper()}"
        header_lines.append(f"static const pubkey_fixture_t {array_name}[] = {{")
        for idx, test_case in enumerate(group.test_cases):
            safe_test_name = sanitize_c_identifier(test_case.name)
            header_lines.append(
                f"// Source: tests/standalone/input_files/pubkey.py > {group_name} > {test_case.name}"
            )
            header_lines.append("{")
            header_lines.append(f"    .name = \"{test_case.name}\",")
            header_lines.append(
                f"    .data = PUBKEY_{group_name}_{idx:03d}_{safe_test_name}_APDU,"
            )
            header_lines.append(
                f"    .data_len = sizeof(PUBKEY_{group_name}_{idx:03d}_{safe_test_name}_APDU),"
            )
            header_lines.append("    .check_expected = SWO_SUCCESS,")
            header_lines.append(
                f"    .expected_response = PUBKEY_{group_name}_{idx:03d}_{safe_test_name}_EXPECTED_RESPONSE,"
            )
            header_lines.append(
                f"    .expected_response_len = sizeof(PUBKEY_{group_name}_{idx:03d}_{safe_test_name}_EXPECTED_RESPONSE),"
            )
            header_lines.append(
                f"    .silent_export_enabled = {'true' if group.silent_export_enabled else 'false'},"
            )
            header_lines.append(
                f"    .expected_policy = {group.expected_policy},"
            )
            header_lines.append("},")
        header_lines.append("};")
        header_lines.append("")

    return "\n".join(header_lines)


def generate_pubkey_fixtures() -> None:
    content = _build_fixtures()
    write_file_safe(FIXTURES_FILE, content)
    print(f"Generated {FIXTURES_FILE}")
