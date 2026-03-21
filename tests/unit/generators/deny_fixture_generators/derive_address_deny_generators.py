# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from typing import Any

from common import (
    write_generated_c_file,
    sanitize_c_identifier,
    _ensure_base58_module,
    _add_tests_to_sys_path,
    extract_apdu_payload,
    format_bytes_as_c_array,
)
from paths import GENERATED_DERIVE_ADDRESS_DIR
from application_client.command_builder import P1Type

GENERATED_DENY_HEADER = GENERATED_DERIVE_ADDRESS_DIR / "test_address_derivation_fixtures_deny.h"

# ==============================================================================
# Step 1: Load Deny Test Cases from Ragger Tests
# ==============================================================================


def _load_address_derivation_deny_test_cases() -> list[Any]:
    """
    Load address derivation deny test cases from ragger standalone tests.

    These test cases verify that the device properly denies invalid address
    derivation requests according to the security policy. Each test case
    represents a violation of BIP44 path validation or address type rules.

    Returns:
        List of DeriveAddressTestCase objects that should be denied
    """
    _ensure_base58_module()
    _add_tests_to_sys_path()

    # Import deny test cases from ragger standalone input files
    from standalone.input_files.derive_address import (  # type: ignore
        denyTestCases,
    )

    return denyTestCases


# ==============================================================================
# Step 2: Serialize Test Case to APDU Command
# ==============================================================================


def _serialize_deny_test_case_to_apdu(test_case: Any) -> bytes:
    """
    Serialize a deny test case into APDU command bytes.

    Uses CommandBuilder.derive_address() to serialize the test case with the
    same logic used by ragger tests. This ensures we test deny of properly
    formatted APDUs that violate security policy (not malformed APDUs).

    Args:
        test_case: DeriveAddressTestCase object from ragger deny tests

    Returns:
        Complete APDU command bytes (including header)

    Note:
        For deny tests, P1 parameter doesn't matter since the request
        should be denied before display logic is reached.
    """
    from application_client.command_builder import CommandBuilder, P1Type  # type: ignore

    command_builder = CommandBuilder()

    # Use P1_ADDRESS_RETURN for deny tests (simpler, display shouldn't be reached)
    complete_apdu_command = command_builder.derive_address(
        P1Type.P1_ADDRESS_RETURN,
        test_case,
    )

    return complete_apdu_command


# ==============================================================================
# Step 3: Generate C Code for Deny Fixtures
# ==============================================================================



def _format_hex_comment(data: bytes, line_width: int | None = None) -> list[str]:
    """
    Produce comment lines containing a compact hex representation of the data.

    Args:
        data: Raw bytes to describe
        line_width: Maximum number of hex characters per comment line; if None use entire string

    Returns:
        List of comment lines with uppercase hex strings
    """
    if not data:
        return []

    hex_string = data.hex().upper()
    width = len(hex_string) if line_width is None else max(1, line_width)
    lines = []
    for start in range(0, len(hex_string), width):
        chunk = hex_string[start : start + width]
        lines.append(f"// {chunk}")

    return lines


def _generate_c_byte_array_for_apdu(
    apdu_bytes: bytes,
    array_name: str,
    bytes_per_line: int = 16,
) -> list[str]:
    """
    Generate C code lines for a byte array containing APDU command.

    Args:
        apdu_bytes: Raw APDU command bytes
        array_name: C identifier for the array
        bytes_per_line: Number of bytes to display per line (for readability)

    Returns:
        List of C code lines defining the byte array
    """
    code_lines = format_bytes_as_c_array(
        apdu_bytes,
        array_name,
        bytes_per_line=bytes_per_line,
        return_as_list=True,
    )

    hex_comment_lines = _format_hex_comment(apdu_bytes)
    code_lines.extend(hex_comment_lines)

    return code_lines


def _get_expected_deny_reason(test_case: Any) -> str:
    """
    Determine the expected deny reason based on test case characteristics.

    This maps the test case to the expected error code from securityPolicy.c
    validation logic.

    Args:
        test_case: DeriveAddressTestCase from deny tests

    Returns:
        String describing expected deny reason (for documentation)

    Note:
        The actual deny is tested by verifying the handler returns an
        error status code. This string is for human-readable documentation.
    """
    test_name_lower = test_case.name.lower()

    # Map test characteristics to expected deny reasons
    if "path too short" in test_name_lower:
        return "SWO_SECURITY_CONDITION_NOT_SATISFIED"
    elif "invalid path" in test_name_lower:
        return "SWO_SECURITY_CONDITION_NOT_SATISFIED"
    elif "byron with shelley" in test_name_lower or "shelley path" in test_name_lower:
        return "SWO_SECURITY_CONDITION_NOT_SATISFIED"
    elif (
        "wrong spending path" in test_name_lower
        or "wrong staking path" in test_name_lower
    ):
        return "SWO_SECURITY_CONDITION_NOT_SATISFIED"
    elif "scripthash/keyhash not allowed" in test_name_lower:
        return "SWO_SECURITY_CONDITION_NOT_SATISFIED"
    else:
        return "SWO_SECURITY_CONDITION_NOT_SATISFIED"


def _generate_fixture_code_for_deny_test_case(
    test_case: Any,
    test_number: int,
) -> list[str]:
    """
    Generate C code for a single address derivation deny test fixture.

    Args:
        test_case: DeriveAddressTestCase from ragger deny tests
        test_number: Sequential test number (1-based)

    Returns:
        List of C code lines defining the deny test fixture
    """
    code_lines = []

    # Get expected deny reason for documentation
    deny_reason = _get_expected_deny_reason(test_case)

    # Add descriptive comment header
    code_lines.append(
        "// ----------------------------------------------------------------------"
    )
    code_lines.append(f"// Deny Test {test_number}: {test_case.name}")
    code_lines.append(f"// Expected deny SW: {deny_reason}")
    code_lines.append(f"// Address Type: {test_case.addrType.name}")
    code_lines.append(f"// Source: tests/standalone/input_files/derive_address.py > deny tests > {test_case.name}")
    code_lines.append(f"// Spending: {test_case.spendingValue}")
    if test_case.stakingValue:
        code_lines.append(f"// Staking: {test_case.stakingValue}")
    code_lines.append(
        "// ----------------------------------------------------------------------"
    )
    code_lines.append("")

    # Serialize test case to APDU command using CommandBuilder
    apdu_command_bytes = _serialize_deny_test_case_to_apdu(test_case)

    # Extract just the payload (skip the 5-byte APDU header: CLA, INS, P1, P2, Lc)
    payload_bytes = extract_apdu_payload(apdu_command_bytes)

    # Generate safe C identifier from test name
    safe_test_name = sanitize_c_identifier(test_case.name)

    # Generate C array for complete APDU command
    payload_array_name = (
        f"DERIVE_ADDRESS_DENY_{test_number:03d}_{safe_test_name}_APDU"
    )
    payload_array_code = _generate_c_byte_array_for_apdu(
        payload_bytes,
        payload_array_name,
        bytes_per_line=16,
    )
    code_lines.extend(payload_array_code)
    code_lines.append("")

    return code_lines


# ==============================================================================
# Step 4: Build Complete C Header File
# ==============================================================================


def _build_deny_fixtures_header() -> str:
    """
    Generate complete C header file content for address derivation deny fixtures.

    Returns:
        Complete C header file content as string
    """
    # Load deny test cases from ragger tests
    deny_test_cases = _load_address_derivation_deny_test_cases()

    print(f"Generating deny fixtures for {len(deny_test_cases)} test cases...")
    print()

    # Start building header content
    header_lines = [
        "// Auto-generated address derivation deny-test fixtures",
        "// Generated from ragger standalone test cases",
        "//",
        "// These tests verify that the device properly denies invalid address",
        "// derivation requests according to the security policy defined in",
        "// src/securityPolicy/securityPolicy.c",
        "//",
        f"// Total deny tests: {len(deny_test_cases)}",
        "",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        '#include "test_fixture_types.h"',
        '#include "cardano_swo.h"',
        "",
        f"#define P1_ADDRESS_RETURN  0x{int(P1Type.P1_ADDRESS_RETURN):02X}",
        "// ======================================================================",
        "// Address Derivation Deny Test Fixtures",
        "// ======================================================================",
        "",
        "",
    ]

    # Generate fixture code for each deny test case
    for test_number, test_case in enumerate(deny_test_cases, start=1):
        print(f"  [{test_number}/{len(deny_test_cases)}] {test_case.name}")

        fixture_code = _generate_fixture_code_for_deny_test_case(
            test_case,
            test_number,
        )
        header_lines.extend(fixture_code)

    header_lines.append(
        "static const derive_address_fixture_t DERIVE_ADDRESS_DENY_FIXTURES[] = {"
    )

    for test_number, test_case in enumerate(deny_test_cases, start=1):
        # Generate fixture struct
        # Extract just the payload (skip the 5-byte APDU header: CLA, INS, P1, P2, Lc)
        safe_test_name = sanitize_c_identifier(test_case.name)
        payload_array_name = (
            f"DERIVE_ADDRESS_DENY_{test_number:03d}_{safe_test_name}_APDU"
        )
        # Generate safe C identifier from test name
        deny_reason = _get_expected_deny_reason(test_case)

        # Add source traceability comment
        header_lines.append(f"// Source: tests/standalone/input_files/derive_address.py > deny tests > {test_case.name}")
        header_lines.append("{")

        header_lines.append(f'    .name = "{test_case.name}",')
        header_lines.append("    .p1 = P1_ADDRESS_RETURN,")
        header_lines.append(f"    .data = {payload_array_name},")
        header_lines.append(f"    .data_len = sizeof({payload_array_name}),")
        header_lines.append(f"    .check_expected = {deny_reason},")
        header_lines.append("},")

    header_lines.append("};")
    header_lines.append("")


    header_lines.append(
        f"#define DERIVE_ADDRESS_DENY_FIXTURE_COUNT {len(deny_test_cases)}"
    )
    
    print()
    print(f"Generated {len(deny_test_cases)} deny test fixtures")

    return "\n".join(header_lines)


# ==============================================================================
# Step 5: Main Entry Point
# ==============================================================================


def generate_address_derivation_deny_fixtures() -> None:
    """
    Generate address derivation deny-test fixture header.

    This is the main entry point called from generate_unit_tests_from_ragger.py.
    Creates a single header file with all deny test fixtures.

    The generated fixtures test that the device properly denies invalid
    address derivation requests according to securityPolicy.c validation rules.
    """

    # Build header file content
    header_content = _build_deny_fixtures_header()
    # Write to file
    write_generated_c_file(GENERATED_DENY_HEADER, header_content)
    print(f"Generated {GENERATED_DENY_HEADER}")
