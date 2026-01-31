from __future__ import annotations

from typing import Any, List

from common import (
    write_file_safe,
    _ensure_base58_module,
    _add_tests_to_sys_path,
    REPO_ROOT,
)

GENERATED_REJECT_HEADER = (
    REPO_ROOT / "unit-tests" / "test_address_derivation_fixtures_rejects.h"
)

# ==============================================================================
# Step 1: Load Rejection Test Cases from Ragger Tests
# ==============================================================================


def _load_address_derivation_reject_test_cases() -> List[Any]:
    """
    Load address derivation rejection test cases from ragger standalone tests.

    These test cases verify that the device properly rejects invalid address
    derivation requests according to the security policy. Each test case
    represents a violation of BIP44 path validation or address type rules.

    Returns:
        List of DeriveAddressTestCase objects that should be rejected
    """
    _ensure_base58_module()
    _add_tests_to_sys_path()

    # Import rejection test cases from ragger standalone input files
    from standalone.input_files.derive_address import (  # type: ignore
        rejectTestCases,
    )

    return rejectTestCases


# ==============================================================================
# Step 2: Serialize Test Case to APDU Command
# ==============================================================================


def _serialize_reject_test_case_to_apdu(test_case: Any) -> bytes:
    """
    Serialize a rejection test case into APDU command bytes.

    Uses CommandBuilder.derive_address() to serialize the test case with the
    same logic used by ragger tests. This ensures we test rejection of properly
    formatted APDUs that violate security policy (not malformed APDUs).

    Args:
        test_case: DeriveAddressTestCase object from ragger reject tests

    Returns:
        Complete APDU command bytes (including header)

    Note:
        For rejection tests, P1 parameter doesn't matter since the request
        should be rejected before display logic is reached.
    """
    from application_client.command_builder import CommandBuilder, P1Type  # type: ignore

    command_builder = CommandBuilder()

    # Use P1_ADDRESS_RETURN for rejection tests (simpler, display shouldn't be reached)
    complete_apdu_command = command_builder.derive_address(
        P1Type.P1_ADDRESS_RETURN,
        test_case,
    )

    return complete_apdu_command


# ==============================================================================
# Step 3: Generate C Code for Rejection Fixtures
# ==============================================================================


def _sanitize_test_name_for_c_identifier(test_name: str) -> str:
    """
    Convert test name to valid C identifier.

    Args:
        test_name: Human-readable test name from DeriveAddressTestCase

    Returns:
        Valid C identifier in UPPER_SNAKE_CASE

    Example:
        >>> _sanitize_test_name_for_c_identifier("path too short")
        'PATH_TOO_SHORT'
        >>> _sanitize_test_name_for_c_identifier("base key/key with wrong path")
        'BASE_KEY_KEY_WITH_WRONG_PATH'
    """
    # Replace non-alphanumeric characters with underscores
    safe_name = "".join(
        character if character.isalnum() else "_" for character in test_name
    )

    # Collapse multiple consecutive underscores
    while "__" in safe_name:
        safe_name = safe_name.replace("__", "_")

    return safe_name.strip("_").upper()


def _format_hex_comment(data: bytes, line_width: int | None = None) -> List[str]:
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
) -> List[str]:
    """
    Generate C code lines for a byte array containing APDU command.

    Args:
        apdu_bytes: Raw APDU command bytes
        array_name: C identifier for the array
        bytes_per_line: Number of bytes to display per line (for readability)

    Returns:
        List of C code lines defining the byte array
    """
    code_lines = []

    code_lines.append(f"static const uint8_t {array_name}[] = {{")

    for byte_index in range(0, len(apdu_bytes), bytes_per_line):
        byte_chunk = apdu_bytes[byte_index : byte_index + bytes_per_line]
        hex_values = ", ".join(f"0x{byte:02X}" for byte in byte_chunk)
        code_lines.append(f"    {hex_values},")

    code_lines.append("};")

    hex_comment_lines = _format_hex_comment(apdu_bytes)
    code_lines.extend(hex_comment_lines)

    return code_lines


def _get_expected_rejection_reason(test_case: Any) -> str:
    """
    Determine the expected rejection reason based on test case characteristics.

    This maps the test case to the expected error code from securityPolicy.c
    validation logic.

    Args:
        test_case: DeriveAddressTestCase from reject tests

    Returns:
        String describing expected rejection reason (for documentation)

    Note:
        The actual rejection is tested by verifying the handler returns an
        error status code. This string is for human-readable documentation.
    """
    test_name_lower = test_case.name.lower()

    # Map test characteristics to expected rejection reasons
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


def _extract_apdu_payload_bytes(complete_apdu_command: bytes) -> bytes:
    """
    Extract payload data from a complete APDU command.

    APDU command structure:
        [CLA: 1 byte][INS: 1 byte][P1: 1 byte][P2: 1 byte][Lc: 1 byte][Payload: Lc bytes]

    Args:
        complete_apdu_command: Full APDU command from CommandBuilder

    Returns:
        Just the payload bytes (after the 5-byte header)

    Raises:
        ValueError: If APDU structure is invalid
    """
    APDU_HEADER_LENGTH = 5

    if len(complete_apdu_command) < APDU_HEADER_LENGTH:
        raise ValueError(
            f"APDU command too short: {len(complete_apdu_command)} bytes "
            f"(expected at least {APDU_HEADER_LENGTH})"
        )

    # Byte 4 (index 4) contains the payload length (Lc field)
    payload_length = complete_apdu_command[4]

    # Extract payload starting at byte 5 (index 5)
    payload_bytes = complete_apdu_command[5 : 5 + payload_length]

    if len(payload_bytes) != payload_length:
        raise ValueError(
            f"Payload length mismatch: Lc field says {payload_length} bytes, "
            f"but got {len(payload_bytes)} bytes"
        )

    return payload_bytes


def _generate_fixture_code_for_reject_test_case(
    test_case: Any,
    test_number: int,
) -> List[str]:
    """
    Generate C code for a single address derivation rejection test fixture.

    Args:
        test_case: DeriveAddressTestCase from ragger reject tests
        test_number: Sequential test number (1-based)

    Returns:
        List of C code lines defining the rejection test fixture
    """
    code_lines = []

    # Get expected rejection reason for documentation
    rejection_reason = _get_expected_rejection_reason(test_case)

    # Add descriptive comment header
    code_lines.append(
        "// ----------------------------------------------------------------------"
    )
    code_lines.append(f"// Reject Test {test_number}: {test_case.name}")
    code_lines.append(f"// Expected rejection: {rejection_reason}")
    code_lines.append(f"// Address Type: {test_case.addrType.name}")
    code_lines.append(f"// Spending: {test_case.spendingValue}")
    if test_case.stakingValue:
        code_lines.append(f"// Staking: {test_case.stakingValue}")
    code_lines.append(
        "// ----------------------------------------------------------------------"
    )
    code_lines.append("")

    # Serialize test case to APDU command using CommandBuilder
    apdu_command_bytes = _serialize_reject_test_case_to_apdu(test_case)

    # Extract just the payload (skip the 5-byte APDU header: CLA, INS, P1, P2, Lc)
    payload_bytes = _extract_apdu_payload_bytes(apdu_command_bytes)

    # Generate safe C identifier from test name
    safe_test_name = _sanitize_test_name_for_c_identifier(test_case.name)

    # Generate C array for complete APDU command
    payload_array_name = (
        f"DERIVE_ADDRESS_REJECT_{test_number:03d}_{safe_test_name}_APDU"
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


def _build_reject_fixtures_header() -> str:
    """
    Generate complete C header file content for address derivation rejection fixtures.

    Returns:
        Complete C header file content as string
    """
    # Load rejection test cases from ragger tests
    reject_test_cases = _load_address_derivation_reject_test_cases()

    print(f"Generating rejection fixtures for {len(reject_test_cases)} test cases...")
    print()

    # Start building header content
    header_lines = [
        "// Auto-generated address derivation rejection test fixtures",
        "// Generated from ragger standalone test cases",
        "//",
        "// These tests verify that the device properly rejects invalid address",
        "// derivation requests according to the security policy defined in",
        "// src/securityPolicy.c",
        "//",
        f"// Total rejection tests: {len(reject_test_cases)}",
        "",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        '#include "test_fixture_types.h"',
        '#include "cardano_swo.h"',
        "",
        "#define P1_ADDRESS_RETURN  0x20",
        "// ======================================================================",
        "// Address Derivation Rejection Test Fixtures",
        "// ======================================================================",
        "",
        "",
    ]

    # Generate fixture code for each rejection test case
    for test_number, test_case in enumerate(reject_test_cases, start=1):
        print(f"  [{test_number}/{len(reject_test_cases)}] {test_case.name}")

        fixture_code = _generate_fixture_code_for_reject_test_case(
            test_case,
            test_number,
        )
        header_lines.extend(fixture_code)

    header_lines.append(
        "static const derive_address_fixture_t DERIVE_ADDRESS_REJECT_FIXTURES[] = {"
    )

    for test_number, test_case in enumerate(reject_test_cases, start=1):
        # Generate fixture struct
        # Extract just the payload (skip the 5-byte APDU header: CLA, INS, P1, P2, Lc)
        safe_test_name = _sanitize_test_name_for_c_identifier(test_case.name)
        payload_array_name = (
            f"DERIVE_ADDRESS_REJECT_{test_number:03d}_{safe_test_name}_APDU"
        )
        # Generate safe C identifier from test name
        rejection_reason = _get_expected_rejection_reason(test_case)

        # Generate C array for complete APDU command
        header_lines.append("{")

        header_lines.append(f'    .name = "{test_case.name}",')
        header_lines.append(f"    .p1 = P1_ADDRESS_RETURN,")
        header_lines.append(f"    .data = {payload_array_name},")
        header_lines.append(f"    .data_len = sizeof({payload_array_name}),")
        header_lines.append(f"    .check_expected = {rejection_reason},")
        header_lines.append("},")

    header_lines.append("};")
    header_lines.append("")


    header_lines.append(
        f"#define DERIVE_ADDRESS_REJECT_FIXTURE_COUNT {len(reject_test_cases)}"
    )
    
    print()
    print(f"Generated {len(reject_test_cases)} rejection test fixtures")

    return "\n".join(header_lines)


# ==============================================================================
# Step 5: Main Entry Point
# ==============================================================================


def generate_address_derivation_reject_fixtures() -> None:
    """
    Generate address derivation rejection test fixture header.

    This is the main entry point called from generate_unit_tests_from_ragger.py.
    Creates a single header file with all rejection test fixtures.

    The generated fixtures test that the device properly rejects invalid
    address derivation requests according to securityPolicy.c validation rules.
    """

    # Build header file content
    header_content = _build_reject_fixtures_header()
    # Write to file
    write_file_safe(GENERATED_REJECT_HEADER, header_content)
    print(f"Generated {GENERATED_REJECT_HEADER}")
