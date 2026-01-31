from __future__ import annotations

from typing import Any, List, NamedTuple
from enum import Enum

from common import (
    _ensure_base58_module,
    _add_tests_to_sys_path,
    REPO_ROOT,
)

FIXTURES_FILE = (
    REPO_ROOT / "unit-tests" / "test_derive_address_fixtures.h"
)

# ==============================================================================
# Step 1: Load Test Cases from Ragger Tests
# ==============================================================================

class P1DisplayType(Enum):
    P1_ADDRESS_RETURN = "P1_ADDRESS_RETURN"
    P1_ADDRESS_DISPLAY = "P1_ADDRESS_DISPLAY"

class TestCaseCategory(NamedTuple):
    p1_value: str
    type: str
    test_cases: List[Any]


def _load_address_derivation_test_cases() -> List[Any]:
    """
    Load address derivation test cases from ragger standalone tests.

    These test cases verify that the device properly handles address
    derivation requests.

    """
    _ensure_base58_module()
    _add_tests_to_sys_path()

    # Import  test cases from ragger standalone input files
    from standalone.input_files.derive_address import (  # type: ignore
        byronTestCases,
        shelleyTestCasesNoConfirm,
        shelleyTestCasesWithConfirm,
    )

    all_test_cases = {
        "byronTestCases": byronTestCases,
        "shelleyTestCasesNoConfirm": shelleyTestCasesNoConfirm,
        "shelleyTestCasesWithConfirm": shelleyTestCasesWithConfirm,
    }
    categorized_test_cases = {
        # Byron addresses with P1_ADDRESS_RETURN (no user confirmation required)
        "test_derive_address_byron": TestCaseCategory(
            p1_value=P1DisplayType.P1_ADDRESS_RETURN.value,
            type="byronTestCases",
            test_cases=byronTestCases
        ),
        "test_derive_address_byron_show": TestCaseCategory(
            p1_value=P1DisplayType.P1_ADDRESS_DISPLAY.value,
            type="byronTestCases",
            test_cases=byronTestCases
        ),
        "test_derive_address_shelley": TestCaseCategory(
            p1_value=P1DisplayType.P1_ADDRESS_RETURN.value,
            type="shelleyTestCasesNoConfirm",
            test_cases=shelleyTestCasesNoConfirm
        ),
        "test_derive_address_shelley_confirm": TestCaseCategory(
            p1_value=P1DisplayType.P1_ADDRESS_RETURN.value,
            type="shelleyTestCasesWithConfirm",
            test_cases=shelleyTestCasesWithConfirm
        ),
        "test_derive_address_shelley_show_no_confirm": TestCaseCategory(
            p1_value=P1DisplayType.P1_ADDRESS_DISPLAY.value,
            type="shelleyTestCasesNoConfirm",
            test_cases=shelleyTestCasesNoConfirm
        ),
        "test_derive_address_shelley_show_with_confirm": TestCaseCategory(
            p1_value=P1DisplayType.P1_ADDRESS_DISPLAY.value,
            type="shelleyTestCasesWithConfirm",
            test_cases=shelleyTestCasesWithConfirm
        ),
    }
    return all_test_cases, categorized_test_cases

# ==============================================================================
# Step 2: Serialize Test Case to APDU Command
# ==============================================================================


def _serialize_test_case_to_apdu(test_case: Any) -> bytes:
    """
    Serialize a  test case into APDU command bytes.

    Uses CommandBuilder.derive_address() to serialize the test case with the
    same logic used by ragger tests. 

    Args:
        test_case: DeriveAddressTestCase object from ragger tests

    Returns:
        Complete APDU command bytes (including header)

    Note:
        P1 parameter doesn't matter since we only need the payload.
    """
    from application_client.command_builder import CommandBuilder, P1Type  # type: ignore

    command_builder = CommandBuilder()
    
    complete_apdu_command = command_builder.derive_address(
        P1Type.P1_ADDRESS_RETURN, # P1 value doesn't matter for payload serialization
        test_case,
    )

    return complete_apdu_command


# ==============================================================================
# Step 3: Generate C Code for Fixtures
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

    return code_lines


def _generate_c_byte_array_from_bytes(
    array_bytes: bytes,
    array_name: str,
    bytes_per_line: int = 16,
) -> List[str]:
    code_lines = []
    code_lines.append(f"static const uint8_t {array_name}[] = {{")
    for byte_index in range(0, len(array_bytes), bytes_per_line):
        byte_chunk = array_bytes[byte_index : byte_index + bytes_per_line]
        hex_values = ", ".join(f"0x{byte:02X}" for byte in byte_chunk)
        code_lines.append(f"    {hex_values},")
    code_lines.append("};")
    return code_lines


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


def _generate_fixture_code_for_test_case(
    type_test: str,
    test_case: Any,
    test_number: int,
) -> List[str]:
    """
    Generate C code for a single address derivation test fixture.

    Args:
        test_case: DeriveAddressTestCase from ragger tests
        test_number: Sequential test number (1-based)

    Returns:
        List of C code lines defining the test fixture
    """
    code_lines = []

    # Add descriptive comment header
    code_lines.append(
        "// ----------------------------------------------------------------------"
    )
    code_lines.append(f"// Test type: {type_test}")
    code_lines.append(f"// Test {test_number}: {test_case.name}")
    code_lines.append(f"// Address Type: {test_case.addrType.name}")
    code_lines.append(f"// Spending: {test_case.spendingValue}")
    if test_case.stakingValue:
        code_lines.append(f"// Staking: {test_case.stakingValue}")
    code_lines.append(
        "// ----------------------------------------------------------------------"
    )
    code_lines.append("")

    # Serialize test case to APDU command using CommandBuilder
    apdu_command_bytes = _serialize_test_case_to_apdu(test_case)

    # Extract just the payload (skip the 5-byte APDU header: CLA, INS, P1, P2, Lc)
    payload_bytes = _extract_apdu_payload_bytes(apdu_command_bytes)

    # Generate safe C identifier from test name
    safe_test_name = _sanitize_test_name_for_c_identifier(test_case.name)

    # Generate C array for complete APDU command
    payload_array_name = (
        f"DERIVE_ADDRESS_{type_test}_{test_number:03d}_{safe_test_name}_APDU"
    )
    payload_array_code = _generate_c_byte_array_for_apdu(
        payload_bytes,
        payload_array_name,
        bytes_per_line=16,
    )
    code_lines.extend(payload_array_code)
    code_lines.append("")

    expected_hex = getattr(test_case, "result_hex", None)
    if expected_hex:
        expected_bytes = bytes.fromhex(expected_hex)
        expected_array_name = (
            f"DERIVE_ADDRESS_{type_test}_{test_number:03d}_{safe_test_name}_EXPECTED_ADDRESS"
        )
        expected_array_code = _generate_c_byte_array_from_bytes(
            expected_bytes,
            expected_array_name,
            bytes_per_line=16,
        )
        code_lines.extend(expected_array_code)
        code_lines.append("")

    return code_lines


# ==============================================================================
# Step 4: Build Complete C Header File
# ==============================================================================


def _build_fixtures() -> str:
    """
    Generate complete C file content for address derivation fixtures.

    Returns:
        Complete C file content as string
    """
    # Load test cases from ragger tests
    all_test_cases, categorized_test_cases = _load_address_derivation_test_cases()

    print(f"Generating fixtures for {len(categorized_test_cases)} categories of test cases...")
    print()

    # Start building header content
    header_lines = [
        "// Auto-generated address derivation test fixtures",
        "// Generated from ragger standalone test cases",
        "//",
        "//",
        f"// Total categories of tests: {len(categorized_test_cases)}",
        "",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        '#include "test_fixture_types.h"',
        '#include "cardano_swo.h"',
        '#include "test_derive_address_common.h"',
        "",
        "// ======================================================================",
        "// Address Derivation Test Fixtures",
        "// ======================================================================",
        "",
        "",
    ]

    # Generate fixture data for each test case
    for type_test, tests in all_test_cases.items():
        print(f"Processing type: {type_test} with {len(tests)} test cases")
        for test_number, test_case in enumerate(tests):
            print(f"  [{test_number}/{len(tests)}] {test_case.name}")

            fixture_code = _generate_fixture_code_for_test_case(
                type_test,
                test_case,
                test_number,
            )
            header_lines.extend(fixture_code)
        
    # For each category, generate fixture arrays
    for category_name, category in categorized_test_cases.items():
        test_cases = category.test_cases
        
        header_lines.append(
            f"static const derive_address_fixture_t DERIVE_ADDRESS_FIXTURES_{category_name.upper()}[] = {{"
        )

        for test_number, test_case in enumerate(test_cases):

            # Generate fixture struct
            # Extract just the payload (skip the 5-byte APDU header: CLA, INS, P1, P2, Lc)
            safe_test_name = _sanitize_test_name_for_c_identifier(test_case.name)
            
            payload_array_name = (
                f"DERIVE_ADDRESS_{category.type}_{test_number:03d}_{safe_test_name}_APDU"
            )
            # Generate safe C identifier from test name
            # Generate C array for complete APDU command
            header_lines.append("{")

            header_lines.append(f'    .name = "{test_case.name}",')
            header_lines.append(f"    .p1 = {category.p1_value},")
            header_lines.append(f"    .data = {payload_array_name},")
            header_lines.append(f"    .data_len = sizeof({payload_array_name}),")
            header_lines.append(f"    .check_expected = SWO_SUCCESS,")
            expected_hex = getattr(test_case, "result_hex", None)
            if expected_hex:
                expected_array_name = (
                    f"DERIVE_ADDRESS_{category.type}_{test_number:03d}_{safe_test_name}_EXPECTED_ADDRESS"
                )
                header_lines.append(f"    .expected_address = {expected_array_name},")
                header_lines.append(f"    .expected_address_len = sizeof({expected_array_name}),")
            else:
                header_lines.append("    .expected_address = NULL,")
                header_lines.append("    .expected_address_len = 0,")
            header_lines.append("},")

        header_lines.append("};")
        header_lines.append("")

    return "\n".join(header_lines)

# ==============================================================================
# Step 5: Main Entry Point
# ==============================================================================


def generate_address_derivation_fixtures() -> None:
    """
    Generate address derivation test fixture header.

    This is the main entry point called from generate_unit_tests_from_ragger.py.
    Creates a single header file with all test fixtures.
    
    """

    # Build header file content
    fixtures = _build_fixtures()
    # Write to file
    FIXTURES_FILE.write_text(fixtures)
    print(f"Generated {FIXTURES_FILE}")
