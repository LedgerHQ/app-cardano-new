import argparse
import hashlib
import json
import re
import subprocess
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Type

from common_generators import (
    _ensure_base58_module,
    _add_tests_to_sys_path,
    UNIT_TESTS_DIR,
)

def _load_address_derivation_tests() -> Dict[str, Any]:
    _ensure_base58_module()
    _add_tests_to_sys_path()
    from standalone.input_files.derive_address import (  # type: ignore
        byronTestCases,
    )
    
    era_tests = {
        "byron": byronTestCases,
    }

    return {
        "era_tests": era_tests,
    }

def _extract_apdu_payload_bytes(complete_apdu_command: bytes) -> bytes:
    """
    Extract payload data from a complete APDU command.
    
    APDU command structure:
        [CLA: 1 byte][INS: 1 byte][P1: 1 byte][P2: 1 byte][Lc: 1 byte][Payload: Lc bytes]
    
    Args:
        complete_apdu_command: Full APDU command from CommandBuilder
        
    Returns:
        Just the payload bytes (after the 5-byte header)
    """
    APDU_HEADER_LENGTH = 5
    
    if len(complete_apdu_command) < APDU_HEADER_LENGTH:
        raise ValueError(
            f"APDU command too short: {len(complete_apdu_command)} bytes "
            f"(expected at least {APDU_HEADER_LENGTH})"
        )
    
    # Byte 4 (index 4) contains the payload length
    payload_length = complete_apdu_command[4]
    
    # Extract payload starting at byte 5 (index 5)
    payload_bytes = complete_apdu_command[5 : 5 + payload_length]
    
    if len(payload_bytes) != payload_length:
        raise ValueError(
            f"Payload length mismatch: header says {payload_length} bytes, "
            f"but got {len(payload_bytes)} bytes"
        )
    
    return payload_bytes

def _generate_fixture_code_for_one_test_case(
    test_case: Any,
    test_number: int,
    era_name: str,
) -> List[str]:
    """
    Generate C code lines for a single address derivation test fixture.
    
    Uses CommandBuilder.derive_address() to serialize the test case into
    the APDU format that the Ledger device expects.
    
    Args:
        test_case: DeriveAddressTestCase object from ragger tests
        test_number: Sequential test number (starting from 1)
        era_name: Era identifier ("byron" or "shelley")
        
    Returns:
        List of C code lines (without trailing newlines)
    """
    from application_client.command_builder import CommandBuilder, P1Type  # type: ignore
    
    code_lines = []
    
    # Add a descriptive comment header
    code_lines.append("// ----------------------------------------------------------------------")
    code_lines.append(f"// Test {test_number}: {test_case.name}")
    code_lines.append("// ----------------------------------------------------------------------")
    code_lines.append("")
    
    # Use CommandBuilder to serialize this test case into APDU format
    # This guarantees we use the same serialization logic as the ragger tests
    command_builder = CommandBuilder()
    
    # Determine if address should be displayed to user or just returned
    should_display_address = getattr(test_case, "displayAddress", False)
    p1_parameter = P1Type.P1_ADDRESS_DISPLAY if should_display_address else P1Type.P1_ADDRESS_RETURN
    
    # Generate complete APDU command using trusted serialization
    complete_apdu = command_builder.derive_address(p1_parameter, test_case)
    
    # Extract just the payload (skip the 5-byte APDU header)
    payload_bytes = _extract_apdu_payload_bytes(complete_apdu)
    
    # Generate C array for the APDU payload
    code_lines.append(f"static const uint8_t apdu_payload_{era_name}_{test_number}[] = {{")
    for byte_index in range(0, len(payload_bytes), 16):
        byte_chunk = payload_bytes[byte_index : byte_index + 16]
        hex_values = ", ".join(f"0x{byte:02X}" for byte in byte_chunk)
        code_lines.append(f"    {hex_values},")
    code_lines.append("};")
    code_lines.append("")
    
    # Generate C array for expected address string (null-terminated)
    expected_address = test_case.result
    address_bytes = expected_address.encode("utf-8") + b"\x00"
    
    code_lines.append(f"static const uint8_t expected_address_{era_name}_{test_number}[] = {{")
    for byte_index in range(0, len(address_bytes), 32):
        byte_chunk = address_bytes[byte_index : byte_index + 32]
        hex_values = ", ".join(f"0x{byte:02X}" for byte in byte_chunk)
        code_lines.append(f"    {hex_values},")
    code_lines.append("};")
    code_lines.append("")
    
    # Generate the fixture struct
    code_lines.append(f"static const derive_address_fixture_t fixture_{era_name}_{test_number} = {{")
    code_lines.append(f'    .name = "{test_case.name}",')
    code_lines.append(f"    .data = apdu_payload_{era_name}_{test_number},")
    code_lines.append(f"    .data_len = sizeof(apdu_payload_{era_name}_{test_number}),")
    code_lines.append(f"    .check_expected = (const char *)expected_address_{era_name}_{test_number},")
    code_lines.append("};")
    code_lines.append("")
    
    return code_lines

def _generate_fixtures_for_era(
    era_key: str,
    test_cases: Sequence[Any],
) -> None:
    from application_client.command_builder import CommandBuilder  # type: ignore
    
    print(f"Generating C fixtures for {era_key.upper()} era ({len(test_cases)} tests)...")
    print()
    
    header_lines = [
        f"// Auto-generated fixtures for {era_key.upper()} era transaction tests",
        "// Generated from LedgerJS signTx.ts test cases",
        "//",
        f"// Total tests: {len(test_cases)}",
        "",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        '#include "test_fixture_types.h"',
        "",
        "// ======================================================================",
        "// Fixtures",
        "// ======================================================================",
        "",
        "#if defined(__clang__)",
        "#pragma clang diagnostic push",
        '#pragma clang diagnostic ignored "-Woverlength-strings"',
        "#elif defined(__GNUC__)",
        "#pragma GCC diagnostic push",
        '#pragma GCC diagnostic ignored "-Woverlength-strings"',
        "#endif",
        "",
    ]
    # Generate fixture code for each test case
    for test_number, test_case in enumerate(test_cases, start=1):
        print(f"  [{test_number}/{len(test_cases)}] {test_case.name}")
        
        fixture_code = _generate_fixture_code_for_one_test_case(test_case, test_number, era_key)
        header_lines.extend(fixture_code)
    
    # Generate array of all fixtures
    header_lines.append("// Array of all test fixtures for this era")
    header_lines.append(f"static const derive_address_fixture_t *fixtures_{era_key}[] = {{")
    for test_number in range(1, len(test_cases) + 1):
        header_lines.append(f"    &fixture_{era_key}_{test_number},")
    header_lines.append("};")
    header_lines.append("")
    header_lines.append(f"#define FIXTURE_COUNT_{era_key.upper()} {len(test_cases)}")
    header_lines.append("")
    
    # Restore compiler warning settings
    header_lines.append("#if defined(__clang__)")
    header_lines.append("#pragma clang diagnostic pop")
    header_lines.append("#elif defined(__GNUC__)")
    header_lines.append("#pragma GCC diagnostic pop")
    header_lines.append("#endif")
    header_lines.append("")
    
    # Write to file
    output_file_name = f"test_derive_address_fixtures_{era_key.lower()}.h"
    output_file_path = UNIT_TESTS_DIR / output_file_name
    
    file_content = "\n".join(header_lines)
    output_file_path.write_text(file_content)


def generate_address_derivation_fixtures() -> None:
    print("Generating address derivation fixtures...")
    """
    address_derivation_data = _load_address_derivation_tests()
    era_tests = address_derivation_data["era_tests"]

    for era_key in sorted(era_tests.keys()):
        tests = era_tests[era_key]
        _generate_fixtures_for_era(era_key, tests)
    """
