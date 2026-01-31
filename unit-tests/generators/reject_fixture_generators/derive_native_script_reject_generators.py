from __future__ import annotations

from typing import Any

from common import (
    write_file_safe,
    _ensure_base58_module,
    _add_tests_to_sys_path,
    extract_apdu_payload,
)
from paths import UNIT_TESTS_DIR
from native_script_codegen import generate_native_script_tree_recursive
    
FIXTURES_FILE = UNIT_TESTS_DIR / "test_derive_native_script_reject_fixtures.h"

def _load_native_script_test_cases() -> list[Any]:
    """
    Load native script test cases from ragger standalone tests.

    These test cases verify that the device properly handles native script
    hash derivation requests.

    Returns:
        List of ValidNativeScriptTestCase objects from ragger tests
    """
    _ensure_base58_module()
    _add_tests_to_sys_path()

    # Import test cases from ragger standalone input files
    from standalone.input_files.native_script import (  # type: ignore
        InvalidScriptTestCases
    )

    return InvalidScriptTestCases


def _generate_simple_script_apdu_array(
    script_identifier: str,
    script: NativeScript,
) -> tuple[list[str], str]:
    """
    Generate APDU payload array for a simple script.
    
    Args:
        script_identifier: Unique identifier for this script
        script: Native script object
    
    Returns:
        Tuple of (C code lines, array name)
    """
    from application_client.command_builder import CommandBuilder  # type: ignore

    command_builder = CommandBuilder()
    full_apdu = command_builder.derive_script_add_simple(script)
    apdu_payload = extract_apdu_payload(full_apdu)
    
    lines = []
    array_name = f"APDU_PAYLOAD_{script_identifier}"
    
    lines.append(f"// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE")
    lines.append(f"// Script type: {script.type.name}")
    lines.append(f"static const uint8_t {array_name}[{len(apdu_payload)}] = {{")
    
    # Format bytes in rows of 8 for readability
    for i in range(0, len(apdu_payload), 8):
        byte_chunk = apdu_payload[i:i+8]
        hex_bytes = ", ".join(f"0x{b:02x}" for b in byte_chunk)
        trailing_comma = "," if i + 8 < len(apdu_payload) else ""
        lines.append(f"    {hex_bytes}{trailing_comma}")
    
    lines.append("};")
    lines.append("")
    
    return lines, array_name

def _generate_simple_script_fixture(
    script_identifier: str,
    script: NativeScript,
) -> list[str]:
    """
    Generate complete simple script fixture.
    
    Args:
        script_identifier: Unique identifier
        script: Native script object
    
    Returns:
        List of C code lines
    """
    lines = []
    
    # Generate APDU payload array
    apdu_lines, apdu_array_name = _generate_simple_script_apdu_array(
        script_identifier, script
    )
    lines.extend(apdu_lines)
    
    # Generate script structure
    script_type_enum = f"NATIVE_SCRIPT_TYPE_{script.type.name}"
    
    lines.append(f"static const native_script_t SCRIPT_{script_identifier} = {{")
    lines.append(f"    .type = {script_type_enum},")
    lines.append(f"    .impl = {{")
    lines.append(f"        .simple = {{")
    lines.append(f"            .apdu_payload = {apdu_array_name},")
    lines.append(f"            .apdu_payload_length = sizeof({apdu_array_name}),")
    lines.append(f"        }}")
    lines.append(f"    }}")
    lines.append("};")
    lines.append("")
    
    return lines


def _build_fixtures() -> str:
    """
    Generate complete C file content for native script hash derivation fixtures.
     
    Tree structure:
    - Each test case is a root of a native script tree
    - Leaf nodes: SIMPLE scripts (PUBKEY, INVALID_BEFORE/HEREAFTER)
    - Internal nodes: COMPLEX scripts (ALL, ANY, N_OF_K) with children
    
    Returns:
        Complete C file content as string
    """
    # Load test cases from ragger tests
    all_test_cases = _load_native_script_test_cases()
    
    print(f"  Loaded {len(all_test_cases)} test cases")
    print()

    # Start building header content
    header_lines = [
        "// Auto-generated native script hash derivation test fixtures",
        "// Generated from ragger standalone test cases",
        "//",
        "//",
        "// Tree Structure:",
        "//   - Each test case is a root of a native script tree",
        "//   - Leaf nodes (SIMPLE scripts): PUBKEY_DEVICE_OWNED, PUBKEY_THIRD_PARTY,",
        "//                                   INVALID_BEFORE, INVALID_HEREAFTER",
        "//   - Internal nodes (COMPLEX scripts): ALL, ANY, N_OF_K",
        "//   - Internal nodes contain children (can be leaf or internal nodes)",
        "//",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        '#include "cardano_swo.h"',
        '#include "status_words.h"',
        '#include "test_fixture_types.h"',
        "",
        "#define SCRIPT_HASH_LENGTH 28  // Blake2b-224",
        "#define KEY_HASH_LENGTH 28     // Blake2b-224",
        "",
        "",
        "// ======================================================================",
        "// Native Script Tree Fixtures",
        "// ======================================================================",
        "",
    ]
    
    # Generate each test case as a script tree
    test_case_root_identifiers = []
    
    for test_case_index, test_case in enumerate(all_test_cases):
        test_case_name_sanitized = test_case.name.replace(" ", "_").replace("#", "NUM")
        base_id = f"TC{test_case_index}_{test_case_name_sanitized.upper()}"
        
        print(f"  [{test_case_index:2d}] Generating tree for: {test_case.name}")
        
        header_lines.append(f"// ======================================================================")
        header_lines.append(f"// Test Case [{test_case_index}]: {test_case.name}")
        header_lines.append(f"// Source: tests/standalone/input_files/native_script.py > reject tests")
        header_lines.append(f"// ======================================================================")
        header_lines.append("")
        
        # Recursively generate script tree
        tree_lines, root_script_id = generate_native_script_tree_recursive(
            test_case.script,
            base_id,
            0,
            _generate_simple_script_fixture
        )
        header_lines.extend(tree_lines)
        header_lines.append("")
        
        # Generate finish APDU payload
        finish_lines, finish_array_name = _generate_finish_apdu_payload(
            base_id,
            test_case.displayFormat
        )
        header_lines.extend(finish_lines)
        
        # Store root identifier for test case array
        test_case_root_identifiers.append((
            base_id,
            test_case.name,
            root_script_id,
            finish_array_name,
            test_case.nano_skip,
            test_case.expected.sw.name
        ))
    # Generate test case array
    header_lines.extend([
        "// ======================================================================",
        "// Test Case Array",
        "// ======================================================================",
        "",
        "static const native_script_test_case_t NATIVE_SCRIPT_FIXTURES[] = {",
    ])
    
    for base_id, name, root_id, finish_apdu_array, nano_skip, expected_swo in test_case_root_identifiers:
        nano_skip_str = "true" if nano_skip else "false"
        # Add source traceability comment
        header_lines.append(f"    // Source: tests/standalone/input_files/native_script.py > reject tests > {name}")
        header_lines.append(f"    {{")
        header_lines.append(f'        .name = "{name}",')
        header_lines.append(f"        .root_script = (const native_script_t*)&{root_id},")
        header_lines.append(f"        .expected_response = {expected_swo},")
        header_lines.append(f"        .nano_skip = {nano_skip_str},")
        header_lines.append(f"        .finish_apdu_payload = {finish_apdu_array},")
        header_lines.append(f"        .finish_apdu_payload_length = sizeof({finish_apdu_array}),")
        header_lines.append(f"    }},")
    
    header_lines.extend([
        "};",
        "",
        f"#define NATIVE_SCRIPT_FIXTURES_COUNT {len(test_case_root_identifiers)}",
        "",
    ])
    
    return "\n".join(header_lines)

def _generate_finish_apdu_payload(
    test_case_id: str,
    display_format,
) -> tuple[list[str], str]:
    """
    Generate APDU payload for derive_script_finish.
    
    Args:
        test_case_id: Test case identifier
        display_format: NativeScriptHashDisplayFormat enum value from test case
    
    Returns:
        Tuple of (C code lines, array name)
    """
    from application_client.command_builder import CommandBuilder  # type: ignore
    
    command_builder = CommandBuilder()
    full_apdu = command_builder.derive_script_finish(display_format)
    apdu_payload = extract_apdu_payload(full_apdu)
    
    lines = []
    array_name = f"FINISH_APDU_PAYLOAD_{test_case_id}"
    
    lines.append(f"// APDU payload for P1_NATIVE_SCRIPT_FINISH")
    lines.append(f"// Display format: {display_format.name} (0x{display_format.value:02x})")
    lines.append(f"static const uint8_t {array_name}[{len(apdu_payload)}] = {{")
    
    # Format bytes in rows of 8 for readability
    for i in range(0, len(apdu_payload), 8):
        byte_chunk = apdu_payload[i:i+8]
        hex_bytes = ", ".join(f"0x{b:02x}" for b in byte_chunk)
        trailing_comma = "," if i + 8 < len(apdu_payload) else ""
        lines.append(f"    {hex_bytes}{trailing_comma}")
    
    lines.append("};")
    lines.append("")
    
    return lines, array_name

def generate_derive_native_script_reject_fixtures() -> None:
    """
    Generate native script hash derivation test fixture header.

    This is the main entry point called from generate_unit_tests_from_ragger.py.
    Creates a single header file with all test fixtures as script trees:
    - Leaf nodes: SIMPLE scripts (PUBKEY, INVALID_BEFORE/HEREAFTER)
    - Internal nodes: COMPLEX scripts (ALL, ANY, N_OF_K) containing children
    

    """
    print("Generating derive_native_script_fixtures.h...")
    print()

    fixtures = _build_fixtures()
    write_file_safe(FIXTURES_FILE, fixtures)
    
    print()
    print(f"Generated {FIXTURES_FILE}")
