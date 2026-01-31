from __future__ import annotations

from typing import Any, List
from pathlib import Path

from common import (
    write_file_safe,
    _ensure_base58_module,
    _add_tests_to_sys_path,
    REPO_ROOT,
    extract_apdu_payload,
)
    
FIXTURES_FILE = (
    REPO_ROOT / "unit-tests" / "test_derive_native_script_fixtures.h"
)

def _load_native_script_test_cases() -> List[Any]:
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
        ValidNativeScriptTestCases
    )

    return ValidNativeScriptTestCases


def _is_simple_native_script(native_script) -> bool:
    """
    Determine if a native script is SIMPLE (leaf node in tree).
    
    SIMPLE scripts (LEAF NODES) are:
    - PUBKEY_DEVICE_OWNED
    - PUBKEY_THIRD_PARTY
    - INVALID_BEFORE
    - INVALID_HEREAFTER
    
    COMPLEX scripts (INTERNAL NODES) contain child scripts:
    - ALL (contains array of child scripts)
    - ANY (contains array of child scripts)
    - N_OF_K (contains array of child scripts)
    
    Tree structure:
    - Leaf nodes: SIMPLE scripts (no children)
    - Internal nodes: COMPLEX scripts (can contain SIMPLE or COMPLEX children)
    
    Args:
        native_script: NativeScript object from ragger tests
        
    Returns:
        True if script is SIMPLE (leaf), False if COMPLEX (internal node)
    """
    from standalone.input_files.native_script import NativeScriptType  # type: ignore
    
    simple_script_types = {
        NativeScriptType.PUBKEY_DEVICE_OWNED,
        NativeScriptType.PUBKEY_THIRD_PARTY,
        NativeScriptType.INVALID_BEFORE,
        NativeScriptType.INVALID_HEREAFTER,
    }
    
    return native_script.type in simple_script_types

def _generate_simple_script_apdu_array(
    script_identifier: str,
    script: NativeScript,
) -> tuple[List[str], str]:
    """
    Generate APDU payload array for a simple script.
    
    Args:
        script_identifier: Unique identifier for this script
        script: Native script object
    
    Returns:
        Tuple of (C code lines, array name)
    """
    from application_client.command_builder import CommandBuilder

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
) -> List[str]:
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

def _generate_native_script_tree_recursive(
    native_script,
    base_unique_id: str,
    child_index: int = 0
) -> tuple[List[str], str]:
    """
    Recursively generate C structs for a native script tree.
    
    Tree structure:
    - Leaf nodes: SIMPLE scripts (PUBKEY, INVALID_BEFORE/HEREAFTER)
    - Internal nodes: COMPLEX scripts (ALL, ANY, N_OF_K) containing children
    
    This function performs a depth-first traversal of the script tree,
    generating C structs in post-order (children before parents).
    
    Args:
        native_script: NativeScript object (can be SIMPLE or COMPLEX)
        base_unique_id: Base identifier for naming
        child_index: Index of this script among its siblings
        
    Returns:
        Tuple of (list of C code lines, identifier of generated struct)
    """
    from standalone.input_files.native_script import NativeScriptType  # type: ignore
    
    current_unique_id = f"{base_unique_id}_C{child_index}"
    fixture_lines = []
    
    is_leaf_node = _is_simple_native_script(native_script)
    
    if is_leaf_node:
        # Leaf node: SIMPLE script (no children)
        simple_script_lines = _generate_simple_script_fixture(
            current_unique_id,
            native_script
        )
        """
        simple_script_lines = _generate_simple_native_script_c_struct(
            native_script,
            current_unique_id
        )
        """
        fixture_lines.extend(simple_script_lines)
        return fixture_lines, f"SCRIPT_{current_unique_id}"
    
    else:
        # Internal node: COMPLEX script (has children)
        # Generate all child scripts first (post-order traversal)
        
        script_type = native_script.type
        child_script_identifiers = []
        
        if script_type == NativeScriptType.ALL:
            # NativeScriptParamsScripts: has 'scripts' field (list of NativeScript)
            child_scripts_list = native_script.params.scripts
            
            fixture_lines.append(f"// {script_type.name} (internal node): {len(child_scripts_list)} children")
            
            # Recursively generate each child
            for child_idx, child_script in enumerate(child_scripts_list):
                child_lines, child_struct_id = _generate_native_script_tree_recursive(
                    child_script,
                    current_unique_id,
                    child_idx
                )
                fixture_lines.extend(child_lines)
                fixture_lines.append("")
                child_script_identifiers.append(child_struct_id)

            # Generate array of child script pointers
            fixture_lines.append(f"static const native_script_t* CHILDREN_{current_unique_id}[] = {{")
            if(len(child_script_identifiers) == 0):
                fixture_lines.append(f"    NULL")
            else:
                for child_id in child_script_identifiers:
                    fixture_lines.append(f"    (const native_script_t*)&{child_id},")
            fixture_lines.append("};")
            fixture_lines.append("")
            
            # Generate parent COMPLEX script struct
            fixture_lines.append(f"static const native_script_t SCRIPT_{current_unique_id} = {{")
            fixture_lines.append(f"    .type = NATIVE_SCRIPT_TYPE_{script_type.name},")
            fixture_lines.append(f"    .impl = {{")
            fixture_lines.append(f"        .complex = {{")
            fixture_lines.append(f"             .params = {{")
            fixture_lines.append(f"                 .all = {{")
            fixture_lines.append(f"                     .scripts = CHILDREN_{current_unique_id},")
            fixture_lines.append(f"                     .scripts_count = {len(child_scripts_list)},")
            fixture_lines.append(f"                 }}")
            fixture_lines.append(f"             }}")
            fixture_lines.append(f"         }}")
            fixture_lines.append(f"     }}")
            fixture_lines.append("};")
    
        elif script_type == NativeScriptType.ANY:
            # NativeScriptParamsScripts: has 'scripts' field (list of NativeScript)
            child_scripts_list = native_script.params.scripts
            
            fixture_lines.append(f"// {script_type.name} (internal node): {len(child_scripts_list)} children")
            
            # Recursively generate each child
            for child_idx, child_script in enumerate(child_scripts_list):
                child_lines, child_struct_id = _generate_native_script_tree_recursive(
                    child_script,
                    current_unique_id,
                    child_idx
                )
                fixture_lines.extend(child_lines)
                fixture_lines.append("")
                child_script_identifiers.append(child_struct_id)

            # Generate array of child script pointers
            fixture_lines.append(f"static const native_script_t* CHILDREN_{current_unique_id}[] = {{")
            if(len(child_script_identifiers) == 0):
                fixture_lines.append(f"    NULL")
            else:
                for child_id in child_script_identifiers:
                    fixture_lines.append(f"    (const native_script_t*)&{child_id},")
            fixture_lines.append("};")
            fixture_lines.append("")
            
            # Generate parent COMPLEX script struct
            fixture_lines.append(f"static const native_script_t SCRIPT_{current_unique_id} = {{")
            fixture_lines.append(f"    .type = NATIVE_SCRIPT_TYPE_{script_type.name},")
            fixture_lines.append(f"    .impl = {{")
            fixture_lines.append(f"        .complex = {{")
            fixture_lines.append(f"             .params = {{")
            fixture_lines.append(f"                 .any = {{")
            fixture_lines.append(f"                     .scripts = CHILDREN_{current_unique_id},")
            fixture_lines.append(f"                     .scripts_count = {len(child_scripts_list)},")
            fixture_lines.append(f"                 }}")
            fixture_lines.append(f"             }}")
            fixture_lines.append(f"         }}")
            fixture_lines.append(f"     }}")
            fixture_lines.append("};")
            
        elif script_type == NativeScriptType.N_OF_K:
            # NativeScriptParamsNofK: has 'requiredCount' and 'scripts' fields
            required_count = native_script.params.requiredCount
            child_scripts_list = native_script.params.scripts
            
            fixture_lines.append(f"// N_OF_K (internal node): {required_count} of {len(child_scripts_list)} children required")
            
            # Recursively generate each child
            for child_idx, child_script in enumerate(child_scripts_list):
                child_lines, child_struct_id = _generate_native_script_tree_recursive(
                    child_script,
                    current_unique_id,
                    child_idx
                )
                fixture_lines.extend(child_lines)
                fixture_lines.append("")
                child_script_identifiers.append(child_struct_id)
            
            # Generate array of child script pointers
            
            fixture_lines.append(f"static const native_script_t* CHILDREN_{current_unique_id}[] = {{")
            if(len(child_script_identifiers) == 0):
                fixture_lines.append(f"    NULL")
            else:
                for child_id in child_script_identifiers:
                    fixture_lines.append(f"    (const native_script_t*)&{child_id},")
            fixture_lines.append("};")
            fixture_lines.append("")
            
            # Generate parent COMPLEX script struct
            fixture_lines.append(f"static const native_script_t SCRIPT_{current_unique_id} = {{")
            fixture_lines.append(f"    .type = NATIVE_SCRIPT_TYPE_N_OF_K,")
            fixture_lines.append(f"    .impl = {{")
            fixture_lines.append(f"        .complex = {{")
            fixture_lines.append(f"            .params = {{")
            fixture_lines.append(f"                 .n_of_k = {{")
            fixture_lines.append(f"                     .required_count = {required_count},")
            fixture_lines.append(f"                     .scripts = CHILDREN_{current_unique_id},")
            fixture_lines.append(f"                     .scripts_count = {len(child_scripts_list)},")
            fixture_lines.append(f"                 }}")
            fixture_lines.append(f"            }}")
            fixture_lines.append(f"        }}")
            fixture_lines.append(f"    }}")
            fixture_lines.append("};")
        
        return fixture_lines, f"SCRIPT_{current_unique_id}"


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
        '#include "test_fixture_types.h"',
        "",
        "#define SCRIPT_HASH_LENGTH 28  // Blake2b-224",
        "#define KEY_HASH_LENGTH 28     // Blake2b-224",
        "",
        "",
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
         
        header_lines.append(f"// ======================================================================")
        header_lines.append(f"// Test Case [{test_case_index}]: {test_case.name}")
        header_lines.append(f"// Source: tests/standalone/input_files/native_script.py")
        header_lines.append(f"// ======================================================================")
        header_lines.append("")
        
        # Generate expected hash
        expected_hash_bytes = bytes.fromhex(test_case.expected.hash)
        header_lines.append(f"static const uint8_t EXPECTED_HASH_{base_id}[SCRIPT_HASH_LENGTH] = {{")
        for chunk_start in range(0, len(expected_hash_bytes), 8):
            chunk = expected_hash_bytes[chunk_start:chunk_start + 8]
            hex_str = ", ".join(f"0x{byte:02x}" for byte in chunk)
            header_lines.append(f"    {hex_str},")
        header_lines.append("};")
        header_lines.append("")
        
        # Recursively generate script tree
        tree_lines, root_script_id = _generate_native_script_tree_recursive(
            test_case.script,
            base_id,
            0
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
            test_case.nano_skip
        ))
    # Generate test case array
    header_lines.extend([
        "// ======================================================================",
        "// Test Case Array",
        "// ======================================================================",
        "",
        "static const native_script_test_case_t NATIVE_SCRIPT_FIXTURES[] = {",
    ])
    
    for base_id, name, root_id, finish_apdu_array, nano_skip in test_case_root_identifiers:
        nano_skip_str = "true" if nano_skip else "false"
        # Add source traceability comment
        header_lines.append(f"    // Source: tests/standalone/input_files/native_script.py > {name}")
        header_lines.append(f"    {{")
        header_lines.append(f'        .name = "{name}",')
        header_lines.append(f"        .root_script = (const native_script_t*)&{root_id},")
        header_lines.append(f"        .expected_hash = EXPECTED_HASH_{base_id},")
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
) -> tuple[List[str], str]:
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

def generate_derive_native_script_fixtures() -> None:
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