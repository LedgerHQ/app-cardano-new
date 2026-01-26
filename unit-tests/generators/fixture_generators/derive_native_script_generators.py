from __future__ import annotations

from typing import Any, List
from pathlib import Path

from common import (
    _ensure_base58_module,
    _add_tests_to_sys_path,
    REPO_ROOT,
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
    from standalone.input_files.derive_native_script import (  # type: ignore
        ValidNativeScriptTestCases
    )

    return ValidNativeScriptTestCases


def _is_simple_native_script(native_script) -> bool:
    """
    Determine if a native script is SIMPLE (leaf node in tree).
    
    Following AGENTS.md: "Use long, descriptive variable names"
    
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
    from standalone.input_files.derive_native_script import NativeScriptType  # type: ignore
    
    simple_script_types = {
        NativeScriptType.PUBKEY_DEVICE_OWNED,
        NativeScriptType.PUBKEY_THIRD_PARTY,
        NativeScriptType.INVALID_BEFORE,
        NativeScriptType.INVALID_HEREAFTER,
    }
    
    return native_script.type in simple_script_types


def _parse_bip44_path(path_str: str) -> List[int]:
    """
    Parse BIP44 path string to list of uint32_t components.
    
    Following AGENTS.md: "Use long, descriptive variable names"
    
    Example:
        "m/1852'/1815'/0'/0/0" -> [0x8000073c, 0x80000717, 0x80000000, 0x00000000, 0x00000000]
    
    Args:
        path_str: BIP44 path string (e.g., "m/1852'/1815'/0'/0/0")
        
    Returns:
        List of uint32_t path components with hardened bit set appropriately
    """
    HARDENED_OFFSET = 0x80000000
    
    # Remove 'm/' prefix
    path_str = path_str.replace("m/", "").strip()
    
    path_components = []
    for component_str in path_str.split("/"):
        # Check if hardened (ends with ')
        is_hardened = component_str.endswith("'")
        component_value = int(component_str.rstrip("'"))
        
        # Hardened derivation sets bit 31 (0x80000000)
        if is_hardened:
            component_value |= HARDENED_OFFSET
            
        path_components.append(component_value)
    
    return path_components


def _format_path_component(component: int) -> str:
    """
    Format a BIP44 path component for human-readable comment.
    
    Args:
        component: uint32_t path component
        
    Returns:
        Formatted string (e.g., "1852'" or "0")
    """
    HARDENED_OFFSET = 0x80000000
    
    if component & HARDENED_OFFSET:
        value = component & ~HARDENED_OFFSET
        return f"{value}'"
    else:
        return str(component)


def _generate_simple_native_script_c_struct(
    native_script,
    unique_id: str,
    indent_level: int = 0
) -> List[str]:
    """
    Generate C struct for a SIMPLE native script (leaf node).
    
    Following AGENTS.md: "Mimic Established Patterns"
    
    SIMPLE scripts are leaf nodes in the tree with no children.
    
    Args:
        native_script: NativeScript object (SIMPLE type)
        unique_id: Unique identifier for this script node
        indent_level: Current indentation depth (for nested scripts)
        
    Returns:
        List of C code lines for the script struct
    """
    from standalone.input_files.derive_native_script import NativeScriptType  # type: ignore
    
    fixture_lines = []
    indent = "    " * indent_level
    script_type = native_script.type
    
    # Access params fields correctly based on Python dataclass structure
    
    if script_type == NativeScriptType.PUBKEY_DEVICE_OWNED:
        # NativeScriptParamsPubkey: has 'key' field (BIP44 path string)
        path_str = native_script.params.key
        path_components = _parse_bip44_path(path_str)
        
        fixture_lines.append(f"{indent}// PUBKEY_DEVICE_OWNED (leaf): {path_str}")
        fixture_lines.append(f"{indent}static const uint32_t PATH_{unique_id}[] = {{")
        for component in path_components:
            fixture_lines.append(f"{indent}    0x{component:08x},  // {_format_path_component(component)}")
        fixture_lines.append(f"{indent}}};")
        fixture_lines.append(f"{indent}static const native_script_simple_t SCRIPT_{unique_id} = {{")
        fixture_lines.append(f"{indent}    .type = NATIVE_SCRIPT_TYPE_PUBKEY_DEVICE_OWNED,")
        fixture_lines.append(f"{indent}    .params = {{")
        fixture_lines.append(f"{indent}        .pubkey_device_owned = {{")
        fixture_lines.append(f"{indent}            .path = PATH_{unique_id},")
        fixture_lines.append(f"{indent}            .path_len = {len(path_components)},")
        fixture_lines.append(f"{indent}        }}")
        fixture_lines.append(f"{indent}    }}")
        fixture_lines.append(f"{indent}}};")
        
    elif script_type == NativeScriptType.PUBKEY_THIRD_PARTY:
        # NativeScriptParamsPubkey: has 'key' field (key hash hex string)
        key_hash_hex = native_script.params.key
        key_hash_bytes = bytes.fromhex(key_hash_hex)
        
        fixture_lines.append(f"{indent}// PUBKEY_THIRD_PARTY (leaf): {key_hash_hex}")
        fixture_lines.append(f"{indent}static const uint8_t KEY_HASH_{unique_id}[KEY_HASH_LENGTH] = {{")
        for chunk_start in range(0, len(key_hash_bytes), 8):
            chunk = key_hash_bytes[chunk_start:chunk_start + 8]
            hex_str = ", ".join(f"0x{byte:02x}" for byte in chunk)
            fixture_lines.append(f"{indent}    {hex_str},")
        fixture_lines.append(f"{indent}}};")
        fixture_lines.append(f"{indent}static const native_script_simple_t SCRIPT_{unique_id} = {{")
        fixture_lines.append(f"{indent}    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,")
        fixture_lines.append(f"{indent}    .params = {{")
        fixture_lines.append(f"{indent}        .pubkey_third_party = {{")
        fixture_lines.append(f"{indent}            .key_hash = KEY_HASH_{unique_id},")
        fixture_lines.append(f"{indent}        }}")
        fixture_lines.append(f"{indent}    }}")
        fixture_lines.append(f"{indent}}};")
        
    elif script_type == NativeScriptType.INVALID_BEFORE:
        # NativeScriptParamsInvalid: has 'slot' field
        slot_number = native_script.params.slot
        
        fixture_lines.append(f"{indent}// INVALID_BEFORE (leaf): slot {slot_number}")
        fixture_lines.append(f"{indent}static const native_script_simple_t SCRIPT_{unique_id} = {{")
        fixture_lines.append(f"{indent}    .type = NATIVE_SCRIPT_TYPE_INVALID_BEFORE,")
        fixture_lines.append(f"{indent}    .params = {{")
        fixture_lines.append(f"{indent}        .timelock = {{")
        fixture_lines.append(f"{indent}            .slot = {slot_number}ULL,")
        fixture_lines.append(f"{indent}        }}")
        fixture_lines.append(f"{indent}    }}")
        fixture_lines.append(f"{indent}}};")
        
    elif script_type == NativeScriptType.INVALID_HEREAFTER:
        # NativeScriptParamsInvalid: has 'slot' field
        slot_number = native_script.params.slot
        
        fixture_lines.append(f"{indent}// INVALID_HEREAFTER (leaf): slot {slot_number}")
        fixture_lines.append(f"{indent}static const native_script_simple_t SCRIPT_{unique_id} = {{")
        fixture_lines.append(f"{indent}    .type = NATIVE_SCRIPT_TYPE_INVALID_HEREAFTER,")
        fixture_lines.append(f"{indent}    .params = {{")
        fixture_lines.append(f"{indent}        .timelock = {{")
        fixture_lines.append(f"{indent}            .slot = {slot_number}ULL,")
        fixture_lines.append(f"{indent}        }}")
        fixture_lines.append(f"{indent}    }}")
        fixture_lines.append(f"{indent}}};")
    
    return fixture_lines


def _generate_native_script_tree_recursive(
    native_script,
    base_unique_id: str,
    child_index: int = 0
) -> tuple[List[str], str]:
    """
    Recursively generate C structs for a native script tree.
    
    Following AGENTS.md: "Security focus: Be thorough and paranoid"
    
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
    from standalone.input_files.derive_native_script import NativeScriptType  # type: ignore
    
    current_unique_id = f"{base_unique_id}_C{child_index}"
    fixture_lines = []
    
    is_leaf_node = _is_simple_native_script(native_script)
    
    if is_leaf_node:
        # Leaf node: SIMPLE script (no children)
        simple_script_lines = _generate_simple_native_script_c_struct(
            native_script,
            current_unique_id
        )
        fixture_lines.extend(simple_script_lines)
        return fixture_lines, f"SCRIPT_{current_unique_id}"
    
    else:
        # Internal node: COMPLEX script (has children)
        # Generate all child scripts first (post-order traversal)
        
        script_type = native_script.type
        child_script_identifiers = []
        
        if script_type in (NativeScriptType.ALL, NativeScriptType.ANY):
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
            
            # TODO: Handle zero children - add NULL pointer if needed
            
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
            fixture_lines.append(f"static const native_script_complex_t SCRIPT_{current_unique_id} = {{")
            fixture_lines.append(f"    .type = NATIVE_SCRIPT_TYPE_{script_type.name},")
            fixture_lines.append(f"    .params = {{")
            fixture_lines.append(f"        .scripts = {{")
            fixture_lines.append(f"            .scripts = CHILDREN_{current_unique_id},")
            fixture_lines.append(f"            .scripts_count = {len(child_scripts_list)},")
            fixture_lines.append(f"        }}")
            fixture_lines.append(f"    }}")
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
            for child_id in child_script_identifiers:
                fixture_lines.append(f"    (const native_script_t*)&{child_id},")
            fixture_lines.append("};")
            fixture_lines.append("")
            
            # Generate parent COMPLEX script struct
            fixture_lines.append(f"static const native_script_complex_t SCRIPT_{current_unique_id} = {{")
            fixture_lines.append(f"    .type = NATIVE_SCRIPT_TYPE_N_OF_K,")
            fixture_lines.append(f"    .params = {{")
            fixture_lines.append(f"        .n_of_k = {{")
            fixture_lines.append(f"            .required_count = {required_count},")
            fixture_lines.append(f"            .scripts = CHILDREN_{current_unique_id},")
            fixture_lines.append(f"            .scripts_count = {len(child_scripts_list)},")
            fixture_lines.append(f"        }}")
            fixture_lines.append(f"    }}")
            fixture_lines.append("};")
        
        return fixture_lines, f"SCRIPT_{current_unique_id}"


def _build_fixtures() -> str:
    """
    Generate complete C file content for native script hash derivation fixtures.
    
    Following AGENTS.md: "Mimic Established Patterns"
    
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
        "// Following AGENTS.md: 'Mimic Established Patterns'",
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
        "",
        "// Following AGENTS.md: 'Use long, descriptive variable names'",
        "#define SCRIPT_HASH_LENGTH 28  // Blake2b-224",
        "#define KEY_HASH_LENGTH 28     // Blake2b-224",
        "",
        "// Forward declaration for tree structure",
        "typedef struct native_script_s native_script_t;",
        "",
        "// Native script types (matching CBOR encoding)",
        "typedef enum {",
        "    NATIVE_SCRIPT_TYPE_PUBKEY_DEVICE_OWNED = 0x00,",
        "    NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY = 0xF0,",
        "    NATIVE_SCRIPT_TYPE_ALL = 0x01,",
        "    NATIVE_SCRIPT_TYPE_ANY = 0x02,",
        "    NATIVE_SCRIPT_TYPE_N_OF_K = 0x03,",
        "    NATIVE_SCRIPT_TYPE_INVALID_BEFORE = 0x04,",
        "    NATIVE_SCRIPT_TYPE_INVALID_HEREAFTER = 0x05,",
        "} native_script_type_e;",
        "",
        "// SIMPLE script structure (leaf node)",
        "typedef struct {",
        "    native_script_type_e type;",
        "    union {",
        "        struct {",
        "            const uint32_t* path;",
        "            uint32_t path_len;",
        "        } pubkey_device_owned;",
        "        struct {",
        "            const uint8_t* key_hash;",
        "        } pubkey_third_party;",
        "        struct {",
        "            uint64_t slot;",
        "        } timelock;",
        "    } params;",
        "} native_script_simple_t;",
        "",
        "// COMPLEX script structure (internal node with children)",
        "typedef struct {",
        "    native_script_type_e type;",
        "    union {",
        "        struct {",
        "            const native_script_t** scripts;",
        "            size_t scripts_count;",
        "        } scripts;",
        "        struct {",
        "            uint32_t required_count;",
        "            const native_script_t** scripts;",
        "            size_t scripts_count;",
        "        } n_of_k;",
        "    } params;",
        "} native_script_complex_t;",
        "",
        "// Generic native script (can be simple or complex)",
        "struct native_script_s {",
        "    native_script_type_e type;",
        "    union {",
        "        native_script_simple_t simple;",
        "        native_script_complex_t complex;",
        "    } impl;",
        "};",
        "",
        "// Test case structure",
        "typedef struct {",
        "    const char* name;",
        "    const native_script_t* root_script;  // Root of script tree",
        "    const uint8_t* expected_hash;",
        "    bool nano_skip;",
        "} native_script_test_case_t;",
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
        
        # Store root identifier for test case array
        test_case_root_identifiers.append((base_id, test_case.name, root_script_id, test_case.nano_skip))
    
    # Generate test case array
    header_lines.extend([
        "// ======================================================================",
        "// Test Case Array",
        "// ======================================================================",
        "",
        "static const native_script_test_case_t NATIVE_SCRIPT_FIXTURES[] = {",
    ])
    
    for base_id, name, root_id, nano_skip in test_case_root_identifiers:
        nano_skip_str = "true" if nano_skip else "false"
        header_lines.append(f"    {{")
        header_lines.append(f'        .name = "{name}",')
        header_lines.append(f"        .root_script = (const native_script_t*)&{root_id},")
        header_lines.append(f"        .expected_hash = EXPECTED_HASH_{base_id},")
        header_lines.append(f"        .nano_skip = {nano_skip_str},")
        header_lines.append(f"    }},")
    
    header_lines.extend([
        "};",
        "",
        f"#define NATIVE_SCRIPT_FIXTURES_COUNT {len(test_case_root_identifiers)}",
        "",
    ])
    
    return "\n".join(header_lines)


def generate_derive_native_script_fixtures() -> None:
    """
    Generate native script hash derivation test fixture header.

    This is the main entry point called from generate_unit_tests_from_ragger.py.
    Creates a single header file with all test fixtures as script trees:
    - Leaf nodes: SIMPLE scripts (PUBKEY, INVALID_BEFORE/HEREAFTER)
    - Internal nodes: COMPLEX scripts (ALL, ANY, N_OF_K) containing children
    
    Following AGENTS.md: "Mimic Established Patterns"
    """
    print("Generating derive_native_script_fixtures.h...")
    print()

    fixtures = _build_fixtures()
    FIXTURES_FILE.write_text(fixtures)
    
    print()
    print(f"Generated {FIXTURES_FILE}")