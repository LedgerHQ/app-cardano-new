"""
Shared code generation utilities for native script fixtures.

This module contains the recursive tree generation logic used by both
fixture generators (valid and reject test cases).
"""

from __future__ import annotations
from typing import Any


def _is_simple_native_script(native_script: Any) -> bool:
    """
    Determine if a native script is a simple (leaf) script.

    Args:
        native_script: NativeScript object

    Returns:
        True if SIMPLE (leaf node), False if COMPLEX (internal node)
    """
    from standalone.input_files.native_script import NativeScriptType  # type: ignore

    simple_types = {
        NativeScriptType.PUBKEY_DEVICE_OWNED,
        NativeScriptType.PUBKEY_THIRD_PARTY,
        NativeScriptType.INVALID_BEFORE,
        NativeScriptType.INVALID_HEREAFTER,
    }
    return native_script.type in simple_types


def generate_native_script_tree_recursive(
    native_script: Any,
    base_unique_id: str,
    child_index: int = 0,
    simple_script_generator_func: Any = None,
) -> tuple[list[str], str]:
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
        simple_script_generator_func: Function to generate simple script fixtures
                                      (takes current_unique_id and native_script)

    Returns:
        Tuple of (list of C code lines, identifier of generated struct)
    """
    from standalone.input_files.native_script import NativeScriptType  # type: ignore

    current_unique_id = f"{base_unique_id}_C{child_index}"
    fixture_lines = []

    is_leaf_node = _is_simple_native_script(native_script)

    if is_leaf_node:
        # Leaf node: SIMPLE script (no children)
        simple_script_lines = simple_script_generator_func(
            current_unique_id,
            native_script
        )
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
                child_lines, child_struct_id = generate_native_script_tree_recursive(
                    child_script,
                    current_unique_id,
                    child_idx,
                    simple_script_generator_func
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
                child_lines, child_struct_id = generate_native_script_tree_recursive(
                    child_script,
                    current_unique_id,
                    child_idx,
                    simple_script_generator_func
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
                child_lines, child_struct_id = generate_native_script_tree_recursive(
                    child_script,
                    current_unique_id,
                    child_idx,
                    simple_script_generator_func
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
