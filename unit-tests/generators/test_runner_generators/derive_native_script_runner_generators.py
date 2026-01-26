import re
from pathlib import Path
from typing import List

from common import UNIT_TESTS_DIR


def extract_native_script_fixture_names(header_file_path: Path) -> List[str]:
    """
    Extract test case names from native script fixtures header.
    
    Following AGENTS.md: "Use long, descriptive variable names"
    
    Args:
        header_file_path: Path to test_derive_native_script_fixtures.h
        
    Returns:
        List of test case names in order
    """
    fixture_names = []
    
    with open(header_file_path, 'r') as header_file:
        header_content = header_file.read()
    
    # Find the NATIVE_SCRIPT_FIXTURES array definition
    # Pattern matches: .name = "test_name",
    name_pattern = re.compile(r'\.name\s*=\s*"([^"]+)"')
    
    # Extract all test case names
    for match in name_pattern.finditer(header_content):
        test_case_name = match.group(1)
        fixture_names.append(test_case_name)
    
    return fixture_names


def _sanitize_test_function_name(test_case_name: str) -> str:
    """
    Sanitize test case name for C function identifier.
    
    Following AGENTS.md: "Use long, descriptive variable names"
    
    Args:
        test_case_name: Original test case name from fixtures
        
    Returns:
        Sanitized name suitable for C function identifier
    """
    # Replace problematic characters for C identifiers
    sanitized_name = test_case_name.lower()
    sanitized_name = sanitized_name.replace(" ", "_")
    sanitized_name = sanitized_name.replace("#", "num")
    sanitized_name = sanitized_name.replace("-", "_")
    sanitized_name = sanitized_name.replace("'", "")
    sanitized_name = sanitized_name.replace("(", "")
    sanitized_name = sanitized_name.replace(")", "")
    sanitized_name = sanitized_name.replace("/", "_")
    
    return sanitized_name


def _build_test_file_header() -> str:
    """
    Build header section of test file.
    
    Following AGENTS.md: "Mimic Established Patterns"
    
    Returns:
        Header section as string
    """
    return """// Unit tests for native script hash derivation (auto-generated)
// Following AGENTS.md: 'Mimic Established Patterns'

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

//#include "test_derive_native_script_fixtures.h"
#include "test_derive_native_script_common.h"

// ======================================================================
// Native Script Hash Derivation Tests (Auto-Generated)
// ======================================================================

"""


def _build_test_functions(fixture_names: List[str]) -> tuple[str, List[str]]:
    """
    Build individual test functions for each fixture.
    
    Following AGENTS.md: "Mimic Established Patterns"
    Mimics structure from test_derive_address.c
    
    Args:
        fixture_names: List of test case names from fixtures
        
    Returns:
        Tuple of (test functions as string, list of function names)
    """
    test_functions_lines = []
    test_function_names = []
    
    for test_case_index, test_case_name in enumerate(fixture_names):
        test_case_name_sanitized = _sanitize_test_function_name(test_case_name)
        test_function_name = f"test_derive_native_script_{test_case_name_sanitized}"
        
        test_functions_lines.extend([
            f"static void {test_function_name}(void **state) {{",
            f"    (void) state;",
            f"    run_fixture(&NATIVE_SCRIPT_FIXTURES[{test_case_index}]);",
            f"}}",
            "",
        ])
        
        test_function_names.append(test_function_name)
    
    return "\n".join(test_functions_lines), test_function_names


def _build_main_function(test_function_names: List[str]) -> str:
    """
    Build main() function with CMocka test array.
    
    Following AGENTS.md: "Mimic Established Patterns"
    
    Args:
        test_function_names: List of test function names
        
    Returns:
        Main function as string
    """
    main_lines = [
        "// ======================================================================",
        "// Main",
        "// ======================================================================",
        "",
        "int main(void) {",
        "    const struct CMUnitTest tests[] = {",
    ]
    
    # Add all test functions to cmocka test array
    for test_function_name in test_function_names:
        main_lines.append(f"        cmocka_unit_test({test_function_name}),")
    
    main_lines.extend([
        "    };",
        "    return cmocka_run_group_tests(tests, NULL, NULL);",
        "}",
        "",
    ])
    
    return "\n".join(main_lines)


def generate_native_script_test_runners() -> None:
    """
    Generate native script test runner C file from existing fixtures header.
    
    Following AGENTS.md: "Mimic Established Patterns"
    This generator reads the already-generated test_derive_native_script_fixtures.h
    and creates the corresponding test_derive_native_script.c runner file.
    """
    print("=" * 80)
    print("Generating native script test runner...")
    print("=" * 80)
    print()
    
    fixture_header_path = UNIT_TESTS_DIR / "test_derive_native_script_fixtures.h"
    test_c_file = UNIT_TESTS_DIR / "test_derive_native_script.c"

    if not fixture_header_path.exists():
        raise FileNotFoundError(
            f"Fixtures header not found: {fixture_header_path}\n"
            "Generate fixtures first using fixture_generators/derive_native_script_generators.py"
        )

    # Extract fixture names from generated header
    print(f"Reading fixtures from: {fixture_header_path}")
    fixture_names = extract_native_script_fixture_names(fixture_header_path)
    
    print(f"Found {len(fixture_names)} test fixtures:")
    print()
    
    # Display fixture names for verification
    for fixture_index, fixture_name in enumerate(fixture_names):
        print(f"  [{fixture_index:2d}] {fixture_name}")
    
    print()
    print(f"Generating test runner C file: {test_c_file}")
    print()
    
    # Build complete test file
    header_section = _build_test_file_header()
    test_functions_section, test_function_names = _build_test_functions(fixture_names)
    main_section = _build_main_function(test_function_names)
    
    complete_file_content = (
        header_section +
        test_functions_section +
        main_section
    )
    
    # Write test file
    test_c_file.write_text(complete_file_content)
    
    print(f"✓ Generated {test_c_file}")
    print(f"  - {len(test_function_names)} test functions")
    print(f"  - CMocka test array with {len(test_function_names)} tests")
    print()
    print("=" * 80)
    print("Native script test runner generation complete!")
    print("=" * 80)