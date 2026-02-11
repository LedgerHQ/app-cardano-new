import re
from pathlib import Path


from common import UNIT_TESTS_DIR, read_file_safe, write_file_safe, sanitize_c_identifier

_DENY_ARRAY_PATTERN = re.compile(
    r"static\s+const\s+pubkey_fixture_t\s+PUBKEY_DENY_FIXTURES\[\]\s*=\s*\{(.*?)\};",
    re.DOTALL,
)
_NAME_PATTERN = re.compile(r'\.name\s*=\s*"([^"]+)"')


def _extract_deny_fixture_names(header_path: Path) -> list[str]:
    if not header_path.exists():
        raise FileNotFoundError(f"Fixture header not found: {header_path}")

    header_content = read_file_safe(header_path)
    array_match = _DENY_ARRAY_PATTERN.search(header_content)
    if not array_match:
        raise ValueError("PUBKEY_DENY_FIXTURES array not found in header")

    fixture_names = _NAME_PATTERN.findall(array_match.group(1))

    if not fixture_names:
        raise ValueError("No deny fixtures found in header")

    return fixture_names


def _build_test_file_header() -> str:
    return """// Unit tests for public key export deny tests (auto-generated)

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include \"test_pubkey_fixtures_deny.h\"
#include \"test_pubkey_common.h\"

// ======================================================================
// Public Key Export Deny Tests (Auto-Generated)
// ======================================================================

"""


def _build_test_functions(fixture_names: list[str]) -> tuple[str, list[str]]:
    test_functions: list[str] = []
    test_function_names: list[str] = []

    for idx, fixture_name in enumerate(fixture_names):
        sanitized = sanitize_c_identifier(fixture_name, uppercase=False, handle_leading_digit=True)
        test_function_name = f"test_pubkey_deny_{idx}_{sanitized}"

        test_functions.append(
            f"static void {test_function_name}(void **state) {{\n"
            f"    (void) state;\n"
            f"    run_fixture(&PUBKEY_DENY_FIXTURES[{idx}]);\n"
            f"}}\n"
        )
        test_function_names.append(test_function_name)

    return "\n".join(test_functions), test_function_names


def _build_main_function(test_function_names: list[str]) -> str:
    registrations = ",\n        ".join(
        f"cmocka_unit_test({name})" for name in test_function_names
    )

    return (
        "int main(void) {\n"
        "    const struct CMUnitTest tests[] = {\n"
        f"        {registrations},\n"
        "    };\n\n"
        "    return cmocka_run_group_tests(tests, NULL, NULL);\n"
        "}\n"
    )


def generate_pubkey_deny_test_runners() -> None:
    fixture_header_path = UNIT_TESTS_DIR / "test_pubkey_fixtures_deny.h"
    test_c_file = UNIT_TESTS_DIR / "test_pubkey_deny_tests.c"

    fixture_names = _extract_deny_fixture_names(fixture_header_path)
    test_functions_section, test_function_names = _build_test_functions(fixture_names)
    main_section = _build_main_function(test_function_names)

    complete_file = (
        _build_test_file_header()
        + test_functions_section
        + "\n"
        + "// ======================================================================\n"
        + "// Main\n"
        + "// ======================================================================\n"
        + "\n"
        + main_section
    )

    write_file_safe(test_c_file, complete_file)
    print(f"Generated {test_c_file}")
