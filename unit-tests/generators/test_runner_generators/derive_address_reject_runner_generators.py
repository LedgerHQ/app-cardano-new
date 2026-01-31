import re
from pathlib import Path
from typing import List

from common import UNIT_TESTS_DIR


def _sanitize_fixture_name_for_c_function(fixture_name: str) -> str:
    sanitized = fixture_name.lower()
    sanitized = re.sub(r'[^a-z0-9_]+', '_', sanitized)
    sanitized = re.sub(r'_+', '_', sanitized).strip('_')

    if sanitized and sanitized[0].isdigit():
        sanitized = f"num_{sanitized}"
    if not sanitized:
        sanitized = "fixture"

    return sanitized


def _extract_reject_fixture_names(header_path: Path) -> List[str]:
    if not header_path.exists():
        raise FileNotFoundError(f"Fixture header not found: {header_path}")

    header_content = header_path.read_text()
    fixture_names = re.findall(r'\.name\s*=\s*"([^"]+)"', header_content)

    if not fixture_names:
        raise ValueError("No reject fixtures found in header")

    return fixture_names


def _build_test_file_header() -> str:
    return """#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>

#include "globals.h"
#include "securityPolicy/securityPolicy.h"
#include "apdu/dispatcher.h"
#include "globals.h"

#include <cmocka.h>
#include "handler/derive_address.h"
#include "hexUtils.h"

#include "blake2b.h"

#include "test_address_derivation_fixtures_rejects.h"
#include "test_fixture_types.h"

// ----------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------

static uint16_t g_last_sw = 0;

// ----------------------------------------------------------------------
// Simple mocks for IO and UI plumbing so we can drive the handler
// ----------------------------------------------------------------------

void ui_deriveAddress_handleReturn(security_policy_t policy, warning_bits_t warnings);
void ui_deriveAddress_handleDisplay(security_policy_t policy, warning_bits_t warnings);

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    (void) buffer;
    (void) bufferLength;
    g_last_sw = swo;
    return 0;
}

int io_send_sw(uint16_t swo) {
    g_last_sw = swo;
    return 0;
}

// ----------------------------------------------------------------------
// Fixture runner
// ----------------------------------------------------------------------

void ui_deriveAddress_handleReturn(security_policy_t policy, warning_bits_t warnings) {
    (void) policy;
    (void) warnings;
}

void ui_deriveAddress_handleDisplay(security_policy_t policy, warning_bits_t warnings) {
    (void) policy;
    (void) warnings;
}

static void run_reject_fixture(const derive_address_fixture_t *fixture) {
    g_last_sw = 0;

    buffer_t buf = {
        .ptr = fixture->data,
        .size = fixture->data_len,
        .offset = 0,
    };
    TRACE_BUFFER(buf.ptr, buf.size);
    TRACE("Running rejection fixture: %s", fixture->name);
    handler_derive_address(&buf, fixture->p1);
    assert_int_equal(g_last_sw, fixture->check_expected);
}

"""


def _build_test_functions(fixture_names: List[str]) -> tuple[str, List[str]]:
    test_functions: List[str] = []
    test_function_names: List[str] = []

    for idx, fixture_name in enumerate(fixture_names):
        sanitized = _sanitize_fixture_name_for_c_function(fixture_name)
        test_function_name = f"test_derive_address_reject_{idx}_{sanitized}"

        test_functions.append(
            f"static void {test_function_name}(void **state) {{\n"
            f"    (void) state;\n"
            f"    run_reject_fixture(&DERIVE_ADDRESS_REJECT_FIXTURES[{idx}]);\n"
            f"}}\n"
        )
        test_function_names.append(test_function_name)

    return "\n".join(test_functions), test_function_names


def _build_main_function(test_function_names: List[str]) -> str:
    registrations = ",\n        ".join(
        f"cmocka_unit_test({name})" for name in test_function_names
    )

    return (
        "int main(void) {\n"
        "    TRACE(\"Starting test_derive_address_rejects\");\n"
        "    const struct CMUnitTest tests[] = {\n"
        f"        {registrations},\n"
        "    };\n\n"
        "    return cmocka_run_group_tests(tests, NULL, NULL);\n"
        "}\n"
    )


def generate_address_derivation_reject_test_runners() -> None:
    fixture_header_path = UNIT_TESTS_DIR / "test_address_derivation_fixtures_rejects.h"
    test_c_file = UNIT_TESTS_DIR / "test_derive_address_rejects.c"

    fixture_names = _extract_reject_fixture_names(fixture_header_path)
    test_functions_section, test_function_names = _build_test_functions(fixture_names)
    main_section = _build_main_function(test_function_names)

    complete_file = (
        _build_test_file_header()
        + test_functions_section
        + "\n"
        + main_section
    )

    test_c_file.write_text(complete_file)
    print(f"Generated {test_c_file}")
