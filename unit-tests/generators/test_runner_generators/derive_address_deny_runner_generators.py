import re
from pathlib import Path


from common import UNIT_TESTS_DIR, read_file_safe, write_file_safe, sanitize_c_identifier

_DENY_ARRAY_PATTERN = re.compile(
    r"static\s+const\s+derive_address_fixture_t\s+DERIVE_ADDRESS_DENY_FIXTURES\[\]\s*=\s*\{(.*?)\};",
    re.DOTALL,
)
_NAME_PATTERN = re.compile(r'\.name\s*=\s*"([^"]+)"')


def _extract_deny_fixture_names(header_path: Path) -> list[str]:
    if not header_path.exists():
        raise FileNotFoundError(f"Fixture header not found: {header_path}")

    header_content = read_file_safe(header_path)
    array_match = _DENY_ARRAY_PATTERN.search(header_content)
    if not array_match:
        raise ValueError("DERIVE_ADDRESS_DENY_FIXTURES array not found in header")

    fixture_names = _NAME_PATTERN.findall(array_match.group(1))

    if not fixture_names:
        raise ValueError("No deny fixtures found in header")

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

#include <cmocka.h>
#include "handler/derive_address.h"
#include "hexUtils.h"
#include "app_context.h"

#include "blake2b.h"

#include "test_address_derivation_fixtures_deny.h"
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

static void run_deny_fixture(const derive_address_fixture_t *fixture) {
    g_last_sw = 0;

    buffer_t buf = {
        .ptr = fixture->data,
        .size = fixture->data_len,
        .offset = 0,
    };
    TRACE_BUFFER(buf.ptr, buf.size);
    TRACE("Running deny fixture: %s", fixture->name);
    apdu_response_begin(INS_DERIVE_ADDRESS);
    handler_derive_address(&buf, fixture->p1);
    apdu_response_assert_sent_or_deferred();
    assert_int_equal(g_last_sw, fixture->check_expected);
}

"""


def _build_test_functions(fixture_names: list[str]) -> tuple[str, list[str]]:
    test_functions: list[str] = []
    test_function_names: list[str] = []

    for idx, fixture_name in enumerate(fixture_names):
        sanitized = sanitize_c_identifier(fixture_name, uppercase=False, handle_leading_digit=True)
        test_function_name = f"test_derive_address_deny_{idx}_{sanitized}"

        test_functions.append(
            f"static void {test_function_name}(void **state) {{\n"
            f"    (void) state;\n"
            f"    run_deny_fixture(&DERIVE_ADDRESS_DENY_FIXTURES[{idx}]);\n"
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
        "    TRACE(\"Starting test_derive_address_deny_tests\");\n"
        "    const struct CMUnitTest tests[] = {\n"
        f"        {registrations},\n"
        "    };\n\n"
        "    return cmocka_run_group_tests(tests, NULL, NULL);\n"
        "}\n"
    )


def generate_address_derivation_deny_test_runners() -> None:
    fixture_header_path = UNIT_TESTS_DIR / "test_address_derivation_fixtures_deny.h"
    test_c_file = UNIT_TESTS_DIR / "test_derive_address_deny_tests.c"

    fixture_names = _extract_deny_fixture_names(fixture_header_path)
    test_functions_section, test_function_names = _build_test_functions(fixture_names)
    main_section = _build_main_function(test_function_names)

    complete_file = (
        _build_test_file_header()
        + test_functions_section
        + "\n"
        + main_section
    )

    write_file_safe(test_c_file, complete_file)
    print(f"Generated {test_c_file}")
