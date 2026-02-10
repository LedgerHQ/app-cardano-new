from __future__ import annotations

import re
from pathlib import Path

from common import read_file_safe, write_file_safe, sanitize_c_identifier
from paths import UNIT_TESTS_DIR

FIXTURE_HEADER = UNIT_TESTS_DIR / "test_opcert_fixtures.h"
TEST_FILE = UNIT_TESTS_DIR / "test_opcert.c"

_NAME_PATTERN = re.compile(r'\.name\s*=\s*"([^"]+)"')


def _extract_fixture_names(header: Path) -> list[str]:
    content = read_file_safe(header)
    return _NAME_PATTERN.findall(content)


def _build_file_header() -> str:
    return """// Unit tests for Sign Operational Certificate (auto-generated)

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>

#include <cmocka.h>

#include "cardano_constants.h"
#include "buffer.h"
#include "cardano_swo.h"
#include "globals.h"
#include "../src/securityPolicy/securityPolicy.h"
#include "handler/sign_opcert.h"
#include "opcert/opcert_types.h"
#include "test_opcert_fixtures.h"
#include "app_context.h"

"""


def _build_helpers() -> str:
    return """static uint16_t g_last_sw = 0;
static uint8_t g_last_response[ED25519_SIGNATURE_LENGTH];
static size_t g_last_response_len = 0;

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    assert_true(bufferLength <= sizeof(g_last_response));
    memcpy(g_last_response, buffer, bufferLength);
    g_last_response_len = bufferLength;
    g_last_sw = swo;
    return 0;
}

int io_send_sw(uint16_t swo) {
    g_last_sw = swo;
    return 0;
}

void ui_display_opcert(security_policy_t securityPolicy, warning_bits_t warnings) {
    (void)securityPolicy;
    (void)warnings;
    finalize_sign_opcert(true);
}

void ui_menu_main(void) {
    // no-op stub used by nbgl_useCaseStatus callbacks
}

void nbgl_useCaseStatus(const char *text, bool success, void (*callback)(void)) {
    (void)text;
    (void)success;
    if (callback != NULL) {
        callback();
    }
}

void reset_opcert_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    g_last_sw = 0;
    g_last_response_len = 0;
}

static void run_opcert_fixture(const opcert_fixture_t *fixture) {
    assert_non_null(fixture);
    reset_opcert_context();
    buffer_t data = {.ptr = fixture->payload, .size = fixture->payload_len, .offset = 0};
    apdu_response_begin(INS_SIGN_OPCERT);
    handler_sign_opcert(&data);
    apdu_response_assert_sent_or_deferred();
    assert_int_equal(g_last_sw, SWO_SUCCESS);
    assert_int_equal(g_last_response_len, ED25519_SIGNATURE_LENGTH);
}

"""


def _build_test_functions(fixture_names: list[str]) -> tuple[str, list[str]]:
    lines = []
    function_names = []
    for idx, raw_name in enumerate(fixture_names):
        sanitized = sanitize_c_identifier(raw_name, uppercase=False)
        prefix = "sign_opcert_"
        if sanitized.startswith(prefix):
            sanitized = sanitized[len(prefix):]
        function_name = f"test_opCert_{sanitized}_{idx}"
        lines.extend([
            f"static void {function_name}(void **state) {{",
            f"    (void) state;",
            f"    run_opcert_fixture(&OPCERT_FIXTURES[{idx}]);",
            f"}}",
            "",
        ])
        function_names.append(function_name)
    return "\n".join(lines), function_names


def _build_main(function_names: list[str]) -> str:
    lines = [
        "// ======================================================================",
        "// Main",
        "// ======================================================================",
        "",
        "int main(void) {",
        "    const struct CMUnitTest tests[] = {",
    ]
    for name in function_names:
        lines.append(f"        cmocka_unit_test({name}),")
    lines.extend([
        "    };",
        "    return cmocka_run_group_tests(tests, NULL, NULL);",
        "}",
    ])
    return "\n".join(lines)


def generate_opcert_test_runners() -> None:
    if not FIXTURE_HEADER.exists():
        raise FileNotFoundError("Opcert fixtures missing. Run generate_unit_tests_from_ragger.py fixtures stage first.")

    fixture_names = _extract_fixture_names(FIXTURE_HEADER)
    if not fixture_names:
        raise RuntimeError("No opcert fixtures found")

    header = _build_file_header()
    helpers = _build_helpers()
    test_funcs, func_names = _build_test_functions(fixture_names)
    main = _build_main(func_names)

    content = "\n".join([header, helpers, test_funcs, main, ""]) 
    write_file_safe(TEST_FILE, content)
