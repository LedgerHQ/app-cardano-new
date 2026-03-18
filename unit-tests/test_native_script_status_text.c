/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>

#include <cmocka.h>

#include "apdu/dispatcher.h"
#include "apdu_finalization_check.h"
#include "app_context.h"
#include "cardano_swo.h"
#include "globals.h"
#include "handler/derive_native_script_hash.h"
#include "nbgl_mock.h"
#include "test_native_script_utils.h"

static void test_native_script_finish_confirm_shows_expected_status_text(void **state) {
    (void) state;

    reset_context();
    assert_true(test_mem_init());
    reset_response_buffer();
    nbgl_mock_reset();
    nbgl_mock_set_streaming_start_auto_complete(true, true);

    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_sw(), SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_DERIVE_NATIVE_SCRIPT_HASH);

    uint8_t simple_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    simple_payload[0] = NATIVE_SCRIPT_PUBKEY;
    simple_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    for (size_t i = 0; i < ADDRESS_KEY_HASH_LENGTH; i++) {
        simple_payload[2 + i] = (uint8_t) i;
    }
    buffer_t simple_buf = {
        .ptr = simple_payload,
        .size = sizeof(simple_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&simple_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_sw(), SWO_SUCCESS);

    uint8_t finish_payload[1] = {DISPLAY_NATIVE_SCRIPT_HASH_BECH32};
    buffer_t finish_buf = {
        .ptr = finish_payload,
        .size = sizeof(finish_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&finish_buf, P1_NATIVE_SCRIPT_FINISH);

    assert_int_equal(get_last_sw(), SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_true(nbgl_mock_last_status_success());
    assert_string_equal(nbgl_mock_last_status_message(), "Script hash exported");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_native_script_finish_confirm_shows_expected_status_text),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
