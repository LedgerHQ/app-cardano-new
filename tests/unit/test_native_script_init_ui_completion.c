/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>

#include <cmocka.h>

#include "apdu/dispatcher.h"
#include "app_context.h"
#include "cardano_swo.h"
#include "globals.h"
#include "handler/derive_native_script_hash.h"
#include "nbgl_use_case.h"
#include "nbgl_mock.h"
#include "test_native_script_utils.h"
#include "apdu_finalization_check.h"

static void native_script_init_continue(bool confirm) {
    if (confirm) {
        apdu_response_send_data(NULL, 0, SWO_SUCCESS);
    } else {
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
    }
}

void ui_start_native_script_streaming(void) {
    nbgl_useCaseReviewStreamingStart(TYPE_OPERATION,
                                     NULL,
                                     "Review Script",
                                     NULL,
                                     native_script_init_continue);
}

void ui_display_native_script_hash(void) {
    apdu_response_send_data(NULL, 0, SWO_SUCCESS);
}

static void test_init_confirm_completes_apdu_and_keeps_request_active(void **state) {
    (void) state;
    reset_context();
    assert_true(test_mem_init());
    reset_response_buffer();
    nbgl_mock_reset();
    nbgl_mock_set_streaming_start_auto_complete(true, true);

    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_DERIVE_NATIVE_SCRIPT_HASH);

    uint8_t simple_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    simple_payload[0] = NATIVE_SCRIPT_PUBKEY;
    simple_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    buffer_t simple_buf = {
        .ptr = simple_payload,
        .size = sizeof(simple_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&simple_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);
}

static void test_init_reject_completes_apdu_and_resets_request(void **state) {
    (void) state;
    reset_context();
    assert_true(test_mem_init());
    reset_response_buffer();
    nbgl_mock_reset();
    nbgl_mock_set_streaming_start_auto_complete(true, false);

    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_CONDITIONS_NOT_SATISFIED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);

    uint8_t simple_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    simple_payload[0] = NATIVE_SCRIPT_PUBKEY;
    simple_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    buffer_t simple_buf = {
        .ptr = simple_payload,
        .size = sizeof(simple_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&simple_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_COMMAND_NOT_ALLOWED);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_init_confirm_completes_apdu_and_keeps_request_active),
        cmocka_unit_test(test_init_reject_completes_apdu_and_resets_request),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
