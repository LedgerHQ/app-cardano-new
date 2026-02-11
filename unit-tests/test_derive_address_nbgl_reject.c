/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "apdu/dispatcher.h"
#include "app_context.h"
#include "app_mem_utils.h"
#include "buffer.h"
#include "cardano_swo.h"
#include "globals.h"
#include "handler/derive_address.h"
#include "io_capture.h"
#include "nbgl_mock.h"
#include "apdu_finalization_check.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static const uint8_t SHELLEY_DISPLAY_APDU_PAYLOAD[] = {
    0x00, 0x03, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80,
    0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x22,
    0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
};

static void reset_test_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    io_capture_reset();
    nbgl_mock_reset();
    assert_true(mem_utils_init(test_heap, sizeof(test_heap)));
}

static void test_nbgl_reject_on_address_review_resets_context(void **state) {
    (void) state;
    reset_test_context();

    const bool final_decisions[] = {false};
    nbgl_mock_set_final_decisions(final_decisions, ARRAY_LEN(final_decisions));

    buffer_t buf = {
        .ptr = (uint8_t *) SHELLEY_DISPLAY_APDU_PAYLOAD,
        .size = sizeof(SHELLEY_DISPLAY_APDU_PAYLOAD),
        .offset = 0,
    };

    apdu_response_begin(INS_DERIVE_ADDRESS);
    handler_derive_address(&buf, P1_ADDRESS_DISPLAY);
    apdu_response_assert_sent_or_deferred();

    assert_int_equal(g_last_response_sw, SWO_CONDITIONS_NOT_SATISFIED);
    assert_int_equal(g_last_response_len, 0);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.derive_address_state, DERIVE_ADDRESS_STATE_NONE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_nbgl_reject_on_address_review_resets_context),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
