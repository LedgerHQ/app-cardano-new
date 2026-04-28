/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "apdu/dispatcher.h"
#include "app_context.h"
#include "cardano_swo.h"
#include "globals.h"
#include "handler/sign_tx.h"
#include "init_apdu.h"
#include "sign_tx_ctx.h"
#include "apdu_finalization_check.h"
#include "test_sign_tx_common.h"
#include "test_sign_tx_fixtures_shelley.h"

static bool g_force_tx_render_ui_failure = false;

void ui_display_transaction(void) {
}

void ui_display_blind_signing_choice(void) {
}

bool tx_render_ui_or_fail(tx_ui_review_mode_e review_mode) {
    (void) review_mode;
    if (!g_force_tx_render_ui_failure) {
        return true;
    }

    g_force_tx_render_ui_failure = false;
    send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
    return false;
}

static void test_sign_tx_confirm_returns_insufficient_memory_when_ui_render_fails(void **state) {
    (void) state;

    const tx_fixture_t *fixture = &FIXTURE_SHELLEY_SIGN_TX_WITHOUT_CHANGE_ADDRESS;

    reset_context();
    assert_true(test_mem_init());

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);

    g_force_tx_render_ui_failure = true;
    run_sign_tx_body_chunked(fixture->raw_tx, fixture->raw_tx_len);

    assert_int_equal(g_last_response_swo, SWO_INSUFFICIENT_MEMORY);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.tx_state, TX_STATE_NONE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sign_tx_confirm_returns_insufficient_memory_when_ui_render_fails),
    };

    return _cmocka_run_group_tests("test_handler_sign_tx_ui_render_failure",
                                   tests,
                                   ARRAY_LEN(tests),
                                   NULL,
                                   assert_no_pending_apdu_response);
}
