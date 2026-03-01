/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>

#include <cmocka.h>

#include "cardano_swo.h"
#include "globals.h"
#include "sign_tx_ctx.h"
#include "init_apdu.h"
#include "swap.h"
#include "swap_test_stubs.h"
#include "test_sign_tx_common.h"
#include "test_sign_tx_fixtures_shelley.h"
#include "apdu_finalization_check.h"

static void test_sign_tx_swap_mode_skips_ui_and_validates_exchange_parameters(void **state) {
    (void) state;

    const tx_fixture_t *fixture = &FIXTURE_SHELLEY_SIGN_TX_WITHOUT_CHANGE_ADDRESS;

    reset_context();
    assert_true(test_mem_init());
    swap_test_stubs_reset();
    swap_test_stubs_set_initialized(true);
    swap_test_stubs_set_validation_results(true, true, true);
    G_called_from_swap = true;
    G_swap_response_ready = false;

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_sw, SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);
    assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);

    run_sign_tx_body_chunked(fixture->raw_tx, fixture->raw_tx_len);

    assert_int_equal(g_last_response_sw, SWO_SUCCESS);
    assert_int_equal(g_last_response_len, TX_HASH_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);
    assert_int_equal(G_context.state.tx_state, TX_STATE_APPROVED);
    // In swap mode UI is skipped, so planned_ui_pairs is set but never consumed.
    // Direct struct access: state is TX_STATE_APPROVED, but body slot was populated
    // before the transition and remains readable here for this assertion.
    assert_true(G_context.tx_info.body.planned_ui_pairs > 0);
    assert_false(G_swap_response_ready);

    assert_int_equal(g_swap_stub_fee_check_calls, 1);
    assert_int_equal(g_swap_stub_destination_check_calls, 1);
    assert_int_equal(g_swap_stub_amount_check_calls, 1);

    tx_context_cleanup();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sign_tx_swap_mode_skips_ui_and_validates_exchange_parameters),
    };
    return _cmocka_run_group_tests("test_handler_sign_tx_swap",
                                   tests,
                                   ARRAY_LEN(tests),
                                   NULL,
                                   assert_no_pending_apdu_response);
}
