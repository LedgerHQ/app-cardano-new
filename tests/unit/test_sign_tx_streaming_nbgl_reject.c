/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Unit tests for streaming-specific reject paths in ui_display_tx.c:
 *   - tx_streaming_start_choice(false)  — user rejects at the initial "Review transaction" screen
 *   - tx_streaming_continue_choice(false) — user rejects at an intermediate streaming chunk
 *
 * These paths are not exercised by the auto-generated reject tests, which only trigger
 * the final-screen reject (tx_review_choice).
 */

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
#include "nbgl_mock.h"
#include "test_sign_tx_common.h"
#include "test_sign_tx_fixtures_streaming.h"
#include "apdu_finalization_check.h"

// Streaming mode is only active when expert mode is on (more UI pairs are generated,
// exceeding the single-chunk limit). Expert-off renders fewer pairs that fit in one chunk
// and takes the non-streaming path, so only expert_on variants are meaningful here.

// ======================================================================
// tx_streaming_start_choice(false): reject at the initial "Review transaction" screen
// ======================================================================

static void test_streaming_reject_at_start(void **state) {
    (void) state;
    run_fixture_reject_streaming_start_with_expert_mode(
        &FIXTURE_STREAMING_SIGN_TX_STREAMING_MANY_REQUIRED_SIGNERS, true);
}

// ======================================================================
// tx_streaming_continue_choice(false): reject at the first intermediate chunk
// ======================================================================

static void test_streaming_reject_at_continue(void **state) {
    (void) state;
    run_fixture_reject_streaming_continue_with_expert_mode(
        &FIXTURE_STREAMING_SIGN_TX_STREAMING_MANY_REQUIRED_SIGNERS, true);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_streaming_reject_at_start),
        cmocka_unit_test(test_streaming_reject_at_continue),
    };
    return _cmocka_run_group_tests("test_sign_tx_streaming_nbgl_reject",
                                   tests,
                                   ARRAY_LEN(tests),
                                   NULL,
                                   assert_no_pending_apdu_response);
}
