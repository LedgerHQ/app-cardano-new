/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "mem.h"
#include "ui_utils.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

// test_ui_utils links ui_utils.c in isolation and does not exercise warning paths.
void ui_free_warnings(void) {
}

// ======================================================================
// Helpers
// ======================================================================

static void init_heap(void) {
    assert_true(mem_utils_init(test_heap, sizeof(test_heap)));
}

// ======================================================================
// Existing tests
// ======================================================================

static void test_ui_pairs_add_static_label_stores_value(void **state) {
    (void) state;
    init_heap();
    assert_true(ui_pairs_init(1));

    char *tmp = NULL;
    assert_true(APP_MEM_CALLOC((void **) &tmp, 16));
    memcpy(tmp, "hello", sizeof("hello"));

    assert_true(ui_pairs_add_static_label("Label", tmp));
    assert_string_equal(g_pairs[0].item, "Label");
    assert_string_equal(g_pairs[0].value, "hello");

    ui_free_pairs();
}

// ======================================================================
// ui_render_session_begin / ui_render_session_end pairing
// ======================================================================

static void test_render_session_begin_end_pair(void **state) {
    (void) state;
    init_heap();
    assert_true(ui_pairs_init(1));
    ui_reset_error_status();

    ui_render_session_t session = {0};
    ui_render_session_begin(&session, 0);
    // Confirm a pair can be added inside the session without assertions firing
    char *tmp = NULL;
    assert_true(APP_MEM_CALLOC((void **) &tmp, 8));
    memcpy(tmp, "val", sizeof("val"));
    assert_true(ui_pairs_add_static_label("Key", tmp));
    ui_render_session_end();

    assert_int_equal(ui_get_error_status(), UI_STATUS_SUCCESS);
    ui_free_pairs();
}

// ======================================================================
// ui_get_error_status transitions
// ======================================================================

static void test_error_status_starts_success_after_reset(void **state) {
    (void) state;
    ui_reset_error_status();
    assert_int_equal(ui_get_error_status(), UI_STATUS_SUCCESS);
}

static void test_error_status_transitions_to_out_of_memory(void **state) {
    (void) state;
    ui_reset_error_status();
    ui_set_error_status(UI_STATUS_OUT_OF_MEMORY);
    assert_int_equal(ui_get_error_status(), UI_STATUS_OUT_OF_MEMORY);
}

static void test_error_status_transitions_to_chunk_full(void **state) {
    (void) state;
    ui_reset_error_status();
    ui_set_error_status(UI_STATUS_CHUNK_FULL);
    assert_int_equal(ui_get_error_status(), UI_STATUS_CHUNK_FULL);
}

static void test_error_status_stays_oom_on_repeated_set(void **state) {
    (void) state;
    ui_reset_error_status();
    ui_set_error_status(UI_STATUS_OUT_OF_MEMORY);
    // Setting OOM again should be idempotent (same status)
    ui_set_error_status(UI_STATUS_OUT_OF_MEMORY);
    assert_int_equal(ui_get_error_status(), UI_STATUS_OUT_OF_MEMORY);
}

// ======================================================================
// ui_pairs_force_new_page cleared on all exit paths
// ======================================================================

static void test_force_new_page_consumed_by_subsequent_add(void **state) {
    (void) state;
    init_heap();
    assert_true(ui_pairs_init(2));
    ui_reset_error_status();

    ui_render_session_t session = {0};
    ui_render_session_begin(&session, 0);

    char *tmp1 = NULL;
    assert_true(APP_MEM_CALLOC((void **) &tmp1, 8));
    memcpy(tmp1, "first", sizeof("first"));
    assert_true(ui_pairs_add_static_label("K1", tmp1));

    ui_pairs_force_new_page();

    char *tmp2 = NULL;
    assert_true(APP_MEM_CALLOC((void **) &tmp2, 8));
    memcpy(tmp2, "second", sizeof("second"));
    assert_true(ui_pairs_add_static_label("K2", tmp2));

    // Confirm the second pair has forcePageStart set.
    // forcePageStart is int8_t:1 (1-bit signed field); storing 1 yields -1.
    assert_int_not_equal(g_pairs[1].forcePageStart, 0);

    ui_render_session_end();
    // ui_free_pairs must not assert — flag was consumed
    ui_free_pairs();
}

static void test_force_new_page_cleared_when_pair_skipped_before_window(void **state) {
    (void) state;
    init_heap();
    // Two pairs total; render_from_pair_index=1 so pair 0 is before the window.
    assert_true(ui_pairs_init(2));
    ui_reset_error_status();

    ui_render_session_t session = {0};
    ui_render_session_begin(&session, 1);

    // Force a new page, then call ui_render_should_skip() for pair 0 (before window).
    // ui_render_should_skip() must clear the pending flag when skipping.
    ui_pairs_force_new_page();
    assert_true(ui_render_should_skip());  // pair 0 is before window — skip

    // pair 1: inside window — should be skippable or addable cleanly, no dangling flag
    assert_false(ui_render_should_skip());  // pair 1 is in window — don't skip

    char *tmp1 = NULL;
    assert_true(APP_MEM_CALLOC((void **) &tmp1, 8));
    memcpy(tmp1, "kept", sizeof("kept"));
    assert_true(ui_pairs_add_static_label("K1", tmp1));

    ui_render_session_end();
    // ui_free_pairs must not assert — flag was cleared during skip
    ui_free_pairs();
}

// ======================================================================
// ui_render_should_skip gates OOM/CHUNK_FULL
// ======================================================================

static void test_render_should_skip_when_oom(void **state) {
    (void) state;
    init_heap();
    assert_true(ui_pairs_init(3));
    ui_reset_error_status();

    ui_render_session_t session = {0};
    ui_render_session_begin(&session, 0);

    // Pair 0: in window, no error — should NOT be skipped
    assert_false(ui_render_should_skip());

    // Manually set OOM
    ui_set_error_status(UI_STATUS_OUT_OF_MEMORY);

    // Pair 1: OOM is set — ui_render_should_skip() must return true
    assert_true(ui_render_should_skip());

    // Pair 2: still OOM — must still skip
    assert_true(ui_render_should_skip());

    assert_int_equal(ui_get_error_status(), UI_STATUS_OUT_OF_MEMORY);
    ui_render_session_end();
    ui_free_pairs();
}

// ======================================================================
// Main
// ======================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ui_pairs_add_static_label_stores_value),
        cmocka_unit_test(test_render_session_begin_end_pair),
        cmocka_unit_test(test_error_status_starts_success_after_reset),
        cmocka_unit_test(test_error_status_transitions_to_out_of_memory),
        cmocka_unit_test(test_error_status_transitions_to_chunk_full),
        cmocka_unit_test(test_error_status_stays_oom_on_repeated_set),
        cmocka_unit_test(test_force_new_page_consumed_by_subsequent_add),
        cmocka_unit_test(test_force_new_page_cleared_when_pair_skipped_before_window),
        cmocka_unit_test(test_render_should_skip_when_oom),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
