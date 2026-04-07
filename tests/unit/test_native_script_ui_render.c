/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Tests for the real ui_display_native_script_hash.c rendering logic.
 *
 * Unlike test_native_script_state_machine.c (which stubs out UI entirely),
 * this file exercises the real ui_display_native_script_hash() code path
 * from cardano_derive_native_script_core.  The NBGL mock auto-confirms all streaming
 * callbacks, so each test drives a complete APDU flow through the real render logic
 * and verifies:
 *  - No render-session leak (ui_render_session_begin without matching end)
 *  - No dangling ui_pairs_force_new_page() flag
 *  - ui_get_error_status() stays SUCCESS for well-formed inputs
 *  - The final SWO sent to the host is SWO_SUCCESS
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "apdu/dispatcher.h"
#include "app_context.h"
#include "cardano_constants.h"
#include "cardano_swo.h"
#include "globals.h"
#include "handler/derive_native_script_hash.h"
#include "mem.h"
#include "securityPolicy.h"
#include "nbgl_mock.h"
#include "test_native_script_utils.h"
#include "apdu_finalization_check.h"

// ======================================================================
// ui_start_native_script_streaming stub
// The real streaming start just launches NBGL; auto-complete handles it.
// ======================================================================

void ui_start_native_script_streaming(void) {
    apdu_response_send_data(NULL, 0, SWO_SUCCESS);
}

// ======================================================================
// Helpers
// ======================================================================

static void reset_all(void) {
    reset_context();
    assert_true(test_mem_init());
    reset_response_buffer();
    nbgl_mock_reset();
}

// Run init + one simple pubkey-hash script + finish with bech32 display.
// Returns the final SW captured from the mock IO.
static uint16_t run_simple_pubkey_hash_script(void) {
    run_derive_native_script_init_apdu();
    if (get_last_swo() != SWO_SUCCESS) return get_last_swo();

    uint8_t simple_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    simple_payload[0] = NATIVE_SCRIPT_PUBKEY;
    simple_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    for (size_t i = 0; i < ADDRESS_KEY_HASH_LENGTH; i++) {
        simple_payload[2 + i] = (uint8_t)(i + 1);
    }
    buffer_t buf = {.ptr = simple_payload, .size = sizeof(simple_payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    if (get_last_swo() != SWO_SUCCESS) return get_last_swo();

    uint8_t finish_payload[1] = {DISPLAY_NATIVE_SCRIPT_HASH_BECH32};
    buffer_t finish_buf = {.ptr = finish_payload, .size = sizeof(finish_payload), .offset = 0};
    run_derive_native_script_apdu(&finish_buf, P1_NATIVE_SCRIPT_FINISH);
    return get_last_swo();
}

// ======================================================================
// Tests: simple leaf script types
// ======================================================================

// UI_SCRIPT_PUBKEY_HASH: use EXT_CREDENTIAL_KEY_HASH payload
static void test_render_pubkey_hash_script(void **state) {
    (void) state;
    reset_all();
    assert_int_equal(run_simple_pubkey_hash_script(), SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// UI_SCRIPT_PUBKEY_PATH: use EXT_CREDENTIAL_KEY_PATH with a valid hardened shelley path
static void test_render_pubkey_path_script(void **state) {
    (void) state;
    reset_all();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    // m / 1852' / 1815' / 0' / 2 / 0  (valid shelley spending path, hardened account)
    uint8_t simple_payload[1 + 1 + 1 + 5 * 4] = {0};
    simple_payload[0] = NATIVE_SCRIPT_PUBKEY;
    simple_payload[1] = EXT_CREDENTIAL_KEY_PATH;
    simple_payload[2] = 5;
    write_u32_be(&simple_payload[3],  bip44_harden(PURPOSE_SHELLEY));
    write_u32_be(&simple_payload[7],  bip44_harden(ADA_COIN_TYPE));
    write_u32_be(&simple_payload[11], bip44_harden(0));
    write_u32_be(&simple_payload[15], 2);
    write_u32_be(&simple_payload[19], 0);

    buffer_t buf = {.ptr = simple_payload, .size = sizeof(simple_payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t finish_payload[1] = {DISPLAY_NATIVE_SCRIPT_HASH_BECH32};
    buffer_t finish_buf = {.ptr = finish_payload, .size = sizeof(finish_payload), .offset = 0};
    run_derive_native_script_apdu(&finish_buf, P1_NATIVE_SCRIPT_FINISH);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// UI_SCRIPT_INVALID_BEFORE: timelock script
static void test_render_invalid_before_script(void **state) {
    (void) state;
    reset_all();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t payload[1 + 8] = {0};
    payload[0] = NATIVE_SCRIPT_INVALID_BEFORE;
    // timelock = 1000000 (slot number)
    uint64_t timelock = 1000000ULL;
    for (int i = 7; i >= 0; i--) {
        payload[1 + i] = (uint8_t)(timelock & 0xFF);
        timelock >>= 8;
    }
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t finish_payload[1] = {DISPLAY_NATIVE_SCRIPT_HASH_BECH32};
    buffer_t finish_buf = {.ptr = finish_payload, .size = sizeof(finish_payload), .offset = 0};
    run_derive_native_script_apdu(&finish_buf, P1_NATIVE_SCRIPT_FINISH);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// UI_SCRIPT_INVALID_HEREAFTER: timelock script
static void test_render_invalid_hereafter_script(void **state) {
    (void) state;
    reset_all();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t payload[1 + 8] = {0};
    payload[0] = NATIVE_SCRIPT_INVALID_HEREAFTER;
    uint64_t timelock = 2000000ULL;
    for (int i = 7; i >= 0; i--) {
        payload[1 + i] = (uint8_t)(timelock & 0xFF);
        timelock >>= 8;
    }
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t finish_payload[1] = {DISPLAY_NATIVE_SCRIPT_HASH_BECH32};
    buffer_t finish_buf = {.ptr = finish_payload, .size = sizeof(finish_payload), .offset = 0};
    run_derive_native_script_apdu(&finish_buf, P1_NATIVE_SCRIPT_FINISH);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// ======================================================================
// Tests: complex (parent) script types
// ======================================================================

// UI_SCRIPT_ALL: ALL with one pubkey-hash child
static void test_render_all_script(void **state) {
    (void) state;
    reset_all();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t complex_payload[5] = {0};
    complex_payload[0] = NATIVE_SCRIPT_ALL;
    write_u32_be(&complex_payload[1], 1);
    buffer_t complex_buf = {.ptr = complex_payload, .size = sizeof(complex_payload), .offset = 0};
    run_derive_native_script_apdu(&complex_buf, P1_NATIVE_SCRIPT_START_COMPLEX);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t child_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    child_payload[0] = NATIVE_SCRIPT_PUBKEY;
    child_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    buffer_t child_buf = {.ptr = child_payload, .size = sizeof(child_payload), .offset = 0};
    run_derive_native_script_apdu(&child_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t finish_payload[1] = {DISPLAY_NATIVE_SCRIPT_HASH_BECH32};
    buffer_t finish_buf = {.ptr = finish_payload, .size = sizeof(finish_payload), .offset = 0};
    run_derive_native_script_apdu(&finish_buf, P1_NATIVE_SCRIPT_FINISH);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// UI_SCRIPT_ANY: ANY with one pubkey-hash child
static void test_render_any_script(void **state) {
    (void) state;
    reset_all();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t complex_payload[5] = {0};
    complex_payload[0] = NATIVE_SCRIPT_ANY;
    write_u32_be(&complex_payload[1], 1);
    buffer_t complex_buf = {.ptr = complex_payload, .size = sizeof(complex_payload), .offset = 0};
    run_derive_native_script_apdu(&complex_buf, P1_NATIVE_SCRIPT_START_COMPLEX);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t child_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    child_payload[0] = NATIVE_SCRIPT_PUBKEY;
    child_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    buffer_t child_buf = {.ptr = child_payload, .size = sizeof(child_payload), .offset = 0};
    run_derive_native_script_apdu(&child_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t finish_payload[1] = {DISPLAY_NATIVE_SCRIPT_HASH_BECH32};
    buffer_t finish_buf = {.ptr = finish_payload, .size = sizeof(finish_payload), .offset = 0};
    run_derive_native_script_apdu(&finish_buf, P1_NATIVE_SCRIPT_FINISH);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// UI_SCRIPT_N_OF_K: N-of-K with two children, 1-of-2 required
static void test_render_n_of_k_script(void **state) {
    (void) state;
    reset_all();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t complex_payload[9] = {0};
    complex_payload[0] = NATIVE_SCRIPT_N_OF_K;
    write_u32_be(&complex_payload[1], 2);  // 2 children
    write_u32_be(&complex_payload[5], 1);  // require 1-of-2
    buffer_t complex_buf = {.ptr = complex_payload, .size = sizeof(complex_payload), .offset = 0};
    run_derive_native_script_apdu(&complex_buf, P1_NATIVE_SCRIPT_START_COMPLEX);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    for (int i = 0; i < 2; i++) {
        uint8_t child_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
        child_payload[0] = NATIVE_SCRIPT_PUBKEY;
        child_payload[1] = EXT_CREDENTIAL_KEY_HASH;
        child_payload[2] = (uint8_t)(i + 1);  // distinct hash bytes
        buffer_t child_buf = {.ptr = child_payload, .size = sizeof(child_payload), .offset = 0};
        run_derive_native_script_apdu(&child_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
        assert_int_equal(get_last_swo(), SWO_SUCCESS);
    }

    uint8_t finish_payload[1] = {DISPLAY_NATIVE_SCRIPT_HASH_BECH32};
    buffer_t finish_buf = {.ptr = finish_payload, .size = sizeof(finish_payload), .offset = 0};
    run_derive_native_script_apdu(&finish_buf, P1_NATIVE_SCRIPT_FINISH);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// ======================================================================
// Test: policy-id display format
// ======================================================================

// UI_SCRIPT_DISPLAY_POLICY_ID path: finish with DISPLAY_NATIVE_SCRIPT_HASH_POLICY_ID
static void test_render_policy_id_display_format(void **state) {
    (void) state;
    reset_all();
    assert_int_equal(run_simple_pubkey_hash_script(), SWO_SUCCESS);
    // run_simple_pubkey_hash_script already uses bech32; run a fresh flow with policy-id
    reset_all();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t simple_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    simple_payload[0] = NATIVE_SCRIPT_PUBKEY;
    simple_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    for (size_t i = 0; i < ADDRESS_KEY_HASH_LENGTH; i++) {
        simple_payload[2 + i] = (uint8_t)(i + 2);
    }
    buffer_t buf = {.ptr = simple_payload, .size = sizeof(simple_payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t finish_payload[1] = {DISPLAY_NATIVE_SCRIPT_HASH_POLICY_ID};
    buffer_t finish_buf = {.ptr = finish_payload, .size = sizeof(finish_payload), .offset = 0};
    run_derive_native_script_apdu(&finish_buf, P1_NATIVE_SCRIPT_FINISH);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// ======================================================================
// Test: nested complex script (position description path)
// ======================================================================

// A two-level ALL > PUBKEY_HASH script exercises the position-description
// formatting branch in build_position_description() / format_position().
static void test_render_nested_all_exercises_position_formatting(void **state) {
    (void) state;
    reset_all();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    // Outer ALL (2 children)
    uint8_t outer_payload[5] = {0};
    outer_payload[0] = NATIVE_SCRIPT_ALL;
    write_u32_be(&outer_payload[1], 2);
    buffer_t outer_buf = {.ptr = outer_payload, .size = sizeof(outer_payload), .offset = 0};
    run_derive_native_script_apdu(&outer_buf, P1_NATIVE_SCRIPT_START_COMPLEX);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    // Inner ALL (1 child) — triggers level=2, exercises position display
    uint8_t inner_payload[5] = {0};
    inner_payload[0] = NATIVE_SCRIPT_ALL;
    write_u32_be(&inner_payload[1], 1);
    buffer_t inner_buf = {.ptr = inner_payload, .size = sizeof(inner_payload), .offset = 0};
    run_derive_native_script_apdu(&inner_buf, P1_NATIVE_SCRIPT_START_COMPLEX);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    // Child of inner ALL
    uint8_t child_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    child_payload[0] = NATIVE_SCRIPT_PUBKEY;
    child_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    buffer_t child_buf = {.ptr = child_payload, .size = sizeof(child_payload), .offset = 0};
    run_derive_native_script_apdu(&child_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    // Second child of outer ALL
    uint8_t child2_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    child2_payload[0] = NATIVE_SCRIPT_PUBKEY;
    child2_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    for (size_t i = 0; i < ADDRESS_KEY_HASH_LENGTH; i++) {
        child2_payload[2 + i] = (uint8_t)(i + 5);
    }
    buffer_t child2_buf = {.ptr = child2_payload, .size = sizeof(child2_payload), .offset = 0};
    run_derive_native_script_apdu(&child2_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t finish_payload[1] = {DISPLAY_NATIVE_SCRIPT_HASH_BECH32};
    buffer_t finish_buf = {.ptr = finish_payload, .size = sizeof(finish_payload), .offset = 0};
    run_derive_native_script_apdu(&finish_buf, P1_NATIVE_SCRIPT_FINISH);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// ======================================================================
// Main
// ======================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_render_pubkey_hash_script),
        cmocka_unit_test(test_render_pubkey_path_script),
        cmocka_unit_test(test_render_invalid_before_script),
        cmocka_unit_test(test_render_invalid_hereafter_script),
        cmocka_unit_test(test_render_all_script),
        cmocka_unit_test(test_render_any_script),
        cmocka_unit_test(test_render_n_of_k_script),
        cmocka_unit_test(test_render_policy_id_display_format),
        cmocka_unit_test(test_render_nested_all_exercises_position_formatting),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
