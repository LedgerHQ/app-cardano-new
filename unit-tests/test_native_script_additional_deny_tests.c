/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "globals.h"
#include "handler/derive_native_script_hash.h"
#include "cardano_swo.h"
#include "mem.h"
#include "securityPolicy.h"
#include "apdu/dispatcher.h"
#include "app_context.h"
#include "io.h"
#include "test_native_script_utils.h"
#include "apdu_finalization_check.h"

// UI mock for additional deny tests
void ui_start_native_script_streaming(void) {
    apdu_response_send_data(NULL, 0, SWO_SUCCESS);
}

void ui_display_native_script_hash(void) {
    // Send success for all script types
    apdu_response_send_data(NULL, 0, SWO_SUCCESS);
}

// Test: requiredScripts > remainingScripts rejection for N-of-K
static void test_n_of_k_required_greater_than_remaining(void **state) {
    (void) state;
    reset_context();
    assert_true(test_mem_init());
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_sw(), SWO_SUCCESS);

    // Start N_OF_K with requiredScripts=5, remainingScripts=3 (invalid!)
    uint8_t complex_payload[9] = {0};
    complex_payload[0] = NATIVE_SCRIPT_N_OF_K;
    write_u32_be(&complex_payload[1], 3);  // remainingScripts = 3
    write_u32_be(&complex_payload[5], 5);  // requiredScripts = 5 (invalid: > remainingScripts)

    buffer_t buf = {
        .ptr = complex_payload,
        .size = sizeof(complex_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);

    // Should be rejected with script count error
    assert_int_equal(get_last_sw(), SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_COUNT);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// Test: invalid displayFormat byte in finish APDU
static void test_invalid_display_format(void **state) {
    (void) state;
    reset_context();
    assert_true(test_mem_init());
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_sw(), SWO_SUCCESS);

    // Add one simple valid script first
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

    // Send finish with invalid displayFormat byte (valid are 0x00 and 0x01)
    uint8_t finish_payload[1] = {0xFF};  // Invalid display format
    buffer_t finish_buf = {
        .ptr = finish_payload,
        .size = sizeof(finish_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&finish_buf, P1_NATIVE_SCRIPT_FINISH);

    // Should be rejected with display format error
    assert_int_equal(get_last_sw(), SWO_NATIVE_SCRIPT_PARSING_FAIL_DISPLAY_FORMAT);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// Test: MAX_SCRIPT_DEPTH limit (11 levels deep)
// This test creates a deeply nested ALL script to hit the depth limit
static void test_max_script_depth_exceeded(void **state) {
    (void) state;
    reset_context();
    assert_true(test_mem_init());
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_sw(), SWO_SUCCESS);

    // Nest ALL scripts up to MAX_SCRIPT_DEPTH
    // MAX_SCRIPT_DEPTH is 11, so we can nest 10 times (level 0 is root)
    for (int i = 0; i < MAX_SCRIPT_DEPTH; i++) {
        uint8_t complex_payload[5] = {0};
        complex_payload[0] = NATIVE_SCRIPT_ALL;
        write_u32_be(&complex_payload[1], 1);  // 1 child script

        buffer_t buf = {
            .ptr = complex_payload,
            .size = sizeof(complex_payload),
            .offset = 0,
        };
        run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);

        if (i < MAX_SCRIPT_DEPTH - 1) {
            // Should succeed for depths below the limit
            assert_int_equal(get_last_sw(), SWO_SUCCESS);
        } else {
            // The MAX_SCRIPT_DEPTH'th nesting should fail
            assert_int_equal(get_last_sw(), SWO_NATIVE_SCRIPT_PARSING_FAIL_DEPTH_UNSUPPORTED);
            assert_int_equal(G_context.req_type, REQUEST_NONE);
            return;  // Test passed
        }
    }

    // If we reach here, we didn't hit the depth limit as expected
    fail_msg("Expected depth limit to be enforced");
}

// Test: finish called before all scripts are processed
static void test_finish_with_remaining_scripts(void **state) {
    (void) state;
    reset_context();
    assert_true(test_mem_init());
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_sw(), SWO_SUCCESS);

    // Start an ALL script with 2 children
    uint8_t complex_payload[5] = {0};
    complex_payload[0] = NATIVE_SCRIPT_ALL;
    write_u32_be(&complex_payload[1], 2);  // Expecting 2 child scripts

    buffer_t buf = {
        .ptr = complex_payload,
        .size = sizeof(complex_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);
    assert_int_equal(get_last_sw(), SWO_SUCCESS);

    // Add only 1 child (missing the second one)
    uint8_t simple_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    simple_payload[0] = NATIVE_SCRIPT_PUBKEY;
    simple_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    buffer_t simple_buf = {
        .ptr = simple_payload,
        .size = sizeof(simple_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&simple_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_sw(), SWO_SUCCESS);

    // Try to finish prematurely (1 script remaining)
    uint8_t finish_payload[1] = {DISPLAY_NATIVE_SCRIPT_HASH_BECH32};
    buffer_t finish_buf = {
        .ptr = finish_payload,
        .size = sizeof(finish_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&finish_buf, P1_NATIVE_SCRIPT_FINISH);

    // Should be rejected with nesting error
    assert_int_equal(get_last_sw(), SWO_NATIVE_SCRIPT_PARSING_FAIL_NESTING);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// Test: parse-valid but classification-invalid key path is denied by policy
static void test_pubkey_device_owned_invalid_classified_path_denied(void **state) {
    (void) state;
    reset_context();
    assert_true(test_mem_init());
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_sw(), SWO_SUCCESS);

    // PUBKEY + KEY_PATH (path_len=5)
    // m / 1852' / 1815' / 0 / 0 / 0
    // Account is not hardened, so bip44_classifyPath() => PATH_INVALID
    uint8_t simple_payload[1 + 1 + 1 + 5 * 4] = {0};
    simple_payload[0] = NATIVE_SCRIPT_PUBKEY;
    simple_payload[1] = EXT_CREDENTIAL_KEY_PATH;
    simple_payload[2] = 5;
    write_u32_be(&simple_payload[3], bip44_harden(PURPOSE_SHELLEY));
    write_u32_be(&simple_payload[7], bip44_harden(ADA_COIN_TYPE));
    write_u32_be(&simple_payload[11], 0);  // invalid: account must be hardened
    write_u32_be(&simple_payload[15], 0);
    write_u32_be(&simple_payload[19], 0);

    buffer_t simple_buf = {
        .ptr = simple_payload,
        .size = sizeof(simple_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&simple_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);

    assert_int_equal(get_last_sw(), SWO_SECURITY_CONDITION_NOT_SATISFIED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_n_of_k_required_greater_than_remaining),
        cmocka_unit_test(test_invalid_display_format),
        cmocka_unit_test(test_max_script_depth_exceeded),
        cmocka_unit_test(test_finish_with_remaining_scripts),
        cmocka_unit_test(test_pubkey_device_owned_invalid_classified_path_denied),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
