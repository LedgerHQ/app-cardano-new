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

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];
static uint16_t g_last_sw = 0;

static inline bool test_mem_init(void) {
    return mem_utils_init(test_heap, sizeof(test_heap));
}

static void reset_test_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    g_last_sw = 0;
    assert_true(test_mem_init());
}

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    (void) buffer;
    (void) bufferLength;
    g_last_sw = swo;
    return 0;
}

int io_send_sw(uint16_t swo) {
    g_last_sw = swo;
    return 0;
}

// Drive native script steps forward without ragger/NBGL interaction.
// For final hash display we intentionally do nothing to model "waiting for final confirmation".
void ui_display_native_script_hash(security_policy_t securityPolicy) {
    (void) securityPolicy;
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    switch (ctx->ui_scriptType) {
        case UI_SCRIPT_DISPLAY_BECH32:
        case UI_SCRIPT_DISPLAY_POLICY_ID:
            return;
        default:
            io_send_response_pointer(NULL, 0, SWO_SUCCESS);
            return;
    }
}

static void test_finish_must_keep_request_lock_until_user_confirmation(void **state) {
    (void) state;
    reset_test_context();

    // Add one simple valid script: [type=PUBKEY, cred=KEY_HASH, 28-byte hash]
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
    handler_derive_native_script_hash(&simple_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(g_last_sw, SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_DERIVE_NATIVE_SCRIPT_HASH);

    uint8_t finish_payload[1] = {DISPLAY_NATIVE_SCRIPT_HASH_BECH32};
    buffer_t finish_buf = {
        .ptr = finish_payload,
        .size = sizeof(finish_payload),
        .offset = 0,
    };
    handler_derive_native_script_hash(&finish_buf, P1_NATIVE_SCRIPT_FINISH);

    // Expected invariant: request lock remains active while waiting for final confirmation.
    // Current implementation clears req_type too early; this test is meant to catch that.
    assert_int_equal(G_context.req_type, REQUEST_DERIVE_NATIVE_SCRIPT_HASH);
}

static void test_simple_parse_failure_must_not_reach_postparse_state_mutation(void **state) {
    (void) state;
    reset_test_context();

    // Invalid device-owned key path fixture from reject vectors.
    uint8_t invalid_payload[27] = {
        0x00, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    buffer_t invalid_buf = {
        .ptr = invalid_payload,
        .size = sizeof(invalid_payload),
        .offset = 0,
    };

    // This should produce a rejection SW and clean reset only.
    // Current code continues into simpleScriptFinished() and hits ASSERT after reset.
    handler_derive_native_script_hash(&invalid_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(g_last_sw, SWO_NATIVE_SCRIPT_PARSING_FAIL_PUBKEY_CREDENTIAL);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_finish_must_keep_request_lock_until_user_confirmation),
        cmocka_unit_test(test_simple_parse_failure_must_not_reach_postparse_state_mutation),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

