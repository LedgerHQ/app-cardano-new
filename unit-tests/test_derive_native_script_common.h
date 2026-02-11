/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>

#include "globals.h"
#include "securityPolicy/securityPolicy.h"
#include "apdu/dispatcher.h"
#include "globals.h"
#include <assert.h>

#include <cmocka.h>
#include "handler/derive_address.h"
#include "app_context.h"
#include "mock_crypto/crypto_mock_data.h"
#include "blake2b.h"
#include "mem.h"

#include "handler/derive_native_script_hash.h"

// ----------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------

static uint16_t g_last_sw = 0;

#define MAX_RESPONSE_BUFFER_SIZE 28
static uint8_t g_response_buffer[MAX_RESPONSE_BUFFER_SIZE];
static size_t g_response_buffer_length = 0;
// ----------------------------------------------------------------------
// Simple mocks for IO and UI plumbing so we can drive the handler
// ----------------------------------------------------------------------
#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static inline bool test_mem_init(void) {
    return mem_utils_init(test_heap, sizeof(test_heap));
}

extern bool app_mem_init(void);
static inline void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
}

static inline void run_derive_native_script_apdu(buffer_t *buffer, uint8_t p1) {
    apdu_response_begin(INS_DERIVE_NATIVE_SCRIPT_HASH);
    handler_derive_native_script_hash(buffer, p1);
    apdu_response_assert_sent_or_deferred();
}

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    LEDGER_ASSERT(bufferLength <= MAX_RESPONSE_BUFFER_SIZE, "Response buffer overflow");

    // Save response data to global buffer
    if (buffer != NULL && bufferLength > 0) {
        memcpy(g_response_buffer, buffer, bufferLength);
        g_response_buffer_length = bufferLength;
    } else {
        g_response_buffer_length = 0;
    }

    g_last_sw = swo;
    return 0;
}

int io_send_sw(uint16_t swo) {
    g_last_sw = swo;
    return 0;
}

void ui_display_native_script_hash(security_policy_t securityPolicy);

void ui_display_native_script_hash(security_policy_t securityPolicy) {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;

    TRACE("securityPolicy: %d", securityPolicy);
    if (securityPolicy == POLICY_DENY) {
        TRACE("Security condition not satisfied");
        send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        return;
    }

    switch (ctx->ui_scriptType) {
        case UI_SCRIPT_INIT: {
            TRACE("UI_SCRIPT_INIT");
            return;
        }
        case UI_SCRIPT_ALL: {
            TRACE("UI_SCRIPT_ALL");
            apdu_response_send_data(NULL, 0, SWO_SUCCESS);
            break;
        }
        case UI_SCRIPT_N_OF_K: {
            TRACE("UI_SCRIPT_N_OF_K");
            apdu_response_send_data(NULL, 0, SWO_SUCCESS);
            break;
        }
        case UI_SCRIPT_ANY: {
            TRACE("UI_SCRIPT_ANY");
            apdu_response_send_data(NULL, 0, SWO_SUCCESS);
            break;
        }
        case UI_SCRIPT_PUBKEY_PATH: {
            TRACE("UI_SCRIPT_PUBKEY_PATH");
            apdu_response_send_data(NULL, 0, SWO_SUCCESS);
            break;
        }
        case UI_SCRIPT_PUBKEY_HASH: {
            TRACE("UI_SCRIPT_PUBKEY_HASH");
            apdu_response_send_data(NULL, 0, SWO_SUCCESS);
            break;
        }
        case UI_SCRIPT_INVALID_BEFORE: {
            TRACE("UI_SCRIPT_INVALID_BEFORE");
            apdu_response_send_data(NULL, 0, SWO_SUCCESS);
            break;
        }
        case UI_SCRIPT_INVALID_HEREAFTER: {
            TRACE("UI_SCRIPT_INVALID_HEREAFTER");
            apdu_response_send_data(NULL, 0, SWO_SUCCESS);
            break;
        }
        case UI_SCRIPT_DISPLAY_BECH32: {
            TRACE("UI_SCRIPT_DISPLAY_BECH32");
            apdu_response_send_data(ctx->scriptHashBuffer, SCRIPT_HASH_LENGTH, SWO_SUCCESS);
            break;
        }
        case UI_SCRIPT_DISPLAY_POLICY_ID: {
            TRACE("UI_SCRIPT_DISPLAY_POLICY_ID");
            apdu_response_send_data(ctx->scriptHashBuffer, SCRIPT_HASH_LENGTH, SWO_SUCCESS);
            break;
        }
        default: {
            TRACE("Invalid UI step");
            send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
            return;
        }
    }
    return;
}

// Helper to write uint32 in big-endian format
static inline void write_u32_be(uint8_t *buffer, uint32_t value) {
    buffer[0] = (value >> 24) & 0xFF;
    buffer[1] = (value >> 16) & 0xFF;
    buffer[2] = (value >> 8) & 0xFF;
    buffer[3] = value & 0xFF;
}

// Construct APDU buffer for complex script start
// Format: [script_type: 1 byte][children_count: 4 bytes BE]
// For N_OF_K, add: [required_count: 4 bytes BE]
static inline void build_complex_script_start_buffer(
    uint8_t *buffer,
    size_t *buffer_length,
    uint8_t script_type,
    uint32_t children_count,
    uint32_t required_count  // Only used for N_OF_K
) {
    LEDGER_ASSERT(script_type == NATIVE_SCRIPT_ALL || script_type == NATIVE_SCRIPT_ANY ||
                      script_type == NATIVE_SCRIPT_N_OF_K,
                  "Invalid complex script type");

    size_t offset = 0;

    // Byte 0: script type
    buffer[offset++] = script_type;

    // Bytes 1-4: children count (big-endian)
    write_u32_be(&buffer[offset], children_count);
    offset += 4;

    // Bytes 5-8: required count (only for N_OF_K)
    if (script_type == NATIVE_SCRIPT_N_OF_K) {
        write_u32_be(&buffer[offset], required_count);
        offset += 4;
    }

    *buffer_length = offset;
}

void run_recursive_fixture(const native_script_t *script) {
    if (script == NULL) {
        TRACE("  NULL script!\n");
    } else {
        TRACE("Running script type: %d\n", script->type);
        switch (script->type) {
            case NATIVE_SCRIPT_TYPE_INVALID_HEREAFTER:
            case NATIVE_SCRIPT_TYPE_INVALID_BEFORE:
            case NATIVE_SCRIPT_TYPE_PUBKEY_DEVICE_OWNED:
            case NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY: {
                g_last_sw = 0;
                buffer_t buf = {
                    .ptr = script->impl.simple.apdu_payload,
                    .size = script->impl.simple.apdu_payload_length,
                    .offset = 0,
                };
                run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
                assert_int_equal(g_last_sw, SWO_SUCCESS);
            } break;
            case NATIVE_SCRIPT_TYPE_ALL: {
                TRACE("  ALL\n");
                g_last_sw = 0;

                uint8_t apdu_buffer[64] = {0};
                size_t apdu_length = 0;
                build_complex_script_start_buffer(
                    apdu_buffer,
                    &apdu_length,
                    NATIVE_SCRIPT_ALL,
                    (uint32_t) script->impl.complex.params.all.scripts_count,
                    0  // required_count unused for ALL
                );

                // Create buffer_t for handler
                buffer_t buf = {
                    .ptr = apdu_buffer,
                    .size = apdu_length,
                    .offset = 0,
                };
                run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);
                assert_int_equal(g_last_sw, SWO_SUCCESS);

                for (size_t i = 0; i < script->impl.complex.params.all.scripts_count; i++) {
                    run_recursive_fixture(script->impl.complex.params.all.scripts[i]);
                }
                break;
            }
            case NATIVE_SCRIPT_TYPE_ANY: {
                TRACE("  ANY\n");
                g_last_sw = 0;

                uint8_t apdu_buffer[64] = {0};
                size_t apdu_length = 0;
                build_complex_script_start_buffer(
                    apdu_buffer,
                    &apdu_length,
                    NATIVE_SCRIPT_ANY,
                    (uint32_t) script->impl.complex.params.any.scripts_count,
                    0  // required_count unused for ANY
                );

                // Create buffer_t for handler
                buffer_t buf = {
                    .ptr = apdu_buffer,
                    .size = apdu_length,
                    .offset = 0,
                };

                TRACE_BUFFER(buf.ptr, buf.size);
                run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);
                assert_int_equal(g_last_sw, SWO_SUCCESS);

                for (size_t i = 0; i < script->impl.complex.params.any.scripts_count; i++) {
                    run_recursive_fixture(script->impl.complex.params.any.scripts[i]);
                }
                break;
            }
            case NATIVE_SCRIPT_TYPE_N_OF_K: {
                TRACE("  N_OF_K\n");
                g_last_sw = 0;

                uint8_t apdu_buffer[64] = {0};
                size_t apdu_length = 0;
                build_complex_script_start_buffer(
                    apdu_buffer,
                    &apdu_length,
                    NATIVE_SCRIPT_N_OF_K,
                    (uint32_t) script->impl.complex.params.n_of_k.scripts_count,
                    (uint32_t) script->impl.complex.params.n_of_k.required_count);

                // Create buffer_t for handler
                buffer_t buf = {
                    .ptr = apdu_buffer,
                    .size = apdu_length,
                    .offset = 0,
                };
                run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);
                assert_int_equal(g_last_sw, SWO_SUCCESS);

                for (size_t i = 0; i < script->impl.complex.params.n_of_k.scripts_count; i++) {
                    run_recursive_fixture(script->impl.complex.params.n_of_k.scripts[i]);
                }
                break;
            }
            default:
                TRACE("  Unknown script type!\n");
                assert_true(false);
        }
    }
}

static inline void run_fixture(const native_script_test_case_t *fixture) {
    reset_context();
    assert_true(test_mem_init());

    // Initialize response buffer to zero
    memset(g_response_buffer, 0, sizeof(g_response_buffer));
    g_response_buffer_length = 0;
    g_last_sw = 0;

    // Check not null
    TRACE("Running derive address fixture: %s\n", fixture->name);

    assert_true(fixture->root_script != NULL);

    // Send all scripts recursively
    run_recursive_fixture(fixture->root_script);

    // Send finish APDU
    g_last_sw = 0;
    // Create buffer_t for handler
    buffer_t buf = {
        .ptr = fixture->finish_apdu_payload,
        .size = fixture->finish_apdu_payload_length,
        .offset = 0,
    };
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_FINISH);

    // Compare derived hash with expected hash using buffer_equals
    assert_memory_equal(g_response_buffer, fixture->expected_hash, SCRIPT_HASH_LENGTH);
    assert_int_equal(g_last_sw, SWO_SUCCESS);
}
