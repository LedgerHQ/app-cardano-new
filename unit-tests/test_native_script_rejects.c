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
#include "hexUtils.h"
#include "mock_crypto/crypto_mock_data.h"
#include "blake2b.h"
#include "memory/mem.h"

#include "test_derive_native_script_reject_fixtures.h"
#include "deriveNativeScriptHash/deriveNativeScriptHash_types.h"
#include "handler/derive_native_script_hash.h"
#include "apdu/dispatcher.h"
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

void ui_display_native_script_hash(security_policy_t securityPolicy);

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static inline bool test_mem_init(void) {
    return mem_utils_init(test_heap, sizeof(test_heap));
}
extern bool app_mem_init(void);
static inline void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
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

void send_swo_and_reset(uint16_t swo) {
    TRACE("send_swo_and_reset swo=0x%04x", swo);
    g_last_sw = swo;
}

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

void ui_display_native_script_hash(security_policy_t securityPolicy) {
    (void) securityPolicy;
}

// ----------------------------------------------------------------------
// Fixture runner
// ----------------------------------------------------------------------

void run_recursive_fixture(const native_script_t *script, uint16_t expected_response) {
    if (script == NULL) {
        TRACE("  NULL script!");
    } else {
        TRACE("Running script type: %d", script->type);
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
                handler_derive_native_script_hash(&buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
                if (g_last_sw != SWO_SUCCESS) {
                    assert_int_equal(g_last_sw, expected_response);
                }
            } break;
            case NATIVE_SCRIPT_TYPE_ALL: {
                TRACE("  ALL");
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

                handler_derive_native_script_hash(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);
                if (g_last_sw != SWO_SUCCESS) {
                    assert_int_equal(g_last_sw, expected_response);
                }

                for (size_t i = 0; i < script->impl.complex.params.all.scripts_count; i++) {
                    run_recursive_fixture(script->impl.complex.params.all.scripts[i],
                                          expected_response);
                }
                break;
            }
            case NATIVE_SCRIPT_TYPE_ANY: {
                TRACE("  ANY");
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
                handler_derive_native_script_hash(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);
                if (g_last_sw != SWO_SUCCESS) {
                    assert_int_equal(g_last_sw, expected_response);
                }

                for (size_t i = 0; i < script->impl.complex.params.any.scripts_count; i++) {
                    run_recursive_fixture(script->impl.complex.params.any.scripts[i],
                                          expected_response);
                }
                break;
            }
            case NATIVE_SCRIPT_TYPE_N_OF_K: {
                TRACE("  N_OF_K");
                g_last_sw = 0;

                uint8_t apdu_buffer[64] = {0};
                size_t apdu_length = 0;
                TRACE("    scripts_count=%u, required_count=%u",
                      script->impl.complex.params.n_of_k.scripts_count,
                      script->impl.complex.params.n_of_k.required_count);
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

                handler_derive_native_script_hash(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);
                if (g_last_sw != SWO_SUCCESS) {
                    assert_int_equal(g_last_sw, expected_response);
                }

                for (size_t i = 0; i < script->impl.complex.params.n_of_k.scripts_count; i++) {
                    run_recursive_fixture(script->impl.complex.params.n_of_k.scripts[i],
                                          expected_response);
                }
                break;
            }
            default:
                TRACE("  Unknown script type!");
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
    TRACE("Running derive address fixture: %s", fixture->name);

    assert_true(fixture->root_script != NULL);

    TRACE("Expected response: 0x%04X", fixture->expected_response);
    // Send all scripts recursively
    run_recursive_fixture(fixture->root_script, fixture->expected_response);

    // Send finish APDU
    if (g_last_sw == SWO_SUCCESS){
        // Create buffer_t for handler
        buffer_t buf = {
            .ptr = fixture->finish_apdu_payload,
            .size = fixture->finish_apdu_payload_length,
            .offset = 0,
        };
        handler_derive_native_script_hash(&buf, P1_NATIVE_SCRIPT_FINISH);

        {
            assert_int_equal(g_last_sw, fixture->expected_response);
        }
    }
}

// Test function that iterates through all rejection fixtures
static void test_native_script_fixture(void **state) {
    const native_script_test_case_t *fixture = *state;
    TRACE("Starting fixture: %s", fixture->name);
    run_fixture(fixture);
}

int main(void) {
    TRACE("Starting test_native_script_rejects");

    struct CMUnitTest *tests = calloc(NATIVE_SCRIPT_FIXTURES_COUNT, sizeof(*tests));
    if (tests == NULL) {
        return 1;
    }

    for (size_t i = 0; i < NATIVE_SCRIPT_FIXTURES_COUNT; i++) {
        tests[i].name = NATIVE_SCRIPT_FIXTURES[i].name;
        tests[i].test_func = test_native_script_fixture;
        tests[i].initial_state = (void *)&NATIVE_SCRIPT_FIXTURES[i];
    }

    int result = _cmocka_run_group_tests("native_script_rejects",
                                         tests,
                                         NATIVE_SCRIPT_FIXTURES_COUNT,
                                         NULL,
                                         NULL);
    free(tests);
    return result;
}
