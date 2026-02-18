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
#include "hexUtils.h"
#include "mock_crypto/crypto_mock_data.h"
#include "blake2b.h"
#include "mem.h"

#include "test_derive_native_script_deny_fixtures.h"
#include "deriveNativeScriptHash/deriveNativeScriptHash_types.h"
#include "handler/derive_native_script_hash.h"
#include "apdu/dispatcher.h"
#include "app_context.h"
#include "test_native_script_utils.h"
#include "nbgl_mock.h"
#include "apdu_finalization_check.h"
#include "test_read_buffer_helpers.h"

// ----------------------------------------------------------------------
// Fixture runner
// ----------------------------------------------------------------------

// Recursive fixture runner for deny tests
void run_recursive_fixture_deny(const native_script_t *script, uint16_t expected_response) {
    if (script == NULL) {
        TRACE("  NULL script!");
    } else {
        TRACE("Running script type: %d", script->type);
        switch (script->type) {
            case NATIVE_SCRIPT_TYPE_INVALID_HEREAFTER:
            case NATIVE_SCRIPT_TYPE_INVALID_BEFORE:
            case NATIVE_SCRIPT_TYPE_PUBKEY_DEVICE_OWNED:
            case NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY: {
                test_read_buffer_t native_script_simple_buffer = make_test_read_buffer(
                    script->impl.simple.apdu_payload,
                    script->impl.simple.apdu_payload_length
                );
                run_derive_native_script_apdu(&native_script_simple_buffer.sdk_buffer, P1_NATIVE_SCRIPT_ADD_SIMPLE);
                assert_read_buffer_unchanged_and_cleanup(
                    &native_script_simple_buffer,
                    script->impl.simple.apdu_payload
                );
                if (get_last_sw() != SWO_SUCCESS) {
                    assert_int_equal(get_last_sw(), expected_response);
                }
            } break;
            case NATIVE_SCRIPT_TYPE_ALL: {
                TRACE("  ALL");

                uint8_t apdu_buffer[64] = {0};
                size_t apdu_length = 0;
                build_complex_script_start_buffer(
                    apdu_buffer,
                    &apdu_length,
                    NATIVE_SCRIPT_ALL,
                    (uint32_t) script->impl.complex.params.all.scripts_count,
                    0  // required_count unused for ALL
                );

                buffer_t buf = {
                    .ptr = apdu_buffer,
                    .size = apdu_length,
                    .offset = 0,
                };

                run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);
                if (get_last_sw() != SWO_SUCCESS) {
                    assert_int_equal(get_last_sw(), expected_response);
                }

                for (size_t i = 0; i < script->impl.complex.params.all.scripts_count; i++) {
                    run_recursive_fixture_deny(script->impl.complex.params.all.scripts[i],
                                          expected_response);
                }
                break;
            }
            case NATIVE_SCRIPT_TYPE_ANY: {
                TRACE("  ANY");

                uint8_t apdu_buffer[64] = {0};
                size_t apdu_length = 0;
                build_complex_script_start_buffer(
                    apdu_buffer,
                    &apdu_length,
                    NATIVE_SCRIPT_ANY,
                    (uint32_t) script->impl.complex.params.any.scripts_count,
                    0  // required_count unused for ANY
                );

                buffer_t buf = {
                    .ptr = apdu_buffer,
                    .size = apdu_length,
                    .offset = 0,
                };

                TRACE_BUFFER(buf.ptr, buf.size);
                run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);
                if (get_last_sw() != SWO_SUCCESS) {
                    assert_int_equal(get_last_sw(), expected_response);
                }

                for (size_t i = 0; i < script->impl.complex.params.any.scripts_count; i++) {
                    run_recursive_fixture_deny(script->impl.complex.params.any.scripts[i],
                                          expected_response);
                }
                break;
            }
            case NATIVE_SCRIPT_TYPE_N_OF_K: {
                TRACE("  N_OF_K");

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

                buffer_t buf = {
                    .ptr = apdu_buffer,
                    .size = apdu_length,
                    .offset = 0,
                };

                run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);
                if (get_last_sw() != SWO_SUCCESS) {
                    assert_int_equal(get_last_sw(), expected_response);
                }

                for (size_t i = 0; i < script->impl.complex.params.n_of_k.scripts_count; i++) {
                    run_recursive_fixture_deny(script->impl.complex.params.n_of_k.scripts[i],
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
    reset_response_buffer();
    nbgl_mock_reset();
    nbgl_mock_set_streaming_start_auto_complete(true, true);

    // Check not null
    TRACE("Running derive address fixture: %s", fixture->name);
    assert_true(fixture->root_script != NULL);

    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_sw(), SWO_SUCCESS);

    TRACE("Expected response: 0x%04X", fixture->expected_response);
    // Send all scripts recursively
    run_recursive_fixture_deny(fixture->root_script, fixture->expected_response);

    // Send finish APDU if last operation succeeded
    if (get_last_sw() == SWO_SUCCESS){
        test_read_buffer_t native_script_finish_buffer = make_test_read_buffer(
            fixture->finish_apdu_payload,
            fixture->finish_apdu_payload_length
        );
        run_derive_native_script_apdu(&native_script_finish_buffer.sdk_buffer, P1_NATIVE_SCRIPT_FINISH);
        assert_read_buffer_unchanged_and_cleanup(
            &native_script_finish_buffer,
            fixture->finish_apdu_payload
        );
        assert_int_equal(get_last_sw(), fixture->expected_response);
    }
}

// Test function that iterates through all deny fixtures
static void test_native_script_fixture(void **state) {
    const native_script_test_case_t *fixture = *state;
    TRACE("Starting fixture: %s", fixture->name);
    run_fixture(fixture);
}

int main(void) {
    TRACE("Starting test_native_script_deny_tests");

    struct CMUnitTest *tests = calloc(NATIVE_SCRIPT_FIXTURES_COUNT, sizeof(*tests));
    if (tests == NULL) {
        return 1;
    }

    for (size_t i = 0; i < NATIVE_SCRIPT_FIXTURES_COUNT; i++) {
        tests[i].name = NATIVE_SCRIPT_FIXTURES[i].name;
        tests[i].test_func = test_native_script_fixture;
        tests[i].initial_state = (void *)&NATIVE_SCRIPT_FIXTURES[i];
    }

    int result = _cmocka_run_group_tests("native_script_deny_tests",
                                         tests,
                                         NATIVE_SCRIPT_FIXTURES_COUNT,
                                         NULL,
                                         assert_no_pending_apdu_response);
    free(tests);
    return result;
}
