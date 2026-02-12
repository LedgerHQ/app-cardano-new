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
#include "test_native_script_utils.h"
#include "nbgl_mock.h"

// Recursive fixture runner for success tests
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
                buffer_t buf = {
                    .ptr = script->impl.simple.apdu_payload,
                    .size = script->impl.simple.apdu_payload_length,
                    .offset = 0,
                };
                run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
                assert_int_equal(get_last_sw(), SWO_SUCCESS);
            } break;
            case NATIVE_SCRIPT_TYPE_ALL: {
                TRACE("  ALL\n");

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
                assert_int_equal(get_last_sw(), SWO_SUCCESS);

                for (size_t i = 0; i < script->impl.complex.params.all.scripts_count; i++) {
                    run_recursive_fixture(script->impl.complex.params.all.scripts[i]);
                }
                break;
            }
            case NATIVE_SCRIPT_TYPE_ANY: {
                TRACE("  ANY\n");

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
                assert_int_equal(get_last_sw(), SWO_SUCCESS);

                for (size_t i = 0; i < script->impl.complex.params.any.scripts_count; i++) {
                    run_recursive_fixture(script->impl.complex.params.any.scripts[i]);
                }
                break;
            }
            case NATIVE_SCRIPT_TYPE_N_OF_K: {
                TRACE("  N_OF_K\n");

                uint8_t apdu_buffer[64] = {0};
                size_t apdu_length = 0;
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
                assert_int_equal(get_last_sw(), SWO_SUCCESS);

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
    reset_response_buffer();
    nbgl_mock_reset();
    nbgl_mock_set_streaming_start_auto_complete(true, true);

    // Check not null
    TRACE("Running derive address fixture: %s\n", fixture->name);
    assert_true(fixture->root_script != NULL);

    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_sw(), SWO_SUCCESS);

    // Send all scripts recursively
    run_recursive_fixture(fixture->root_script);

    // Send finish APDU
    buffer_t buf = {
        .ptr = fixture->finish_apdu_payload,
        .size = fixture->finish_apdu_payload_length,
        .offset = 0,
    };
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_FINISH);

    // Compare derived hash with expected hash
    assert_memory_equal(get_response_buffer(), fixture->expected_hash, SCRIPT_HASH_LENGTH);
    assert_int_equal(get_last_sw(), SWO_SUCCESS);
}
