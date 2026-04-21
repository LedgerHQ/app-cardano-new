/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "cardano_constants.h"
#include "globals.h"
#include "sign_tx_ctx.h"
#include "handler/sign_tx.h"
#include "securityPolicy.h"
#include "addressUtils/bip44.h"
#include "cardano_swo.h"
#include "app_context.h"
#include "mock_crypto/crypto_mock_data.h"
#include "test_fixture_types.h"
#include "test_sign_tx_common.h"
#include "test_utils/init_apdu.h"
#include "generated/sign_tx/test_sign_tx_fixtures_pool_registration.h"
#include "apdu_finalization_check.h"

static void reset_test_context(void) {
    reset_context();
    assert_true(test_mem_init());
}

// NBGL and UI mocks provided by cardano_sign_tx_core (nbgl_mock.c + real UI files)

static uint32_t harden(uint32_t value) {
    return value | HARDENED_BIP32;
}

static void setup_active_sign_tx_request(tx_state_e tx_state) {
    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = tx_state;
}

static size_t write_bip44_path(uint8_t *out,
                               size_t out_size,
                               const uint32_t *path,
                               size_t path_len) {
    size_t required = 1 + path_len * 4;
    assert_true(required <= out_size);
    assert_true(path_len <= BIP44_MAX_PATH_ELEMENTS);

    out[0] = (uint8_t) path_len;
    for (size_t i = 0; i < path_len; i++) {
        uint32_t value = path[i];
        out[1 + i * 4] = (uint8_t) ((value >> 24) & 0xFF);
        out[2 + i * 4] = (uint8_t) ((value >> 16) & 0xFF);
        out[3 + i * 4] = (uint8_t) ((value >> 8) & 0xFF);
        out[4 + i * 4] = (uint8_t) (value & 0xFF);
    }
    return required;
}

static size_t write_standard_payment_path(uint8_t *out, size_t out_size) {
    const uint32_t path[] = {
        harden(PURPOSE_SHELLEY),
        harden(ADA_COIN_TYPE),
        harden(0),
        0,
        0,
    };
    return write_bip44_path(out, out_size, path, sizeof(path) / sizeof(path[0]));
}

static void init_and_run_fixture_until_hash_ready(const tx_fixture_t *fixture) {
    assert_non_null(fixture);
    reset_test_context();

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);
    assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);

    run_sign_tx_body_chunked(fixture->raw_tx, fixture->raw_tx_len);
}

static void test_sign_tx_init_deny_when_request_is_active(void **state) {
    (void) state;
    reset_test_context();

    setup_active_sign_tx_request(TX_STATE_NONE);
    uint8_t dummy = 0;
    buffer_t init_buf = {
        .ptr = &dummy,
        .size = 0,
        .offset = 0,
    };

    run_sign_tx_apdu(&init_buf, P1_TX_INIT);
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.tx_state, TX_STATE_NONE);
}

static void test_sign_tx_chunk_deny_without_active_request(void **state) {
    (void) state;
    reset_test_context();

    uint8_t chunk[2] = {0x00, 0x00};
    buffer_t chunk_buf = {
        .ptr = chunk,
        .size = sizeof(chunk),
        .offset = 0,
    };

    run_sign_tx_apdu(&chunk_buf, P1_TX_CHUNK);
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_sign_tx_confirm_stops_after_chunk_error(void **state) {
    (void) state;
    reset_test_context();

    // Confirm is only valid from TX_STATE_CHUNKS. Any other active tx state must be rejected.
    setup_active_sign_tx_request(TX_STATE_NONE);

    uint8_t chunk[1] = {0x00};
    buffer_t confirm_buf = {
        .ptr = chunk,
        .size = sizeof(chunk),
        .offset = 0,
    };

    run_sign_tx_apdu(&confirm_buf, P1_TX_CONFIRM);
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.tx_state, TX_STATE_NONE);
}

static void test_sign_tx_witness_deny_before_approved_state(void **state) {
    (void) state;
    reset_test_context();

    setup_active_sign_tx_request(TX_STATE_NONE);
    G_context.tx_info.num_witnesses = 1;
    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY;

    uint8_t path_raw[32] = {0};
    size_t path_len = write_standard_payment_path(path_raw, sizeof(path_raw));

    buffer_t witness_buf = {
        .ptr = path_raw,
        .size = path_len,
        .offset = 0,
    };

    run_sign_tx_witness_apdu(&witness_buf);
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_sign_tx_witness_flow_signs_and_resets_context(void **state) {
    (void) state;

    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_and_run_fixture_until_hash_ready(fixture);

    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(g_last_response_len, TX_HASH_LENGTH);
    assert_int_equal(G_context.state.tx_state, TX_STATE_APPROVED);
    assert_int_equal(tx_witness_ctx()->current_witness, 0);
    assert_int_equal(G_context.tx_info.num_witnesses, 1);
    uint8_t tx_hash_before_witness[TX_HASH_LENGTH] = {0};
    memcpy(tx_hash_before_witness, g_last_response, TX_HASH_LENGTH);

    reset_mock_signature_state();

    const uint32_t witness_path[] = {
        harden(PURPOSE_SHELLEY),
        harden(ADA_COIN_TYPE),
        harden(0),
        2,
        0,
    };
    uint8_t witness_path_apdu[1 + 4 * BIP44_MAX_PATH_ELEMENTS] = {0};
    const size_t witness_path_apdu_len = write_bip44_path(witness_path_apdu,
                                                          sizeof(witness_path_apdu),
                                                          witness_path,
                                                          ARRAY_LEN(witness_path));
    run_sign_tx_witness_apdu(&(buffer_t){
        .ptr = witness_path_apdu,
        .size = witness_path_apdu_len,
        .offset = 0,
    });

    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(g_last_response_len, ED25519_SIGNATURE_LENGTH);
    assert_non_null(g_mock_last_signature_entry);
    assert_int_equal(g_mock_last_signed_message_len, TX_HASH_LENGTH);
    assert_memory_equal(g_mock_last_signed_message, tx_hash_before_witness, TX_HASH_LENGTH);
    assert_memory_equal(g_last_response,
                        g_mock_last_signature_entry->signature,
                        ED25519_SIGNATURE_LENGTH);

    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.tx_state, TX_STATE_NONE);
}

static void test_sign_tx_zero_witnesses_auto_resets_context(void **state) {
    (void) state;

    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    reset_test_context();

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    params.numWitnesses = 0;
    params.rawTxTotalLength = (uint16_t) fixture->raw_tx_len;
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(G_context.tx_info.num_witnesses, 0);
    assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);

    run_sign_tx_body_chunked(fixture->raw_tx, fixture->raw_tx_len);

    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(g_last_response_len, TX_HASH_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.tx_state, TX_STATE_NONE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sign_tx_init_deny_when_request_is_active),
        cmocka_unit_test(test_sign_tx_chunk_deny_without_active_request),
        cmocka_unit_test(test_sign_tx_confirm_stops_after_chunk_error),
        cmocka_unit_test(test_sign_tx_witness_deny_before_approved_state),
        cmocka_unit_test(test_sign_tx_witness_flow_signs_and_resets_context),
        cmocka_unit_test(test_sign_tx_zero_witnesses_auto_resets_context),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
