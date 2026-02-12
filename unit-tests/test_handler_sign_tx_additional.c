/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "addressUtils/bip44.h"
#include "cardano_constants.h"
#include "cardano_swo.h"
#include "mock_crypto/crypto_mock_data.h"
#include "globals.h"
#include "init_apdu.h"
#include "test_sign_tx_common.h"
#include "test_sign_tx_fixtures_pool_registration.h"
#include "apdu_finalization_check.h"

static uint32_t harden(uint32_t value) {
    return value | HARDENED_BIP32;
}

static size_t write_bip44_path(uint8_t *out,
                               size_t out_size,
                               const uint32_t *path,
                               size_t path_len) {
    const size_t required = 1 + 4 * path_len;
    assert_true(required <= out_size);
    assert_true(path_len <= BIP44_MAX_PATH_ELEMENTS);

    out[0] = (uint8_t) path_len;
    for (size_t i = 0; i < path_len; i++) {
        out[1 + i * 4] = (uint8_t) ((path[i] >> 24) & 0xFFu);
        out[2 + i * 4] = (uint8_t) ((path[i] >> 16) & 0xFFu);
        out[3 + i * 4] = (uint8_t) ((path[i] >> 8) & 0xFFu);
        out[4 + i * 4] = (uint8_t) (path[i] & 0xFFu);
    }
    return required;
}

static void init_and_run_fixture_until_hash_ready(const tx_fixture_t *fixture) {
    assert_non_null(fixture);
    reset_context();
    assert_true(test_mem_init());

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_sw, SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);
    assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);

    run_sign_tx_body_chunked(fixture->raw_tx, fixture->raw_tx_len);
}

static void test_sign_tx_witness_flow_signs_and_resets_context(void **state) {
    (void) state;

    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_and_run_fixture_until_hash_ready(fixture);

    assert_int_equal(g_last_response_sw, SWO_SUCCESS);
    assert_int_equal(g_last_response_len, TX_HASH_LENGTH);
    assert_int_equal(G_context.state.tx_state, TX_STATE_APPROVED);
    assert_int_equal(G_context.tx_info.current_witness, 0);
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

    assert_int_equal(g_last_response_sw, SWO_SUCCESS);
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
    reset_context();
    assert_true(test_mem_init());

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    params.numWitnesses = 0;
    params.rawTxTotalLength = (uint16_t)fixture->raw_tx_len;
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_sw, SWO_SUCCESS);
    assert_int_equal(G_context.tx_info.num_witnesses, 0);
    assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);

    run_sign_tx_body_chunked(fixture->raw_tx, fixture->raw_tx_len);

    assert_int_equal(g_last_response_sw, SWO_SUCCESS);
    assert_int_equal(g_last_response_len, TX_HASH_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.tx_state, TX_STATE_NONE);
}

static void test_sign_tx_rejects_empty_non_final_chunk(void **state) {
    (void) state;

    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    reset_context();
    assert_true(test_mem_init());

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_sw, SWO_SUCCESS);
    assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);

    run_sign_tx_apdu(&(buffer_t){.ptr = NULL, .size = 0, .offset = 0}, P1_TX_CHUNK);

    assert_int_equal(g_last_response_sw, SWO_WRONG_DATA_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.tx_state, TX_STATE_NONE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sign_tx_witness_flow_signs_and_resets_context),
        cmocka_unit_test(test_sign_tx_zero_witnesses_auto_resets_context),
        cmocka_unit_test(test_sign_tx_rejects_empty_non_final_chunk),
    };
    return _cmocka_run_group_tests("test_handler_sign_tx_additional",
                                   tests,
                                   ARRAY_LEN(tests),
                                   NULL,
                                   assert_no_pending_apdu_response);
}
