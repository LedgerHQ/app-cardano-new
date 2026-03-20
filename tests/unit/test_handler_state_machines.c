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
#include "mem.h"
#include "app_context.h"
#include "mock_crypto/crypto_mock_data.h"
#include "test_fixture_types.h"
#include "test_utils/init_apdu.h"
#include "generated/sign_tx/test_sign_tx_fixtures_pool_registration.h"
#include "apdu_finalization_check.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];
static uint16_t g_last_sw = 0;
static uint8_t g_last_response[ED25519_SIGNATURE_LENGTH];
static size_t g_last_response_len = 0;

static inline void run_sign_tx_apdu(buffer_t *buffer, uint8_t p1) {
    apdu_response_begin(INS_SIGN_TX);
    handler_sign_tx(buffer, p1);
    apdu_response_assert_sent_or_deferred();
}

static inline void run_sign_tx_witness_apdu(buffer_t *buffer) {
    apdu_response_begin(INS_SIGN_TX);
    handler_sign_tx_witness(buffer);
    apdu_response_assert_sent_or_deferred();
}

static inline bool test_mem_init(void) {
    return mem_utils_init(test_heap, sizeof(test_heap));
}

static void reset_test_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    memset(g_last_response, 0, sizeof(g_last_response));
    g_last_response_len = 0;
    g_last_sw = 0;
    assert_true(test_mem_init());
}

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    assert_true(bufferLength <= sizeof(g_last_response));
    if (buffer != NULL && bufferLength > 0) {
        memcpy(g_last_response, buffer, bufferLength);
    }
    g_last_response_len = bufferLength;
    g_last_sw = swo;
    return 0;
}

int io_send_sw(uint16_t swo) {
    g_last_sw = swo;
    return 0;
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

static init_apdu_params_t build_init_params_from_fixture_local(const tx_fixture_t *fixture) {
    assert_non_null(fixture);
    return (init_apdu_params_t) {
        .options = fixture->options,
        .networkId = fixture->network_id,
        .protocolMagic = fixture->protocol_magic,
        .signingMode = fixture->signing_mode,
        .numInputs = fixture->num_inputs,
        .numOutputs = fixture->num_outputs,
        .includeTtl = fixture->include_ttl,
        .numCertificates = fixture->num_certificates,
        .numWithdrawals = fixture->num_withdrawals,
        .includeAuxData = fixture->include_aux_data_hash,
        .auxDataType = fixture->aux_data_type,
        .auxDataHash = NULL,
        .auxDataHashLen = 0,
        .includeValidityIntervalStart = fixture->include_validity_interval_start,
        .numMintAssetGroups = fixture->num_mint_asset_groups,
        .includeScriptDataHash = fixture->include_script_data_hash,
        .numCollateralInputs = fixture->num_collateral_inputs,
        .numRequiredSigners = fixture->num_required_signers,
        .includeNetworkId = fixture->include_network_id,
        .includeCollateralOutput = fixture->include_collateral_output,
        .includeTotalCollateral = fixture->include_total_collateral,
        .numReferenceInputs = fixture->num_reference_inputs,
        .numVoters = fixture->num_voters,
        .includeTreasury = fixture->include_treasury,
        .includeDonation = fixture->include_donation,
        .numWitnesses = fixture->num_witnesses,
        .rawTxTotalLength = (uint16_t) fixture->raw_tx_len,
    };
}

static void run_sign_tx_body_chunked_local(const uint8_t *raw_tx, size_t raw_tx_len) {
    assert_non_null(raw_tx);
    assert_true(raw_tx_len > 0);

    size_t tx_offset = 0;
    while (tx_offset < raw_tx_len) {
        size_t remaining_bytes = raw_tx_len - tx_offset;
        size_t current_chunk_size = (remaining_bytes > MAX_SIGN_TX_CHUNK_SIZE)
                                        ? MAX_SIGN_TX_CHUNK_SIZE
                                        : remaining_bytes;
        uint8_t p1 = (tx_offset + current_chunk_size < raw_tx_len) ? P1_TX_CHUNK : P1_TX_CONFIRM;

        buffer_t chunk_buf = {
            .ptr = (uint8_t *) (raw_tx + tx_offset),
            .size = current_chunk_size,
            .offset = 0,
        };
        run_sign_tx_apdu(&chunk_buf, p1);
        assert_int_equal(g_last_sw, SWO_SUCCESS);
        tx_offset += current_chunk_size;
    }
}

static void init_and_run_fixture_until_hash_ready(const tx_fixture_t *fixture) {
    assert_non_null(fixture);
    reset_test_context();

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture_local(fixture);
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_sw, SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);
    assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);

    run_sign_tx_body_chunked_local(fixture->raw_tx, fixture->raw_tx_len);
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
    assert_int_equal(g_last_sw, SWO_COMMAND_NOT_ALLOWED);
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
    assert_int_equal(g_last_sw, SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_sign_tx_confirm_stops_after_chunk_error(void **state) {
    (void) state;
    reset_test_context();

    // Mimic an in-progress request with invalid chunk state:
    // handle_tx_data_chunk() returns error and resets context.
    setup_active_sign_tx_request(TX_STATE_NONE);

    uint8_t chunk[1] = {0x00};
    buffer_t confirm_buf = {
        .ptr = chunk,
        .size = sizeof(chunk),
        .offset = 0,
    };

    run_sign_tx_apdu(&confirm_buf, P1_TX_CONFIRM);
    assert_int_equal(g_last_sw, SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.tx_state, TX_STATE_NONE);
}

static void test_sign_tx_witness_deny_before_approved_state(void **state) {
    (void) state;
    reset_test_context();

    setup_active_sign_tx_request(TX_STATE_NONE);
    G_context.tx_info.num_witnesses = 1;
    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;

    uint8_t path_raw[32] = {0};
    size_t path_len = write_standard_payment_path(path_raw, sizeof(path_raw));

    buffer_t witness_buf = {
        .ptr = path_raw,
        .size = path_len,
        .offset = 0,
    };

    run_sign_tx_witness_apdu(&witness_buf);
    assert_int_equal(g_last_sw, SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_sign_tx_witness_flow_signs_and_resets_context(void **state) {
    (void) state;

    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_and_run_fixture_until_hash_ready(fixture);

    assert_int_equal(g_last_sw, SWO_SUCCESS);
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

    assert_int_equal(g_last_sw, SWO_SUCCESS);
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
    init_apdu_params_t params = build_init_params_from_fixture_local(fixture);
    params.numWitnesses = 0;
    params.rawTxTotalLength = (uint16_t) fixture->raw_tx_len;
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_sw, SWO_SUCCESS);
    assert_int_equal(G_context.tx_info.num_witnesses, 0);
    assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);

    run_sign_tx_body_chunked_local(fixture->raw_tx, fixture->raw_tx_len);

    assert_int_equal(g_last_sw, SWO_SUCCESS);
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
