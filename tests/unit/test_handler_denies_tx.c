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
#include "handler/sign_tx.h"
#include "globals.h"
#include "sign_tx_ctx.h"
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

static init_apdu_params_t make_default_init_apdu_params(void) {
    return (init_apdu_params_t) {
        .options = 0,
        .networkId = MAINNET_NETWORK_ID,
        .protocolMagic = MAINNET_PROTOCOL_MAGIC,
        .signingMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX,
        .numInputs = 1,
        .numOutputs = 1,
        .includeTtl = false,
        .numCertificates = 0,
        .numWithdrawals = 0,
        .includeAuxData = false,
        .auxDataType = AUX_DATA_TYPE_ARBITRARY_HASH,
        .auxDataHash = NULL,
        .auxDataHashLen = 0,
        .includeValidityIntervalStart = false,
        .numMintAssetGroups = 0,
        .includeScriptDataHash = false,
        .numCollateralInputs = 0,
        .numRequiredSigners = 0,
        .includeNetworkId = false,
        .includeCollateralOutput = false,
        .includeTotalCollateral = false,
        .numReferenceInputs = 0,
        .numVoters = 0,
        .includeTreasury = false,
        .includeDonation = false,
        .numWitnesses = 0,
        .rawTxTotalLength = 100,
    };
}

static void run_sign_tx_init_case(const init_apdu_params_t *params,
                                  size_t expected_apdu_size,
                                  uint16_t expected_sw) {
    assert_non_null(params);

    reset_context();
    assert_true(test_mem_init());

    uint8_t init_raw[512];
    const size_t init_len = build_init_apdu(params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);
    assert_true(init_len >= expected_apdu_size);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = expected_apdu_size, .offset = 0},
                     P1_TX_INIT);

    assert_int_equal(g_last_response_sw, expected_sw);
}

static void run_sign_tx_init_case_full(const init_apdu_params_t *params, uint16_t expected_sw) {
    assert_non_null(params);

    reset_context();
    assert_true(test_mem_init());

    uint8_t init_raw[512];
    const size_t init_len = build_init_apdu(params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);

    assert_int_equal(g_last_response_sw, expected_sw);
}

static void test_tx_init_invalid_signing_mode(void **state) {
    (void) state;
    init_apdu_params_t params = make_default_init_apdu_params();
    params.signingMode = 0xFF;
    run_sign_tx_init_case_full(&params, SWO_INVALID_TX_SIGNING_MODE);
}

static void test_tx_init_trailing_bytes(void **state) {
    (void) state;

    uint8_t init_raw[256];
    init_apdu_params_t params = make_default_init_apdu_params();

    reset_context();
    assert_true(test_mem_init());

    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);
    init_raw[init_len] = 0x00;

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len + 1, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_sw, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_init_zero_inputs_denied_for_pool_registration_owner(void **state) {
    (void) state;
    init_apdu_params_t params = make_default_init_apdu_params();
    params.signingMode = SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER;
    params.numInputs = 0;
    params.numCertificates = 1;
    run_sign_tx_init_case_full(&params, SWO_SECURITY_CONDITION_NOT_SATISFIED);
}

static void test_tx_init_denied_when_active(void **state) {
    (void) state;

    reset_context();
    assert_true(test_mem_init());

    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = TX_STATE_NONE;

    run_sign_tx_apdu(&(buffer_t){.ptr = NULL, .size = 0, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_sw, SWO_COMMAND_NOT_ALLOWED);
}

static void test_tx_init_missing_inputs_outputs_counts(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 14, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_init_missing_ttl_flag(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 18, SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
}

static void test_tx_init_missing_certificates_count(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 19, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_init_missing_withdrawals_count(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 21, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_init_missing_aux_data_flag(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 23, SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
}

static void test_tx_init_missing_validity_interval_start_flag(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 24, SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
}

static void test_tx_init_missing_mint_count(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 25, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_init_missing_script_data_hash_flag(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 27, SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
}

static void test_tx_init_missing_collateral_inputs_count(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 28, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_init_missing_required_signers_count(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 30, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_init_missing_network_id_flag(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 32, SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
}

static void test_tx_init_missing_collateral_output_flag(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 33, SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
}

static void test_tx_init_missing_total_collateral_flag(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 34, SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
}

static void test_tx_init_missing_reference_inputs_count(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 35, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_init_missing_voters_count(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 37, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_init_missing_treasury_flag(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 39, SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
}

static void test_tx_init_missing_donation_flag(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 40, SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
}

static void test_tx_init_missing_witnesses_count(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    run_sign_tx_init_case(&params, 41, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_init_missing_raw_tx_total_length(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);

    reset_context();
    assert_true(test_mem_init());

    uint8_t init_raw[512];
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 2);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len - 2, .offset = 0},
                     P1_TX_INIT);
    assert_int_equal(g_last_response_sw, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_init_zero_raw_tx_total_length(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    params.rawTxTotalLength = 0;
    run_sign_tx_init_case_full(&params, SWO_WRONG_TX_INIT_APDU_DATA);
}

static void test_tx_init_oversized_raw_tx_total_length(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    params.rawTxTotalLength = (uint16_t) (MAX_TX_BUFFER_SIZE + 1u);
    run_sign_tx_init_case_full(&params, SWO_INVALID_TX_LENGTH);
}

static void test_tx_init_unsupported_options(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    params.options = 0x8000000000000000ULL;
    run_sign_tx_init_case_full(&params, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_init_missing_options(void **state) {
    (void) state;
    reset_context();
    assert_true(test_mem_init());

    run_sign_tx_apdu(&(buffer_t){.ptr = NULL, .size = 0, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_sw, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_init_unsupported_aux_data_type(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    params.includeAuxData = true;
    params.auxDataType = (aux_data_type_t) 0xFF;
    run_sign_tx_init_case_full(&params, SWO_WRONG_TX_INIT_APDU_DATA);
}

static void test_tx_init_missing_aux_data_type(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    uint8_t dummy_aux_data_hash[AUX_DATA_HASH_LENGTH] = {0};
    init_apdu_params_t params = build_init_params_from_fixture(fixture, dummy_aux_data_hash, sizeof(dummy_aux_data_hash));
    params.includeAuxData = true;
    params.auxDataType = AUX_DATA_TYPE_ARBITRARY_HASH;
    params.auxDataHash = dummy_aux_data_hash;
    params.auxDataHashLen = sizeof(dummy_aux_data_hash);
    run_sign_tx_init_case(&params, 24, SWO_WRONG_TX_INIT_APDU_DATA);
}

static void test_tx_init_missing_aux_data_hash_bytes(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    uint8_t dummy_aux_data_hash[AUX_DATA_HASH_LENGTH] = {0};
    init_apdu_params_t params = build_init_params_from_fixture(fixture, dummy_aux_data_hash, sizeof(dummy_aux_data_hash));
    params.includeAuxData = true;
    params.auxDataType = AUX_DATA_TYPE_ARBITRARY_HASH;
    params.auxDataHash = dummy_aux_data_hash;
    params.auxDataHashLen = sizeof(dummy_aux_data_hash);
    run_sign_tx_init_case(&params, 25, SWO_WRONG_TX_INIT_APDU_DATA);
}

static void test_tx_init_rejects_trailing_bytes_after_valid_fields(void **state) {
    (void) state;
    const tx_fixture_t *fixture =
        &FIXTURE_POOL_REGISTRATION_SIGN_TX_WITNESS_VALID_MULTIPLE_MIXED_OWNERS_ALL_RELAYS_POOL_REGISTRATION;
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);

    reset_context();
    assert_true(test_mem_init());

    uint8_t init_raw[512];
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);
    init_raw[init_len] = 0x00;

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len + 1, .offset = 0},
                     P1_TX_INIT);
    assert_int_equal(g_last_response_sw, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_confirm_rejects_empty_final_chunk(void **state) {
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

    run_sign_tx_apdu(&(buffer_t){.ptr = NULL, .size = 0, .offset = 0}, P1_TX_CONFIRM);
    assert_int_equal(g_last_response_sw, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_confirm_rejects_oversized_final_chunk(void **state) {
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

    uint8_t oversized_final_chunk[MAX_SIGN_TX_CHUNK_SIZE + 1] = {0};
    run_sign_tx_apdu(&(buffer_t){
                         .ptr = oversized_final_chunk,
                         .size = sizeof(oversized_final_chunk),
                         .offset = 0,
                     },
                     P1_TX_CONFIRM);
    assert_int_equal(g_last_response_sw, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_rejects_invalid_p1(void **state) {
    (void) state;
    reset_context();
    assert_true(test_mem_init());

    run_sign_tx_apdu(&(buffer_t){.ptr = NULL, .size = 0, .offset = 0}, 0xFF);
    assert_int_equal(g_last_response_sw, SWO_INCORRECT_P1_P2);
}

static void test_tx_aux_data_rejects_invalid_p2(void **state) {
    (void) state;
    reset_context();
    assert_true(test_mem_init());

    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = TX_STATE_AUX_DATA;

    run_sign_tx_aux_data_apdu(&(buffer_t){.ptr = NULL, .size = 0, .offset = 0}, 0xFF);
    assert_int_equal(g_last_response_sw, SWO_INCORRECT_P1_P2);
}

static void test_tx_rejects_empty_non_final_chunk(void **state) {
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
}

static void test_tx_witness_rejects_too_many_witnesses(void **state) {
    (void) state;

    reset_context();
    assert_true(test_mem_init());

    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = TX_STATE_APPROVED;
    G_context.tx_info.num_witnesses = 1;
    tx_witness_ctx()->current_witness = 1;

    run_sign_tx_witness_apdu(&(buffer_t){.ptr = NULL, .size = 0, .offset = 0});
    assert_int_equal(g_last_response_sw, SWO_COMMAND_NOT_ALLOWED);
}

static void test_tx_witness_rejects_truncated_bip44_path(void **state) {
    (void) state;

    reset_context();
    assert_true(test_mem_init());

    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = TX_STATE_APPROVED;
    G_context.tx_info.num_witnesses = 1;
    tx_witness_ctx()->current_witness = 0;

    run_sign_tx_witness_apdu(&(buffer_t){.ptr = NULL, .size = 0, .offset = 0});
    assert_int_equal(g_last_response_sw, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_witness_trailing_bytes(void **state) {
    (void) state;

    reset_context();
    assert_true(test_mem_init());

    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = TX_STATE_APPROVED;
    G_context.tx_info.num_witnesses = 1;
    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.num_mint_asset_groups = 0;

    uint8_t path_raw[32];
    size_t path_len = write_standard_payment_path(path_raw, sizeof(path_raw));
    path_raw[path_len] = 0x00;

    run_sign_tx_witness_apdu(&(buffer_t){.ptr = path_raw, .size = path_len + 1, .offset = 0});
    assert_int_equal(g_last_response_sw, SWO_WRONG_DATA_LENGTH);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tx_init_invalid_signing_mode),
        cmocka_unit_test(test_tx_init_trailing_bytes),
        cmocka_unit_test(test_tx_init_zero_inputs_denied_for_pool_registration_owner),
        cmocka_unit_test(test_tx_init_denied_when_active),
        cmocka_unit_test(test_tx_init_missing_inputs_outputs_counts),
        cmocka_unit_test(test_tx_init_missing_ttl_flag),
        cmocka_unit_test(test_tx_init_missing_certificates_count),
        cmocka_unit_test(test_tx_init_missing_withdrawals_count),
        cmocka_unit_test(test_tx_init_missing_aux_data_flag),
        cmocka_unit_test(test_tx_init_missing_validity_interval_start_flag),
        cmocka_unit_test(test_tx_init_missing_raw_tx_total_length),
        cmocka_unit_test(test_tx_init_zero_raw_tx_total_length),
        cmocka_unit_test(test_tx_init_oversized_raw_tx_total_length),
        cmocka_unit_test(test_tx_init_unsupported_options),
        cmocka_unit_test(test_tx_init_missing_options),
        cmocka_unit_test(test_tx_init_unsupported_aux_data_type),
        cmocka_unit_test(test_tx_init_missing_aux_data_type),
        cmocka_unit_test(test_tx_init_missing_aux_data_hash_bytes),
        cmocka_unit_test(test_tx_init_rejects_trailing_bytes_after_valid_fields),
        cmocka_unit_test(test_tx_init_missing_mint_count),
        cmocka_unit_test(test_tx_init_missing_script_data_hash_flag),
        cmocka_unit_test(test_tx_init_missing_collateral_inputs_count),
        cmocka_unit_test(test_tx_init_missing_required_signers_count),
        cmocka_unit_test(test_tx_init_missing_network_id_flag),
        cmocka_unit_test(test_tx_init_missing_collateral_output_flag),
        cmocka_unit_test(test_tx_init_missing_total_collateral_flag),
        cmocka_unit_test(test_tx_init_missing_reference_inputs_count),
        cmocka_unit_test(test_tx_init_missing_voters_count),
        cmocka_unit_test(test_tx_init_missing_treasury_flag),
        cmocka_unit_test(test_tx_init_missing_donation_flag),
        cmocka_unit_test(test_tx_init_missing_witnesses_count),
        cmocka_unit_test(test_tx_confirm_rejects_empty_final_chunk),
        cmocka_unit_test(test_tx_confirm_rejects_oversized_final_chunk),
        cmocka_unit_test(test_tx_rejects_invalid_p1),
        cmocka_unit_test(test_tx_aux_data_rejects_invalid_p2),
        cmocka_unit_test(test_tx_rejects_empty_non_final_chunk),
        cmocka_unit_test(test_tx_witness_rejects_too_many_witnesses),
        cmocka_unit_test(test_tx_witness_rejects_truncated_bip44_path),
        cmocka_unit_test(test_tx_witness_trailing_bytes),
    };
    return _cmocka_run_group_tests("test_handler_denies_tx",
                                   tests,
                                   ARRAY_LEN(tests),
                                   NULL,
                                   assert_no_pending_apdu_response);
}
