#pragma once

#include <cmocka.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "buffer.h"
#include "handler/sign_tx.h"
#include "handler/sign_tx_aux_data.h"
#include "hexUtils.h"
#include "tx.h"
#include "blake2b.h"
#include "globals.h"
#include "cardano_settings.h"
#include "cardano_constants.h"
#include "test_fixture_types.h"
#include "apdu/dispatcher.h"
#include "ui_display_tx.h"
#include "app_mem_utils.h"
#include "app_context.h"
#include "nbgl_mock.h"
#include "io_capture.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static inline bool test_mem_init(void) {
    return mem_utils_init(test_heap, sizeof(test_heap));
}
extern bool unit_test_expert_mode_enabled;

static inline void run_sign_tx_apdu(buffer_t *buffer, uint8_t p1) {
    apdu_response_begin(INS_SIGN_TX);
    handler_sign_tx(buffer, p1);
    apdu_response_assert_sent_or_deferred();
}

static inline void run_sign_tx_aux_data_apdu(buffer_t *buffer, uint8_t p2) {
    apdu_response_begin(INS_SIGN_TX);
    handler_sign_tx_aux_data(buffer, p2);
    apdu_response_assert_sent_or_deferred();
}

static inline void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    io_capture_reset();
    nbgl_mock_reset();
}

static inline void run_tx_and_verify(const uint8_t* init_raw,
                                     size_t init_len,
                                     const uint8_t* raw_tx,
                                     size_t raw_tx_len,
                                     bool include_aux_data_hash,
                                     uint8_t aux_data_type,
                                     const uint8_t* aux_data_init_payload,
                                     size_t aux_data_init_payload_len,
                                     const aux_data_payload_t* aux_data_delegations,
                                     size_t aux_data_delegation_count,
                                     const char* cbor_hex,
                                     const char* expected_hash_hex,
                                     uint16_t num_witnesses,
                                     bool include_ttl,
                                     bool include_validity_interval_start,
                                     const uint8_t* response_buf,
                                     size_t* response_len,
                                     uint16_t* response_sw) {
    assert_true(init_len > 0);
    run_sign_tx_apdu(&(buffer_t){.ptr = (uint8_t*)init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);
    if (include_aux_data_hash && aux_data_type == AUX_DATA_TYPE_CVOTE_REGISTRATION) {
        assert_int_equal(G_context.state.tx_state, TX_STATE_AUX_DATA);
    } else {
        assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);
    }
    assert_int_equal(G_context.tx_info.num_witnesses, num_witnesses);
    assert_int_equal(G_context.tx_info.transaction.includeTtl, include_ttl);
    assert_int_equal(G_context.tx_info.transaction.includeValidityIntervalStart, include_validity_interval_start);

    if (include_aux_data_hash && aux_data_type == AUX_DATA_TYPE_CVOTE_REGISTRATION) {
        assert_non_null(aux_data_init_payload);
        assert_true(aux_data_init_payload_len > 0);
        buffer_t aux_init_buf = {
            .ptr = (uint8_t*) aux_data_init_payload,
            .size = aux_data_init_payload_len,
            .offset = 0,
        };
        run_sign_tx_aux_data_apdu(&aux_init_buf, P2_AUX_DATA_INIT);

        for (size_t i = 0; i < aux_data_delegation_count; i++) {
            const aux_data_payload_t* delegation = &aux_data_delegations[i];
            assert_non_null(delegation->payload);
            assert_true(delegation->payload_len > 0);
            buffer_t aux_reg_buf = {
                .ptr = (uint8_t*) delegation->payload,
                .size = delegation->payload_len,
                .offset = 0,
            };
            run_sign_tx_aux_data_apdu(&aux_reg_buf, P2_AUX_DATA_DELEGATION);
        }

        assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);
    }

    buffer_t tx_buf = {
        .ptr = (uint8_t*) raw_tx,
        .size = raw_tx_len,
        .offset = 0,
    };
    run_sign_tx_apdu(&tx_buf, P1_TX_CONFIRM);

    uint8_t expected_cbor[100 * 1024];
    size_t cbor_len = hex_to_bytes(cbor_hex, expected_cbor, sizeof(expected_cbor));
    assert_true(cbor_len > 0);

    uint8_t expected_hash[TX_HASH_LENGTH];
    size_t expected_hash_len = hex_to_bytes(expected_hash_hex, expected_hash, sizeof(expected_hash));
    assert_int_equal(expected_hash_len, TX_HASH_LENGTH);

    assert_int_equal(*response_len, TX_HASH_LENGTH);
    assert_memory_equal(response_buf, expected_hash, TX_HASH_LENGTH);
    assert_int_equal(*response_sw, SWO_SUCCESS);

    // When using real UI code: if there are witnesses, req_type stays REQUEST_SIGN_TRANSACTION
    // If no witnesses, finalize_sign_tx() calls reset_app_context() which sets req_type to REQUEST_NONE
    if (num_witnesses > 0) {
        assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);
        assert_int_equal(G_context.state.tx_state, TX_STATE_APPROVED);
        // Manually clean up for tests since we won't process witnesses
        tx_review_cleanup();
        tx_context_cleanup();
    } else {
        assert_int_equal(G_context.req_type, REQUEST_NONE);
        assert_int_equal(G_context.state.tx_state, TX_STATE_NONE);
    }
}

static inline void run_fixture(const tx_fixture_t *fixture) {
    reset_context();
    assert_true(test_mem_init());

    uint8_t init_raw[512];
    uint8_t aux_data_hash[AUX_DATA_HASH_LENGTH] = {0};
    size_t aux_hash_len = 0;
    if (fixture->include_aux_data_hash && fixture->aux_data_type == AUX_DATA_TYPE_ARBITRARY_HASH) {
        assert_non_null(fixture->aux_data_hash_hex);
        aux_hash_len = hex_to_bytes(fixture->aux_data_hash_hex, aux_data_hash, sizeof(aux_data_hash));
        assert_int_equal(aux_hash_len, AUX_DATA_HASH_LENGTH);
    }

    init_apdu_params_t params = {
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
        .auxDataHash = (fixture->include_aux_data_hash &&
                        fixture->aux_data_type == AUX_DATA_TYPE_ARBITRARY_HASH) ? aux_data_hash : NULL,
        .auxDataHashLen = (fixture->include_aux_data_hash &&
                           fixture->aux_data_type == AUX_DATA_TYPE_ARBITRARY_HASH) ? aux_hash_len : 0,
        .includeScriptDataHash = fixture->include_script_data_hash,
        .includeValidityIntervalStart = fixture->include_validity_interval_start,
        .numMintAssetGroups = fixture->num_mint_asset_groups,
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
    };
    size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_tx_and_verify(init_raw,
                      init_len,
                      fixture->raw_tx,
                      fixture->raw_tx_len,
                      fixture->include_aux_data_hash,
                      fixture->aux_data_type,
                      fixture->aux_data_init_payload,
                      fixture->aux_data_init_payload_len,
                      fixture->aux_data_delegations,
                      fixture->aux_data_delegation_count,
                      fixture->tx_body_cbor_hex,
                      fixture->expected_hash_hex,
                      fixture->num_witnesses,
                      fixture->include_ttl,
                      fixture->include_validity_interval_start,
                      g_last_response,
                      &g_last_response_len,
                      &g_last_response_sw);
}

static inline void run_fixture_with_expert_mode(const tx_fixture_t *fixture, bool expert_mode) {
    extern bool unit_test_expert_mode_enabled;
    const bool previous_mode = unit_test_expert_mode_enabled;
    unit_test_expert_mode_enabled = expert_mode;
    run_fixture(fixture);
    unit_test_expert_mode_enabled = previous_mode;
}

static inline bool fixture_has_cvote_aux_data(const tx_fixture_t *fixture) {
    return fixture->include_aux_data_hash &&
           fixture->aux_data_type == AUX_DATA_TYPE_CVOTE_REGISTRATION;
}

typedef enum {
    REJECT_STAGE_TX = 0,
    REJECT_STAGE_AUX = 1,
} reject_stage_t;

static inline void run_fixture_reject_with_expert_mode(const tx_fixture_t *fixture,
                                                       bool expert_mode,
                                                       reject_stage_t reject_stage) {
    LEDGER_ASSERT(fixture != NULL, "NULL fixture");
    LEDGER_ASSERT(reject_stage == REJECT_STAGE_TX || reject_stage == REJECT_STAGE_AUX,
                  "Unknown reject stage");
    if (reject_stage == REJECT_STAGE_AUX) {
        LEDGER_ASSERT(fixture_has_cvote_aux_data(fixture), "AUX reject requested for non-CVote fixture");
    }

    extern bool unit_test_expert_mode_enabled;
    const bool previous_mode = unit_test_expert_mode_enabled;
    unit_test_expert_mode_enabled = expert_mode;

    reset_context();
    assert_true(test_mem_init());

    uint8_t init_raw[512];
    uint8_t aux_data_hash[AUX_DATA_HASH_LENGTH] = {0};
    size_t aux_hash_len = 0;
    if (fixture->include_aux_data_hash && fixture->aux_data_type == AUX_DATA_TYPE_ARBITRARY_HASH) {
        assert_non_null(fixture->aux_data_hash_hex);
        aux_hash_len = hex_to_bytes(fixture->aux_data_hash_hex, aux_data_hash, sizeof(aux_data_hash));
        assert_int_equal(aux_hash_len, AUX_DATA_HASH_LENGTH);
    }

    init_apdu_params_t params = {
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
        .auxDataHash = (fixture->include_aux_data_hash &&
                        fixture->aux_data_type == AUX_DATA_TYPE_ARBITRARY_HASH) ? aux_data_hash : NULL,
        .auxDataHashLen = (fixture->include_aux_data_hash &&
                           fixture->aux_data_type == AUX_DATA_TYPE_ARBITRARY_HASH) ? aux_hash_len : 0,
        .includeScriptDataHash = fixture->include_script_data_hash,
        .includeValidityIntervalStart = fixture->include_validity_interval_start,
        .numMintAssetGroups = fixture->num_mint_asset_groups,
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
    };
    size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = (uint8_t *) init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_sw, SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);

    if (fixture_has_cvote_aux_data(fixture)) {
        assert_int_equal(G_context.state.tx_state, TX_STATE_AUX_DATA);
        if (reject_stage == REJECT_STAGE_AUX) {
            const bool final_decisions[] = {false};
            nbgl_mock_set_final_decisions(final_decisions, ARRAY_LEN(final_decisions));
        }

        assert_non_null(fixture->aux_data_init_payload);
        assert_true(fixture->aux_data_init_payload_len > 0);
        buffer_t aux_init_buf = {
            .ptr = (uint8_t *) fixture->aux_data_init_payload,
            .size = fixture->aux_data_init_payload_len,
            .offset = 0,
        };
        run_sign_tx_aux_data_apdu(&aux_init_buf, P2_AUX_DATA_INIT);

        if (g_last_response_sw == SWO_CONDITIONS_NOT_SATISFIED) {
            goto reject_assertions;
        }
        assert_int_equal(g_last_response_sw, SWO_SUCCESS);

        for (size_t i = 0; i < fixture->aux_data_delegation_count; i++) {
            const aux_data_payload_t *delegation = &fixture->aux_data_delegations[i];
            assert_non_null(delegation->payload);
            assert_true(delegation->payload_len > 0);
            buffer_t aux_reg_buf = {
                .ptr = (uint8_t *) delegation->payload,
                .size = delegation->payload_len,
                .offset = 0,
            };
            run_sign_tx_aux_data_apdu(&aux_reg_buf, P2_AUX_DATA_DELEGATION);
            if (g_last_response_sw == SWO_CONDITIONS_NOT_SATISFIED) {
                goto reject_assertions;
            }
            assert_int_equal(g_last_response_sw, SWO_SUCCESS);
        }

        assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);
    }

    if (reject_stage == REJECT_STAGE_TX) {
        const bool final_decisions[] = {false};
        nbgl_mock_set_final_decisions(final_decisions, ARRAY_LEN(final_decisions));
    }

    {
        buffer_t tx_buf = {
            .ptr = (uint8_t *) fixture->raw_tx,
            .size = fixture->raw_tx_len,
            .offset = 0,
        };
        run_sign_tx_apdu(&tx_buf, P1_TX_CONFIRM);
    }

reject_assertions:
    assert_int_equal(g_last_response_sw, SWO_CONDITIONS_NOT_SATISFIED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.tx_state, TX_STATE_NONE);

    unit_test_expert_mode_enabled = previous_mode;
}

static inline void run_fixture_reject_tx_with_expert_mode(const tx_fixture_t *fixture,
                                                          bool expert_mode) {
    run_fixture_reject_with_expert_mode(
        fixture,
        expert_mode,
        REJECT_STAGE_TX);
}

static inline void run_fixture_reject_aux_with_expert_mode(const tx_fixture_t *fixture,
                                                           bool expert_mode) {
    run_fixture_reject_with_expert_mode(fixture, expert_mode, REJECT_STAGE_AUX);
}
