/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include <cmocka.h>

#include "handler/sign_tx.h"
#include "handler/get_public_key.h"
#include "buffer.h"
#include "cardano_swo.h"
#include "cardano_constants.h"
#include "globals.h"
#include "init_apdu.h"
#include "securityPolicy.h"
#include "addressUtils/bip44.h"
#include "app_mem_utils.h"
#include "app_context.h"
#include "apdu_finalization_check.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

// P1 constants now defined in dispatcher.h (included via globals.h)

static uint16_t g_last_sw = 0;

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

static inline void run_get_public_key_apdu(buffer_t *buffer) {
    apdu_response_begin(INS_GET_PUBLIC_KEY);
    handler_get_public_key(buffer);
    apdu_response_assert_sent_or_deferred();
}

static void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    g_last_sw = 0;
    assert_true(mem_utils_init(test_heap, sizeof(test_heap)));
}

static uint32_t harden(uint32_t value) {
    return value | HARDENED_BIP32;
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

// NBGL and UI mocks provided by cardano_sign_tx_core (nbgl_mock.c + real UI files)
// These tests verify early rejection before UI is reached, so real UI is fine

void ui_display_pubkey(security_policy_t policy, warning_bits_t warnings) {
    (void) policy;
    (void) warnings;
}

static void test_tx_init_invalid_signing_mode(void **state) {
    (void) state;
    reset_context();

    uint8_t init_raw[256];
    init_apdu_params_t params = {
        .options = 0,
        .networkId = MAINNET_NETWORK_ID,
        .protocolMagic = MAINNET_PROTOCOL_MAGIC,
        .signingMode = 0xFF,
        .numInputs = 0,
        .numOutputs = 0,
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
        .rawTxTotalLength = 100,  // Non-zero value for valid INIT
    };
    size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    buffer_t init_buf = {
        .ptr = init_raw,
        .size = init_len,
        .offset = 0,
    };
    run_sign_tx_apdu(&init_buf, P1_TX_INIT);
    assert_int_equal(g_last_sw, SWO_INVALID_TX_SIGNING_MODE);
}

static void test_tx_init_trailing_bytes(void **state) {
    (void) state;
    reset_context();

    uint8_t init_raw[256];
    init_apdu_params_t params = {
        .options = 0,
        .networkId = MAINNET_NETWORK_ID,
        .protocolMagic = MAINNET_PROTOCOL_MAGIC,
        .signingMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX,
        .numInputs = 0,
        .numOutputs = 0,
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
        .rawTxTotalLength = 100,  // Non-zero value for valid INIT
    };
    size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);
    init_raw[init_len] = 0x00;

    buffer_t init_buf = {
        .ptr = init_raw,
        .size = init_len + 1,
        .offset = 0,
    };
    run_sign_tx_apdu(&init_buf, P1_TX_INIT);
    assert_int_equal(g_last_sw, SWO_WRONG_DATA_LENGTH);
}

static void test_tx_init_rejected_when_active(void **state) {
    (void) state;
    reset_context();

    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = TX_STATE_NONE;
    uint8_t dummy = 0;

    buffer_t init_buf = {
        .ptr = &dummy,
        .size = 0,
        .offset = 0,
    };
    run_sign_tx_apdu(&init_buf, P1_TX_INIT);
    assert_int_equal(g_last_sw, SWO_COMMAND_NOT_ALLOWED);
}

static void test_witness_trailing_bytes(void **state) {
    (void) state;
    reset_context();

    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = TX_STATE_APPROVED;
    G_context.tx_info.current_witness = 0;
    G_context.tx_info.num_witnesses = 1;
    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.num_mint_asset_groups = 0;

    uint32_t path[] = {
        harden(PURPOSE_SHELLEY),
        harden(ADA_COIN_TYPE),
        harden(0),
        0,
        0,
    };
    uint8_t path_raw[32];
    size_t path_len = write_bip44_path(path_raw,
                                       sizeof(path_raw),
                                       path,
                                       sizeof(path) / sizeof(path[0]));
    path_raw[path_len] = 0x00;

    buffer_t witness_buf = {
        .ptr = path_raw,
        .size = path_len + 1,
        .offset = 0,
    };
    run_sign_tx_witness_apdu(&witness_buf);
    assert_int_equal(g_last_sw, SWO_WRONG_DATA_LENGTH);
}

static void test_get_public_key_trailing_bytes(void **state) {
    (void) state;
    reset_context();

    uint32_t path[] = {
        harden(PURPOSE_SHELLEY),
        harden(ADA_COIN_TYPE),
        harden(0),
        0,
        0,
    };
    uint8_t path_raw[32];
    size_t path_len = write_bip44_path(path_raw,
                                       sizeof(path_raw),
                                       path,
                                       sizeof(path) / sizeof(path[0]));
    path_raw[path_len] = 0x00;

    buffer_t pubkey_buf = {
        .ptr = path_raw,
        .size = path_len + 1,
        .offset = 0,
    };
    run_get_public_key_apdu(&pubkey_buf);
    assert_int_equal(g_last_sw, SWO_WRONG_DATA_LENGTH);
}

// Interleaved flow violation tests

static void test_handler_state_during_active_request(void **state) {
    (void) state;
    reset_context();

    // Set up an active transaction signing state
    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = TX_STATE_NONE;

    // Test that witness handler properly validates state
    // This mimics the dispatcher's interleaving detection
    uint32_t path[] = {
        harden(PURPOSE_SHELLEY),
        harden(ADA_COIN_TYPE),
        harden(0),
        0,
        0,
    };
    uint8_t path_raw[32];
    size_t path_len = write_bip44_path(path_raw,
                                       sizeof(path_raw),
                                       path,
                                       sizeof(path) / sizeof(path[0]));

    // Attempting to call witness handler with wrong state should fail
    buffer_t witness_buf = {
        .ptr = path_raw,
        .size = path_len,
        .offset = 0,
    };
    // Set wrong state (not APPROVED)
    G_context.state.tx_state = TX_STATE_NONE;
    G_context.tx_info.current_witness = 0;
    G_context.tx_info.num_witnesses = 1;
    run_sign_tx_witness_apdu(&witness_buf);
    assert_int_equal(g_last_sw, SWO_COMMAND_NOT_ALLOWED);
}

static void test_opcert_signing_during_tx_signing(void **state) {
    (void) state;
    reset_context();

    // Set up an active transaction signing state
    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = TX_STATE_APPROVED;

    // Attempt to start opcert signing while tx signing is active
    // This would require attempting to call handler_sign_opcert, but we can verify
    // the state check by trying another tx operation that should fail
    uint8_t init_raw[256];
    init_apdu_params_t params = {
        .options = 0,
        .networkId = MAINNET_NETWORK_ID,
        .protocolMagic = MAINNET_PROTOCOL_MAGIC,
        .signingMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX,
        .numInputs = 0,
        .numOutputs = 0,
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
        .rawTxTotalLength = 100,  // Non-zero value for valid INIT
    };
    size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    buffer_t init_buf = {
        .ptr = init_raw,
        .size = init_len,
        .offset = 0,
    };

    // This should fail because tx signing is already active
    run_sign_tx_apdu(&init_buf, P1_TX_INIT);
    assert_int_equal(g_last_sw, SWO_COMMAND_NOT_ALLOWED);
}

static void test_witness_extraction_with_wrong_state(void **state) {
    (void) state;
    reset_context();

    // Set up a transaction context but in wrong state (not APPROVED)
    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = TX_STATE_NONE;  // Not approved, should be TX_STATE_APPROVED
    G_context.tx_info.current_witness = 0;
    G_context.tx_info.num_witnesses = 1;
    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.num_mint_asset_groups = 0;

    uint32_t path[] = {
        harden(PURPOSE_SHELLEY),
        harden(ADA_COIN_TYPE),
        harden(0),
        0,
        0,
    };
    uint8_t path_raw[32];
    size_t path_len = write_bip44_path(path_raw,
                                       sizeof(path_raw),
                                       path,
                                       sizeof(path) / sizeof(path[0]));

    buffer_t witness_buf = {
        .ptr = path_raw,
        .size = path_len,
        .offset = 0,
    };
    run_sign_tx_witness_apdu(&witness_buf);
    // Should fail because tx_state is not APPROVED
    assert_int_equal(g_last_sw, SWO_COMMAND_NOT_ALLOWED);
}

static void test_multiple_reinit_attempts(void **state) {
    (void) state;

    // First successful init
    reset_context();
    uint8_t init_raw[256];
    init_apdu_params_t params = {
        .options = 0,
        .networkId = MAINNET_NETWORK_ID,
        .protocolMagic = MAINNET_PROTOCOL_MAGIC,
        .signingMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX,
        .numInputs = 1,  // At least one input required for replay protection
        .numOutputs = 0,
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
        .rawTxTotalLength = 100,  // Non-zero value for valid INIT
    };
    size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    buffer_t init_buf = {
        .ptr = init_raw,
        .size = init_len,
        .offset = 0,
    };
    run_sign_tx_apdu(&init_buf, P1_TX_INIT);
    assert_int_equal(g_last_sw, SWO_SUCCESS);

    // Second init attempt should fail
    reset_context();
    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = TX_STATE_NONE;

    init_buf.offset = 0;
    run_sign_tx_apdu(&init_buf, P1_TX_INIT);
    assert_int_equal(g_last_sw, SWO_COMMAND_NOT_ALLOWED);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tx_init_invalid_signing_mode),
        cmocka_unit_test(test_tx_init_trailing_bytes),
        cmocka_unit_test(test_tx_init_rejected_when_active),
        cmocka_unit_test(test_witness_trailing_bytes),
        cmocka_unit_test(test_get_public_key_trailing_bytes),
        cmocka_unit_test(test_handler_state_during_active_request),
        cmocka_unit_test(test_opcert_signing_during_tx_signing),
        cmocka_unit_test(test_witness_extraction_with_wrong_state),
        cmocka_unit_test(test_multiple_reinit_attempts),
    };

    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
