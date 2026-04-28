/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include <cmocka.h>

#include "addressUtils/bip44.h"
#include "cardano_swo.h"
#include "globals.h"
#include "sign_tx_ctx.h"
#include "init_apdu.h"
#include "swap.h"
#include "swap_lib.h"
#include "swap_error_code_helpers.h"
#include "swap_test_stubs.h"
#include "test_sign_tx_common.h"
#include "test_sign_tx_fixtures_shelley.h"
#include "apdu_finalization_check.h"

static bip44_path_t make_swap_test_ordinary_payment_path(void) {
    bip44_path_t path;
    memset(&path, 0, sizeof(path));
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(0);
    path.path[3] = 1;
    path.path[4] = 0;
    return path;
}

static bip44_path_t make_swap_test_ordinary_staking_path(void) {
    bip44_path_t path;
    memset(&path, 0, sizeof(path));
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(0);
    path.path[3] = 2;
    path.path[4] = 0;
    return path;
}

static address_params_t make_swap_test_standard_change_address_params(void) {
    address_params_t params;
    memset(&params, 0, sizeof(params));
    params.type = BASE_PAYMENT_KEY_STAKE_KEY;
    params.networkId = MAINNET_NETWORK_ID;
    params.paymentPartType = PAYMENT_PART_KEY_PATH;
    params.paymentKeyPath = make_swap_test_ordinary_payment_path();
    params.stakingPartType = STAKING_PART_KEY_PATH;
    params.stakingKeyPath = make_swap_test_ordinary_staking_path();
    return params;
}

static bool g_expect_os_lib_end_abort = false;
static jmp_buf g_os_lib_end_abort_jmp_buf;

__attribute__((noreturn)) void abort(void) {
    if (g_expect_os_lib_end_abort) {
        g_expect_os_lib_end_abort = false;
        longjmp(g_os_lib_end_abort_jmp_buf, 1);
    }

    raise(SIGABRT);
    _exit(128 + SIGABRT);
}

static tx_params_t make_swap_test_base_tx_params(void) {
    tx_params_t tx_params;
    memset(&tx_params, 0, sizeof(tx_params));
    tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY;
    tx_params.networkId = MAINNET_NETWORK_ID;
    tx_params.protocolMagic = MAINNET_PROTOCOL_MAGIC;
    tx_params.num_inputs = 1;
    tx_params.num_outputs = 2;
    tx_params.includeTtl = true;
    tx_params.includeValidityIntervalStart = true;
    return tx_params;
}

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

static void run_sign_tx_apdu_expect_swap_reject(buffer_t *buffer,
                                                uint8_t p1,
                                                uint16_t expected_common_error_code,
                                                uint8_t expected_app_error_code) {
    jmp_buf reject_jmp_buf;
    swap_test_stubs_set_reject_jmp_buf(&reject_jmp_buf);
    if (setjmp(reject_jmp_buf) == 0) {
        apdu_response_begin(INS_SIGN_TX);
        handler_sign_tx(buffer, p1);
        fail_msg("Expected swap_reject_and_exit");
    }
    apdu_response_finalize_after_handler();
    swap_test_stubs_set_reject_jmp_buf(NULL);
    assert_int_equal(g_swap_reject_common_error_code, expected_common_error_code);
    assert_int_equal(g_swap_reject_app_error_code, expected_app_error_code);
}

static void run_sign_tx_witness_apdu_expect_swap_reject(buffer_t *buffer,
                                                        uint16_t expected_common_error_code,
                                                        uint8_t expected_app_error_code) {
    jmp_buf reject_jmp_buf;
    swap_test_stubs_set_reject_jmp_buf(&reject_jmp_buf);
    if (setjmp(reject_jmp_buf) == 0) {
        apdu_response_begin(INS_SIGN_TX);
        handler_sign_tx_witness(buffer);
        fail_msg("Expected swap_reject_and_exit");
    }
    swap_test_stubs_set_reject_jmp_buf(NULL);
    apdu_response_finalize_after_handler();
    assert_int_equal(g_swap_reject_common_error_code, expected_common_error_code);
    assert_int_equal(g_swap_reject_app_error_code, expected_app_error_code);
}

static void run_sign_tx_witness_apdu_expect_os_lib_end(buffer_t *buffer) {
    if (setjmp(g_os_lib_end_abort_jmp_buf) == 0) {
        g_expect_os_lib_end_abort = true;
        apdu_response_begin(INS_SIGN_TX);
        handler_sign_tx_witness(buffer);
        fail_msg("Expected os_lib_end");
    }
    apdu_response_state_force_reset();
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(g_last_response_len, ED25519_SIGNATURE_LENGTH);
    assert_true(G_swap_response_ready);
    G_swap_response_ready = false;
    G_called_from_swap = false;
    reset_app_context();
}

static void test_sign_tx_swap_init_policy_allows_plain_ada_swap_shape(void **state) {
    (void) state;

    reset_context();

    tx_params_t tx_params = make_swap_test_base_tx_params();
    warning_bits_t w = 0;

    security_policy_t policy = policyForSignTxSwapInit(&tx_params, &w);
    assert_int_equal(policy, POLICY_HIDE);
}

static void test_sign_tx_swap_init_policy_rejects_required_signers(void **state) {
    (void) state;

    reset_context();

    tx_params_t tx_params = make_swap_test_base_tx_params();
    tx_params.num_required_signers = 1;
    warning_bits_t w = 0;

    security_policy_t policy = policyForSignTxSwapInit(&tx_params, &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_sign_tx_swap_output_policy_allows_plain_ada_device_owned_change(void **state) {
    (void) state;

    reset_context();

    tx_output_description_t output = {
        .format = MAP_BABBAGE,
        .destination =
            {
                .type = DESTINATION_DEVICE_OWNED,
                .params = make_swap_test_standard_change_address_params(),
            },
        .amount = 10,
        .numAssetGroups = 0,
        .includeDatum = false,
        .includeRefScript = false,
    };
    warning_bits_t w = 0;

    security_policy_t policy = policyForSignTxSwapOutput(&output,
                                                         SIGN_TX_SIGNINGMODE_ORDINARY,
                                                         MAINNET_NETWORK_ID,
                                                         MAINNET_PROTOCOL_MAGIC,
                                                         &w);
    assert_int_equal(policy, POLICY_HIDE);
}

static void test_sign_tx_swap_output_policy_rejects_change_tokens(void **state) {
    (void) state;

    reset_context();

    tx_output_description_t output = {
        .format = MAP_BABBAGE,
        .destination =
            {
                .type = DESTINATION_DEVICE_OWNED,
                .params = make_swap_test_standard_change_address_params(),
            },
        .amount = 10,
        .numAssetGroups = 1,
        .includeDatum = false,
        .includeRefScript = false,
    };
    warning_bits_t w = 0;

    security_policy_t policy = policyForSignTxSwapOutput(&output,
                                                         SIGN_TX_SIGNINGMODE_ORDINARY,
                                                         MAINNET_NETWORK_ID,
                                                         MAINNET_PROTOCOL_MAGIC,
                                                         &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_sign_tx_swap_output_policy_rejects_change_datum(void **state) {
    (void) state;

    reset_context();

    tx_output_description_t output = {
        .format = MAP_BABBAGE,
        .destination =
            {
                .type = DESTINATION_DEVICE_OWNED,
                .params = make_swap_test_standard_change_address_params(),
            },
        .amount = 10,
        .numAssetGroups = 0,
        .includeDatum = true,
        .includeRefScript = false,
    };
    warning_bits_t w = 0;

    security_policy_t policy = policyForSignTxSwapOutput(&output,
                                                         SIGN_TX_SIGNINGMODE_ORDINARY,
                                                         MAINNET_NETWORK_ID,
                                                         MAINNET_PROTOCOL_MAGIC,
                                                         &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_sign_tx_swap_mode_skips_ui_and_validates_exchange_parameters(void **state) {
    (void) state;

    const tx_fixture_t *fixture = &FIXTURE_SHELLEY_SIGN_TX_WITHOUT_CHANGE_ADDRESS;

    reset_context();
    assert_true(test_mem_init());
    swap_test_stubs_reset();
    swap_test_stubs_set_initialized(true);
    swap_test_stubs_set_validation_results(true, true, true);
    G_called_from_swap = true;
    G_swap_response_ready = false;

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);
    assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);

    run_sign_tx_body_chunked(fixture->raw_tx, fixture->raw_tx_len);

    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(g_last_response_len, TX_HASH_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);
    assert_int_equal(G_context.state.tx_state, TX_STATE_APPROVED);
    // In swap mode UI is skipped, so total_ui_pairs is set but never consumed.
    // Direct struct access: state is TX_STATE_APPROVED, but body slot was populated
    // before the transition and remains readable here for this assertion.
    assert_true(G_context.tx_info.body.total_ui_pairs > 0);
    assert_false(G_swap_response_ready);

    assert_int_equal(g_swap_stub_fee_check_calls, 1);
    assert_int_equal(g_swap_stub_destination_check_calls, 1);
    assert_int_equal(g_swap_stub_amount_check_calls, 1);

    tx_context_cleanup();
}

static void test_sign_tx_swap_init_rejects_multiple_witnesses(void **state) {
    (void) state;

    const tx_fixture_t *fixture = &FIXTURE_SHELLEY_SIGN_TX_WITHOUT_CHANGE_ADDRESS;

    reset_context();
    assert_true(test_mem_init());
    swap_test_stubs_reset();
    swap_test_stubs_set_initialized(true);
    swap_test_stubs_set_validation_results(true, true, true);
    G_called_from_swap = true;
    G_swap_response_ready = false;

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    params.numWitnesses = 2;
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu_expect_swap_reject(&(buffer_t){
                                            .ptr = init_raw,
                                            .size = init_len,
                                            .offset = 0,
                                        },
                                        P1_TX_INIT,
                                        SWAP_EC_ERROR_GENERIC,
                                        SWAP_APP_CODE_DEFAULT);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);

    tx_context_cleanup();
}

static void test_sign_tx_swap_init_rejects_policy_denial(void **state) {
    (void) state;

    const tx_fixture_t *fixture = &FIXTURE_SHELLEY_SIGN_TX_WITHOUT_CHANGE_ADDRESS;

    reset_context();
    assert_true(test_mem_init());
    swap_test_stubs_reset();
    swap_test_stubs_set_initialized(true);
    swap_test_stubs_set_validation_results(true, true, true);
    G_called_from_swap = true;
    G_swap_response_ready = false;

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    params.numRequiredSigners = 1;
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu_expect_swap_reject(&(buffer_t){
                                            .ptr = init_raw,
                                            .size = init_len,
                                            .offset = 0,
                                        },
                                        P1_TX_INIT,
                                        SWAP_EC_ERROR_GENERIC,
                                        SWAP_APP_CODE_DEFAULT);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);

    tx_context_cleanup();
}

static void test_sign_tx_swap_init_rejects_double_signing(void **state) {
    (void) state;

    reset_context();
    assert_true(test_mem_init());
    swap_test_stubs_reset();
    swap_test_stubs_set_initialized(true);
    swap_test_stubs_set_validation_results(true, true, true);
    G_called_from_swap = true;
    G_swap_response_ready = true;

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture(
        &FIXTURE_SHELLEY_SIGN_TX_WITHOUT_CHANGE_ADDRESS, NULL, 0);
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu_expect_swap_reject(&(buffer_t){
                                            .ptr = init_raw,
                                            .size = init_len,
                                            .offset = 0,
                                        },
                                        P1_TX_INIT,
                                        SWAP_EC_ERROR_GENERIC,
                                        SWAP_APP_CODE_MULTI_SIGN);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);

    tx_context_cleanup();
}

static void test_sign_tx_swap_witness_rejects_non_payment_path(void **state) {
    (void) state;

    const tx_fixture_t *fixture = &FIXTURE_SHELLEY_SIGN_TX_WITHOUT_CHANGE_ADDRESS;

    reset_context();
    assert_true(test_mem_init());
    swap_test_stubs_reset();
    swap_test_stubs_set_initialized(true);
    swap_test_stubs_set_validation_results(true, true, true);
    G_called_from_swap = true;
    G_swap_response_ready = false;

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    run_sign_tx_body_chunked(fixture->raw_tx, fixture->raw_tx_len);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(G_context.state.tx_state, TX_STATE_APPROVED);

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

    run_sign_tx_witness_apdu_expect_swap_reject(
        &(buffer_t){.ptr = witness_path_apdu, .size = witness_path_apdu_len, .offset = 0},
        SWAP_EC_ERROR_GENERIC,
        SWAP_APP_CODE_DENIED_WITNESS_POLICY);

    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);

    G_swap_response_ready = false;
    G_called_from_swap = false;
    reset_app_context();
    tx_context_cleanup();
}

static void test_sign_tx_swap_witness_finalization_triggers_os_lib_end(void **state) {
    (void) state;

    const tx_fixture_t *fixture = &FIXTURE_SHELLEY_SIGN_TX_WITHOUT_CHANGE_ADDRESS;

    reset_context();
    assert_true(test_mem_init());
    swap_test_stubs_reset();
    swap_test_stubs_set_initialized(true);
    swap_test_stubs_set_validation_results(true, true, true);
    G_called_from_swap = true;
    G_swap_response_ready = false;

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    const size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);

    run_sign_tx_body_chunked(fixture->raw_tx, fixture->raw_tx_len);

    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(G_context.state.tx_state, TX_STATE_APPROVED);
    assert_false(G_swap_response_ready);

    assert_true(fixture->witness_payload_count > 0);
    const witness_payload_t *witness_payload = &fixture->witness_payloads[0];
    run_sign_tx_witness_apdu_expect_os_lib_end(&(buffer_t){
        .ptr = (uint8_t *) witness_payload->payload,
        .size = witness_payload->payload_len,
        .offset = 0,
    });
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sign_tx_swap_init_policy_allows_plain_ada_swap_shape),
        cmocka_unit_test(test_sign_tx_swap_init_policy_rejects_required_signers),
        cmocka_unit_test(test_sign_tx_swap_output_policy_allows_plain_ada_device_owned_change),
        cmocka_unit_test(test_sign_tx_swap_output_policy_rejects_change_tokens),
        cmocka_unit_test(test_sign_tx_swap_output_policy_rejects_change_datum),
        cmocka_unit_test(test_sign_tx_swap_mode_skips_ui_and_validates_exchange_parameters),
        cmocka_unit_test(test_sign_tx_swap_init_rejects_multiple_witnesses),
        cmocka_unit_test(test_sign_tx_swap_init_rejects_policy_denial),
        cmocka_unit_test(test_sign_tx_swap_init_rejects_double_signing),
        cmocka_unit_test(test_sign_tx_swap_witness_rejects_non_payment_path),
        cmocka_unit_test(test_sign_tx_swap_witness_finalization_triggers_os_lib_end),
    };
    return _cmocka_run_group_tests("test_handler_sign_tx_swap",
                                   tests,
                                   ARRAY_LEN(tests),
                                   NULL,
                                   assert_no_pending_apdu_response);
}
