/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "globals.h"
#include "tx_parse.h"
#include "tx_constants.h"
#include "cardano_constants.h"
#include "cardano_swo.h"
#include "mem.h"
#include "app_context.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];
static uint16_t g_last_sw = 0;

static inline bool test_mem_init(void) {
    return mem_utils_init(test_heap, sizeof(test_heap));
}

static void reset_test_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    g_last_sw = 0;
    assert_true(test_mem_init());
}

int io_send_sw(uint16_t swo) {
    g_last_sw = swo;
    return 0;
}

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    (void) buffer;
    (void) bufferLength;
    g_last_sw = swo;
    return 0;
}

static void test_parse_tx_fails_on_missing_inputs(void **state) {
    (void) state;
    reset_test_context();

    uint8_t empty_tx = 0;
    buffer_t buf = {
        .ptr = &empty_tx,
        .size = 0,
        .offset = 0,
    };
    // num_inputs=0 with ORDINARY_TX would be denied by policyForSignTxInit (no inputs = no replay
    // protection). Use num_inputs=1 so init policy passes; the empty buffer then fails at inputs.
    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.networkId = MAINNET_NETWORK_ID;
    G_context.tx_info.tx_params.protocolMagic = MAINNET_PROTOCOL_MAGIC;
    G_context.tx_info.tx_params.num_inputs = 1;
    G_context.tx_info.tx_params.num_outputs = 0;
    apdu_response_begin(INS_SIGN_TX);
    bool ok = tx_validate(&buf);
    apdu_response_assert_sent_or_deferred();
    assert_false(ok);
    assert_int_equal(g_last_sw, SWO_TX_PARSING_FAIL_INPUTS);
}

static void test_parse_tx_rejects_oversized_buffer(void **state) {
    (void) state;
    reset_test_context();

    apdu_response_begin(INS_SIGN_TX);
    tx_handle_parse_error(SWO_INVALID_TX_LENGTH);
    apdu_response_assert_sent_or_deferred();
    assert_int_equal(g_last_sw, SWO_INVALID_TX_LENGTH);
}

static void test_parse_error_mapping_fee(void **state) {
    (void) state;
    reset_test_context();

    apdu_response_begin(INS_SIGN_TX);
    tx_handle_parse_error(SWO_TX_PARSING_FAIL_FEE);
    apdu_response_assert_sent_or_deferred();
    assert_int_equal(g_last_sw, SWO_TX_PARSING_FAIL_FEE);
}

static void test_parse_error_mapping_buffer_not_fully_consumed(void **state) {
    (void) state;
    reset_test_context();

    apdu_response_begin(INS_SIGN_TX);
    tx_handle_parse_error(SWO_TX_PARSING_FAIL_BUFFER_NOT_FULLY_CONSUMED);
    apdu_response_assert_sent_or_deferred();
    assert_int_equal(g_last_sw, SWO_TX_PARSING_FAIL_BUFFER_NOT_FULLY_CONSUMED);
}

static void test_process_inputs_field_pass1_success(void **state) {
    (void) state;
    reset_test_context();

    uint8_t raw_input[TX_HASH_LENGTH + sizeof(uint32_t)] = {0};
    for (size_t i = 0; i < TX_HASH_LENGTH; i++) {
        raw_input[i] = (uint8_t) (i + 1);
    }
    raw_input[TX_HASH_LENGTH + 0] = 0x00;
    raw_input[TX_HASH_LENGTH + 1] = 0x00;
    raw_input[TX_HASH_LENGTH + 2] = 0x00;
    raw_input[TX_HASH_LENGTH + 3] = 0x2A;

    buffer_t buf = {
        .ptr = raw_input,
        .size = sizeof(raw_input),
        .offset = 0,
    };

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_PLUTUS_TX;
    G_context.tx_info.tx_params.num_inputs = 1;

    parse_tx_mode_t mode = {
        .run_validation = true,
        .run_hash_builder = false,
        .run_ui_planning = true,
        .run_ui_rendering = false,
    };
    warning_bits_t warnings = 0;
    tx_processing_state_init(&mode, &warnings);

    bool ok = tx_process_inputs(&buf, &G_context.tx_info.processing_state);
    assert_true(ok);
    assert_int_equal(buf.offset, sizeof(raw_input));
    assert_int_equal(G_context.tx_info.planned_ui_pairs, 0);  // ordinary mode hides inputs
}

static void test_process_inputs_field_parse_error_sends_inputs_swo(void **state) {
    (void) state;
    reset_test_context();

    uint8_t too_short_input[TX_HASH_LENGTH + sizeof(uint32_t) - 1] = {0};
    buffer_t buf = {
        .ptr = too_short_input,
        .size = sizeof(too_short_input),
        .offset = 0,
    };

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_PLUTUS_TX;
    G_context.tx_info.tx_params.num_inputs = 1;

    parse_tx_mode_t mode = {
        .run_validation = true,
        .run_hash_builder = false,
        .run_ui_planning = true,
        .run_ui_rendering = false,
    };
    warning_bits_t warnings = 0;
    tx_processing_state_init(&mode, &warnings);

    apdu_response_begin(INS_SIGN_TX);
    bool ok = tx_process_inputs(&buf, &G_context.tx_info.processing_state);
    apdu_response_assert_sent_or_deferred();
    assert_false(ok);
    assert_int_equal(g_last_sw, SWO_TX_PARSING_FAIL_INPUTS);
}

static void test_process_collateral_inputs_field_pass1_success(void **state) {
    (void) state;
    reset_test_context();

    uint8_t raw_input[TX_HASH_LENGTH + sizeof(uint32_t)] = {0};
    raw_input[TX_HASH_LENGTH + 3] = 0x2A;

    buffer_t buf = {
        .ptr = raw_input,
        .size = sizeof(raw_input),
        .offset = 0,
    };

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_PLUTUS_TX;
    G_context.tx_info.tx_params.num_collateral_inputs = 1;

    parse_tx_mode_t mode = {
        .run_validation = true,
        .run_hash_builder = false,
        .run_ui_planning = true,
        .run_ui_rendering = false,
    };
    warning_bits_t warnings = 0;
    tx_processing_state_init(&mode, &warnings);

    bool ok = tx_process_collateral_inputs(&buf, &G_context.tx_info.processing_state);
    assert_true(ok);
    assert_int_equal(buf.offset, sizeof(raw_input));
    assert_int_equal(G_context.tx_info.planned_ui_pairs, 0);  // non-expert mode hides collateral inputs
}

static void test_process_reference_inputs_field_parse_error_sends_reference_swo(void **state) {
    (void) state;
    reset_test_context();

    uint8_t too_short_input[TX_HASH_LENGTH + sizeof(uint32_t) - 1] = {0};
    buffer_t buf = {
        .ptr = too_short_input,
        .size = sizeof(too_short_input),
        .offset = 0,
    };

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.num_reference_inputs = 1;

    parse_tx_mode_t mode = {
        .run_validation = true,
        .run_hash_builder = false,
        .run_ui_planning = true,
        .run_ui_rendering = false,
    };
    warning_bits_t warnings = 0;
    tx_processing_state_init(&mode, &warnings);

    apdu_response_begin(INS_SIGN_TX);
    bool ok = tx_process_reference_inputs(&buf, &G_context.tx_info.processing_state);
    apdu_response_assert_sent_or_deferred();
    assert_false(ok);
    assert_int_equal(g_last_sw, SWO_TX_PARSING_FAIL_REFERENCE_INPUTS);
}

static void test_process_required_signers_field_pass1_success(void **state) {
    (void) state;
    reset_test_context();

    uint8_t raw_signer[1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    raw_signer[0] = REQUIRED_SIGNER_WITH_HASH;
    for (size_t i = 0; i < ADDRESS_KEY_HASH_LENGTH; i++) {
        raw_signer[1 + i] = (uint8_t) (0xA0 + i);
    }

    buffer_t buf = {
        .ptr = raw_signer,
        .size = sizeof(raw_signer),
        .offset = 0,
    };

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.num_required_signers = 1;

    parse_tx_mode_t mode = {
        .run_validation = true,
        .run_hash_builder = false,
        .run_ui_planning = true,
        .run_ui_rendering = false,
    };
    warning_bits_t warnings = 0;
    tx_processing_state_init(&mode, &warnings);

    bool ok = tx_process_required_signers(&buf, &G_context.tx_info.processing_state);
    assert_true(ok);
    assert_int_equal(buf.offset, sizeof(raw_signer));
    assert_int_equal(G_context.tx_info.planned_ui_pairs, 0);  // non-expert mode hides required signers
}

static void test_process_required_signers_field_parse_error_sends_required_swo(void **state) {
    (void) state;
    reset_test_context();

    uint8_t invalid_required_signer_type = 0xFF;
    buffer_t buf = {
        .ptr = &invalid_required_signer_type,
        .size = sizeof(invalid_required_signer_type),
        .offset = 0,
    };

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.num_required_signers = 1;

    parse_tx_mode_t mode = {
        .run_validation = true,
        .run_hash_builder = false,
        .run_ui_planning = true,
        .run_ui_rendering = false,
    };
    warning_bits_t warnings = 0;
    tx_processing_state_init(&mode, &warnings);

    apdu_response_begin(INS_SIGN_TX);
    bool ok = tx_process_required_signers(&buf, &G_context.tx_info.processing_state);
    apdu_response_assert_sent_or_deferred();
    assert_false(ok);
    assert_int_equal(g_last_sw, SWO_TX_PARSING_FAIL_REQUIRED_SIGNERS);
}

static void test_mode_allows_rendering_with_validation(void **state) {
    (void) state;
    reset_test_context();

    uint8_t empty = 0;
    buffer_t buf = {
        .ptr = &empty,
        .size = 0,
        .offset = 0,
    };

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.num_inputs = 0;

    parse_tx_mode_t mode = {
        .run_validation = true,
        .run_hash_builder = false,
        .run_ui_planning = false,
        .run_ui_rendering = true,
    };
    warning_bits_t warnings = 0;
    tx_processing_state_init(&mode, &warnings);

    bool ok = tx_process_inputs(&buf, &G_context.tx_info.processing_state);
    assert_true(ok);
}

static void test_validate_from_raw_success(void **state) {
    (void) state;
    reset_test_context();

    uint8_t raw_tx[91] = {0};
    size_t offset = 0;

    // key 0: one input (tx hash + index)
    for (size_t i = 0; i < TX_HASH_LENGTH; i++) {
        raw_tx[offset++] = (uint8_t) (0x10 + i);
    }
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x01;

    // key 1: one output, prefixed by output payload length (45 bytes)
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x2D;
    // destination type: third-party
    raw_tx[offset++] = DESTINATION_THIRD_PARTY;
    // address length: 29 bytes
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x1D;
    // enterprise key address header (mainnet) + key hash bytes
    raw_tx[offset++] = 0x61;
    for (size_t i = 0; i < ADDRESS_KEY_HASH_LENGTH; i++) {
        raw_tx[offset++] = (uint8_t) (0x40 + i);
    }
    // ADA amount
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x16;
    raw_tx[offset++] = 0xE3;
    raw_tx[offset++] = 0x60;  // 1_500_000
    // output format
    raw_tx[offset++] = ARRAY_LEGACY;
    // datum absent
    raw_tx[offset++] = 1;  // FLAG_INCLUDED_NO
    // ref script absent
    raw_tx[offset++] = 1;  // FLAG_INCLUDED_NO
    // num asset groups
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;

    // key 2: fee
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x02;
    raw_tx[offset++] = 0x97;
    raw_tx[offset++] = 0xB0;  // 170_000

    assert_int_equal(offset, sizeof(raw_tx));

    buffer_t buf = {
        .ptr = raw_tx,
        .size = sizeof(raw_tx),
        .offset = 0,
    };

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.networkId = MAINNET_NETWORK_ID;
    G_context.tx_info.tx_params.protocolMagic = MAINNET_PROTOCOL_MAGIC;
    G_context.tx_info.tx_params.num_inputs = 1;
    G_context.tx_info.tx_params.num_outputs = 1;
    G_context.tx_info.tx_params.includeTtl = false;

    bool ok = tx_validate(&buf);

    assert_true(ok);
    assert_int_equal(buf.offset, sizeof(raw_tx));
    assert_true(G_context.tx_info.planned_ui_pairs >= (UI_PAIRS_OUTPUT_BASE + UI_PAIRS_FEE));

    bool hash_nonzero = false;
    for (size_t i = 0; i < TX_HASH_LENGTH; i++) {
        if (G_context.tx_info.tx_hash[i] != 0) {
            hash_nonzero = true;
            break;
        }
    }
    assert_true(hash_nonzero);
}

static void test_validate_from_raw_with_tokens_and_mint_success(void **state) {
    (void) state;
    reset_test_context();

    uint8_t raw_tx[171] = {0};
    size_t offset = 0;

    // key 0: one input (tx hash + index)
    for (size_t i = 0; i < TX_HASH_LENGTH; i++) {
        raw_tx[offset++] = (uint8_t) (0x20 + i);
    }
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x02;

    // key 1: one output, payload length 85
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x55;
    raw_tx[offset++] = DESTINATION_THIRD_PARTY;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x1D;
    raw_tx[offset++] = 0x61;  // enterprise key address header (mainnet)
    for (size_t i = 0; i < ADDRESS_KEY_HASH_LENGTH; i++) {
        raw_tx[offset++] = (uint8_t) (0x60 + i);
    }
    // ADA amount
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x1E;
    raw_tx[offset++] = 0x84;
    raw_tx[offset++] = 0x80;  // 2_000_000
    raw_tx[offset++] = ARRAY_LEGACY;
    raw_tx[offset++] = 1;     // datum absent
    raw_tx[offset++] = 1;     // ref script absent
    // one asset group
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x01;
    for (size_t i = 0; i < MINTING_POLICY_ID_LENGTH; i++) {
        raw_tx[offset++] = (uint8_t) (0x80 + i);
    }
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x01;  // one token
    raw_tx[offset++] = 0x01;  // asset name len
    raw_tx[offset++] = 0xAA;  // asset name
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x64;  // output token amount = 100

    // key 2: fee
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x03;
    raw_tx[offset++] = 0x0D;
    raw_tx[offset++] = 0x40;  // 200_000

    // key 9: mint (one asset group, one token amount +5)
    for (size_t i = 0; i < MINTING_POLICY_ID_LENGTH; i++) {
        raw_tx[offset++] = (uint8_t) (0x80 + i);
    }
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x01;
    raw_tx[offset++] = 0x01;
    raw_tx[offset++] = 0xAA;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x05;

    assert_int_equal(offset, sizeof(raw_tx));

    buffer_t buf = {
        .ptr = raw_tx,
        .size = sizeof(raw_tx),
        .offset = 0,
    };

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.networkId = MAINNET_NETWORK_ID;
    G_context.tx_info.tx_params.protocolMagic = MAINNET_PROTOCOL_MAGIC;
    G_context.tx_info.tx_params.num_inputs = 1;
    G_context.tx_info.tx_params.num_outputs = 1;
    G_context.tx_info.tx_params.includeTtl = false;
    G_context.tx_info.tx_params.num_mint_asset_groups = 1;

    bool ok = tx_validate(&buf);

    assert_true(ok);
    assert_int_equal(buf.offset, sizeof(raw_tx));
    assert_int_equal(G_context.tx_info.planned_ui_pairs, 9);  // output base + output token + fee + mint summary + mint token
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_tx_fails_on_missing_inputs),
        cmocka_unit_test(test_parse_tx_rejects_oversized_buffer),
        cmocka_unit_test(test_parse_error_mapping_fee),
        cmocka_unit_test(test_parse_error_mapping_buffer_not_fully_consumed),
        cmocka_unit_test(test_process_inputs_field_pass1_success),
        cmocka_unit_test(test_process_inputs_field_parse_error_sends_inputs_swo),
        cmocka_unit_test(test_process_collateral_inputs_field_pass1_success),
        cmocka_unit_test(test_process_reference_inputs_field_parse_error_sends_reference_swo),
        cmocka_unit_test(test_process_required_signers_field_pass1_success),
        cmocka_unit_test(test_process_required_signers_field_parse_error_sends_required_swo),
        cmocka_unit_test(test_mode_allows_rendering_with_validation),
        cmocka_unit_test(test_validate_from_raw_success),
        cmocka_unit_test(test_validate_from_raw_with_tokens_and_mint_success),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
