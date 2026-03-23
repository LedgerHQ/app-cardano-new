/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "globals.h"
#include "sign_tx_ctx.h"
#include "cvote_parser.h"
#include "cardano_constants.h"
#include "cardano_swo.h"
#include "mem.h"

uint16_t __wrap_parse_output_destination(buffer_t *buf, tx_output_destination_t *destination) {
    (void) destination;
    // consume 1 byte to simulate parsing
    uint8_t dummy;
    buffer_read_u8(buf, &dummy);
    return mock_type(uint16_t);
}

// Define a heap to test out-of-memory cases
static uint8_t test_heap[8192];
static void reset_test_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = TX_STATE_AUX_DATA;
    memset(tx_aux_data_ctx(), 0, sizeof(*tx_aux_data_ctx()));
    mem_utils_init(test_heap, sizeof(test_heap));
}

// -----------------------------------------------------------------------------
// Tests for buffer_read_cvote_credential
// -----------------------------------------------------------------------------

static void test_buffer_read_cvote_credential_empty(void **state) {
    (void) state;
    buffer_t buf = buffer_create(NULL, 0);
    cvote_credential_t cred = {0};
    assert_false(buffer_read_cvote_credential(&buf, &cred));
}

static void test_buffer_read_cvote_credential_invalid_type(void **state) {
    (void) state;
    uint8_t raw[] = {0x01}; // Type 1 is not allowed
    buffer_t buf = buffer_create(raw, sizeof(raw));
    cvote_credential_t cred = {0};
    assert_false(buffer_read_cvote_credential(&buf, &cred));
}

static void test_buffer_read_cvote_credential_key_path_truncated(void **state) {
    (void) state;
    uint8_t raw[] = {CVOTE_CREDENTIAL_KEY_PATH, 0x01, 0x02}; // Truncated path
    buffer_t buf = buffer_create(raw, sizeof(raw));
    cvote_credential_t cred = {0};
    assert_false(buffer_read_cvote_credential(&buf, &cred));
}

static void test_buffer_read_cvote_credential_key_truncated(void **state) {
    (void) state;
    uint8_t raw[] = {CVOTE_CREDENTIAL_KEY, 0x00, 0x01}; // Less than 32 bytes
    buffer_t buf = buffer_create(raw, sizeof(raw));
    cvote_credential_t cred = {0};
    assert_false(buffer_read_cvote_credential(&buf, &cred));
}

// -----------------------------------------------------------------------------
// Tests for cvote_parse_destination
// -----------------------------------------------------------------------------

static void test_cvote_parse_destination_invalid_format(void **state) {
    (void) state;
    reset_test_context();
    uint8_t raw[] = {0xFF}; // Invalid destination format
    buffer_t buf = buffer_create(raw, sizeof(raw));
    tx_output_destination_t dest = {0};
    will_return(__wrap_parse_output_destination, 1);
    assert_int_equal(cvote_parse_destination(&buf, &dest), CVOTE_PARSER_INVALID_FORMAT);
}

static void test_cvote_parse_destination_out_of_memory(void **state) {
    (void) state;
    reset_test_context();
    mem_utils_init(test_heap, 0);

    uint8_t raw[] = {DESTINATION_THIRD_PARTY, 0x00, 0x00, 0x00, 0x01, 0x00};
    buffer_t buf = buffer_create(raw, sizeof(raw));
    tx_output_destination_t dest = {0};
    will_return(__wrap_parse_output_destination, SWO_INSUFFICIENT_MEMORY);
    assert_int_equal(cvote_parse_destination(&buf, &dest), CVOTE_PARSER_OUT_OF_MEMORY);
}

// -----------------------------------------------------------------------------
// Tests for cvote_parse_aux_data_init
// -----------------------------------------------------------------------------

static void test_cvote_parse_init_too_short(void **state) {
    (void) state;
    reset_test_context();
    uint8_t raw[] = {0x01, 0x00}; // Only 2 bytes, needs at least 3
    tx_aux_data_ctx()->raw_cvote_init_data = raw;
    tx_aux_data_ctx()->raw_cvote_init_data_len = sizeof(raw);
    cvote_aux_data_t out_data = {0};
    assert_int_equal(cvote_parse_aux_data_init(&out_data), CVOTE_PARSER_INVALID_FORMAT);
}

static void test_cvote_parse_init_invalid_format(void **state) {
    (void) state;
    reset_test_context();
    // Format 3 (invalid), 0 delegations
    uint8_t raw[] = {0x03, 0x00, 0x00}; 
    tx_aux_data_ctx()->raw_cvote_init_data = raw;
    tx_aux_data_ctx()->raw_cvote_init_data_len = sizeof(raw);
    cvote_aux_data_t out_data = {0};
    assert_int_equal(cvote_parse_aux_data_init(&out_data), CVOTE_PARSER_INVALID_FORMAT);
}

static void test_cvote_parse_init_cip15_with_delegations(void **state) {
    (void) state;
    reset_test_context();
    // CIP15 (1), 1 delegation
    uint8_t raw[] = {CIP15, 0x00, 0x01};
    tx_aux_data_ctx()->raw_cvote_init_data = raw;
    tx_aux_data_ctx()->raw_cvote_init_data_len = sizeof(raw);
    cvote_aux_data_t out_data = {0};
    assert_int_equal(cvote_parse_aux_data_init(&out_data), CVOTE_PARSER_INVALID_FORMAT);
}

static void test_cvote_parse_init_staking_credential_truncated(void **state) {
    (void) state;
    reset_test_context();
    // CIP36, 0 delegations, truncated staking cred
    uint8_t raw[] = {CIP36, 0x00, 0x00, CVOTE_CREDENTIAL_KEY, 0x01, 0x02};
    tx_aux_data_ctx()->raw_cvote_init_data = raw;
    tx_aux_data_ctx()->raw_cvote_init_data_len = sizeof(raw);
    cvote_aux_data_t out_data = {0};
    assert_int_equal(cvote_parse_aux_data_init(&out_data), CVOTE_PARSER_INVALID_FORMAT);
}

static void test_cvote_parse_init_destination_truncated(void **state) {
    (void) state;
    reset_test_context();
    // CIP36, 0 delegations
    // Staking credential: Key path with 1 element
    uint8_t raw[] = {
        CIP36, 0x00, 0x00, 
        CVOTE_CREDENTIAL_KEY_PATH, 0x01, 0x80, 0x00, 0x00, 0x00, // Staking cred (valid path len=1, path=0x80000000)
        0xFF // Invalid dest format
    };
    tx_aux_data_ctx()->raw_cvote_init_data = raw;
    tx_aux_data_ctx()->raw_cvote_init_data_len = sizeof(raw);
    cvote_aux_data_t out_data = {0};
    will_return(__wrap_parse_output_destination, 1);
    assert_int_equal(cvote_parse_aux_data_init(&out_data), CVOTE_PARSER_INVALID_FORMAT);
}

static void test_cvote_parse_init_nonce_truncated(void **state) {
    (void) state;
    reset_test_context();
    uint8_t raw[] = {
        CIP36, 0x00, 0x00, 
        CVOTE_CREDENTIAL_KEY_PATH, 0x01, 0x80, 0x00, 0x00, 0x00,
        DESTINATION_THIRD_PARTY, // Dest: third party, 1 byte address
        0x00, 0x00 // Truncated nonce
    };
    tx_aux_data_ctx()->raw_cvote_init_data = raw;
    tx_aux_data_ctx()->raw_cvote_init_data_len = sizeof(raw);
    cvote_aux_data_t out_data = {0};
    will_return(__wrap_parse_output_destination, 0); // Success
    assert_int_equal(cvote_parse_aux_data_init(&out_data), CVOTE_PARSER_INVALID_FORMAT);
}

static void test_cvote_parse_init_cip36_voting_purpose_truncated(void **state) {
    (void) state;
    reset_test_context();
    uint8_t raw[] = {
        CIP36, 0x00, 0x00, 
        CVOTE_CREDENTIAL_KEY_PATH, 0x01, 0x80, 0x00, 0x00, 0x00,
        DESTINATION_THIRD_PARTY,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Nonce (8 bytes)
        0x00 // Truncated voting purpose
    };
    tx_aux_data_ctx()->raw_cvote_init_data = raw;
    tx_aux_data_ctx()->raw_cvote_init_data_len = sizeof(raw);
    cvote_aux_data_t out_data = {0};
    will_return(__wrap_parse_output_destination, 0); // Success
    assert_int_equal(cvote_parse_aux_data_init(&out_data), CVOTE_PARSER_INVALID_FORMAT);
}

static void test_cvote_parse_init_cip36_vote_cred_truncated(void **state) {
    (void) state;
    reset_test_context();
    uint8_t raw[] = {
        CIP36, 0x00, 0x00, 
        CVOTE_CREDENTIAL_KEY_PATH, 0x01, 0x80, 0x00, 0x00, 0x00,
        DESTINATION_THIRD_PARTY,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Nonce (8 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Voting purpose (8 bytes)
        0x01 // Invalid vote credential
    };
    tx_aux_data_ctx()->raw_cvote_init_data = raw;
    tx_aux_data_ctx()->raw_cvote_init_data_len = sizeof(raw);
    cvote_aux_data_t out_data = {0};
    will_return(__wrap_parse_output_destination, 0); // Success
    assert_int_equal(cvote_parse_aux_data_init(&out_data), CVOTE_PARSER_INVALID_FORMAT);
}

static void test_cvote_parse_init_cip15_vote_cred_truncated(void **state) {
    (void) state;
    reset_test_context();
    uint8_t raw[] = {
        CIP15, 0x00, 0x00, 
        CVOTE_CREDENTIAL_KEY_PATH, 0x01, 0x80, 0x00, 0x00, 0x00,
        DESTINATION_THIRD_PARTY,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Nonce (8 bytes)
        0x01 // Invalid vote credential
    };
    tx_aux_data_ctx()->raw_cvote_init_data = raw;
    tx_aux_data_ctx()->raw_cvote_init_data_len = sizeof(raw);
    cvote_aux_data_t out_data = {0};
    will_return(__wrap_parse_output_destination, 0); // Success
    assert_int_equal(cvote_parse_aux_data_init(&out_data), CVOTE_PARSER_INVALID_FORMAT);
}

static void test_cvote_parse_init_not_fully_consumed(void **state) {
    (void) state;
    reset_test_context();
    uint8_t raw[] = {
        CIP15, 0x00, 0x00, 
        CVOTE_CREDENTIAL_KEY_PATH, 0x01, 0x80, 0x00, 0x00, 0x00, // Staking cred
        DESTINATION_THIRD_PARTY, // Dest
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Nonce (8 bytes)
        CVOTE_CREDENTIAL_KEY_PATH, 0x01, 0x80, 0x00, 0x00, 0x00, // Vote cred
        0xEE // EXTRA BYTE
    };
    tx_aux_data_ctx()->raw_cvote_init_data = raw;
    tx_aux_data_ctx()->raw_cvote_init_data_len = sizeof(raw);
    cvote_aux_data_t out_data = {0};
    will_return(__wrap_parse_output_destination, 0); // Success
    assert_int_equal(cvote_parse_aux_data_init(&out_data), CVOTE_PARSER_INVALID_FORMAT);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_buffer_read_cvote_credential_empty),
        cmocka_unit_test(test_buffer_read_cvote_credential_invalid_type),
        cmocka_unit_test(test_buffer_read_cvote_credential_key_path_truncated),
        cmocka_unit_test(test_buffer_read_cvote_credential_key_truncated),
        cmocka_unit_test(test_cvote_parse_destination_invalid_format),
        cmocka_unit_test(test_cvote_parse_destination_out_of_memory),
        cmocka_unit_test(test_cvote_parse_init_too_short),
        cmocka_unit_test(test_cvote_parse_init_invalid_format),
        cmocka_unit_test(test_cvote_parse_init_cip15_with_delegations),
        cmocka_unit_test(test_cvote_parse_init_staking_credential_truncated),
        cmocka_unit_test(test_cvote_parse_init_destination_truncated),
        cmocka_unit_test(test_cvote_parse_init_nonce_truncated),
        cmocka_unit_test(test_cvote_parse_init_cip36_voting_purpose_truncated),
        cmocka_unit_test(test_cvote_parse_init_cip36_vote_cred_truncated),
        cmocka_unit_test(test_cvote_parse_init_cip15_vote_cred_truncated),
        cmocka_unit_test(test_cvote_parse_init_not_fully_consumed),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
