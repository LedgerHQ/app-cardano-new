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
#include "sign_tx_ctx.h"
#include "handler/sign_tx.h"
#include "securityPolicy.h"
#include "addressUtils/bip44.h"
#include "cardano_swo.h"
#include "mem.h"
#include "app_context.h"
#include "apdu_finalization_check.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];
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

static inline bool test_mem_init(void) {
    return mem_utils_init(test_heap, sizeof(test_heap));
}

static void reset_test_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    g_last_sw = 0;
    assert_true(test_mem_init());
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

static void test_sign_tx_init_deny_when_request_is_active(void **state) {
    (void) state;
    reset_test_context();

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
    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = TX_STATE_NONE;

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

    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = TX_STATE_NONE;
    G_context.tx_info.num_witnesses = 1;
    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;

    uint32_t path[] = {
        harden(PURPOSE_SHELLEY),
        harden(ADA_COIN_TYPE),
        harden(0),
        0,
        0,
    };
    uint8_t path_raw[32] = {0};
    size_t path_len =
        write_bip44_path(path_raw, sizeof(path_raw), path, sizeof(path) / sizeof(path[0]));

    buffer_t witness_buf = {
        .ptr = path_raw,
        .size = path_len,
        .offset = 0,
    };

    run_sign_tx_witness_apdu(&witness_buf);
    assert_int_equal(g_last_sw, SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sign_tx_init_deny_when_request_is_active),
        cmocka_unit_test(test_sign_tx_chunk_deny_without_active_request),
        cmocka_unit_test(test_sign_tx_confirm_stops_after_chunk_error),
        cmocka_unit_test(test_sign_tx_witness_deny_before_approved_state),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
