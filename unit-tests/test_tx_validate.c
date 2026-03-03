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
#include "cardano_swo.h"
#include "tx_parse.h"
#include "tx_constants.h"
#include "app_mem_utils.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static void reset_context(void) {
    explicit_bzero(&G_context, sizeof(G_context));
    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = TX_STATE_RECEIVED;
    assert_true(mem_utils_init(test_heap, sizeof(test_heap)));
}

static void test_compute_tx_hash_and_plan_ui_counts_ttl(void **state) {
    (void) state;
    reset_context();

    static uint8_t raw_tx[] = {
        // input tx hash (32B) + output index (4B)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        // fee = 42 lovelace
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A,
        // ttl = 123
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7B,
    };
    tx_body_ctx()->raw_tx = raw_tx;
    G_context.tx_info.raw_tx_total_length = SIZEOF(raw_tx);
    tx_body_ctx()->raw_tx_current_length = SIZEOF(raw_tx);

    G_context.tx_info.tx_params.num_inputs = 1;
    G_context.tx_info.tx_params.num_outputs = 0;
    G_context.tx_info.tx_params.includeTtl = true;
    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.networkId = MAINNET_NETWORK_ID;
    G_context.tx_info.tx_params.protocolMagic = MAINNET_PROTOCOL_MAGIC;

    bool result = tx_validate();
    assert_true(result);
    assert_true(tx_body_ctx()->total_ui_pairs >= 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_compute_tx_hash_and_plan_ui_counts_ttl),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
