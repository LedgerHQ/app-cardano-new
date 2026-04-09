/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "addressUtilsShelley.h"
#include "bip44.h"
#include "mem.h"
#include "tx_ui_pair_counts.h"
#include "ui_address_fields.h"
#include "ui_utils.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static const uint8_t TEST_PAYMENT_SCRIPT_HASH[SCRIPT_HASH_LENGTH] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
    0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
};

static const uint8_t TEST_STAKING_KEY_HASH[ADDRESS_KEY_HASH_LENGTH] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
    0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
};

static const uint8_t TEST_STAKING_SCRIPT_HASH[SCRIPT_HASH_LENGTH] = {
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
    0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B,
};

static void prepare_ui_capture(uint16_t pair_count, ui_render_session_t *render_session) {
    assert_true(mem_utils_init(test_heap, sizeof(test_heap)));
    ui_reset_error_status();
    assert_true(ui_pairs_init(pair_count));
    ui_render_session_begin(render_session, 0);
}

static void finish_ui_capture(void) {
    ui_render_session_end();
    assert_int_equal(ui_get_error_status(), UI_STATUS_SUCCESS);
    ui_free_pairs();
}

static void test_add_payment_info_ui_pairs_labels(void **state) {
    (void) state;

    const struct {
        const char *name;
        address_params_t address_params;
        const char *expected_label;
    } test_cases[] = {
        {
            .name = "payment path",
            .address_params =
                {
                    .type = BASE_PAYMENT_KEY_STAKE_KEY,
                    .networkId = TESTNET_NETWORK_ID,
                    .paymentPartType = PAYMENT_PART_KEY_PATH,
                    .paymentKeyPath =
                        {
                            .length = 5,
                            .path =
                                {
                                    1852 + HARDENED_BIP32,
                                    ADA_COIN_TYPE + HARDENED_BIP32,
                                    0 + HARDENED_BIP32,
                                    0,
                                    0,
                                },
                        },
                    .stakingPartType = STAKING_PART_KEY_PATH,
                    .stakingKeyPath =
                        {
                            .length = 5,
                            .path =
                                {
                                    1852 + HARDENED_BIP32,
                                    ADA_COIN_TYPE + HARDENED_BIP32,
                                    0 + HARDENED_BIP32,
                                    2,
                                    0,
                                },
                        },
                },
            .expected_label = UI_LABEL_BY_SCREEN("Payment key path", "Pay path"),
        },
        {
            .name = "payment script hash",
            .address_params =
                {
                    .type = BASE_PAYMENT_SCRIPT_STAKE_KEY,
                    .networkId = TESTNET_NETWORK_ID,
                    .paymentPartType = PAYMENT_PART_SCRIPT_HASH,
                    .paymentScriptHash = TEST_PAYMENT_SCRIPT_HASH,
                    .stakingPartType = STAKING_PART_KEY_PATH,
                    .stakingKeyPath =
                        {
                            .length = 5,
                            .path =
                                {
                                    1852 + HARDENED_BIP32,
                                    ADA_COIN_TYPE + HARDENED_BIP32,
                                    0 + HARDENED_BIP32,
                                    2,
                                    0,
                                },
                        },
                },
            .expected_label = UI_LABEL_BY_SCREEN("Payment script hash", "Pay script"),
        },
    };

    for (size_t i = 0; i < ARRAY_LEN(test_cases); i++) {
        ui_render_session_t render_session = {0};

        prepare_ui_capture(UI_PAIRS_PAYMENT_INFO, &render_session);
        addPaymentInfoUIPairs(&test_cases[i].address_params);

        assert_int_equal(ui_pairs_get_count(), UI_PAIRS_PAYMENT_INFO);
        assert_non_null(g_pairs);
        assert_string_equal(g_pairs[0].item, test_cases[i].expected_label);

        finish_ui_capture();
    }
}

static void test_add_staking_info_ui_pairs_labels(void **state) {
    (void) state;

    const struct {
        const char *name;
        address_params_t address_params;
        const char *expected_label;
    } test_cases[] = {
        {
            .name = "byron warning",
            .address_params =
                {
                    .type = BYRON,
                    .protocolMagic = TESTNET_PROTOCOL_MAGIC_LEGACY,
                    .paymentPartType = PAYMENT_PART_NONE,
                    .stakingPartType = STAKING_PART_NONE,
                },
            .expected_label = "Warning:",
        },
        {
            .name = "enterprise warning",
            .address_params =
                {
                    .type = ENTERPRISE_KEY,
                    .networkId = TESTNET_NETWORK_ID,
                    .paymentPartType = PAYMENT_PART_KEY_PATH,
                    .paymentKeyPath =
                        {
                            .length = 5,
                            .path =
                                {
                                    1852 + HARDENED_BIP32,
                                    ADA_COIN_TYPE + HARDENED_BIP32,
                                    0 + HARDENED_BIP32,
                                    0,
                                    1,
                                },
                        },
                    .stakingPartType = STAKING_PART_NONE,
                },
            .expected_label = "Warning:",
        },
        {
            .name = "stake key hash",
            .address_params =
                {
                    .type = BASE_PAYMENT_KEY_STAKE_KEY,
                    .networkId = TESTNET_NETWORK_ID,
                    .paymentPartType = PAYMENT_PART_KEY_PATH,
                    .paymentKeyPath =
                        {
                            .length = 5,
                            .path =
                                {
                                    1852 + HARDENED_BIP32,
                                    ADA_COIN_TYPE + HARDENED_BIP32,
                                    0 + HARDENED_BIP32,
                                    0,
                                    2,
                                },
                        },
                    .stakingPartType = STAKING_PART_KEY_HASH,
                    .stakingKeyHash = TEST_STAKING_KEY_HASH,
                },
            .expected_label = UI_LABEL_BY_SCREEN("Stake key hash", "Stake key"),
        },
        {
            .name = "stake script hash",
            .address_params =
                {
                    .type = BASE_PAYMENT_KEY_STAKE_SCRIPT,
                    .networkId = TESTNET_NETWORK_ID,
                    .paymentPartType = PAYMENT_PART_KEY_PATH,
                    .paymentKeyPath =
                        {
                            .length = 5,
                            .path =
                                {
                                    1852 + HARDENED_BIP32,
                                    ADA_COIN_TYPE + HARDENED_BIP32,
                                    0 + HARDENED_BIP32,
                                    0,
                                    3,
                                },
                        },
                    .stakingPartType = STAKING_PART_SCRIPT_HASH,
                    .stakingScriptHash = TEST_STAKING_SCRIPT_HASH,
                },
            .expected_label = UI_LABEL_BY_SCREEN("Stake script hash", "Stake hash"),
        },
        {
            .name = "stake pointer",
            .address_params =
                {
                    .type = POINTER_KEY,
                    .networkId = TESTNET_NETWORK_ID,
                    .paymentPartType = PAYMENT_PART_KEY_PATH,
                    .paymentKeyPath =
                        {
                            .length = 5,
                            .path =
                                {
                                    1852 + HARDENED_BIP32,
                                    ADA_COIN_TYPE + HARDENED_BIP32,
                                    0 + HARDENED_BIP32,
                                    0,
                                    4,
                                },
                        },
                    .stakingPartType = STAKING_PART_BLOCKCHAIN_POINTER,
                    .stakingKeyBlockchainPointer =
                        {
                            .blockIndex = 1,
                            .txIndex = 2,
                            .certificateIndex = 3,
                        },
                },
            .expected_label = UI_LABEL_BY_SCREEN("Stake key pointer", "Stake ptr"),
        },
    };

    for (size_t i = 0; i < ARRAY_LEN(test_cases); i++) {
        ui_render_session_t render_session = {0};

        prepare_ui_capture(UI_PAIRS_STAKING_INFO, &render_session);
        addStakingInfoUIPairs(&test_cases[i].address_params);

        assert_int_equal(ui_pairs_get_count(), UI_PAIRS_STAKING_INFO);
        assert_non_null(g_pairs);
        assert_string_equal(g_pairs[0].item, test_cases[i].expected_label);

        finish_ui_capture();
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_add_payment_info_ui_pairs_labels),
        cmocka_unit_test(test_add_staking_info_ui_pairs_labels),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
