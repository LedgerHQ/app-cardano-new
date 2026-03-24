/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "cardano_constants.h"
#include "addressUtils/addressUtilsShelley.h"
#include "addressUtils/addressUtilsByron.h"
#include "addressUtils/bip44.h"
#include "transaction/tx_credential_types.h"
#include "buffer.h"
#include "hexUtils.h"

#define HD HARDENED_BIP32
#define MAX_ADDRESS_LENGTH 128

static void init_path(bip44_path_t* path, const uint32_t* elements, size_t len) {
    path->length = len;
    for (size_t i = 0; i < len; i++) {
        path->path[i] = elements[i];
    }
}

static void testcase_derive_address_shelley(address_type_t type,
                                            uint32_t networkIdOrProtocolMagic,
                                            const uint32_t* paymentPath,
                                            size_t paymentPathLen,
                                            staking_part_type_t stakingPartType,
                                            const uint32_t* stakingPath,
                                            size_t stakingPathLen,
                                            const char* stakingKeyHashHex,
                                            const blockchainPointer_t* pointer,
                                            const char* expectedHex) {
    address_params_t params = {0};

    if (type == BYRON) {
        params.type = type;
        params.protocolMagic = networkIdOrProtocolMagic;
    } else {
        params.type = type;
        params.networkId = (uint8_t) networkIdOrProtocolMagic;
    }

    params.stakingPartType = stakingPartType;

    // Payment credential: all test cases here use KEY_PATH for payment
    params.paymentPartType = PAYMENT_PART_KEY_PATH;
    init_path(&params.paymentKeyPath, paymentPath, paymentPathLen);

    // Staking credential
    if (stakingPathLen > 0) {
        init_path(&params.stakingKeyPath, stakingPath, stakingPathLen);
    }

    // Local buffer that outlives the test scope (static so pointer remains valid)
    static uint8_t stakingKeyHashBuf[ADDRESS_KEY_HASH_LENGTH];
    if (stakingKeyHashHex != NULL) {
        size_t decodedLen = 0;
        assert_true(strlen(stakingKeyHashHex) == ADDRESS_KEY_HASH_LENGTH * 2);
        assert_true(decode_hex(stakingKeyHashHex, stakingKeyHashBuf, sizeof(stakingKeyHashBuf), &decodedLen));
        assert_int_equal(decodedLen, sizeof(stakingKeyHashBuf));
        params.stakingKeyHash = stakingKeyHashBuf;
    }

    if (pointer != NULL) {
        params.stakingKeyBlockchainPointer = *pointer;
    }

    uint8_t out[MAX_ADDRESS_LENGTH];
    size_t outSize = deriveAddress(&params, out, sizeof(out));

    uint8_t expected[MAX_ADDRESS_LENGTH] = {0};
    size_t expectedSize = 0;
    assert_true(decode_hex(expectedHex, expected, sizeof(expected), &expectedSize));

    if (expectedHex != NULL &&
        strcmp(expectedHex,
               "01f90b0dfcace47bf03e88f7469a2f4fb3a7918461aa4765bfaf55f0dae260546c20562e598fb761f419dad27edcd49f4ee4f0540b8e40d4d5") == 0) {
        char out_hex[MAX_ADDRESS_LENGTH * 2 + 1];
        char exp_hex[MAX_ADDRESS_LENGTH * 2 + 1];
        test_bytes_to_lowercase_hex(out_hex, sizeof(out_hex), out, outSize);
        test_bytes_to_lowercase_hex(exp_hex, sizeof(exp_hex), expected, expectedSize);
        PRINTF("derived address: %s", out_hex);
        PRINTF("expected address: %s", exp_hex);
    }

    assert_int_equal(outSize, expectedSize);
    assert_memory_equal(out, expected, expectedSize);
}

static void test_address_derivation(void **state) {
    (void) state;

    testcase_derive_address_shelley(
        BYRON,
        MAINNET_PROTOCOL_MAGIC,
        (uint32_t[]){HD + 44, HD + 1815, HD + 0, 1, 55},
        5,
        STAKING_PART_NONE,
        NULL,
        0,
        NULL,
        NULL,
        "82d818582183581ca39fa49038d760e5ebfdafe4e6fb28bd5506af6be6687e2278e8f13ba0001a5bce789b");

    testcase_derive_address_shelley(
        BASE_PAYMENT_KEY_STAKE_KEY,
        0x03,
        (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 0, 1},
        5,
        STAKING_PART_KEY_PATH,
        (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 2, 0},
        5,
        NULL,
        NULL,
        "035a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b31d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c");

    testcase_derive_address_shelley(
        BASE_PAYMENT_KEY_STAKE_KEY,
        0x00,
        (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 0, 1},
        5,
        STAKING_PART_KEY_PATH,
        (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 2, 0},
        5,
        NULL,
        NULL,
        "005a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b31d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c");

    testcase_derive_address_shelley(
        BASE_PAYMENT_KEY_STAKE_KEY,
        0x00,
        (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 0, 1},
        5,
        STAKING_PART_KEY_HASH,
        NULL,
        0,
        "1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        NULL,
        "005a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b31d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c");

    testcase_derive_address_shelley(
        BASE_PAYMENT_KEY_STAKE_KEY,
        0x03,
        (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 0, 1},
        5,
        STAKING_PART_KEY_HASH,
        NULL,
        0,
        "122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        NULL,
        "035a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277");

    testcase_derive_address_shelley(
        ENTERPRISE_KEY,
        0x00,
        (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 0, 1},
        5,
        STAKING_PART_NONE,
        NULL,
        0,
        NULL,
        NULL,
        "605a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3");

    testcase_derive_address_shelley(
        ENTERPRISE_KEY,
        0x03,
        (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 0, 1},
        5,
        STAKING_PART_NONE,
        NULL,
        0,
        NULL,
        NULL,
        "635a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3");

    testcase_derive_address_shelley(
        POINTER_KEY,
        0x00,
        (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 0, 1},
        5,
        STAKING_PART_BLOCKCHAIN_POINTER,
        NULL,
        0,
        NULL,
        &(blockchainPointer_t){.blockIndex = 1, .txIndex = 2, .certificateIndex = 3},
        "405a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3010203");

    testcase_derive_address_shelley(
        POINTER_KEY,
        0x03,
        (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 0, 1},
        5,
        STAKING_PART_BLOCKCHAIN_POINTER,
        NULL,
        0,
        NULL,
        &(blockchainPointer_t){.blockIndex = 24157, .txIndex = 177, .certificateIndex = 42},
        "435a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b381bc5d81312a");

    testcase_derive_address_shelley(
        POINTER_KEY,
        0x03,
        (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 0, 1},
        5,
        STAKING_PART_BLOCKCHAIN_POINTER,
        NULL,
        0,
        NULL,
        &(blockchainPointer_t){.blockIndex = 0, .txIndex = 0, .certificateIndex = 0},
        "435a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3000000");

    testcase_derive_address_shelley(
        BASE_PAYMENT_KEY_STAKE_KEY,
        MAINNET_NETWORK_ID,
        (uint32_t[]){HD + 1852, HD + 1815, HD + 456, 0, 5000000},
        5,
        STAKING_PART_KEY_PATH,
        (uint32_t[]){HD + 1852, HD + 1815, HD + 456, 2, 0},
        5,
        NULL,
        NULL,
        "01f90b0dfcace47bf03e88f7469a2f4fb3a7918461aa4765bfaf55f0dae260546c20562e598fb761f419dad27edcd49f4ee4f0540b8e40d4d5");
}

static void test_buffer_parse_address_params_payment_script_hash(void **state) {
    (void) state;
    uint8_t serialized[1 + 1 + SCRIPT_HASH_LENGTH + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    size_t offset = 0;

    serialized[offset++] = BASE_PAYMENT_SCRIPT_STAKE_KEY;
    serialized[offset++] = 0x05;  // arbitrary network id

    for (size_t i = 0; i < SCRIPT_HASH_LENGTH; i++) {
        serialized[offset++] = (uint8_t) (0xA0 + i);
    }

    serialized[offset++] = STAKING_PART_KEY_HASH;
    for (size_t i = 0; i < ADDRESS_KEY_HASH_LENGTH; i++) {
        serialized[offset++] = (uint8_t) (0x10 + i);
    }

    buffer_t buf = {
        .ptr = serialized,
        .size = offset,
        .offset = 0,
    };
    address_params_t params = {0};
    assert_true(buffer_read_address_params(&buf, &params));
    assert_int_equal(buf.offset, buf.size);
    assert_int_equal(params.type, BASE_PAYMENT_SCRIPT_STAKE_KEY);
    assert_int_equal(params.networkId, 0x05);
    assert_int_equal(params.paymentPartType, PAYMENT_PART_SCRIPT_HASH);
    assert_non_null(params.paymentScriptHash);
    assert_memory_equal(params.paymentScriptHash, serialized + 2, SCRIPT_HASH_LENGTH);
    assert_int_equal(params.stakingPartType, STAKING_PART_KEY_HASH);
    assert_non_null(params.stakingKeyHash);
    assert_memory_equal(params.stakingKeyHash,
                        serialized + 2 + SCRIPT_HASH_LENGTH + 1,
                        ADDRESS_KEY_HASH_LENGTH);
}

static void test_buffer_parse_address_params_payment_script_hash_with_pointer(void **state) {
    (void) state;
    uint8_t serialized[1 + 1 + SCRIPT_HASH_LENGTH + 1 + sizeof(blockchainPointer_t)] = {0};
    size_t offset = 0;

    serialized[offset++] = POINTER_SCRIPT;
    serialized[offset++] = 0x01;

    for (size_t i = 0; i < SCRIPT_HASH_LENGTH; i++) {
        serialized[offset++] = (uint8_t) (0x40 + i);
    }

    serialized[offset++] = STAKING_PART_BLOCKCHAIN_POINTER;

    uint32_t blockIndex = 0x11223344;
    uint32_t txIndex = 0x55667788;
    uint32_t certIndex = 0x99AABBCC;
    serialized[offset++] = (uint8_t) (blockIndex >> 24);
    serialized[offset++] = (uint8_t) (blockIndex >> 16);
    serialized[offset++] = (uint8_t) (blockIndex >> 8);
    serialized[offset++] = (uint8_t) (blockIndex);
    serialized[offset++] = (uint8_t) (txIndex >> 24);
    serialized[offset++] = (uint8_t) (txIndex >> 16);
    serialized[offset++] = (uint8_t) (txIndex >> 8);
    serialized[offset++] = (uint8_t) (txIndex);
    serialized[offset++] = (uint8_t) (certIndex >> 24);
    serialized[offset++] = (uint8_t) (certIndex >> 16);
    serialized[offset++] = (uint8_t) (certIndex >> 8);
    serialized[offset++] = (uint8_t) (certIndex);

    buffer_t buf = {
        .ptr = serialized,
        .size = offset,
        .offset = 0,
    };
    address_params_t params = {0};
    assert_true(buffer_read_address_params(&buf, &params));
    assert_int_equal(buf.offset, buf.size);
    assert_int_equal(params.type, POINTER_SCRIPT);
    assert_int_equal(params.networkId, 0x01);
    assert_int_equal(params.paymentPartType, PAYMENT_PART_SCRIPT_HASH);
    assert_non_null(params.paymentScriptHash);
    assert_memory_equal(params.paymentScriptHash, serialized + 2, SCRIPT_HASH_LENGTH);
    assert_int_equal(params.stakingPartType, STAKING_PART_BLOCKCHAIN_POINTER);
    assert_int_equal(params.stakingKeyBlockchainPointer.blockIndex, blockIndex);
    assert_int_equal(params.stakingKeyBlockchainPointer.txIndex, txIndex);
    assert_int_equal(params.stakingKeyBlockchainPointer.certificateIndex, certIndex);
}

static void test_buffer_parse_address_params_payment_script_hash_with_stake_path(void **state) {
    (void) state;
    const uint32_t staking_path[] = {HD + 1852, HD + 1815, HD + 0, 2, 0};
    enum { STAKING_PATH_LEN = ARRAY_LEN(staking_path) };

    uint8_t serialized[1 + 1 + SCRIPT_HASH_LENGTH + 1 + 1 + STAKING_PATH_LEN * 4] = {0};
    size_t offset = 0;

    serialized[offset++] = BASE_PAYMENT_SCRIPT_STAKE_KEY;
    serialized[offset++] = 0x02;

    for (size_t i = 0; i < SCRIPT_HASH_LENGTH; i++) {
        serialized[offset++] = (uint8_t) (0xB0 + i);
    }

    serialized[offset++] = STAKING_PART_KEY_PATH;
    serialized[offset++] = (uint8_t) STAKING_PATH_LEN;
    for (size_t i = 0; i < STAKING_PATH_LEN; i++) {
        serialized[offset++] = (uint8_t) (staking_path[i] >> 24);
        serialized[offset++] = (uint8_t) (staking_path[i] >> 16);
        serialized[offset++] = (uint8_t) (staking_path[i] >> 8);
        serialized[offset++] = (uint8_t) (staking_path[i]);
    }

    buffer_t buf = {
        .ptr = serialized,
        .size = offset,
        .offset = 0,
    };
    address_params_t params = {0};
    assert_true(buffer_read_address_params(&buf, &params));
    assert_int_equal(buf.offset, buf.size);
    assert_int_equal(params.type, BASE_PAYMENT_SCRIPT_STAKE_KEY);
    assert_int_equal(params.networkId, 0x02);
    assert_int_equal(params.paymentPartType, PAYMENT_PART_SCRIPT_HASH);
    assert_non_null(params.paymentScriptHash);
    assert_memory_equal(params.paymentScriptHash, serialized + 2, SCRIPT_HASH_LENGTH);
    assert_int_equal(params.stakingPartType, STAKING_PART_KEY_PATH);
    assert_int_equal(params.stakingKeyPath.length, STAKING_PATH_LEN);
    for (size_t i = 0; i < STAKING_PATH_LEN; i++) {
        assert_int_equal(params.stakingKeyPath.path[i], staking_path[i]);
    }
}

// ======================== buffer_read_address_params failure tests ========================

static void testcase_buffer_read_address_params_fails(const uint8_t* data, size_t dataLen) {
    buffer_t buf = {.ptr = (uint8_t*) data, .size = dataLen, .offset = 0};
    address_params_t params = {0};
    assert_false(buffer_read_address_params(&buf, &params));
}

static void test_buffer_parse_address_params_empty_buffer(void **state) {
    (void) state;
    testcase_buffer_read_address_params_fails(NULL, 0);
}

static void test_buffer_parse_address_params_invalid_type(void **state) {
    (void) state;
    // 0x09..0x0D are unsupported address types
    uint8_t data[] = {0x09};
    testcase_buffer_read_address_params_fails(data, sizeof(data));
}

static void test_buffer_parse_address_params_truncated_network_id(void **state) {
    (void) state;
    // valid Shelley type (BASE_PAYMENT_KEY_STAKE_KEY = 0x00) but no network id byte follows
    uint8_t data[] = {BASE_PAYMENT_KEY_STAKE_KEY};
    testcase_buffer_read_address_params_fails(data, sizeof(data));
}

static void test_buffer_parse_address_params_invalid_network_id(void **state) {
    (void) state;
    // valid type, but network id 0xFF is out of range (max is 0x0F)
    uint8_t data[] = {BASE_PAYMENT_KEY_STAKE_KEY, 0xFF};
    testcase_buffer_read_address_params_fails(data, sizeof(data));
}

static void test_buffer_parse_address_params_truncated_payment_path(void **state) {
    (void) state;
    // valid type + valid network id, but no payment path bytes follow
    uint8_t data[] = {ENTERPRISE_KEY, 0x01};
    testcase_buffer_read_address_params_fails(data, sizeof(data));
}

static void test_buffer_parse_address_params_invalid_staking_type(void **state) {
    (void) state;
    // REWARD_KEY has PAYMENT_PART_NONE, so payment parsing is skipped;
    // staking part type byte 0xFF is invalid
    const uint32_t staking_path[] = {HD + 1852, HD + 1815, HD + 0, 2, 0};
    enum { STAKING_PATH_LEN = ARRAY_LEN(staking_path) };

    // Build a valid REWARD_KEY payload up to staking part type, then put 0xFF
    uint8_t data[2 + 1] = {0};
    data[0] = REWARD_KEY;
    data[1] = 0x01;   // network id
    data[2] = 0xFF;   // invalid staking part type
    testcase_buffer_read_address_params_fails(data, sizeof(data));
}

static void test_buffer_parse_address_params_truncated_pointer_txindex(void **state) {
    (void) state;
    // Build POINTER_KEY payload: type + network_id + payment_path + staking_type + blockIndex only
    const uint32_t payment_path[] = {HD + 1852, HD + 1815, HD + 0, 0, 1};
    enum { PAYMENT_PATH_LEN = ARRAY_LEN(payment_path) };

    // type(1) + network_id(1) + path_len(1) + path(5*4=20) + staking_type(1) + blockIndex(4) = 28
    uint8_t data[1 + 1 + 1 + PAYMENT_PATH_LEN * 4 + 1 + 4];
    size_t offset = 0;
    data[offset++] = POINTER_KEY;
    data[offset++] = 0x01;  // network id
    data[offset++] = (uint8_t) PAYMENT_PATH_LEN;
    for (size_t i = 0; i < PAYMENT_PATH_LEN; i++) {
        data[offset++] = (uint8_t) (payment_path[i] >> 24);
        data[offset++] = (uint8_t) (payment_path[i] >> 16);
        data[offset++] = (uint8_t) (payment_path[i] >> 8);
        data[offset++] = (uint8_t) (payment_path[i]);
    }
    data[offset++] = STAKING_PART_BLOCKCHAIN_POINTER;
    // blockIndex only - truncated before txIndex
    data[offset++] = 0x00;
    data[offset++] = 0x00;
    data[offset++] = 0x01;
    data[offset++] = 0x00;
    testcase_buffer_read_address_params_fails(data, offset);
}

static void test_buffer_parse_address_params_truncated_pointer_certindex(void **state) {
    (void) state;
    // Same as above but include txIndex, truncate certIndex
    const uint32_t payment_path[] = {HD + 1852, HD + 1815, HD + 0, 0, 1};
    enum { PAYMENT_PATH_LEN = ARRAY_LEN(payment_path) };

    // type(1) + network_id(1) + path_len(1) + path(20) + staking_type(1) + blockIndex(4) + txIndex(4) = 32
    uint8_t data[1 + 1 + 1 + PAYMENT_PATH_LEN * 4 + 1 + 4 + 4];
    size_t offset = 0;
    data[offset++] = POINTER_KEY;
    data[offset++] = 0x01;
    data[offset++] = (uint8_t) PAYMENT_PATH_LEN;
    for (size_t i = 0; i < PAYMENT_PATH_LEN; i++) {
        data[offset++] = (uint8_t) (payment_path[i] >> 24);
        data[offset++] = (uint8_t) (payment_path[i] >> 16);
        data[offset++] = (uint8_t) (payment_path[i] >> 8);
        data[offset++] = (uint8_t) (payment_path[i]);
    }
    data[offset++] = STAKING_PART_BLOCKCHAIN_POINTER;
    // blockIndex
    data[offset++] = 0x00; data[offset++] = 0x00; data[offset++] = 0x00; data[offset++] = 0x01;
    // txIndex
    data[offset++] = 0x00; data[offset++] = 0x00; data[offset++] = 0x00; data[offset++] = 0x02;
    // certIndex missing
    testcase_buffer_read_address_params_fails(data, offset);
}

// ======================== isValidAddressParams: inconsistent staking type tests ========================

// Each test passes a valid address type but a staking part that doesn't belong to it,
// exercising the break→return false path in is_staking_part_consistent_with_address_type.

static void test_invalid_params_base_key_with_blockchain_pointer(void **state) {
    (void) state;
    // BASE_PAYMENT_KEY_STAKE_KEY only accepts KEY_HASH or KEY_PATH staking, not BLOCKCHAIN_POINTER
    address_params_t params = {0};
    params.type = BASE_PAYMENT_KEY_STAKE_KEY;
    params.networkId = MAINNET_NETWORK_ID;
    params.paymentPartType = PAYMENT_PART_KEY_PATH;
    init_path(&params.paymentKeyPath,
              (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 0, 0}, 5);
    params.stakingPartType = STAKING_PART_BLOCKCHAIN_POINTER;
    assert_false(isValidAddressParams(&params));
}

static void test_invalid_params_pointer_key_with_key_hash(void **state) {
    (void) state;
    // POINTER_KEY only accepts BLOCKCHAIN_POINTER staking, not KEY_HASH
    address_params_t params = {0};
    params.type = POINTER_KEY;
    params.networkId = MAINNET_NETWORK_ID;
    params.paymentPartType = PAYMENT_PART_KEY_PATH;
    init_path(&params.paymentKeyPath,
              (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 0, 0}, 5);
    params.stakingPartType = STAKING_PART_KEY_HASH;
    static uint8_t dummyHash[ADDRESS_KEY_HASH_LENGTH];
    params.stakingKeyHash = dummyHash;
    assert_false(isValidAddressParams(&params));
}

static void test_invalid_params_enterprise_key_with_key_path(void **state) {
    (void) state;
    // ENTERPRISE_KEY only accepts STAKING_PART_NONE, not KEY_PATH
    address_params_t params = {0};
    params.type = ENTERPRISE_KEY;
    params.networkId = MAINNET_NETWORK_ID;
    params.paymentPartType = PAYMENT_PART_KEY_PATH;
    init_path(&params.paymentKeyPath,
              (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 0, 0}, 5);
    params.stakingPartType = STAKING_PART_KEY_PATH;
    init_path(&params.stakingKeyPath,
              (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 2, 0}, 5);
    assert_false(isValidAddressParams(&params));
}

static void test_invalid_params_reward_script_with_key_path(void **state) {
    (void) state;
    // REWARD_SCRIPT only accepts SCRIPT_HASH staking, not KEY_PATH
    address_params_t params = {0};
    params.type = REWARD_SCRIPT;
    params.networkId = MAINNET_NETWORK_ID;
    params.paymentPartType = PAYMENT_PART_NONE;
    params.stakingPartType = STAKING_PART_KEY_PATH;
    init_path(&params.stakingKeyPath,
              (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 2, 0}, 5);
    assert_false(isValidAddressParams(&params));
}

// ======================== determinePaymentChoice tests ========================

static void test_determine_payment_choice_reward(void **state) {
    (void) state;
    assert_int_equal(determinePaymentChoice(REWARD_KEY), PAYMENT_NONE);
    assert_int_equal(determinePaymentChoice(REWARD_SCRIPT), PAYMENT_NONE);
}

// ======================== isShelleyAddressType tests ========================

static void test_is_shelley_address_type_invalid(void **state) {
    (void) state;
    // 0x09 through 0x0D are gaps in the address_type_t enum — not Shelley types
    assert_false(isShelleyAddressType(0x09));
}

// ======================== buffer_read_address_params: Byron protocol magic truncated ========================

static void test_buffer_parse_address_params_byron_truncated_protocol_magic(void **state) {
    (void) state;
    // BYRON type requires 4 bytes of protocol magic; provide only 2
    uint8_t data[] = {BYRON, 0x00, 0x01};
    testcase_buffer_read_address_params_fails(data, sizeof(data));
}

// ======================== buffer_read_address_params: staking part truncations ========================

// Helper: build a minimal valid ENTERPRISE_KEY payload up to (and including) the staking type byte,
// then append any extra bytes the caller wants.
static size_t build_enterprise_key_up_to_staking_type(uint8_t* buf, size_t bufSize,
                                                       uint8_t stakingTypeByte,
                                                       const uint8_t* extra, size_t extraLen) {
    const uint32_t payment_path[] = {HD + 1852, HD + 1815, HD + 0, 0, 1};
    const size_t PAYMENT_PATH_LEN = ARRAY_LEN(payment_path);

    size_t offset = 0;
    buf[offset++] = ENTERPRISE_KEY;
    buf[offset++] = 0x01;  // network id
    buf[offset++] = (uint8_t) PAYMENT_PATH_LEN;
    for (size_t i = 0; i < PAYMENT_PATH_LEN; i++) {
        buf[offset++] = (uint8_t) (payment_path[i] >> 24);
        buf[offset++] = (uint8_t) (payment_path[i] >> 16);
        buf[offset++] = (uint8_t) (payment_path[i] >> 8);
        buf[offset++] = (uint8_t) (payment_path[i]);
    }
    buf[offset++] = stakingTypeByte;
    for (size_t i = 0; i < extraLen && offset < bufSize; i++) {
        buf[offset++] = extra[i];
    }
    return offset;
}

static void test_buffer_parse_address_params_truncated_staking_type_byte(void **state) {
    (void) state;
    // Cut off right after payment path — no staking type byte
    const uint32_t payment_path[] = {HD + 1852, HD + 1815, HD + 0, 0, 1};
    const size_t PAYMENT_PATH_LEN = ARRAY_LEN(payment_path);
    uint8_t data[2 + 1 + PAYMENT_PATH_LEN * 4];
    size_t offset = 0;
    data[offset++] = ENTERPRISE_KEY;
    data[offset++] = 0x01;
    data[offset++] = (uint8_t) PAYMENT_PATH_LEN;
    for (size_t i = 0; i < PAYMENT_PATH_LEN; i++) {
        data[offset++] = (uint8_t) (payment_path[i] >> 24);
        data[offset++] = (uint8_t) (payment_path[i] >> 16);
        data[offset++] = (uint8_t) (payment_path[i] >> 8);
        data[offset++] = (uint8_t) (payment_path[i]);
    }
    testcase_buffer_read_address_params_fails(data, offset);
}

static void test_buffer_parse_address_params_truncated_staking_key_path(void **state) {
    (void) state;
    // STAKING_PART_KEY_PATH byte present but no path bytes follow
    uint8_t data[64];
    // Just the staking type byte, nothing after it
    size_t len = build_enterprise_key_up_to_staking_type(data, sizeof(data),
                                                         STAKING_PART_KEY_PATH, NULL, 0);
    testcase_buffer_read_address_params_fails(data, len);
}

static void test_buffer_parse_address_params_truncated_staking_key_hash(void **state) {
    (void) state;
    // STAKING_PART_KEY_HASH byte present but only 4 bytes of the 28-byte hash follow
    uint8_t extra[] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t data[64];
    size_t len = build_enterprise_key_up_to_staking_type(data, sizeof(data),
                                                         STAKING_PART_KEY_HASH,
                                                         extra, sizeof(extra));
    testcase_buffer_read_address_params_fails(data, len);
}

static void test_buffer_parse_address_params_truncated_staking_script_hash(void **state) {
    (void) state;
    // STAKING_PART_SCRIPT_HASH byte present but only 4 bytes of the 28-byte hash follow
    uint8_t extra[] = {0x11, 0x22, 0x33, 0x44};
    uint8_t data[64];
    size_t len = build_enterprise_key_up_to_staking_type(data, sizeof(data),
                                                         STAKING_PART_SCRIPT_HASH,
                                                         extra, sizeof(extra));
    testcase_buffer_read_address_params_fails(data, len);
}

// ======================== Reward address derivation ========================

static void test_derive_reward_key_address(void **state) {
    (void) state;
    // Derive a REWARD_KEY address and verify the result is non-empty
    address_params_t params = {0};
    params.type = REWARD_KEY;
    params.networkId = MAINNET_NETWORK_ID;
    params.paymentPartType = PAYMENT_PART_NONE;
    params.stakingPartType = STAKING_PART_KEY_PATH;
    init_path(&params.stakingKeyPath,
              (uint32_t[]){HD + 1852, HD + 1815, HD + 0, 2, 0},
              5);

    uint8_t out[MAX_ADDRESS_LENGTH];
    size_t outSize = deriveAddress(&params, out, sizeof(out));
    // Reward address = 1 header + 28 hash bytes = 29 bytes
    assert_int_equal(outSize, 29);
}

// ======================== format_reward_account_from_credential: invalid credential type ========================

static void test_format_reward_account_invalid_credential_type(void **state) {
    (void) state;
    ext_credential_t cred = {0};
    cred.type = (ext_credential_type_t) 0xFF;  // invalid type
    char out[200];
    bool result = format_reward_account_from_credential(MAINNET_NETWORK_ID, &cred, out, sizeof(out));
    assert_false(result);
}

// Test blockchain pointer formatting
static void test_format_blockchain_pointer(void **state) {
    (void) state;

    struct {
        blockchainPointer_t pointer;
        const char* expected;
    } testVectors[] = {
        {{0, 0, 0}, "(0, 0, 0)"},
        {{1, 2, 3}, "(1, 2, 3)"},
        {{12345, 67890, 11111}, "(12345, 67890, 11111)"},
        {{UINT32_MAX, UINT32_MAX, UINT32_MAX}, "(4294967295, 4294967295, 4294967295)"},
    };

    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); i++) {
        char tmp[100] = {0};
        bool success = format_blockchain_pointer(testVectors[i].pointer, tmp, sizeof(tmp));
        assert_true(success);
        size_t len = strlen(tmp);
        assert_int_equal(len, strlen(testVectors[i].expected));
        assert_string_equal(tmp, testVectors[i].expected);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_address_derivation),
        cmocka_unit_test(test_buffer_parse_address_params_payment_script_hash),
        cmocka_unit_test(test_buffer_parse_address_params_payment_script_hash_with_pointer),
        cmocka_unit_test(test_buffer_parse_address_params_payment_script_hash_with_stake_path),
        cmocka_unit_test(test_format_blockchain_pointer),

        // isValidAddressParams inconsistent staking type
        cmocka_unit_test(test_invalid_params_base_key_with_blockchain_pointer),
        cmocka_unit_test(test_invalid_params_pointer_key_with_key_hash),
        cmocka_unit_test(test_invalid_params_enterprise_key_with_key_path),
        cmocka_unit_test(test_invalid_params_reward_script_with_key_path),

        // determinePaymentChoice
        cmocka_unit_test(test_determine_payment_choice_reward),

        // isShelleyAddressType
        cmocka_unit_test(test_is_shelley_address_type_invalid),

        // buffer_read_address_params failure tests
        cmocka_unit_test(test_buffer_parse_address_params_empty_buffer),
        cmocka_unit_test(test_buffer_parse_address_params_invalid_type),
        cmocka_unit_test(test_buffer_parse_address_params_truncated_network_id),
        cmocka_unit_test(test_buffer_parse_address_params_invalid_network_id),
        cmocka_unit_test(test_buffer_parse_address_params_truncated_payment_path),
        cmocka_unit_test(test_buffer_parse_address_params_invalid_staking_type),
        cmocka_unit_test(test_buffer_parse_address_params_truncated_pointer_txindex),
        cmocka_unit_test(test_buffer_parse_address_params_truncated_pointer_certindex),
        cmocka_unit_test(test_buffer_parse_address_params_byron_truncated_protocol_magic),
        cmocka_unit_test(test_buffer_parse_address_params_truncated_staking_type_byte),
        cmocka_unit_test(test_buffer_parse_address_params_truncated_staking_key_path),
        cmocka_unit_test(test_buffer_parse_address_params_truncated_staking_key_hash),
        cmocka_unit_test(test_buffer_parse_address_params_truncated_staking_script_hash),

        // reward address derivation
        cmocka_unit_test(test_derive_reward_key_address),

        // format_reward_account_from_credential
        cmocka_unit_test(test_format_reward_account_invalid_credential_type),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
