/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "addressUtils/bech32.h"
#include "hexUtils.h"

static void test_bech32_empty_prefix(void **state) {
    (void) state;

    // Test with empty input and single character prefix
    const char* hrp = "a";
    uint8_t inputBuffer[1] = {0};
    char outputStr[300] = {0};

    bool formatted = format_bech32(hrp, inputBuffer, 0, outputStr, sizeof(outputStr));
    assert_true(formatted);
    size_t outputLen = strlen(outputStr);
    assert_int_equal(outputLen, strlen("a12uel5l"));
    assert_string_equal(outputStr, "a12uel5l");
}

static void test_bech32_long_prefix(void **state) {
    (void) state;

    // Test with empty input and long human-readable part
    const char* hrp = "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio";
    uint8_t inputBuffer[1] = {0};
    char outputStr[300] = {0};

    bool formatted = format_bech32(hrp, inputBuffer, 0, outputStr, sizeof(outputStr));
    assert_true(formatted);
    size_t outputLen = strlen(outputStr);
    const char* expected = "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs";
    assert_int_equal(outputLen, strlen(expected));
    assert_string_equal(outputStr, expected);
}

static void test_bech32_with_data(void **state) {
    (void) state;

    // Test with actual data payload
    const char* inputHex = "00443214c74254b635cf84653a56d7c675be77df";
    uint8_t inputBuffer[100] = {0};
    size_t inputSize;
    bool success = decode_hex(inputHex, inputBuffer, sizeof(inputBuffer), &inputSize);
    assert_true(success);

    char outputStr[300] = {0};
    bool formatted = format_bech32("abcdef", inputBuffer, inputSize, outputStr, sizeof(outputStr));
    assert_true(formatted);
    size_t outputLen = strlen(outputStr);

    const char* expected = "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw";
    assert_int_equal(outputLen, strlen(expected));
    assert_string_equal(outputStr, expected);
}

static void test_bech32_all_zeros(void **state) {
    (void) state;

    // Test with all zero bytes
    const char* inputHex = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                          "0000000000000";
    uint8_t inputBuffer[100] = {0};
    size_t inputSize;
    bool success = decode_hex(inputHex, inputBuffer, sizeof(inputBuffer), &inputSize);
    assert_true(success);

    char outputStr[300] = {0};
    bool formatted = format_bech32("1", inputBuffer, inputSize, outputStr, sizeof(outputStr));
    assert_true(formatted);
    size_t outputLen = strlen(outputStr);

    const char* expected = "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247"
                          "j";
    assert_int_equal(outputLen, strlen(expected));
    assert_string_equal(outputStr, expected);
}

static void test_bech32_split_example(void **state) {
    (void) state;

    // Test "split" example
    const char* inputHex = "c5f38b70305f519bf66d85fb6cf03058f3dde463ecd7918f2dc743918f2d";
    uint8_t inputBuffer[100] = {0};
    size_t inputSize;
    bool success = decode_hex(inputHex, inputBuffer, sizeof(inputBuffer), &inputSize);
    assert_true(success);

    char outputStr[300] = {0};
    bool formatted = format_bech32("split", inputBuffer, inputSize, outputStr, sizeof(outputStr));
    assert_true(formatted);
    size_t outputLen = strlen(outputStr);

    const char* expected = "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w";
    assert_int_equal(outputLen, strlen(expected));
    assert_string_equal(outputStr, expected);
}

static void test_bech32_cardano_address(void **state) {
    (void) state;

    // Test Cardano address encoding (common stake address format)
    const char* inputHex = "009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d3861e164cab28cb8f0064481"
                          "39c8f1740ffb8e7aa9e5232dc";
    uint8_t inputBuffer[100] = {0};
    size_t inputSize;
    bool success = decode_hex(inputHex, inputBuffer, sizeof(inputBuffer), &inputSize);
    assert_true(success);

    char outputStr[300] = {0};
    bool formatted = format_bech32("addr", inputBuffer, inputSize, outputStr, sizeof(outputStr));
    assert_true(formatted);
    size_t outputLen = strlen(outputStr);

    const char* expected = "addr1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn6"
                          "48jjxtwqcyl47r";
    assert_int_equal(outputLen, strlen(expected));
    assert_string_equal(outputStr, expected);
}

static void test_bech32_large_payload(void **state) {
    (void) state;

    // Test with payload larger than 65 bytes (e.g. 70 bytes)
    // 70 bytes = 140 hex chars
    const char* inputHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                           "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                           "404142434445";
    uint8_t inputBuffer[100] = {0};
    size_t inputSize;
    bool success = decode_hex(inputHex, inputBuffer, sizeof(inputBuffer), &inputSize);
    assert_true(success);
    assert_int_equal(inputSize, 70);

    char outputStr[300] = {0};
    // Should return false with MAX_BECH32_BYTES_LENGTH = 65
    bool formatted = format_bech32("large", inputBuffer, inputSize, outputStr, sizeof(outputStr));
    assert_false(formatted);
}

static void test_bech32_small_buffer(void **state) {
    (void) state;

    const char* hrp = "addr";
    uint8_t inputBuffer[10] = {0};
    // Expected length approx: 4 (hrp) + 1 + ceil(8*10/5)=16 + 6 = 27 chars
    char outputStr[10] = {0}; // Too small

    bool formatted = format_bech32(hrp, inputBuffer, sizeof(inputBuffer), outputStr, sizeof(outputStr));
    assert_false(formatted);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_bech32_empty_prefix),
        cmocka_unit_test(test_bech32_long_prefix),
        cmocka_unit_test(test_bech32_with_data),
        cmocka_unit_test(test_bech32_all_zeros),
        cmocka_unit_test(test_bech32_split_example),
        cmocka_unit_test(test_bech32_cardano_address),
        cmocka_unit_test(test_bech32_large_payload),
        cmocka_unit_test(test_bech32_small_buffer),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
