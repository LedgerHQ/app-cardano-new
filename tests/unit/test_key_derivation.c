/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "keyDerivation.h"
#include "hexUtils.h"

#define HD HARDENED_BIP32

static void init_path(bip44_path_t* dst, const uint32_t* elems, size_t len) {
    dst->length = len;
    for (size_t i = 0; i < len; i++) {
        dst->path[i] = elems[i];
    }
}

static void expect_extended_pubkey(const uint32_t* path,
                                   size_t path_len,
                                   const char* expected_hex) {
    bip44_path_t bip = {0};
    init_path(&bip, path, path_len);

    extendedPublicKey_t ext = {0};
    deriveExtendedPublicKey(&bip, &ext);

    uint8_t expected[PUBLIC_KEY_LENGTH] = {0};
    size_t decodedLen = 0;
    assert_true(decode_hex(expected_hex, expected, sizeof(expected), &decodedLen));
    assert_int_equal(decodedLen, sizeof(expected));
    assert_memory_equal(ext.pubKey, expected, sizeof(expected));
}

static void test_byron_accounts(void** state) {
    (void) state;

    expect_extended_pubkey((uint32_t[]){HD + 44, HD + 1815, HD + 1}, 3,
                           "eb6e933ce45516ac7b0e023de700efae5e212ccc6bf0fcb33ba9243b9d832827");

}

static void test_shelley_accounts(void** state) {
    (void) state;

    expect_extended_pubkey((uint32_t[]){HD + 1852, HD + 1815, HD + 1}, 3,
                           "c9d624c493e269271980bc5e89bcd913719137f3b20c11339f28875951124c82");
}

static void test_pool_cold_key(void** state) {
    (void) state;

    expect_extended_pubkey((uint32_t[]){HD + 1853, HD + 1815, HD + 0, HD + 2}, 4,
                           "0f38ab7679e756ca11924f12e745d154ffbac01bc0f7bf05ba7f658c3a28b0cb");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_byron_accounts),
        cmocka_unit_test(test_shelley_accounts),
        cmocka_unit_test(test_pool_cold_key),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
