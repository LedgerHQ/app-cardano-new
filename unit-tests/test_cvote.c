/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "cardano_constants.h"
#include "messageSigning/messageSigning.h"
#include "addressUtils/bip44.h"

#define HD HARDENED_BIP32

static void init_path(bip44_path_t *dst, const uint32_t *elems, size_t len) {
    dst->length = len;
    for (size_t i = 0; i < len; i++) {
        dst->path[i] = elems[i];
    }
}

static const uint8_t CVOTE_PAYLOAD_HASH[CVOTE_REGISTRATION_PAYLOAD_HASH_LENGTH] = {
    0xf5, 0x14, 0x73, 0xdf, 0x86, 0x3b, 0xe3, 0xe0,
    0x38, 0x3c, 0xe5, 0xa8, 0xda, 0x79, 0xc7, 0xff,
    0x51, 0xb3, 0xd9, 0x8d, 0xad, 0xbb, 0xef, 0xbf,
    0x9f, 0x04, 0x2e, 0x86, 0x01, 0x90, 0x12, 0x69,
};

static const uint8_t EXPECTED_CVOTE_SIGNATURE[ED25519_SIGNATURE_LENGTH] = {
    0xcb, 0xc6, 0x15, 0xa8, 0xaa, 0x97, 0x0c, 0xff,
    0xfc, 0x6d, 0x12, 0x22, 0x89, 0xf5, 0x37, 0x91,
    0x09, 0xcd, 0xe5, 0x39, 0x5c, 0xdc, 0x41, 0xc0,
    0xc1, 0x6b, 0x05, 0x32, 0x83, 0xe3, 0xac, 0x84,
    0x4e, 0x77, 0x3d, 0xdc, 0xa9, 0xc7, 0xdf, 0x30,
    0xe2, 0x69, 0x10, 0xdc, 0xac, 0x54, 0xaf, 0xc5,
    0x66, 0x12, 0x6f, 0x42, 0xef, 0xc1, 0x01, 0x50,
    0x38, 0x5f, 0x26, 0x39, 0xfc, 0xaa, 0x61, 0x02,
};

static void test_cvote_signature(void **state) {
    (void) state;

    bip44_path_t path = {0};
    init_path(&path, (uint32_t[]){HD + 1694, HD + 1815, HD + 0, 0, 1}, 5);

    uint8_t signature[ED25519_SIGNATURE_LENGTH] = {0};
    getCVoteRegistrationSignature(
        &path,
        CVOTE_PAYLOAD_HASH,
        sizeof(CVOTE_PAYLOAD_HASH),
        signature,
        sizeof(signature)
    );

    assert_memory_equal(signature, EXPECTED_CVOTE_SIGNATURE, sizeof(signature));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_cvote_signature),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
