/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cmocka.h>

#include "keyDerivation.h"
#include "hexUtils.h"

#define HD HARDENED_BIP32

typedef struct {
    bool saw_ext_pubkey_scrub;
    bool ext_pubkey_was_nonzero_before_scrub;
} key_derivation_scrub_observation_t;

static key_derivation_scrub_observation_t* g_key_derivation_scrub_observation = NULL;

void explicit_bzero(void* ptr, size_t len) {
    if (g_key_derivation_scrub_observation != NULL && len == sizeof(extendedPublicKey_t)) {
        g_key_derivation_scrub_observation->saw_ext_pubkey_scrub = true;

        const uint8_t* bytes = (const uint8_t*) ptr;
        for (size_t i = 0; i < len; i++) {
            if (bytes[i] != 0) {
                g_key_derivation_scrub_observation->ext_pubkey_was_nonzero_before_scrub = true;
                break;
            }
        }
    }

    memset(ptr, 0, len);
}

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

static void child_key_hash_invalid_size_should_abort_after_scrub(void) {
    bip44_path_t bip = {0};
    init_path(&bip, (uint32_t[]){HD + 1852, HD + 1815, HD + 1}, 3);

    uint8_t hash[27] = {0};
    keyPathToKeyHash(&bip, hash, sizeof(hash));
}

static void test_key_hash_invalid_size_scrubs_extended_pubkey_before_abort(void** state) {
    (void) state;

    key_derivation_scrub_observation_t* observation =
        mmap(NULL,
             sizeof(*observation),
             PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_ANONYMOUS,
             -1,
             0);
    assert_true(observation != MAP_FAILED);
    memset(observation, 0, sizeof(*observation));

    pid_t child_pid = fork();
    assert_true(child_pid >= 0);

    if (child_pid == 0) {
        g_key_derivation_scrub_observation = observation;
        child_key_hash_invalid_size_should_abort_after_scrub();
        _exit(0);
    }

    int status = 0;
    assert_int_equal(waitpid(child_pid, &status, 0), child_pid);
    assert_true(WIFSIGNALED(status));
    assert_int_equal(WTERMSIG(status), SIGABRT);
    assert_true(observation->saw_ext_pubkey_scrub);
    assert_true(observation->ext_pubkey_was_nonzero_before_scrub);

    assert_int_equal(munmap(observation, sizeof(*observation)), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_byron_accounts),
        cmocka_unit_test(test_shelley_accounts),
        cmocka_unit_test(test_pool_cold_key),
        cmocka_unit_test(test_key_hash_invalid_size_scrubs_extended_pubkey_before_abort),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
