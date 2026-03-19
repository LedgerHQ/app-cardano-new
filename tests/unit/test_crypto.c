/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cmocka.h>

#include "crypto.h"
#include "keyDerivation.h"

typedef struct {
    bool saw_privkey_scrub;
    bool privkey_was_nonzero_before_scrub;
    bool saw_sig_scrub;
    bool sig_was_nonzero_before_scrub;
    bool sig_was_zero_after_scrub;
} crypto_scrub_observation_t;

static crypto_scrub_observation_t* g_crypto_scrub_observation = NULL;
static uint8_t* g_expected_signature_ptr = NULL;

try_context_t* current_context = NULL;

try_context_t* try_context_get(void) {
    return current_context;
}

try_context_t* try_context_set(try_context_t* ctx) {
    try_context_t* previous_ctx = current_context;
    current_context = ctx;
    return previous_ctx;
}

cx_err_t os_derive_bip32_no_throw(cx_curve_t curve,
                                  const unsigned int* path,
                                  unsigned int path_len,
                                  unsigned char raw_privkey[static 64],
                                  unsigned char* chain_code) {
    (void) curve;
    (void) path;
    (void) path_len;

    memset(raw_privkey, 0x5A, ED25519_EXTENDED_PRIVKEY_LENGTH);
    if (chain_code != NULL) {
        memset(chain_code, 0xC3, CHAIN_CODE_LENGTH);
    }
    return CX_OK;
}

void explicit_bzero(void* ptr, size_t len) {
    if (g_crypto_scrub_observation != NULL) {
        const uint8_t* bytes = (const uint8_t*) ptr;

        if (len == sizeof(cx_ecfp_256_extended_private_key_t)) {
            g_crypto_scrub_observation->saw_privkey_scrub = true;
            for (size_t i = 0; i < len; i++) {
                if (bytes[i] != 0) {
                    g_crypto_scrub_observation->privkey_was_nonzero_before_scrub = true;
                    break;
                }
            }
        }

        if (ptr == g_expected_signature_ptr && len == ED25519_SIGNATURE_LENGTH) {
            g_crypto_scrub_observation->saw_sig_scrub = true;
            for (size_t i = 0; i < len; i++) {
                if (bytes[i] != 0) {
                    g_crypto_scrub_observation->sig_was_nonzero_before_scrub = true;
                    break;
                }
            }
        }
    }

    memset(ptr, 0, len);

    if (g_crypto_scrub_observation != NULL &&
        ptr == g_expected_signature_ptr &&
        len == ED25519_SIGNATURE_LENGTH) {
        g_crypto_scrub_observation->sig_was_zero_after_scrub = true;
        const uint8_t* bytes = (const uint8_t*) ptr;
        for (size_t i = 0; i < len; i++) {
            if (bytes[i] != 0) {
                g_crypto_scrub_observation->sig_was_zero_after_scrub = false;
                break;
            }
        }
    }
}

void os_perso_derive_node_with_seed_key(unsigned int mode,
                                        cx_curve_t curve,
                                        const unsigned int* path,
                                        unsigned int pathLength,
                                        unsigned char* privateKey,
                                        unsigned char* chain,
                                        unsigned char* seed_key,
                                        unsigned int seed_key_length) {
    (void) mode;
    (void) curve;
    (void) path;
    (void) pathLength;
    (void) seed_key;
    (void) seed_key_length;

    memset(privateKey, 0x5A, ED25519_EXTENDED_PRIVKEY_LENGTH);
    if (chain != NULL) {
        memset(chain, 0xC3, CHAIN_CODE_LENGTH);
    }
}

cx_err_t cx_eddsa_get_public_key_no_throw(const cx_ecfp_private_key_t* pv_key,
                                          cx_md_t hashID,
                                          cx_ecfp_public_key_t* pu_key,
                                          uint8_t* a,
                                          size_t a_len,
                                          uint8_t* h,
                                          size_t h_len) {
    (void) pv_key;
    (void) hashID;
    (void) a;
    (void) a_len;
    (void) h;
    (void) h_len;

    pu_key->W_len = ED25519_PUBKEY_UNCOMPRESSED_LENGTH;
    memset(pu_key->W, 0x42, pu_key->W_len);
    return CX_OK;
}

cx_err_t cx_ecdomain_parameters_length(cx_curve_t cv, size_t* length) {
    (void) cv;
    *length = 32;
    return CX_OK;
}

cx_err_t cx_eddsa_sign_no_throw(const cx_ecfp_private_key_t* pvkey,
                                cx_md_t hashID,
                                const uint8_t* hash,
                                size_t hash_len,
                                uint8_t* sig,
                                size_t sig_len) {
    (void) pvkey;
    (void) hashID;
    (void) hash;
    (void) hash_len;

    memset(sig, 0xA5, sig_len);
    return CX_INTERNAL_ERROR;
}

static void child_crypto_sign_failure_should_abort_after_scrub(void) {
    const uint32_t path[] = {HARDENED_BIP32 + 1852, HARDENED_BIP32 + 1815, HARDENED_BIP32 + 0};
    const uint8_t hash[32] = {0x11};
    uint8_t signature[ED25519_SIGNATURE_LENGTH];

    memset(signature, 0x7C, sizeof(signature));
    g_expected_signature_ptr = signature;

    crypto_eddsa_sign(path, sizeof(path) / sizeof(path[0]), hash, sizeof(hash), signature, sizeof(signature));
}

static void test_crypto_sign_failure_scrubs_private_key_and_signature_before_abort(void** state) {
    (void) state;

    crypto_scrub_observation_t* observation =
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
        g_crypto_scrub_observation = observation;
        child_crypto_sign_failure_should_abort_after_scrub();
        _exit(0);
    }

    int status = 0;
    assert_int_equal(waitpid(child_pid, &status, 0), child_pid);
    assert_true(WIFSIGNALED(status));
    assert_int_equal(WTERMSIG(status), SIGABRT);
    assert_true(observation->saw_privkey_scrub);
    assert_true(observation->privkey_was_nonzero_before_scrub);
    assert_true(observation->saw_sig_scrub);
    assert_true(observation->sig_was_nonzero_before_scrub);
    assert_true(observation->sig_was_zero_after_scrub);

    assert_int_equal(munmap(observation, sizeof(*observation)), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_crypto_sign_failure_scrubs_private_key_and_signature_before_abort),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
