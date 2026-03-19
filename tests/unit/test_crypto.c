/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
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

static crypto_scrub_observation_t g_crypto_scrub_observation = {0};
static uint8_t* g_expected_signature_ptr = NULL;

static cx_err_t g_os_derive_result = CX_OK;
static cx_err_t g_pubkey_result = CX_OK;
static unsigned int g_mock_pubkey_length = ED25519_PUBKEY_UNCOMPRESSED_LENGTH;
static cx_err_t g_ecdomain_parameters_length_result = CX_OK;
static size_t g_mock_domain_length = 32;
static cx_err_t g_sign_result = CX_OK;

static bool g_expect_abort = false;
static jmp_buf g_abort_jmp_buf;

try_context_t* current_context = NULL;

static void reset_crypto_test_state(void) {
    memset(&g_crypto_scrub_observation, 0, sizeof(g_crypto_scrub_observation));
    g_expected_signature_ptr = NULL;
    g_os_derive_result = CX_OK;
    g_pubkey_result = CX_OK;
    g_mock_pubkey_length = ED25519_PUBKEY_UNCOMPRESSED_LENGTH;
    g_ecdomain_parameters_length_result = CX_OK;
    g_mock_domain_length = 32;
    g_sign_result = CX_OK;
    g_expect_abort = false;
}

static void assert_all_bytes_equal(const uint8_t* buffer, size_t buffer_size, uint8_t expected_value) {
    for (size_t i = 0; i < buffer_size; i++) {
        assert_int_equal(buffer[i], expected_value);
    }
}

static void assert_all_bytes_zero(const uint8_t* buffer, size_t buffer_size) {
    assert_all_bytes_equal(buffer, buffer_size, 0);
}

try_context_t* try_context_get(void) {
    return current_context;
}

try_context_t* try_context_set(try_context_t* ctx) {
    try_context_t* previous_ctx = current_context;
    current_context = ctx;
    return previous_ctx;
}

__attribute__((noreturn)) void abort(void) {
    if (g_expect_abort) {
        g_expect_abort = false;
        longjmp(g_abort_jmp_buf, 1);
    }

    raise(SIGABRT);
    _exit(128 + SIGABRT);
}

cx_err_t os_derive_bip32_no_throw(cx_curve_t curve,
                                  const unsigned int* path,
                                  unsigned int path_len,
                                  unsigned char raw_privkey[static 64],
                                  unsigned char* chain_code) {
    (void) curve;
    (void) path;
    (void) path_len;

    if (g_os_derive_result != CX_OK) {
        return g_os_derive_result;
    }

    memset(raw_privkey, 0x5A, ED25519_EXTENDED_PRIVKEY_LENGTH);
    if (chain_code != NULL) {
        memset(chain_code, 0xC3, CHAIN_CODE_LENGTH);
    }
    return CX_OK;
}

void explicit_bzero(void* ptr, size_t len) {
    if (len == sizeof(cx_ecfp_256_extended_private_key_t)) {
        const uint8_t* bytes = (const uint8_t*) ptr;

        g_crypto_scrub_observation.saw_privkey_scrub = true;
        for (size_t i = 0; i < len; i++) {
            if (bytes[i] != 0) {
                g_crypto_scrub_observation.privkey_was_nonzero_before_scrub = true;
                break;
            }
        }
    }

    if (ptr == g_expected_signature_ptr && len == ED25519_SIGNATURE_LENGTH) {
        const uint8_t* bytes = (const uint8_t*) ptr;

        g_crypto_scrub_observation.saw_sig_scrub = true;
        for (size_t i = 0; i < len; i++) {
            if (bytes[i] != 0) {
                g_crypto_scrub_observation.sig_was_nonzero_before_scrub = true;
                break;
            }
        }
    }

    memset(ptr, 0, len);

    if (ptr == g_expected_signature_ptr && len == ED25519_SIGNATURE_LENGTH) {
        g_crypto_scrub_observation.sig_was_zero_after_scrub = true;
        const uint8_t* bytes = (const uint8_t*) ptr;
        for (size_t i = 0; i < len; i++) {
            if (bytes[i] != 0) {
                g_crypto_scrub_observation.sig_was_zero_after_scrub = false;
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

    if (g_pubkey_result != CX_OK) {
        return g_pubkey_result;
    }

    pu_key->W_len = g_mock_pubkey_length;
    memset(pu_key->W, 0x42, pu_key->W_len);
    return CX_OK;
}

cx_err_t cx_ecdomain_parameters_length(cx_curve_t cv, size_t* length) {
    (void) cv;

    if (g_ecdomain_parameters_length_result != CX_OK) {
        return g_ecdomain_parameters_length_result;
    }

    *length = g_mock_domain_length;
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
    return g_sign_result;
}

static void test_crypto_get_pubkey_success(void** state) {
    (void) state;
    reset_crypto_test_state();

    const uint32_t path[] = {HARDENED_BIP32 + 1852, HARDENED_BIP32 + 1815, HARDENED_BIP32 + 0};
    uint8_t pubkey[ED25519_PUBKEY_UNCOMPRESSED_LENGTH] = {0};
    uint8_t chain_code[CHAIN_CODE_LENGTH] = {0};

    crypto_get_pubkey(path, sizeof(path) / sizeof(path[0]), pubkey, chain_code);

    assert_all_bytes_equal(pubkey, sizeof(pubkey), 0x42);
    assert_all_bytes_equal(chain_code, sizeof(chain_code), 0xC3);
}

static void test_crypto_get_pubkey_invalid_length_scrubs_output_before_assert(void** state) {
    (void) state;
    reset_crypto_test_state();

    const uint32_t path[] = {HARDENED_BIP32 + 1852, HARDENED_BIP32 + 1815, HARDENED_BIP32 + 0};
    uint8_t pubkey[ED25519_PUBKEY_UNCOMPRESSED_LENGTH];
    uint8_t chain_code[CHAIN_CODE_LENGTH] = {0};

    memset(pubkey, 0x7C, sizeof(pubkey));
    g_mock_pubkey_length = ED25519_PUBKEY_UNCOMPRESSED_LENGTH - 1;

    if (setjmp(g_abort_jmp_buf) == 0) {
        g_expect_abort = true;
        crypto_get_pubkey(path, sizeof(path) / sizeof(path[0]), pubkey, chain_code);
        fail();
    }

    assert_all_bytes_zero(pubkey, sizeof(pubkey));
    assert_true(g_crypto_scrub_observation.saw_privkey_scrub);
    assert_true(g_crypto_scrub_observation.privkey_was_nonzero_before_scrub);
}

static void test_crypto_get_pubkey_derivation_failure_scrubs_output_before_assert(void** state) {
    (void) state;
    reset_crypto_test_state();

    const uint32_t path[] = {HARDENED_BIP32 + 1852, HARDENED_BIP32 + 1815, HARDENED_BIP32 + 0};
    uint8_t pubkey[ED25519_PUBKEY_UNCOMPRESSED_LENGTH];
    uint8_t chain_code[CHAIN_CODE_LENGTH] = {0};

    memset(pubkey, 0x7C, sizeof(pubkey));
    g_os_derive_result = CX_INTERNAL_ERROR;

    if (setjmp(g_abort_jmp_buf) == 0) {
        g_expect_abort = true;
        crypto_get_pubkey(path, sizeof(path) / sizeof(path[0]), pubkey, chain_code);
        fail();
    }

    assert_all_bytes_zero(pubkey, sizeof(pubkey));
}

static void test_crypto_sign_success(void** state) {
    (void) state;
    reset_crypto_test_state();

    const uint32_t path[] = {HARDENED_BIP32 + 1852, HARDENED_BIP32 + 1815, HARDENED_BIP32 + 0};
    const uint8_t hash[32] = {0x11};
    uint8_t signature[ED25519_SIGNATURE_LENGTH] = {0};

    crypto_eddsa_sign(path, sizeof(path) / sizeof(path[0]), hash, sizeof(hash), signature, sizeof(signature));

    assert_all_bytes_equal(signature, sizeof(signature), 0xA5);
}

static void test_crypto_sign_failure_scrubs_private_key_and_signature_before_assert(void** state) {
    (void) state;
    reset_crypto_test_state();

    const uint32_t path[] = {HARDENED_BIP32 + 1852, HARDENED_BIP32 + 1815, HARDENED_BIP32 + 0};
    const uint8_t hash[32] = {0x11};
    uint8_t signature[ED25519_SIGNATURE_LENGTH];

    memset(signature, 0x7C, sizeof(signature));
    g_expected_signature_ptr = signature;
    g_sign_result = CX_INTERNAL_ERROR;

    if (setjmp(g_abort_jmp_buf) == 0) {
        g_expect_abort = true;
        crypto_eddsa_sign(path, sizeof(path) / sizeof(path[0]), hash, sizeof(hash), signature, sizeof(signature));
        fail();
    }

    assert_true(g_crypto_scrub_observation.saw_privkey_scrub);
    assert_true(g_crypto_scrub_observation.privkey_was_nonzero_before_scrub);
    assert_true(g_crypto_scrub_observation.saw_sig_scrub);
    assert_true(g_crypto_scrub_observation.sig_was_nonzero_before_scrub);
    assert_true(g_crypto_scrub_observation.sig_was_zero_after_scrub);
}

static void test_crypto_sign_derivation_failure_scrubs_signature_before_assert(void** state) {
    (void) state;
    reset_crypto_test_state();

    const uint32_t path[] = {HARDENED_BIP32 + 1852, HARDENED_BIP32 + 1815, HARDENED_BIP32 + 0};
    const uint8_t hash[32] = {0x11};
    uint8_t signature[ED25519_SIGNATURE_LENGTH];

    memset(signature, 0x7C, sizeof(signature));
    g_expected_signature_ptr = signature;
    g_os_derive_result = CX_INTERNAL_ERROR;

    if (setjmp(g_abort_jmp_buf) == 0) {
        g_expect_abort = true;
        crypto_eddsa_sign(path, sizeof(path) / sizeof(path[0]), hash, sizeof(hash), signature, sizeof(signature));
        fail();
    }

    assert_true(g_crypto_scrub_observation.saw_sig_scrub);
    assert_true(g_crypto_scrub_observation.sig_was_nonzero_before_scrub);
    assert_true(g_crypto_scrub_observation.sig_was_zero_after_scrub);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_crypto_get_pubkey_success),
        cmocka_unit_test(test_crypto_get_pubkey_invalid_length_scrubs_output_before_assert),
        cmocka_unit_test(test_crypto_get_pubkey_derivation_failure_scrubs_output_before_assert),
        cmocka_unit_test(test_crypto_sign_success),
        cmocka_unit_test(test_crypto_sign_failure_scrubs_private_key_and_signature_before_assert),
        cmocka_unit_test(test_crypto_sign_derivation_failure_scrubs_signature_before_assert),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
