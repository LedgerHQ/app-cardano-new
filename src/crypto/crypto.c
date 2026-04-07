/* SPDX-FileCopyrightText: 2016-2025 Ledger */
/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>   // uint*_t
#include <string.h>   // explicit_bzero
#include <stdbool.h>  // bool

#include "cardano_constants.h"
#include "assert.h"
#include "cx.h"
#include "os.h"

static cx_err_t crypto_init_privkey(const uint32_t* path,
                                    size_t path_len,
                                    cx_ecfp_256_extended_private_key_t* privkey,
                                    uint8_t* chain_code) {
    cx_err_t error = CX_OK;
    uint8_t raw_privkey[ED25519_EXTENDED_PRIVKEY_LENGTH];

    // Derive private key according to BIP32 path
    CX_CHECK(os_derive_bip32_no_throw(CX_CURVE_Ed25519, path, path_len, raw_privkey, chain_code));

    // Init privkey from raw
    // Do not use cx_ecfp_init_private_key_no_throw as it doesn't
    // support 64 bytes for CX_CURVE_Ed25519 curve
    privkey->curve = CX_CURVE_Ed25519;
    privkey->d_len = sizeof(privkey->d);
    memmove(privkey->d, raw_privkey, sizeof(privkey->d));

end:
    explicit_bzero(raw_privkey, sizeof(raw_privkey));

    // CX_CHECK above would set the value of `error` in case of error
    if (error != CX_OK) {
        // Make sure the caller doesn't use uninitialized data in case
        // the return code is not checked.
        explicit_bzero(privkey, sizeof(cx_ecfp_256_extended_private_key_t));
    }
    return error;
}

void crypto_get_pubkey(const uint32_t* path,
                       size_t path_len,
                       uint8_t raw_pubkey[static ED25519_PUBKEY_UNCOMPRESSED_LENGTH],
                       uint8_t* chain_code) {
    cx_ecfp_256_extended_private_key_t privkey = {0};
    cx_ecfp_256_public_key_t pubkey = {0};
    cx_err_t error = CX_OK;

    // Derive private key according to BIP32 path
    CX_CHECK(crypto_init_privkey(path, path_len, &privkey, chain_code));

    // Generate associated pubkey
    // Do not use cx_ecfp_generate_pair2_no_throw as it doesn't
    // support 64 bytes for CX_CURVE_Ed25519 curve
    CX_CHECK(cx_eddsa_get_public_key_no_throw((const struct cx_ecfp_256_private_key_s*) &privkey,
                                              CX_SHA512,
                                              &pubkey,
                                              NULL,
                                              0,
                                              NULL,
                                              0));

    // Check pubkey length then copy it to raw_pubkey
    if (pubkey.W_len != ED25519_PUBKEY_UNCOMPRESSED_LENGTH) {
        error = CX_EC_INVALID_CURVE;
        goto end;
    }
    memmove(raw_pubkey, pubkey.W, pubkey.W_len);

end:
    explicit_bzero(&privkey, sizeof(privkey));

    // CX_CHECK above would set the value of `error` in case of error
    if (error != CX_OK) {
        // Make sure the caller doesn't use uninitialized data if the operation failed.
        explicit_bzero(raw_pubkey, ED25519_PUBKEY_UNCOMPRESSED_LENGTH);
        LEDGER_ASSERT(!error, "crypto_eddsa_sign failed with error 0x%X", error);
    }
}

static void crypto_eddsa_sign_impl(const uint32_t* path,
                                   size_t path_len,
                                   const uint8_t* hash,
                                   size_t hash_len,
                                   uint8_t* sig,
                                   size_t expected_sig_len) {
    ASSERT(path != NULL);
    LEDGER_ASSERT(path_len > 0, "path is empty");
    ASSERT(hash != NULL);
    LEDGER_ASSERT(hash_len > 0, "hash_len is zero");
    ASSERT(sig != NULL);
    LEDGER_ASSERT(expected_sig_len == ED25519_SIGNATURE_LENGTH,
                  "expected_sig_len must equal ED25519_SIGNATURE_LENGTH");

    cx_ecfp_256_extended_private_key_t privkey = {0};
    cx_err_t error = CX_OK;

    {
        // Verify the signature length matches what we expected
        size_t size;
        CX_CHECK(cx_ecdomain_parameters_length(CX_CURVE_Ed25519, &size));
        size_t computed_sig_len = size * 2;
        LEDGER_ASSERT(computed_sig_len == expected_sig_len, "unexpected signature length");
    }

    // Derive private key according to BIP32 path
    CX_CHECK(crypto_init_privkey(path, path_len, &privkey, NULL));

    CX_CHECK(cx_eddsa_sign_no_throw((const struct cx_ecfp_256_private_key_s*) &privkey,
                                    CX_SHA512,
                                    hash,
                                    hash_len,
                                    sig,
                                    expected_sig_len));

end:
    explicit_bzero(&privkey, sizeof(privkey));

    // CX_CHECK above would set the value of `error` in case of error
    if (error != CX_OK) {
        // wipe possibly modified sig buffer, unsafe to let anyone read it
        explicit_bzero(sig, expected_sig_len);
        LEDGER_ASSERT(!error, "crypto_eddsa_sign failed with error 0x%X", error);
    }
}

void crypto_eddsa_sign(const uint32_t* path,
                       size_t path_len,
                       const uint8_t* hash,
                       size_t hash_len,
                       uint8_t* sig,
                       size_t expected_sig_len) {
    crypto_eddsa_sign_impl(path, path_len, hash, hash_len, sig, expected_sig_len);
}
