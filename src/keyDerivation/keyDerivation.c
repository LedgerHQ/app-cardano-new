/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "os_io_seproxyhal.h"
#include <stdint.h>
#include <string.h>  // explicit_bzero

#include "keyDerivation.h"
#include "cbor.h"
#include "hash.h"
#include "utils.h"
#include "securityPolicy.h"
#include "crypto.h"

static void extractRawPublicKey(uint8_t rawPubkey[static ED25519_PUBKEY_UNCOMPRESSED_LENGTH], uint8_t* outBuffer, size_t outSize) {
    // copy public key little endian to big endian
    ASSERT(outSize == PUBLIC_KEY_LENGTH);
    STATIC_ASSERT(PUBLIC_KEY_LENGTH < ED25519_PUBKEY_UNCOMPRESSED_LENGTH,
                  "public key length must fit uncompressed key");

    uint8_t i;
    for (i = 0; i < PUBLIC_KEY_LENGTH; i++) {
        outBuffer[i] = rawPubkey[ED25519_PUBKEY_UNCOMPRESSED_LENGTH - 1 - i];
    }

    if ((rawPubkey[PUBLIC_KEY_LENGTH] & 1) != 0) {
        outBuffer[PUBLIC_KEY_LENGTH - 1] |= 0x80;
    }
}

// pub_key + chain_code
// This function either succeeds or crashes the app (via CX_ASSERT).
// Crypto failures are unrecoverable and indicate broken device, buggy crypto, or wrong usage.
void deriveExtendedPublicKey(const bip44_path_t* path, extendedPublicKey_t* out) {
    uint8_t rawPubkey[ED25519_PUBKEY_UNCOMPRESSED_LENGTH] = {0};
    uint8_t chainCode[CHAIN_CODE_LENGTH] = {0};

    STATIC_ASSERT(SIZEOF(*out) == CHAIN_CODE_LENGTH + PUBLIC_KEY_LENGTH, "bad ext pub key size");

    // Sanity check
    LEDGER_ASSERT(path->length <= ARRAY_LEN(path->path), "BIP44 path length out of bounds");

    // if the path is invalid, it's a bug in previous validation
    LEDGER_ASSERT(policyForDerivePrivateKey(path) != POLICY_DENY,
                  "Private key derivation denied by security policy");

    crypto_get_pubkey(path->path, path->length, rawPubkey, chainCode);

    extractRawPublicKey(rawPubkey, out->pubKey, SIZEOF(out->pubKey));

    // Chain code (we copy it second to avoid mid-updates extractRawPublicKey throws
    STATIC_ASSERT(CHAIN_CODE_LENGTH == SIZEOF(out->chainCode), "bad chain code size");
    STATIC_ASSERT(CHAIN_CODE_LENGTH == SIZEOF(chainCode), "bad chain code size");
    memmove(out->chainCode, chainCode, CHAIN_CODE_LENGTH);

    explicit_bzero(rawPubkey, SIZEOF(rawPubkey));
    explicit_bzero(chainCode, SIZEOF(chainCode));
}

void keyPathToKeyHash(const bip44_path_t* pathSpec, uint8_t* hash, size_t hashSize) {
    ASSERT(hashSize < BUFFER_SIZE_PARANOIA);

    extendedPublicKey_t extPubKey = {0};
    deriveExtendedPublicKey(pathSpec, &extPubKey);

    switch (hashSize) {
        case 28:
            ASSERT(hashSize * 8 == 224);
            blake2b_224_hash(extPubKey.pubKey, SIZEOF(extPubKey.pubKey), hash, hashSize);
            explicit_bzero(&extPubKey, SIZEOF(extPubKey));
            return;

        default:
            explicit_bzero(&extPubKey, SIZEOF(extPubKey));
            ASSERT(false);
    }
}
