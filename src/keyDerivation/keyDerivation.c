#include "os_io_seproxyhal.h"
#include <stdint.h>

#include "keyDerivation.h"
#include "cbor.h"
#include "hash.h"
#include "utils.h"
#include "securityPolicy.h"
#include "crypto.h"

static void extractRawPublicKey(uint8_t rawPubkey[static ED25519_PUBKEY_UNCOMPRESSED_LENGTH], uint8_t* outBuffer, size_t outSize) {
    // copy public key little endian to big endian
    ASSERT(outSize == PUBLIC_KEY_LENGTH);

    uint8_t i;
    for (i = 0; i < PUBLIC_KEY_LENGTH; i++) {
        outBuffer[i] = rawPubkey[ED25519_PUBKEY_UNCOMPRESSED_LENGTH - 1 - i];
    }

    if ((rawPubkey[PUBLIC_KEY_LENGTH] & 1) != 0) {
        outBuffer[PUBLIC_KEY_LENGTH - 1] |= 0x80;
    }
}

// pub_key + chain_code
cx_err_t deriveExtendedPublicKey(const bip44_path_t* path, extendedPublicKey_t* out) {
    cx_err_t error = CX_OK;
    uint8_t rawPubkey[ED25519_PUBKEY_UNCOMPRESSED_LENGTH];
    uint8_t chainCode[CHAIN_CODE_LENGTH];

    STATIC_ASSERT(SIZEOF(*out) == CHAIN_CODE_LENGTH + PUBLIC_KEY_LENGTH, "bad ext pub key size");

    // Sanity check
    ASSERT(path->length <= ARRAY_LEN(path->path));

    // if the path is invalid, it's a bug in previous validation
    ASSERT(policyForDerivePrivateKey(path) != POLICY_DENY);

    CX_CHECK(crypto_get_pubkey(path->path, path->length, rawPubkey, chainCode));

    extractRawPublicKey(rawPubkey, out->pubKey, SIZEOF(out->pubKey));

    // Chain code (we copy it second to avoid mid-updates extractRawPublicKey throws
    STATIC_ASSERT(CHAIN_CODE_LENGTH == SIZEOF(out->chainCode), "bad chain code size");
    STATIC_ASSERT(CHAIN_CODE_LENGTH == SIZEOF(chainCode), "bad chain code size");
    memmove(out->chainCode, chainCode, CHAIN_CODE_LENGTH);

end:
    if (error != CX_OK) {
        TRACE("error: %d", error);
    }
    return error;
}

void keyPathToKeyHash(const bip44_path_t* pathSpec, uint8_t* hash, size_t hashSize) {
    ASSERT(hashSize < BUFFER_SIZE_PARANOIA);

    extendedPublicKey_t extPubKey;
    deriveExtendedPublicKey(pathSpec, &extPubKey);

    switch (hashSize) {
        case 28:
            ASSERT(hashSize * 8 == 224);

            blake2b_224_hash(extPubKey.pubKey, SIZEOF(extPubKey.pubKey), hash, hashSize);
            return;

        default:
            ASSERT(false);
    }
}
