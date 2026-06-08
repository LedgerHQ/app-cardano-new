/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "cx.h"

#include "messageSigning.h"
#include "bip44.h"
#include "securityPolicy.h"
#include "crypto.h"

void signRawMessageWithPath(const bip44_path_t *path,
                            const uint8_t *messageBuffer,
                            size_t messageSize,
                            uint8_t *outBuffer,
                            size_t outSize) {
    ASSERT(messageSize < BUFFER_SIZE_PARANOIA);
    ASSERT(outSize == ED25519_SIGNATURE_LENGTH);

    // Sanity check
    ASSERT(path->length <= ARRAY_LEN(path->path));

    // if the path is invalid, it's a bug in previous validation
    LEDGER_ASSERT(policyForDerivePrivateKey(path) != POLICY_DENY,
                  "Signing denied by private key derivation policy");

    TRACE("signing with path:");
    BIP44_PRINTF(path);
    TRACE("");

    crypto_eddsa_sign(path->path, path->length, messageBuffer, messageSize, outBuffer, outSize);
}

// sign the given hash by the private key derived according to the given path
void getWitness(const bip44_path_t *path,
                const uint8_t *hashBuffer,
                size_t hashSize,
                uint8_t *outBuffer,
                size_t outSize) {
    ASSERT(outSize < BUFFER_SIZE_PARANOIA);
    ASSERT(outSize == ED25519_SIGNATURE_LENGTH);

    signRawMessageWithPath(path, hashBuffer, hashSize, outBuffer, outSize);
}

void getCVoteRegistrationSignature(const bip44_path_t *path,
                                   const uint8_t *payloadHashBuffer,
                                   size_t payloadHashSize,
                                   uint8_t *outBuffer,
                                   size_t outSize) {
    ASSERT(payloadHashSize == CVOTE_REGISTRATION_PAYLOAD_HASH_LENGTH);
    ASSERT(outSize < BUFFER_SIZE_PARANOIA);
    ASSERT(outSize == ED25519_SIGNATURE_LENGTH);
    LEDGER_ASSERT(bip44_isOrdinaryStakingKeyPath(path),
                  "CVote registration signature requires an ordinary staking key path");

    signRawMessageWithPath(path, payloadHashBuffer, payloadHashSize, outBuffer, outSize);
}
