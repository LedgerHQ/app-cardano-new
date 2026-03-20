/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stddef.h>
#include <string.h>

#include "app_context.h"
#include "addressUtilsShelley.h"
#include "aux_data_hash_builder.h"
#include "cardano_constants.h"
#include "cardano_swo.h"
#include "cvote_hash.h"
#include "globals.h"
#include "sign_tx_ctx.h"
#include "io.h"
#include "keyDerivation.h"
#include "messageSigning.h"
#include "tx_utils.h"
#include "utils.h"

static void cvote_extract_pubkey(const cvote_credential_t *credential, uint8_t *out_pubkey, size_t out_pubkey_size) {
    LEDGER_ASSERT(credential != NULL, "NULL credential");
    LEDGER_ASSERT(out_pubkey != NULL, "NULL out_pubkey");
    LEDGER_ASSERT(out_pubkey_size >= PUBLIC_KEY_LENGTH, "Output pubkey buffer too small: %u < %u", (unsigned) out_pubkey_size, PUBLIC_KEY_LENGTH);

    switch (credential->type) {
        case CVOTE_CREDENTIAL_KEY:
            LEDGER_ASSERT(credential->publicKey != NULL, "NULL publicKey");
            memmove(out_pubkey, credential->publicKey, PUBLIC_KEY_LENGTH);
            return;
        case CVOTE_CREDENTIAL_KEY_PATH: {
            extendedPublicKey_t derived_key = {0};
            deriveExtendedPublicKey(&credential->keyPath, &derived_key);
            memmove(out_pubkey, derived_key.pubKey, PUBLIC_KEY_LENGTH);
            explicit_bzero(&derived_key, SIZEOF(derived_key));
            return;
        }
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Invalid CVote credential type %u (only 0=KEY, 2=KEY_PATH allowed)",
                         credential->type);
    }
        // LCOV_EXCL_STOP
}

static void cvote_extract_destination_address(const tx_output_destination_t *destination,
                                              uint8_t *address_buffer,
                                              size_t address_buffer_size,
                                              size_t *out_len) {
    bool parsed = tx_output_destination_to_address_bytes(destination,
                                                         address_buffer,
                                                         address_buffer_size,
                                                         out_len);
    LEDGER_ASSERT(parsed, "CVote destination address conversion failed");
}

void cvote_hash_builder_setup(cvote_aux_data_t *aux_data) {
    LEDGER_ASSERT(aux_data != NULL, "NULL aux_data");

    auxDataHashBuilder_init(&aux_data->hash_builder);
    auxDataHashBuilder_cVoteRegistration_enter(&aux_data->hash_builder, aux_data->format);
    auxDataHashBuilder_cVoteRegistration_enterPayload(&aux_data->hash_builder);
    if (aux_data->format == CIP36 && aux_data->remaining_delegations > 0) {
        auxDataHashBuilder_cVoteRegistration_enterDelegations(&aux_data->hash_builder,
                                                              aux_data->remaining_delegations);
    }
}

static void cvote_hash_builder_add_vote_key(cvote_aux_data_t *aux_data) {
    LEDGER_ASSERT(aux_data != NULL, "NULL aux_data");

    bool should_add_vote_key = false;
    switch (aux_data->format) {
        case CIP15:
            // CIP15: vote key is always included
            should_add_vote_key = true;
            break;
        case CIP36:
            // CIP36: vote key only included if no delegations (not in delegations mode)
            should_add_vote_key = (aux_data->hash_builder.state != AUX_DATA_HASH_BUILDER_IN_CVOTE_REGISTRATION_PAYLOAD_DELEGATIONS);
            break;
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Invalid CVote registration format %u (only CIP15=1, CIP36=2 allowed)",
                         aux_data->format);
    }
        // LCOV_EXCL_STOP

    if (should_add_vote_key) {
        uint8_t pubkey[PUBLIC_KEY_LENGTH] = {0};
        cvote_extract_pubkey(&aux_data->vote_credential, pubkey, sizeof(pubkey));
        auxDataHashBuilder_cVoteRegistration_addVoteKey(&aux_data->hash_builder, pubkey, sizeof(pubkey));
    }
}

static void cvote_hash_builder_add_staking_key(cvote_aux_data_t *aux_data) {
    LEDGER_ASSERT(aux_data != NULL, "NULL aux_data");

    uint8_t pubkey[PUBLIC_KEY_LENGTH] = {0};
    cvote_extract_pubkey(&aux_data->staking_credential, pubkey, sizeof(pubkey));
    auxDataHashBuilder_cVoteRegistration_addStakingKey(&aux_data->hash_builder, pubkey, sizeof(pubkey));
}

static void cvote_hash_builder_add_payment_address(cvote_aux_data_t *aux_data) {
    LEDGER_ASSERT(aux_data != NULL, "NULL aux_data");

    uint8_t address_buffer[MAX_ADDRESS_LENGTH] = {0};
    size_t address_len = 0;
    cvote_extract_destination_address(&aux_data->destination,
                                      address_buffer,
                                      SIZEOF(address_buffer),
                                      &address_len);
    auxDataHashBuilder_cVoteRegistration_addPaymentAddress(&aux_data->hash_builder,
                                                          address_buffer,
                                                          address_len);
}

static void cvote_hash_builder_add_nonce(cvote_aux_data_t *aux_data) {
    LEDGER_ASSERT(aux_data != NULL, "NULL aux_data");

    auxDataHashBuilder_cVoteRegistration_addNonce(&aux_data->hash_builder, aux_data->nonce);
}

static void cvote_hash_builder_add_common_fields(cvote_aux_data_t *aux_data) {
    LEDGER_ASSERT(aux_data != NULL, "NULL aux_data");

    if (aux_data->final_fields_processed) {
        return;
    }

    cvote_hash_builder_add_vote_key(aux_data);
    cvote_hash_builder_add_staking_key(aux_data);
    cvote_hash_builder_add_payment_address(aux_data);
    cvote_hash_builder_add_nonce(aux_data);
    if (aux_data->format == CIP36) {
        auxDataHashBuilder_cVoteRegistration_addVotingPurpose(&aux_data->hash_builder, aux_data->voting_purpose);
    }
    aux_data->final_fields_processed = true;
}

static void cvote_append_registration_signature(cvote_aux_data_t *aux_data) {
    LEDGER_ASSERT(aux_data != NULL, "NULL aux_data");

    // Staking credential must be a key path - validated during parsing and UI policy check
    LEDGER_ASSERT(aux_data->staking_credential.type == CVOTE_CREDENTIAL_KEY_PATH,
                 "CVote staking credential must be KEY_PATH, got type %u",
                 aux_data->staking_credential.type);

    uint8_t payload_hash[CVOTE_REGISTRATION_PAYLOAD_HASH_LENGTH] = {0};
    auxDataHashBuilder_cVoteRegistration_finalizePayload(
        &aux_data->hash_builder,
        payload_hash,
        sizeof(payload_hash));
    TRACE("CVote registration payload hash");
    TRACE_BUFFER(payload_hash, sizeof(payload_hash));

    getCVoteRegistrationSignature(&aux_data->staking_credential.keyPath,
                                  payload_hash,
                                  sizeof(payload_hash),
                                  aux_data->registration_signature,
                                  sizeof(aux_data->registration_signature));
    TRACE("CVote registration signature");
    TRACE_BUFFER(aux_data->registration_signature, sizeof(aux_data->registration_signature));

    auxDataHashBuilder_cVoteRegistration_addSignature(
        &aux_data->hash_builder,
        aux_data->registration_signature,
        sizeof(aux_data->registration_signature));
    auxDataHashBuilder_cVoteRegistration_addAuxiliaryScripts(&aux_data->hash_builder);
}

void cvote_hash_builder_add_delegation(cvote_aux_data_t *aux_data,
                                       const cvote_credential_t *credential,
                                       uint32_t weight) {
    LEDGER_ASSERT(aux_data != NULL, "NULL aux_data");
    LEDGER_ASSERT(credential != NULL, "NULL credential");

    uint8_t pubkey[PUBLIC_KEY_LENGTH] = {0};
    cvote_extract_pubkey(credential, pubkey, sizeof(pubkey));
    auxDataHashBuilder_cVoteRegistration_addDelegation(&aux_data->hash_builder,
                                                      pubkey,
                                                      sizeof(pubkey),
                                                      weight);
}

void cvote_hash_finalize(void) {
    cvote_aux_data_t *aux_data = &tx_aux_data_ctx()->cvote_aux_data;

    if (aux_data->hash_finalized) {
        return;
    }

    cvote_hash_builder_add_common_fields(aux_data);
    cvote_append_registration_signature(aux_data);

    auxDataHashBuilder_finalize(&aux_data->hash_builder,
                                G_context.tx_info.tx_params.auxDataHash,
                                AUX_DATA_HASH_LENGTH);
    aux_data->hash_finalized = true;
}
