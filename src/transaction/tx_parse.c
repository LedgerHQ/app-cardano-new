/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "buffer.h"

#include "cardano_swo.h"
#include "cardano_buffer.h"
#include "cbor.h"
#include "tx_parse.h"
#include "tx_processing.h"
#include "cardano_parsers.h"
#include "tx.h"
#include "utils.h"
#include "assert.h"
#include "tx_constants.h"
#include "keyDerivation.h"
#include "globals.h"
#include "sign_tx_ctx.h"
#include "io.h"

#include <string.h>

// ---------------------------------------------------------------------------
// Mode validator
// ---------------------------------------------------------------------------

void validate_parse_tx_mode(const tx_processing_mode_t *mode) {
    LEDGER_ASSERT(mode != NULL, "NULL mode");

    LEDGER_ASSERT(!mode->run_ui_rendering || !mode->run_hash_builder,
                  "run_ui_rendering implies !run_hash_builder");
    LEDGER_ASSERT(!mode->run_hash_builder || mode->run_validation,
                  "run_hash_builder implies run_validation");
    LEDGER_ASSERT(!mode->run_ui_planning || mode->run_validation,
                  "run_ui_planning implies run_validation");
}

// ---------------------------------------------------------------------------
// Context helpers
// ---------------------------------------------------------------------------

void tx_processing_state_init(const tx_processing_mode_t *mode, warning_bits_t *warning_bits) {
    validate_parse_tx_mode(mode);
    LEDGER_ASSERT(warning_bits != NULL, "NULL warning_bits");

    tx_processing_state_t *state = &tx_body_ctx()->processing_state;
    explicit_bzero(state, sizeof(*state));

    tx_body_ctx()->parse_mode = *mode;
    state->mode = &tx_body_ctx()->parse_mode;
    state->warning_bits = warning_bits;

    if (mode->run_hash_builder) {
        txHashBuilder_init(&state->hash_builder, &G_context.tx_info.tx_params);
        state->hash_builder_initialized = true;
    }
}

tx_processing_ctx_t tx_get_ctx(void) {
    tx_processing_state_t *state = &tx_body_ctx()->processing_state;
    LEDGER_ASSERT(state->mode != NULL, "tx_processing_state not initialized");
    LEDGER_ASSERT(state->warning_bits != NULL, "tx_processing_state not initialized (warnings)");
    validate_parse_tx_mode(state->mode);

    return (tx_processing_ctx_t){
        .tx_params    = &G_context.tx_info.tx_params,
        .mode         = state->mode,
        .warning_bits = state->warning_bits,
        .hash_builder = &state->hash_builder,
    };
}

void tx_handle_parse_error(uint16_t swo) {
    TRACE("tx_handle_parse_error swo=0x%04x", swo);
    send_swo_and_reset(swo);
}

// ---------------------------------------------------------------------------
// Parse-item helpers
// ---------------------------------------------------------------------------

bool parse_input(buffer_t *buf, tx_input_t *out_input) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(out_input != NULL, "NULL out_input");

    if (!buffer_read_bytes_ptr(buf, &out_input->txHash, TX_HASH_LENGTH)) {
        TRACE("Failed to read input txHash");
        return false;
    }
    ASSERT(out_input->txHash != NULL);

    ASSERT_TYPE(out_input->index, uint32_t);
    if (!buffer_read_u32(buf, &out_input->index, BE)) {
        TRACE("Failed to read input index");
        return false;
    }
    return true;
}

bool parse_required_signer(buffer_t *buf, required_signer_t *out_required_signer) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(out_required_signer != NULL, "NULL out_required_signer");

    uint8_t signer_type = 0;
    if (!buffer_read_u8(buf, &signer_type)) {
        TRACE("Failed to read required signer type");
        return false;
    }
    out_required_signer->type = (required_signer_type_t) signer_type;

    switch (out_required_signer->type) {
        case REQUIRED_SIGNER_WITH_PATH:
            if (!buffer_read_bip44_path(buf, &out_required_signer->keyPath)) {
                TRACE("Failed to read required signer path");
                return false;
            }
            break;
        case REQUIRED_SIGNER_WITH_HASH:
            if (!buffer_read_bytes_ptr(buf,
                                       &out_required_signer->keyHash,
                                       ADDRESS_KEY_HASH_LENGTH)) {
                TRACE("Failed to read required signer key hash");
                return false;
            }
            ASSERT(out_required_signer->keyHash != NULL);
            break;
        default:
            TRACE("Unknown required signer type: %u", (unsigned) signer_type);
            return false;
    }

    return true;
}

bool parse_voter_votes_header(buffer_t *buf,
                              ext_voter_t *out_voter,
                              uint16_t *out_num_votes) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(out_voter != NULL, "NULL out_voter");
    LEDGER_ASSERT(out_num_votes != NULL, "NULL out_num_votes");

    explicit_bzero(out_voter, sizeof(*out_voter));

    uint8_t voter_type_byte = 0;
    if (!buffer_read_u8(buf, &voter_type_byte)) {
        TRACE("Failed to read voter type");
        return false;
    }
    out_voter->type = (ext_voter_type_t) voter_type_byte;

    switch (out_voter->type) {
        case EXT_VOTER_COMMITTEE_HOT_KEY_PATH:
        case EXT_VOTER_DREP_KEY_PATH:
        case EXT_VOTER_STAKE_POOL_KEY_PATH:
            if (!buffer_read_bip44_path(buf, &out_voter->keyPath)) {
                TRACE("Failed to read voter path");
                return false;
            }
            break;
        case EXT_VOTER_COMMITTEE_HOT_KEY_HASH:
        case EXT_VOTER_DREP_KEY_HASH:
        case EXT_VOTER_STAKE_POOL_KEY_HASH:
            if (!buffer_read_bytes_ptr(buf, &out_voter->keyHash, ADDRESS_KEY_HASH_LENGTH)) {
                TRACE("Failed to read voter key hash");
                return false;
            }
            ASSERT(out_voter->keyHash != NULL);
            break;
        case EXT_VOTER_COMMITTEE_HOT_SCRIPT_HASH:
        case EXT_VOTER_DREP_SCRIPT_HASH:
            if (!buffer_read_bytes_ptr(buf, &out_voter->scriptHash, SCRIPT_HASH_LENGTH)) {
                TRACE("Failed to read voter script hash");
                return false;
            }
            ASSERT(out_voter->scriptHash != NULL);
            break;
        default:
            TRACE("Unknown voter type: %u", (unsigned) voter_type_byte);
            return false;
    }

    ASSERT_TYPE(*out_num_votes, uint16_t);
    if (!buffer_read_u16(buf, out_num_votes, BE)) {
        TRACE("Failed to read number of votes");
        return false;
    }

    return true;
}

bool parse_vote(buffer_t *buf, vote_item_t *out_vote_item) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(out_vote_item != NULL, "NULL out_vote_item");

    explicit_bzero(out_vote_item, sizeof(*out_vote_item));

    if (!buffer_read_bytes_ptr(buf, &out_vote_item->govActionId.txHash, TX_HASH_LENGTH)) {
        TRACE("Failed to read gov action tx hash");
        return false;
    }
    ASSERT(out_vote_item->govActionId.txHash != NULL);

    ASSERT_TYPE(out_vote_item->govActionId.govActionIndex, uint32_t);
    if (!buffer_read_u32(buf, &out_vote_item->govActionId.govActionIndex, BE)) {
        TRACE("Failed to read gov action index");
        return false;
    }

    uint8_t vote_byte = 0;
    if (!buffer_read_u8(buf, &vote_byte)) {
        TRACE("Failed to read vote option");
        return false;
    }
    switch (vote_byte) {
        case VOTE_NO:
        case VOTE_YES:
        case VOTE_ABSTAIN:
            out_vote_item->voteOption = (vote_t) vote_byte;
            break;
        default:
            TRACE("Unknown vote option: %u", (unsigned) vote_byte);
            return false;
    }

    if (!buffer_read_anchor(buf, &out_vote_item->anchor)) {
        TRACE("Failed to read vote anchor");
        return false;
    }

    return true;
}

bool parse_withdrawal(buffer_t *buf, withdrawal_t *out_withdrawal) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(out_withdrawal != NULL, "NULL out_withdrawal");

    ASSERT_TYPE(out_withdrawal->amount, uint64_t);
    if (!buffer_read_u64(buf, &out_withdrawal->amount, BE)) {
        TRACE("Failed to read withdrawal amount");
        return false;
    }
    if (out_withdrawal->amount >= LOVELACE_MAX_SUPPLY) {
        TRACE("Withdrawal amount too large: %llu", (unsigned long long) out_withdrawal->amount);
        return false;
    }

    if (!buffer_read_credential(buf, &out_withdrawal->stakeCredential)) {
        TRACE("Failed to read withdrawal credential");
        return false;
    }

    return true;
}

bool parse_mint_token(buffer_t *buf, mint_token_t *out_mint_token) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(out_mint_token != NULL, "NULL out_mint_token");

    uint8_t asset_name_length = 0;
    if (!buffer_read_u8(buf, &asset_name_length) || asset_name_length > MAX_MINT_ASSET_NAME_LENGTH) {
        TRACE("Failed to read mint asset name length or too long: %u", (unsigned) asset_name_length);
        return false;
    }

    const uint8_t *asset_name = NULL;
    if (!buffer_read_bytes_ptr(buf, &asset_name, asset_name_length)) {
        TRACE("Failed to read mint asset name");
        return false;
    }
    LEDGER_ASSERT(asset_name != NULL, "NULL mint asset_name");

    int64_t token_amount = 0;
    if (!buffer_read_int64(buf, &token_amount, BE)) {
        TRACE("Failed to read mint token amount");
        return false;
    }
    if (token_amount == 0) {
        TRACE("Mint token amount must be non-zero");
        return false;
    }

    out_mint_token->assetName = asset_name;
    out_mint_token->assetNameLen = asset_name_length;
    out_mint_token->amount = token_amount;
    // out_mint_token->policyId is set by the caller from the outer asset group context
    return true;
}

// ---------------------------------------------------------------------------
// Credential/DRep/voter conversion helpers (ext → hash-builder format)
// ---------------------------------------------------------------------------

credential_t credential_for_tx_hash_from_ext_credential(const ext_credential_t *credential) {
    LEDGER_ASSERT(credential != NULL, "NULL credential");

    credential_t result = {0};
    switch (credential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            result.type = CREDENTIAL_KEY_HASH;
            keyPathToKeyHash(&credential->keyPath, result.keyHash, SIZEOF(result.keyHash));
            break;
        case EXT_CREDENTIAL_KEY_HASH:
            LEDGER_ASSERT(credential->keyHash != NULL, "NULL credential->keyHash");
            result.type = CREDENTIAL_KEY_HASH;
            memmove(result.keyHash, credential->keyHash, SIZEOF(result.keyHash));
            break;
        case EXT_CREDENTIAL_SCRIPT_HASH:
            LEDGER_ASSERT(credential->scriptHash != NULL, "NULL credential->scriptHash");
            result.type = CREDENTIAL_SCRIPT_HASH;
            memmove(result.scriptHash, credential->scriptHash, SIZEOF(result.scriptHash));
            break;
        default:
            LEDGER_ASSERT(false, "Unknown ext credential type");
            break;
    }

    return result;
}

drep_t drep_for_tx_hash_from_ext_drep(const ext_drep_t *ext_drep) {
    LEDGER_ASSERT(ext_drep != NULL, "NULL ext_drep");

    drep_t result = {
        .type = (drep_type_t) ext_drep->type,
    };

    switch (ext_drep->type) {
        case EXT_DREP_KEY_PATH:
            result.type = DREP_KEY_HASH;
            keyPathToKeyHash(&ext_drep->keyPath, result.keyHash, SIZEOF(result.keyHash));
            break;
        case EXT_DREP_KEY_HASH:
            LEDGER_ASSERT(ext_drep->keyHash != NULL, "NULL ext_drep->keyHash");
            result.type = DREP_KEY_HASH;
            memmove(result.keyHash, ext_drep->keyHash, SIZEOF(result.keyHash));
            break;
        case EXT_DREP_SCRIPT_HASH:
            LEDGER_ASSERT(ext_drep->scriptHash != NULL, "NULL ext_drep->scriptHash");
            result.type = DREP_SCRIPT_HASH;
            memmove(result.scriptHash, ext_drep->scriptHash, SIZEOF(result.scriptHash));
            break;
        case EXT_DREP_ABSTAIN:
            result.type = DREP_ABSTAIN;
            break;
        case EXT_DREP_NO_CONFIDENCE:
            result.type = DREP_NO_CONFIDENCE;
            break;
        default:
            LEDGER_ASSERT(false, "Unknown ext drep type");
            break;
    }

    return result;
}

voter_t voter_for_tx_hash_from_ext_voter(const ext_voter_t *ext_voter) {
    LEDGER_ASSERT(ext_voter != NULL, "NULL ext_voter");

    voter_t voter = {0};
    switch (ext_voter->type) {
        case EXT_VOTER_COMMITTEE_HOT_KEY_PATH:
            voter.type = VOTER_COMMITTEE_HOT_KEY_HASH;
            keyPathToKeyHash(&ext_voter->keyPath, voter.keyHash, SIZEOF(voter.keyHash));
            break;
        case EXT_VOTER_DREP_KEY_PATH:
            voter.type = VOTER_DREP_KEY_HASH;
            keyPathToKeyHash(&ext_voter->keyPath, voter.keyHash, SIZEOF(voter.keyHash));
            break;
        case EXT_VOTER_STAKE_POOL_KEY_PATH:
            voter.type = VOTER_STAKE_POOL_KEY_HASH;
            keyPathToKeyHash(&ext_voter->keyPath, voter.keyHash, SIZEOF(voter.keyHash));
            break;
        case EXT_VOTER_COMMITTEE_HOT_KEY_HASH:
            LEDGER_ASSERT(ext_voter->keyHash != NULL, "NULL committee hot key hash voter");
            voter.type = VOTER_COMMITTEE_HOT_KEY_HASH;
            memmove(voter.keyHash, ext_voter->keyHash, SIZEOF(voter.keyHash));
            break;
        case EXT_VOTER_DREP_KEY_HASH:
            LEDGER_ASSERT(ext_voter->keyHash != NULL, "NULL drep key hash voter");
            voter.type = VOTER_DREP_KEY_HASH;
            memmove(voter.keyHash, ext_voter->keyHash, SIZEOF(voter.keyHash));
            break;
        case EXT_VOTER_STAKE_POOL_KEY_HASH:
            LEDGER_ASSERT(ext_voter->keyHash != NULL, "NULL stake pool key hash voter");
            voter.type = VOTER_STAKE_POOL_KEY_HASH;
            memmove(voter.keyHash, ext_voter->keyHash, SIZEOF(voter.keyHash));
            break;
        case EXT_VOTER_COMMITTEE_HOT_SCRIPT_HASH:
            LEDGER_ASSERT(ext_voter->scriptHash != NULL, "NULL committee hot script hash voter");
            voter.type = VOTER_COMMITTEE_HOT_SCRIPT_HASH;
            memmove(voter.scriptHash, ext_voter->scriptHash, SIZEOF(voter.scriptHash));
            break;
        case EXT_VOTER_DREP_SCRIPT_HASH:
            LEDGER_ASSERT(ext_voter->scriptHash != NULL, "NULL drep script hash voter");
            voter.type = VOTER_DREP_SCRIPT_HASH;
            memmove(voter.scriptHash, ext_voter->scriptHash, SIZEOF(voter.scriptHash));
            break;
        default:
            LEDGER_ASSERT(false, "Unknown ext voter type");
            break;
    }

    return voter;
}
