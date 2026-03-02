/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "buffer.h"
#include "mem.h"

#include "cardano_swo.h"
#include "cardano_buffer.h"
#include "app_context.h"
#include "cbor.h"
#include "tx_parse.h"
#include "cardano_parsers.h"
#include "securityPolicy.h"
#include "tx_parse_certificates.h"
#include "tx_parse_outputs.h"
#include "tx_processing.h"
#include "tx_processing_outputs.h"
#include "tx_processing_certificates.h"
#include "tx.h"
#include "utils.h"
#include "assert.h"
#include "tx_constants.h"
#include "tx_output_types.h"
#include "keyDerivation.h"
#include "tx_utils.h"
#include "addressUtilsShelley.h"
#include "globals.h"
#include "sign_tx_ctx.h"
#include "ui_utils.h"
#include "ui_warnings.h"
#include "ui_constants.h"
#include "ui_formatters.h"
#include "ui_address_fields.h"
#include "tx_ui_render.h"
#include "tx_ui_render_certificates.h"
#include "cardano_tokens.h"
#include "bech32.h"
#include "io.h"

#include <stdio.h>
#include <string.h>

#ifdef HAVE_SWAP
#include "swap.h"
#include "swap_lib.h"
#include "swap_error_code_helpers.h"
#endif


// ---------------------------------------------------------------------------
// Mode validator
// ---------------------------------------------------------------------------

void validate_parse_tx_mode(const tx_processing_mode_t *mode) {
    LEDGER_ASSERT(mode != NULL, "NULL mode");

    LEDGER_ASSERT(!mode->ui_render || !mode->run_hash_builder,
                  "ui_render implies !run_hash_builder");
    LEDGER_ASSERT(!mode->run_hash_builder || mode->run_validation,
                  "run_hash_builder implies run_validation");
    LEDGER_ASSERT(!mode->ui_count_pairs || mode->run_validation,
                  "ui_count_pairs implies run_validation");
}

// ---------------------------------------------------------------------------
// Context helpers
// ---------------------------------------------------------------------------

void tx_processing_state_init(const tx_processing_mode_t *mode, warning_bits_t *warning_bits) {
    validate_parse_tx_mode(mode);
    LEDGER_ASSERT(warning_bits != NULL, "NULL warning_bits");

    tx_processing_state_t *state = &tx_body_ctx()->processing_state;
    explicit_bzero(state, sizeof(*state));

    tx_body_ctx()->processing_mode = *mode;
    state->mode = &tx_body_ctx()->processing_mode;
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
        .mode         = *state->mode,
        .warning_bits = state->warning_bits,
        .hash_builder = &state->hash_builder,
    };
}

void tx_handle_parse_error(uint16_t swo) {
    TRACE("tx_handle_parse_error swo=0x%04x", swo);
    send_swo_and_reset(swo);
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

// ---------------------------------------------------------------------------

static void add_ui_network_details(const tx_params_t *tx_params) {
    LEDGER_ASSERT(tx_params != NULL, "NULL tx_params");
    if (!shouldShowNetworkDetails(tx_params)) {
        return;
    }
    UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Network ID", "Net ID"),
                   MAX_UINT64_STRING_LENGTH,
                   format_uint64,
                   (uint64_t) tx_params->networkId);
    UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Protocol magic", "Prot magic"),
                   MAX_UINT64_STRING_LENGTH,
                   format_uint64,
                   (uint64_t) tx_params->protocolMagic);
}

bool tx_process_inputs(buffer_t *buf, tx_processing_state_t *state) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    tx_processing_ctx_t ctx = tx_get_ctx();

    if (ctx.mode.run_hash_builder) {
        LEDGER_ASSERT(state->hash_builder_initialized, "Hash builder not initialized");
        txHashBuilder_enterInputs(ctx.hash_builder);
    }

    for (uint16_t input_index = 0; input_index < ctx.tx_params->num_inputs; input_index++) {
        tx_input_t parsed_input = {0};
        if (!parse_input(buf, &parsed_input)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_INPUTS);
            return false;
        }

        if (ctx.mode.run_validation) {
            security_policy_t input_policy = policyForSignTxInput(
                ctx.tx_params->txSigningMode,
                &parsed_input,
                ctx.warning_bits);

            APPLY_POLICY(input_policy, tx_ui_plan_or_render_input, &ctx.mode, &parsed_input);
        }

        if (ctx.mode.run_hash_builder) {
            txHashBuilder_addInput(ctx.hash_builder, &parsed_input);
        }
    }

    return true;
}

bool tx_process_collateral_inputs(buffer_t *buf, tx_processing_state_t *state) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    tx_processing_ctx_t ctx = tx_get_ctx();

    if (ctx.tx_params->num_collateral_inputs == 0) {
        return true;
    }

    if (ctx.mode.run_hash_builder) {
        LEDGER_ASSERT(state->hash_builder_initialized, "Hash builder not initialized");
        txHashBuilder_enterCollateralInputs(ctx.hash_builder);
    }

    for (uint16_t input_index = 0; input_index < ctx.tx_params->num_collateral_inputs; input_index++) {
        tx_input_t parsed_input = {0};
        if (!parse_input(buf, &parsed_input)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_COLLATERAL_INPUTS);
            return false;
        }

        if (ctx.mode.run_validation) {
            security_policy_t collateral_input_policy = policyForSignTxCollateralInput(
                ctx.tx_params->txSigningMode,
                ctx.tx_params->includeTotalCollateral,
                &parsed_input,
                ctx.warning_bits);

            APPLY_POLICY(collateral_input_policy, tx_ui_plan_or_render_collateral_input, &ctx.mode, &parsed_input);
        }

        if (ctx.mode.run_hash_builder) {
            txHashBuilder_addCollateralInput(ctx.hash_builder, &parsed_input);
        }
    }

    return true;
}

bool tx_process_reference_inputs(buffer_t *buf, tx_processing_state_t *state) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    tx_processing_ctx_t ctx = tx_get_ctx();

    if (ctx.tx_params->num_reference_inputs == 0) {
        return true;
    }

    if (ctx.mode.run_hash_builder) {
        LEDGER_ASSERT(state->hash_builder_initialized, "Hash builder not initialized");
        txHashBuilder_enterReferenceInputs(ctx.hash_builder);
    }

    for (uint16_t input_index = 0; input_index < ctx.tx_params->num_reference_inputs; input_index++) {
        tx_input_t parsed_input = {0};
        if (!parse_input(buf, &parsed_input)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_REFERENCE_INPUTS);
            return false;
        }

        if (ctx.mode.run_validation) {
            security_policy_t reference_input_policy = policyForSignTxReferenceInput(
                ctx.tx_params->txSigningMode,
                &parsed_input,
                ctx.warning_bits);

            APPLY_POLICY(reference_input_policy, tx_ui_plan_or_render_reference_input, &ctx.mode, &parsed_input);
        }

        if (ctx.mode.run_hash_builder) {
            txHashBuilder_addReferenceInput(ctx.hash_builder, &parsed_input);
        }
    }

    return true;
}

static bool tx_process_fee(buffer_t *buf, tx_processing_state_t *state) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    tx_processing_ctx_t ctx = tx_get_ctx();

    uint64_t parsed_fee = 0;
    if (!buffer_read_u64(buf, &parsed_fee, BE)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_FEE);
        return false;
    }

    if (ctx.mode.run_validation) {
        security_policy_t fee_policy = policyForSignTxFee(
            ctx.tx_params->txSigningMode,
            parsed_fee,
            ctx.warning_bits);
        APPLY_POLICY(fee_policy, tx_ui_plan_or_render_fee, &ctx.mode, parsed_fee);
    }
#ifdef HAVE_SWAP
    if (ctx.mode.run_validation &&
        G_called_from_swap &&
        !swap_check_fee_validity(parsed_fee)) {
        swap_reject_and_exit(SWAP_EC_ERROR_WRONG_FEES, SWAP_APP_CODE_DEFAULT);
    }
#endif

    if (ctx.mode.run_hash_builder) {
        txHashBuilder_addFee(&state->hash_builder, parsed_fee);
    }
    return true;
}

static bool tx_process_ttl(buffer_t *buf, tx_processing_state_t *state) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    tx_processing_ctx_t ctx = tx_get_ctx();

    if (!ctx.tx_params->includeTtl) {
        return true;
    }

    uint64_t parsed_ttl = 0;
    if (!buffer_read_u64(buf, &parsed_ttl, BE)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_TTL);
        return false;
    }

    if (ctx.mode.run_validation) {
        security_policy_t ttl_policy = policyForSignTxTtl(parsed_ttl, ctx.warning_bits);
        APPLY_POLICY(ttl_policy, tx_ui_plan_or_render_ttl, &ctx.mode, parsed_ttl);
    }

    if (ctx.mode.run_hash_builder) {
        txHashBuilder_addTtl(&state->hash_builder, parsed_ttl);
    }

    return true;
}

static bool tx_process_withdrawals(buffer_t *buf, tx_processing_state_t *state) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    tx_processing_ctx_t ctx = tx_get_ctx();
    const tx_params_t *tx_params = ctx.tx_params;
    const tx_processing_mode_t *mode = &ctx.mode;

    if (tx_params->num_withdrawals == 0) {
        return true;
    }

    if (mode->run_hash_builder) {
        LEDGER_ASSERT(state->hash_builder_initialized, "Hash builder not initialized");
        txHashBuilder_enterWithdrawals(&state->hash_builder);
    }

    ENFORCE_CANONICAL_ORDERING_START(withdrawal_key_tracker);

    for (uint16_t withdrawal_index = 0; withdrawal_index < tx_params->num_withdrawals;
         withdrawal_index++) {
        withdrawal_t parsed_withdrawal = {0};
        if (!parse_withdrawal(buf, &parsed_withdrawal)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_WITHDRAWALS);
            return false;
        }

        if (mode->run_validation) {
            security_policy_t withdrawal_policy = policyForSignTxWithdrawal(
                tx_params->txSigningMode,
                &parsed_withdrawal.stakeCredential,
                ctx.warning_bits);
            APPLY_POLICY(withdrawal_policy, tx_ui_plan_or_render_withdrawal, mode, &parsed_withdrawal, tx_params->networkId);
        }

        // Optimization: calculate reward address only when needed (canonical check or hashing)
        if (mode->run_validation || mode->run_hash_builder) {
            uint8_t reward_address[REWARD_ACCOUNT_LENGTH] = {0};
            size_t reward_address_length = 0;
            switch (parsed_withdrawal.stakeCredential.type) {
                case EXT_CREDENTIAL_KEY_PATH:
                    reward_address_length = constructRewardAddressFromKeyPath(
                        &parsed_withdrawal.stakeCredential.keyPath,
                        tx_params->networkId,
                        reward_address,
                        SIZEOF(reward_address));
                    break;
                case EXT_CREDENTIAL_KEY_HASH:
                    reward_address_length = constructRewardAddressFromHash(
                        tx_params->networkId,
                        REWARD_HASH_SOURCE_KEY,
                        parsed_withdrawal.stakeCredential.keyHash,
                        ADDRESS_KEY_HASH_LENGTH,
                        reward_address,
                        SIZEOF(reward_address));
                    break;
                case EXT_CREDENTIAL_SCRIPT_HASH:
                    reward_address_length = constructRewardAddressFromHash(
                        tx_params->networkId,
                        REWARD_HASH_SOURCE_SCRIPT,
                        parsed_withdrawal.stakeCredential.scriptHash,
                        SCRIPT_HASH_LENGTH,
                        reward_address,
                        SIZEOF(reward_address));
                    break;
                default:
                    LEDGER_ASSERT(false, "Unknown withdrawal credential type");
                    break;
            }
            LEDGER_ASSERT(reward_address_length == REWARD_ACCOUNT_LENGTH, "Invalid reward address length");

            ENFORCE_CANONICAL_ORDERING_CHECK(withdrawal_key_tracker,
                                             reward_address,
                                             reward_address_length,
                                             SWO_TX_PARSING_FAIL_WITHDRAWALS);

            if (mode->run_hash_builder) {
                txHashBuilder_addWithdrawal(&state->hash_builder,
                                            reward_address,
                                            reward_address_length,
                                            parsed_withdrawal.amount);
            }
        }
    }

    return true;
}

static bool tx_process_aux_data_hash(tx_processing_state_t *state) {
    tx_processing_ctx_t ctx = tx_get_ctx();

    if (!ctx.tx_params->includeAuxDataHash) {
        return true;
    }

    if (ctx.mode.run_validation) {
        security_policy_t aux_data_policy = policyForSignTxAuxData(ctx.tx_params->auxDataType,
                                                                   ctx.warning_bits);
        APPLY_POLICY(aux_data_policy, tx_ui_plan_or_render_aux_data_hash, &ctx.mode, ctx.tx_params->auxDataHash);
    }

    if (ctx.mode.run_hash_builder) {
        txHashBuilder_addAuxData(&state->hash_builder,
                                 ctx.tx_params->auxDataHash,
                                 AUX_DATA_HASH_LENGTH);
    }

    return true;
}

static bool tx_process_validity_interval_start(buffer_t *buf, tx_processing_state_t *state) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    tx_processing_ctx_t ctx = tx_get_ctx();

    if (!ctx.tx_params->includeValidityIntervalStart) {
        return true;
    }

    uint64_t validity_interval_start = 0;
    if (!buffer_read_u64(buf, &validity_interval_start, BE)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_VALIDITY_INTERVAL_START);
        return false;
    }

    if (ctx.mode.run_validation) {
        security_policy_t validity_interval_start_policy = policyForSignTxValidityIntervalStart(
            ctx.warning_bits);
        APPLY_POLICY(validity_interval_start_policy, tx_ui_plan_or_render_validity_interval_start, &ctx.mode, validity_interval_start);
    }

    if (ctx.mode.run_hash_builder) {
        txHashBuilder_addValidityIntervalStart(&state->hash_builder, validity_interval_start);
    }

    return true;
}

static bool tx_process_mint_tokens(buffer_t *buf,
                                    tx_processing_state_t *state,
                                    const uint8_t *policy_id,
                                    uint16_t number_of_tokens,
                                    security_policy_t mint_policy) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(policy_id != NULL, "NULL policy_id");
    tx_processing_ctx_t ctx = tx_get_ctx();

    ENFORCE_CANONICAL_ORDERING_START(asset_name_tracker);
    for (uint16_t token_index = 0; token_index < number_of_tokens; token_index++) {
        mint_token_t parsed_mint_token = {.policyId = policy_id};
        if (!parse_mint_token(buf, &parsed_mint_token)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_MINT);
            return false;
        }

        ENFORCE_CANONICAL_ORDERING_CHECK(asset_name_tracker,
                                         parsed_mint_token.assetName,
                                         parsed_mint_token.assetNameLen,
                                         SWO_TX_PARSING_FAIL_CANONICAL_ORDER);

        if (ctx.mode.run_validation) {
            APPLY_POLICY(mint_policy, tx_ui_plan_or_render_mint_token, &ctx.mode, &parsed_mint_token);
        }

        if (ctx.mode.run_hash_builder) {
            txHashBuilder_addMint_token(&state->hash_builder,
                                        parsed_mint_token.assetName,
                                        parsed_mint_token.assetNameLen,
                                        parsed_mint_token.amount);
        }
    }

    return true;
}

static bool tx_process_mint(buffer_t *buf, tx_processing_state_t *state) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    tx_processing_ctx_t ctx = tx_get_ctx();
    const tx_params_t *tx_params = ctx.tx_params;
    const tx_processing_mode_t *mode = &ctx.mode;

    if (tx_params->num_mint_asset_groups == 0) {
        return true;
    }

    security_policy_t mint_policy = POLICY_DENY;
    if (mode->run_validation) {
        mint_policy = policyForSignTxMintInit(
            tx_params->txSigningMode,
            ctx.warning_bits);
        APPLY_POLICY(mint_policy, tx_ui_plan_or_render_mint_summary, mode, tx_params->num_mint_asset_groups);
    }

    if (mode->run_hash_builder) {
        LEDGER_ASSERT(state->hash_builder_initialized, "Hash builder not initialized");
        txHashBuilder_enterMint(&state->hash_builder);
        txHashBuilder_addMint_topLevelData(&state->hash_builder,
                                           tx_params->num_mint_asset_groups);
    }

    ENFORCE_CANONICAL_ORDERING_START(policy_id_tracker);
    for (uint16_t asset_group_index = 0;
         asset_group_index < tx_params->num_mint_asset_groups;
         asset_group_index++) {
        const uint8_t *policy_id = NULL;
        if (!buffer_read_bytes_ptr(buf, &policy_id, MINTING_POLICY_ID_LENGTH)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_MINT);
            return false;
        }
        ENFORCE_CANONICAL_ORDERING_CHECK(policy_id_tracker,
                                         policy_id, MINTING_POLICY_ID_LENGTH,
                                         SWO_TX_PARSING_FAIL_CANONICAL_ORDER);

        uint16_t number_of_tokens = 0;
        if (!buffer_read_u16(buf, &number_of_tokens, BE)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_MINT);
            return false;
        }

        if (mode->run_hash_builder) {
            txHashBuilder_addMint_tokenGroup(&state->hash_builder,
                                             policy_id,
                                             MINTING_POLICY_ID_LENGTH,
                                             number_of_tokens);
        }

        if (!tx_process_mint_tokens(buf, state, policy_id, number_of_tokens, mint_policy)) {
            return false;
        }
    }

    return true;
}

static bool tx_process_script_data_hash(buffer_t *buf, tx_processing_state_t *state) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    tx_processing_ctx_t ctx = tx_get_ctx();

    if (!ctx.tx_params->includeScriptDataHash) {
        return true;
    }

    const uint8_t *script_data_hash = NULL;
    if (!buffer_read_bytes_ptr(buf, &script_data_hash, SCRIPT_DATA_HASH_LENGTH)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_SCRIPT_DATA_HASH);
        return false;
    }

    if (ctx.mode.run_validation) {
        security_policy_t script_data_hash_policy = policyForSignTxScriptDataHash(
            ctx.tx_params->txSigningMode,
            ctx.warning_bits);
        APPLY_POLICY(script_data_hash_policy, tx_ui_plan_or_render_script_data_hash, &ctx.mode, script_data_hash);
    }

    if (ctx.mode.run_hash_builder) {
        txHashBuilder_addScriptDataHash(&state->hash_builder,
                                        script_data_hash,
                                        SCRIPT_DATA_HASH_LENGTH);
    }

    return true;
}

bool tx_process_required_signers(buffer_t *buf, tx_processing_state_t *state) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    tx_processing_ctx_t ctx = tx_get_ctx();
    const tx_params_t *tx_params = ctx.tx_params;
    const tx_processing_mode_t *mode = &ctx.mode;

    tx_hash_builder_t *hash_builder = ctx.hash_builder;

    if (tx_params->num_required_signers == 0) {
        return true;
    }

    if (mode->run_hash_builder) {
        LEDGER_ASSERT(state->hash_builder_initialized, "Hash builder not initialized");
        txHashBuilder_enterRequiredSigners(hash_builder);
    }

    for (uint16_t signer_index = 0; signer_index < tx_params->num_required_signers; signer_index++) {
        required_signer_t parsed_required_signer = {0};
        if (!parse_required_signer(buf, &parsed_required_signer)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_REQUIRED_SIGNERS);
            return false;
        }

        if (mode->run_validation) {
            security_policy_t signer_policy = policyForSignTxRequiredSigner(
                tx_params->txSigningMode,
                &parsed_required_signer,
                ctx.warning_bits);

            APPLY_POLICY(signer_policy, tx_ui_plan_or_render_required_signer, mode, &parsed_required_signer);
        }

        if (mode->run_hash_builder) {
            uint8_t signer_key_hash[ADDRESS_KEY_HASH_LENGTH] = {0};
            switch (parsed_required_signer.type) {
                case REQUIRED_SIGNER_WITH_PATH:
                    keyPathToKeyHash(&parsed_required_signer.keyPath,
                                     signer_key_hash,
                                     SIZEOF(signer_key_hash));
                    break;
                case REQUIRED_SIGNER_WITH_HASH:
                    LEDGER_ASSERT(parsed_required_signer.keyHash != NULL,
                                  "NULL required signer key hash");
                    memmove(signer_key_hash,
                            parsed_required_signer.keyHash,
                            SIZEOF(signer_key_hash));
                    break;
                default:
                    LEDGER_ASSERT(false, "Unknown required_signer_type_t");
                    break;
            }
            txHashBuilder_addRequiredSigner(hash_builder,
                                            signer_key_hash,
                                            SIZEOF(signer_key_hash));
        }
    }

    return true;
}

static bool tx_process_network_id(tx_processing_state_t *state) {
    tx_processing_ctx_t ctx = tx_get_ctx();

    if (!ctx.tx_params->includeNetworkId) {
        return true;
    }

    if (ctx.mode.run_hash_builder) {
        txHashBuilder_addNetworkId(&state->hash_builder, ctx.tx_params->networkId);
    }

    return true;
}

static bool tx_process_total_collateral(buffer_t *buf, tx_processing_state_t *state) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    tx_processing_ctx_t ctx = tx_get_ctx();

    if (!ctx.tx_params->includeTotalCollateral) {
        return true;
    }

    uint64_t total_collateral = 0;
    if (!buffer_read_u64(buf, &total_collateral, BE)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_TOTAL_COLLATERAL);
        return false;
    }

    if (ctx.mode.run_validation) {
        security_policy_t total_collateral_policy = policyForSignTxTotalCollateral(
            ctx.warning_bits);
        APPLY_POLICY(total_collateral_policy, tx_ui_plan_or_render_total_collateral, &ctx.mode, total_collateral);
    }

    if (ctx.mode.run_hash_builder) {
        txHashBuilder_addTotalCollateral(&state->hash_builder, total_collateral);
    }

    return true;
}

static bool tx_process_vote(tx_processing_state_t *state,
                             const vote_item_t *parsed_vote,
                             security_policy_t voter_policy) {
    tx_processing_ctx_t ctx = tx_get_ctx();

    if (ctx.mode.run_validation) {
        APPLY_POLICY(voter_policy, tx_ui_plan_or_render_vote, &ctx.mode, parsed_vote);
    }

    if (ctx.mode.run_validation && parsed_vote->anchor.isIncluded) {
        security_policy_t anchor_policy = policyForSignTxAnchor(
            &parsed_vote->anchor,
            ctx.warning_bits);
        APPLY_POLICY(anchor_policy, tx_ui_plan_or_render_vote_anchor, &ctx.mode, &parsed_vote->anchor);
    }

    if (ctx.mode.run_hash_builder) {
        voting_procedure_t voting_procedure = {
            .vote = parsed_vote->voteOption,
            .anchor = parsed_vote->anchor,
        };
        gov_action_id_t gov_action_id = parsed_vote->govActionId;
        txHashBuilder_addVote(&state->hash_builder, &gov_action_id, &voting_procedure);
    }

    return true;
}

static bool tx_process_votes(buffer_t *buf,
                              tx_processing_state_t *state,
                              uint16_t num_votes,
                              security_policy_t voter_policy) {
    ENFORCE_CANONICAL_ORDERING_START(vote_key_tracker);

    for (uint16_t vote_index = 0; vote_index < num_votes; vote_index++) {
        vote_item_t parsed_vote = {0};
        if (!parse_vote(buf, &parsed_vote)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_VOTING_PROCEDURES);
            return false;
        }

        uint8_t gov_action_key[MAX_CBOR_GOV_ACTION_MAP_KEY_SIZE] = {0};
        size_t gov_action_key_length = txHashBuilder_serializeGovActionKey(
            &parsed_vote.govActionId,
            gov_action_key,
            SIZEOF(gov_action_key));
        ENFORCE_CANONICAL_ORDERING_CHECK(vote_key_tracker,
                                         gov_action_key,
                                         gov_action_key_length,
                                         SWO_TX_PARSING_FAIL_VOTING_PROCEDURES);

        if (!tx_process_vote(state, &parsed_vote, voter_policy)) {
            return false;
        }
    }

    return true;
}

static bool tx_process_voting_procedures(buffer_t *buf, tx_processing_state_t *state) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    tx_processing_ctx_t ctx = tx_get_ctx();
    const tx_params_t *tx_params = ctx.tx_params;
    const tx_processing_mode_t *mode = &ctx.mode;

    if (tx_params->num_voters == 0) {
        return true;
    }

    if (mode->run_hash_builder) {
        txHashBuilder_enterVotingProcedures(&state->hash_builder);
    }
    ENFORCE_CANONICAL_ORDERING_START(voter_key_tracker);

    for (uint16_t voter_index = 0; voter_index < tx_params->num_voters; voter_index++) {
        ext_voter_t parsed_voter = {0};
        uint16_t num_votes = 0;
        if (!parse_voter_votes_header(buf, &parsed_voter, &num_votes)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_VOTING_PROCEDURES);
            return false;
        }

        security_policy_t voter_policy = POLICY_DENY;
        if (mode->run_validation) {
            voter_policy = policyForSignTxVotingProcedure(
                tx_params->txSigningMode,
                &parsed_voter,
                ctx.warning_bits);
            APPLY_POLICY(voter_policy, tx_ui_plan_or_render_voter, mode, &parsed_voter);
        }

        voter_t voter_for_hashbuilder = voter_for_tx_hash_from_ext_voter(&parsed_voter);
        uint8_t voter_key[MAX_CBOR_VOTER_MAP_KEY_SIZE] = {0};
        size_t voter_key_length = txHashBuilder_serializeVoterKey(
            &voter_for_hashbuilder,
            voter_key,
            SIZEOF(voter_key));
        ENFORCE_CANONICAL_ORDERING_CHECK(voter_key_tracker,
                                         voter_key,
                                         voter_key_length,
                                         SWO_TX_PARSING_FAIL_VOTING_PROCEDURES);

        if (mode->run_hash_builder) {
            txHashBuilder_addVoter(&state->hash_builder, &voter_for_hashbuilder, num_votes);
        }

        if (!tx_process_votes(buf, state, num_votes, voter_policy)) {
            return false;
        }
    }

    return true;
}

static bool tx_process_treasury(buffer_t *buf, tx_processing_state_t *state) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    tx_processing_ctx_t ctx = tx_get_ctx();

    if (!ctx.tx_params->includeTreasury) {
        return true;
    }

    uint64_t treasury = 0;
    if (!buffer_read_u64(buf, &treasury, BE)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_TREASURY);
        return false;
    }

    if (ctx.mode.run_validation) {
        security_policy_t treasury_policy = policyForSignTxTreasury(
            ctx.tx_params->txSigningMode,
            treasury,
            ctx.warning_bits);
        APPLY_POLICY(treasury_policy, tx_ui_plan_or_render_treasury, &ctx.mode, treasury);
    }

    if (ctx.mode.run_hash_builder) {
        txHashBuilder_addTreasury(&state->hash_builder, treasury);
    }

    return true;
}

static bool tx_process_donation(buffer_t *buf, tx_processing_state_t *state) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    tx_processing_ctx_t ctx = tx_get_ctx();

    if (!ctx.tx_params->includeDonation) {
        return true;
    }

    uint64_t donation = 0;
    if (!buffer_read_u64(buf, &donation, BE)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_DONATION);
        return false;
    }

    if (ctx.mode.run_validation) {
        security_policy_t donation_policy = policyForSignTxDonation(
            ctx.tx_params->txSigningMode,
            donation,
            ctx.warning_bits);
        APPLY_POLICY(donation_policy, tx_ui_plan_or_render_donation, &ctx.mode, donation);
    }

    if (ctx.mode.run_hash_builder) {
        txHashBuilder_addDonation(&state->hash_builder, donation);
    }

    return true;
}

static bool tx_process_all_fields(buffer_t *buf, tx_processing_state_t *state) {
    if (!tx_process_inputs(buf, state)) {
        return false;
    }
    if (!tx_process_outputs(buf, state)) {
        return false;
    }
    if (!tx_process_fee(buf, state)) {
        return false;
    }
    if (!tx_process_ttl(buf, state)) {
        return false;
    }
    if (!tx_process_certificates(buf, state)) {
        return false;
    }
    if (!tx_process_withdrawals(buf, state)) {
        return false;
    }
    if (!tx_process_aux_data_hash(state)) {
        return false;
    }
    if (!tx_process_validity_interval_start(buf, state)) {
        return false;
    }
    if (!tx_process_mint(buf, state)) {
        return false;
    }
    if (!tx_process_script_data_hash(buf, state)) {
        return false;
    }
    if (!tx_process_collateral_inputs(buf, state)) {
        return false;
    }
    if (!tx_process_required_signers(buf, state)) {
        return false;
    }
    if (!tx_process_network_id(state)) {
        return false;
    }
    if (!tx_process_collateral_output(buf)) {
        return false;
    }
    if (!tx_process_total_collateral(buf, state)) {
        return false;
    }
    if (!tx_process_reference_inputs(buf, state)) {
        return false;
    }
    if (!tx_process_voting_procedures(buf, state)) {
        return false;
    }
    if (!tx_process_treasury(buf, state)) {
        return false;
    }
    if (!tx_process_donation(buf, state)) {
        return false;
    }
    return true;
}

bool tx_validate(buffer_t *buf) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");

    // Pool owner witness metadata is derived during pass-1 certificate processing.
    G_context.tx_info.pool_owner_path_present = false;

    // Reset warning bits and re-run init policy to set network-level warnings
    // (e.g. WARNING_BIT_NETWORK_UNUSUAL) for UI display. The DENY check was already
    // performed in the init APDU handler; here we only need the side-effect of setting
    // warning bits, so a DENY result is an assertion failure (params haven't changed).
    tx_body_ctx()->warning_bits = 0;
    const tx_params_t *tx_params = &G_context.tx_info.tx_params;
    // Re-run init policy solely to set network-level warning bits (e.g. WARNING_BIT_NETWORK_UNUSUAL).
    // The DENY check was already enforced in the init APDU handler so DENY here is a programming error.
    LEDGER_ASSERT(policyForSignTxInit(tx_params, &tx_body_ctx()->warning_bits) != POLICY_DENY,
                  "policyForSignTxInit unexpectedly denied in tx_validate");

    tx_processing_mode_t mode = {
        .run_validation = true,
        .run_hash_builder = true,
        .ui_count_pairs = true,
        .ui_render = false,
    };
    tx_processing_state_init(&mode, &tx_body_ctx()->warning_bits);

    tx_body_ctx()->total_ui_pairs = 0;

    if (shouldShowNetworkDetails(tx_params)) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_NETWORK_DETAILS;
    }

    tx_processing_state_t *state = &tx_body_ctx()->processing_state;
    if (!tx_process_all_fields(buf, state)) {
        return false;
    }

    if (deny_unconsumed_bytes(buf, SWO_TX_PARSING_FAIL_BUFFER_NOT_FULLY_CONSUMED)) {
        return false;
    }

    txHashBuilder_finalize(&state->hash_builder, G_context.tx_info.tx_hash, TX_HASH_LENGTH);

    security_policy_t tx_hash_policy =
        policyForSignTxDisplayTxHash(tx_params->txSigningMode, &tx_body_ctx()->warning_bits);
    APPLY_POLICY(tx_hash_policy, tx_ui_plan_or_render_tx_hash, &mode, G_context.tx_info.tx_hash);

    TRACE("tx_validate: total_ui_pairs=%u, max_ui_pairs=%u",
          tx_body_ctx()->total_ui_pairs, MAX_UI_PAIRS);
    return true;
}

bool tx_render_ui_chunk(uint16_t from) {
    LEDGER_ASSERT(tx_body_ctx()->raw_tx != NULL, "Missing raw tx for UI rendering");
    buffer_t buf = {
        .ptr = tx_body_ctx()->raw_tx,
        .size = tx_body_ctx()->raw_tx_current_length,
        .offset = 0,
    };

    tx_processing_mode_t mode = {
        .run_validation = true,
        .run_hash_builder = false,
        .ui_count_pairs = false,
        .ui_render = true,
    };
    // Use a copy of warnings for the render pass so it cannot
    // accidentally change global warning state, and we can assert consistency.
    warning_bits_t render_pass_warnings = tx_body_ctx()->warning_bits;
    tx_processing_state_init(&mode, &render_pass_warnings);

    // Set the render window: pairs before `from` are skipped, OOM stops the chunk.
    ui_render_window_init(from);

    const tx_params_t *tx_params = &G_context.tx_info.tx_params;
    if (shouldShowNetworkDetails(tx_params)) {
        START_COUNT();
        add_ui_network_details(tx_params);
        CHECK_COUNT(UI_PAIRS_NETWORK_DETAILS);
    }

    if (!tx_process_all_fields(&buf, &tx_body_ctx()->processing_state)) {
        return false;
    }
    LEDGER_ASSERT(!buffer_can_read(&buf, 1), "Render pass did not consume full tx buffer");

    security_policy_t tx_hash_policy =
        policyForSignTxDisplayTxHash(tx_params->txSigningMode, &render_pass_warnings);
    APPLY_POLICY(tx_hash_policy, tx_ui_plan_or_render_tx_hash, &mode, G_context.tx_info.tx_hash);

    LEDGER_ASSERT(render_pass_warnings == tx_body_ctx()->warning_bits,
                  "Warnings inconsistent between passes");

    return true;
}

bool tx_render_ui_all(void) {
    if (G_context.req_type != REQUEST_SIGN_TRANSACTION) {
        return false;
    }
    LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_HASHED, "UI prep called too early");
    uint16_t total_pairs = tx_body_ctx()->total_ui_pairs;

    TRACE("Preparing TX review: total_ui_pairs=%u max_ui_pairs=%u", total_pairs, MAX_UI_PAIRS);
    LEDGER_ASSERT(total_pairs > 0, "UI pair count is zero - at minimum fee must be displayed");

    // Allocate the full slab; OOM during rendering is the natural chunk boundary.
    uint16_t alloc_count = (total_pairs <= MAX_UI_PAIRS) ? total_pairs : MAX_UI_PAIRS;

    ui_reset_error_status();
    if (!ui_pairs_init(alloc_count)) {
        TRACE("ui_pairs_init failed for %u pairs", alloc_count);
        return false;
    }

    // Try to render everything into the first chunk (from pair 0).
    if (!tx_render_ui_chunk(0)) {
        TRACE("UI build failed in second-pass rendering");
        return false;
    }

    uint16_t cursor_after = ui_render_cursor_get();

    if (ui_get_error_status() == UI_STATUS_SUCCESS) {
        // Everything fit in a single chunk — non-streaming path.
        // cursor_after must equal total_pairs: every UI_ADD_* increments g_pair_scan_index exactly
        // once, so if no OOM occurred the render pass consumed all total pairs.
        LEDGER_ASSERT(cursor_after == total_pairs, "cursor mismatch: render completed without CHUNK_FULL but cursor does not equal total_pairs");
        tx_body_ctx()->streaming_mode = false;
        TRACE("Non-streaming: total=%u rendered=%u",
              (unsigned) total_pairs, (unsigned) ui_pairs_get_count());
        LEDGER_ASSERT(ui_pairs_get_count() == total_pairs, "UI pair count mismatch");
    } else {
        // Does not fit — streaming path. First chunk is already rendered.
        tx_body_ctx()->streaming_mode = true;
        tx_body_ctx()->rendered_ui_pairs = ui_pairs_get_count();
        // Reset chunk-full status: hitting the pairs limit is the expected chunk boundary signal.
        LEDGER_ASSERT(g_ui_error_status == UI_STATUS_CHUNK_FULL,
                      "Expected CHUNK_FULL at streaming boundary, got different status");
        g_ui_error_status = UI_STATUS_SUCCESS;
        TRACE("Streaming: first chunk rendered %u pairs, cursor_after=%u, total=%u",
              (unsigned) ui_pairs_get_count(), cursor_after, (unsigned) total_pairs);
    }

    // Finalize the pairs count for display (may be less than allocated).
    LEDGER_ASSERT(g_pairsList != NULL, "NULL g_pairsList after rendering");
    g_pairsList->nbPairs = (uint8_t) ui_pairs_get_count();

    LEDGER_ASSERT(!warning_bits_has_any_cvote_tx_forbidden(tx_body_ctx()->warning_bits),
                  "CVote warning leaked into transaction warnings");

    ui_status_t warning_status = ui_build_warnings(tx_body_ctx()->warning_bits);
    TRACE("ui_build_warnings returned status=%u", (unsigned) warning_status);
    switch (warning_status) {
        case UI_STATUS_SUCCESS:
            break;
        case UI_STATUS_OUT_OF_MEMORY:
            return false;
        case UI_STATUS_UNINITIALIZED:
        default:
            LEDGER_ASSERT(false, "Unexpected UI warning status");
            return false;
    }

    return true;
}
