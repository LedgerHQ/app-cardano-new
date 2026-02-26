/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "buffer.h"
#include "cardano_swo.h"
#include "app_context.h"
#include "tx_parse.h"
#include "tx_parse_outputs.h"
#include "tx_processing_outputs.h"
#include "tx.h"
#include "utils.h"
#include "assert.h"
#include "tx_constants.h"
#include "tx_output_types.h"
#include "keyDerivation.h"
#include "globals.h"
#include "ui_utils.h"
#include "ui_warnings.h"
#include "ui_constants.h"
#include "ui_formatters.h"
#include "tx_processing.h"
#include "tx_ui_strings_outputs.h"
#include "bech32.h"
#include "securityPolicy.h"
#include "tx_utils.h"

#include <string.h>

#ifdef HAVE_SWAP
#include "swap.h"
#include "swap_lib.h"
#include "swap_error_code_helpers.h"
#endif

// ---------------------------------------------------------------------------
// Hash builder helpers (address bytes conversion for hashing)
// ---------------------------------------------------------------------------

typedef void (*hash_add_output_fn_t)(tx_hash_builder_t *builder,
                                     const tx_output_description_t *output);

static void hash_add_output_top_level(tx_hash_builder_t *tx_hash_builder,
                                      const tx_output_description_t *output_description,
                                      hash_add_output_fn_t hash_fn) {
    LEDGER_ASSERT(tx_hash_builder != NULL, "NULL tx_hash_builder");
    LEDGER_ASSERT(output_description != NULL, "NULL output_description");

    uint8_t address_bytes[MAX_ADDRESS_LENGTH] = {0};
    size_t address_size = 0;
    bool destination_parsed = tx_output_destination_to_address_bytes(
        &output_description->destination,
        address_bytes,
        SIZEOF(address_bytes),
        &address_size);
    LEDGER_ASSERT(destination_parsed, "Failed to build output address bytes for hashing");

    tx_output_description_t hash_description = *output_description;
    hash_description.destination = tx_output_destination_make_third_party(address_bytes, address_size);
    hash_fn(tx_hash_builder, &hash_description);
}

// ---------------------------------------------------------------------------
// Single-output processing
// ---------------------------------------------------------------------------

/**
 * Process one regular output from output_buf (a sub-buffer covering exactly one serialized output).
 */
static bool tx_process_output(buffer_t *output_buf,
                                      uint16_t output_index,
                                      tx_processing_state_t *state) {
    tx_parse_ctx_t ctx = tx_get_ctx();
    const tx_params_t *tx_params = ctx.tx_params;
    const parse_tx_mode_t *mode = ctx.mode;
    tx_hash_builder_t *hash_builder = ctx.hash_builder;

    // --- 1. Parse top-level output fields ---
    tx_output_description_t output_desc = {0};
    uint16_t status = parse_output_top_level(output_buf, &output_desc, SWO_TX_PARSING_FAIL_OUTPUTS);
    if (status != SWO_OK) {
        tx_handle_parse_error(status);
        return false;
    }

    // --- 2. Policy, plan, render: top-level fields ---
    security_policy_t output_policy = POLICY_DENY;
    security_policy_t datum_policy = POLICY_DENY;
    security_policy_t ref_script_policy = POLICY_DENY;

    if (mode->run_validation) {
#ifdef HAVE_SWAP
        if (G_called_from_swap &&
            output_desc.destination.type == DESTINATION_THIRD_PARTY) {
            state->swap_third_party_output_count++;
            if (!swap_check_destination_validity(&output_desc.destination)) {
                swap_reject_and_exit(SWAP_EC_ERROR_WRONG_DESTINATION, SWAP_APP_CODE_DEFAULT);
            }
            if (!swap_check_amount_validity(output_desc.amount)) {
                swap_reject_and_exit(SWAP_EC_ERROR_WRONG_AMOUNT, SWAP_APP_CODE_DEFAULT);
            }
        }
#endif

        output_policy = policyForSignTxOutput(
            &output_desc,
            tx_params->txSigningMode,
            tx_params->networkId,
            tx_params->protocolMagic,
            ctx.warning_bits);
        APPLY_POLICY(output_policy, tx_ui_plan_or_render_output, mode, output_index, &output_desc);

        datum_policy = policyForSignTxOutputDatumHash(output_policy, ctx.warning_bits);
        ref_script_policy = policyForSignTxOutputRefScript(output_policy, ctx.warning_bits);

        if (output_policy == POLICY_HIDE) {
            LEDGER_ASSERT(datum_policy == POLICY_HIDE,
                          "Output datum policy should be hidden when output is hidden");
            LEDGER_ASSERT(ref_script_policy == POLICY_HIDE,
                          "Output ref script policy should be hidden when output is hidden");
        }
    }

    // --- 3. Hash top-level ---
    if (mode->run_hash_builder) {
        hash_add_output_top_level(hash_builder, &output_desc, txHashBuilder_addOutput_topLevelData);
    }

    // --- 4. Asset groups and tokens ---
    ENFORCE_CANONICAL_ORDERING_START(policy_id_tracker);
    uint32_t total_token_count = 0;

    for (uint16_t asset_group_index = 0;
         asset_group_index < output_desc.numAssetGroups;
         asset_group_index++) {

        output_asset_group_t group = {0};
        if (!parse_output_asset_group(output_buf, &group)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_OUTPUTS);
            return false;
        }

        ENFORCE_CANONICAL_ORDERING_CHECK(policy_id_tracker,
                                         group.policyId, MINTING_POLICY_ID_LENGTH,
                                         SWO_TX_PARSING_FAIL_CANONICAL_ORDER);
        total_token_count += group.numTokens;

        if (mode->run_hash_builder) {
            txHashBuilder_addOutput_tokenGroup(hash_builder,
                                               group.policyId,
                                               MINTING_POLICY_ID_LENGTH,
                                               group.numTokens);
        }

        ENFORCE_CANONICAL_ORDERING_START(asset_name_tracker);

        for (uint16_t token_index = 0; token_index < group.numTokens; token_index++) {
            output_token_t token = {0};
            if (!parse_output_token(output_buf, &token)) {
                tx_handle_parse_error(SWO_TX_PARSING_FAIL_OUTPUTS);
                return false;
            }

            ENFORCE_CANONICAL_ORDERING_CHECK(asset_name_tracker,
                                             token.assetName, token.assetNameLen,
                                             SWO_TX_PARSING_FAIL_CANONICAL_ORDER);

            if (mode->run_validation) {
                APPLY_POLICY(output_policy, tx_ui_plan_or_render_output_token, mode, group.policyId, &token);
            }

            if (mode->run_hash_builder) {
                txHashBuilder_addOutput_token(hash_builder,
                                              token.assetName,
                                              token.assetNameLen,
                                              token.amount);
            }
        }
    }

    // Add token pair counts to plan now that total_token_count is known
    if (mode->run_validation && mode->run_ui_planning && output_policy == POLICY_SHOW) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_TOKEN * total_token_count;
    }

    // --- 5. Datum ---
    if (output_desc.includeDatum) {
        output_datum_t datum = {0};
        if (!parse_output_datum(output_buf, &datum)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_OUTPUTS);
            return false;
        }

        if (mode->run_validation) {
            APPLY_POLICY(datum_policy, tx_ui_plan_or_render_output_datum, mode, &datum);
        }

        if (mode->run_hash_builder) {
            if (datum.type == DATUM_HASH) {
                txHashBuilder_addOutput_datum(hash_builder,
                                              DATUM_HASH,
                                              datum.hash,
                                              OUTPUT_DATUM_HASH_LENGTH);
            } else {
                txHashBuilder_addOutput_datum(hash_builder,
                                              DATUM_INLINE,
                                              datum.inline_datum.buffer,
                                              datum.inline_datum.length);
                txHashBuilder_addOutput_datum_inline_chunk(hash_builder,
                                                           datum.inline_datum.buffer,
                                                           datum.inline_datum.length);
            }
        }
    }

    // --- 6. Ref script ---
    if (output_desc.includeRefScript) {
        ref_script_t ref_script = {0};
        if (!parse_output_ref_script(output_buf, &ref_script)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_OUTPUTS);
            return false;
        }

        if (mode->run_validation) {
            APPLY_POLICY(ref_script_policy, tx_ui_plan_or_render_output_ref_script, mode, &ref_script);
        }

        if (mode->run_hash_builder) {
            txHashBuilder_addOutput_referenceScript(hash_builder, ref_script.size);
            txHashBuilder_addOutput_referenceScript_dataChunk(hash_builder,
                                                              ref_script.data,
                                                              ref_script.size);
        }
    }

    if (buffer_can_read(output_buf, 1)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_OUTPUTS);
        return false;
    }

    return true;
}

/**
 * Process the collateral return output from output_buf.
 */
static bool tx_process_collateral_return_output(buffer_t *output_buf) {
    tx_parse_ctx_t ctx = tx_get_ctx();
    const tx_params_t *tx_params = ctx.tx_params;
    const parse_tx_mode_t *mode = ctx.mode;
    tx_hash_builder_t *hash_builder = ctx.hash_builder;

    // --- 1. Parse top-level output fields ---
    tx_output_description_t output_desc = {0};
    uint16_t status = parse_output_top_level(output_buf, &output_desc, SWO_TX_PARSING_FAIL_COLLATERAL_OUTPUT);
    if (status != SWO_OK) {
        tx_handle_parse_error(status);
        return false;
    }

    // --- 2. Policy, plan, render: top-level fields ---
    security_policy_t output_policy = POLICY_DENY;
    security_policy_t collateral_ada_policy = POLICY_DENY;
    security_policy_t collateral_tokens_policy = POLICY_DENY;

    if (mode->run_validation) {
        output_policy = policyForSignTxCollateralOutputAddress(
            &output_desc,
            tx_params->txSigningMode,
            tx_params->networkId,
            tx_params->protocolMagic,
            tx_params->includeTotalCollateral,
            ctx.warning_bits);

        if (output_policy == POLICY_SHOW && output_desc.numAssetGroups > 0) {
            warning_bits_set(ctx.warning_bits, WARNING_BIT_COLLATERAL_OUTPUT_WARNING);
        }
        APPLY_POLICY(output_policy, tx_ui_plan_or_render_collateral_output_address, mode, &output_desc);

        collateral_ada_policy = policyForSignTxCollateralOutputAdaAmount(
            output_policy,
            tx_params->includeTotalCollateral,
            ctx.warning_bits);
        APPLY_POLICY(collateral_ada_policy, tx_ui_plan_or_render_collateral_output_amount, mode, &output_desc);

        collateral_tokens_policy = policyForSignTxCollateralOutputTokens(
            output_policy,
            &output_desc,
            ctx.warning_bits);
    }

    // --- 3. Hash top-level ---
    if (mode->run_hash_builder) {
        hash_add_output_top_level(hash_builder, &output_desc, txHashBuilder_addCollateralOutput);
    }

    // --- 4. Asset groups and tokens ---
    ENFORCE_CANONICAL_ORDERING_START(policy_id_tracker);
    uint32_t total_token_count = 0;

    for (uint16_t asset_group_index = 0;
         asset_group_index < output_desc.numAssetGroups;
         asset_group_index++) {

        output_asset_group_t group = {0};
        if (!parse_output_asset_group(output_buf, &group)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_COLLATERAL_OUTPUT);
            return false;
        }

        ENFORCE_CANONICAL_ORDERING_CHECK(policy_id_tracker,
                                         group.policyId, MINTING_POLICY_ID_LENGTH,
                                         SWO_TX_PARSING_FAIL_CANONICAL_ORDER);
        total_token_count += group.numTokens;

        if (mode->run_hash_builder) {
            txHashBuilder_addCollateralOutput_tokenGroup(hash_builder,
                                                         group.policyId,
                                                         MINTING_POLICY_ID_LENGTH,
                                                         group.numTokens);
        }

        ENFORCE_CANONICAL_ORDERING_START(asset_name_tracker);

        for (uint16_t token_index = 0; token_index < group.numTokens; token_index++) {
            output_token_t token = {0};
            if (!parse_output_token(output_buf, &token)) {
                tx_handle_parse_error(SWO_TX_PARSING_FAIL_COLLATERAL_OUTPUT);
                return false;
            }

            ENFORCE_CANONICAL_ORDERING_CHECK(asset_name_tracker,
                                             token.assetName, token.assetNameLen,
                                             SWO_TX_PARSING_FAIL_CANONICAL_ORDER);

            if (mode->run_validation) {
                APPLY_POLICY(collateral_tokens_policy, tx_ui_plan_or_render_output_token, mode, group.policyId, &token);
            }

            if (mode->run_hash_builder) {
                txHashBuilder_addCollateralOutput_token(hash_builder,
                                                        token.assetName,
                                                        token.assetNameLen,
                                                        token.amount);
            }
        }
    }

    // Add token pair counts to plan now that total_token_count is known
    if (mode->run_validation && mode->run_ui_planning && collateral_tokens_policy == POLICY_SHOW) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_TOKEN * total_token_count;
    }

    // Collateral outputs MUST NOT contain datum or ref script
    LEDGER_ASSERT(!output_desc.includeDatum, "Collateral output with datum");
    LEDGER_ASSERT(!output_desc.includeRefScript, "Collateral output with ref script");

    if (buffer_can_read(output_buf, 1)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_COLLATERAL_OUTPUT);
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool tx_process_outputs(buffer_t *buf, tx_processing_state_t *state) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    tx_parse_ctx_t ctx = tx_get_ctx();
    const tx_params_t *tx_params = ctx.tx_params;
    const parse_tx_mode_t *mode = ctx.mode;

    if (mode->run_hash_builder) {
        LEDGER_ASSERT(state->hash_builder_initialized, "Hash builder not initialized");
        txHashBuilder_enterOutputs(&state->hash_builder);
    }

    for (uint16_t output_index = 0; output_index < tx_params->num_outputs; output_index++) {
        uint16_t output_length = 0;
        if (!buffer_read_u16(buf, &output_length, BE) ||
            !buffer_can_read(buf, output_length)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_OUTPUTS);
            return false;
        }

        const uint8_t *output_data_ptr = buffer_get_cur(buf);
        buffer_t output_buf = {
            .ptr = (uint8_t *) output_data_ptr,
            .size = output_length,
            .offset = 0,
        };

        if (!tx_process_output(&output_buf,
                                       output_index,
                                       state)) {
            return false;
        }

        if (!buffer_seek_cur(buf, output_length)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_OUTPUTS);
            return false;
        }
    }

#ifdef HAVE_SWAP
    if (mode->run_validation &&
        G_called_from_swap &&
        state->swap_third_party_output_count != 1) {
        swap_reject_and_exit(SWAP_EC_ERROR_WRONG_DESTINATION, SWAP_APP_CODE_DEFAULT);
    }
#endif

    return true;
}

bool tx_process_collateral_output(buffer_t *buf) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    tx_parse_ctx_t ctx = tx_get_ctx();
    const tx_params_t *tx_params = ctx.tx_params;

    if (!tx_params->includeCollateralOutput) {
        return true;
    }

    uint16_t output_length = 0;
    if (!buffer_read_u16(buf, &output_length, BE) ||
        !buffer_can_read(buf, output_length)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_COLLATERAL_OUTPUT);
        return false;
    }

    const uint8_t *output_data_ptr = buffer_get_cur(buf);
    buffer_t output_buf = {
        .ptr = (uint8_t *) output_data_ptr,
        .size = output_length,
        .offset = 0,
    };

    if (!tx_process_collateral_return_output(&output_buf)) {
        return false;
    }

    if (!buffer_seek_cur(buf, output_length)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_COLLATERAL_OUTPUT);
        return false;
    }
    return true;
}
