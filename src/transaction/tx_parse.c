/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "buffer.h"
#include "mem.h"

#include "cardano_swo.h"
#include "app_context.h"
#include "cbor.h"
#include "tx_parse.h"
#include "cardano_parsers.h"
#include "tx_parse_certificates.h"
#include "tx_parse_outputs.h"
#include "tx.h"
#include "utils.h"
#include "assert.h"
#include "tx_constants.h"
#include "tx_output_types.h"
#include "globals.h"

static parser_status_e parse_input_item(buffer_t *buf, flist_node_t **list_head, parser_status_e error_on_failure);
static parser_status_e parse_tx_inputs(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body);
static parser_status_e parse_tx_outputs(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body);
static parser_status_e parse_tx_mint_groups(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body);
static parser_status_e parse_tx_certificates(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body);
static parser_status_e parse_tx_withdrawals(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body);
static parser_status_e parse_tx_collateral_inputs(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body);
static parser_status_e parse_tx_required_signers(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body);
static parser_status_e parse_tx_collateral_output(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body);
static parser_status_e parse_tx_voting_procedures(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body);

static uint16_t _map_parser_status_to_swo(parser_status_e status) {
    switch (status) {
        // Transaction body CBOR key order:
        case INPUTS_PARSING_ERROR:              // key 0
        case INPUTS_COUNT_PARSING_ERROR:
            return SWO_TX_PARSING_FAIL_INPUTS;
        case OUTPUTS_PARSING_ERROR:             // key 1
        case OUTPUTS_COUNT_PARSING_ERROR:
        case OUTPUT_DESTINATION_TYPE_ERROR:
        case OUTPUT_ADDRESS_SIZE_ERROR:
            return SWO_TX_PARSING_FAIL_OUTPUTS;
        case FEE_PARSING_ERROR:                 // key 2
            return SWO_TX_PARSING_FAIL_FEE;
        case TTL_PARSING_ERROR:                 // key 3
            return SWO_TX_PARSING_FAIL_TTL;
        case CERTIFICATES_PARSING_ERROR:        // key 4
            return SWO_TX_PARSING_FAIL_CERTIFICATES;
        case WITHDRAWALS_PARSING_ERROR:         // key 5
            return SWO_TX_PARSING_FAIL_WITHDRAWALS;
        // key 7 is update (not supported)
        case VALIDITY_INTERVAL_START_PARSING_ERROR:  // key 8
            return SWO_TX_PARSING_FAIL_VALIDITY_INTERVAL_START;
        case MINT_PARSING_ERROR:                // key 9
            return SWO_TX_PARSING_FAIL_MINT;
        case SCRIPT_DATA_HASH_PARSING_ERROR:    // key 11
            return SWO_TX_PARSING_FAIL_SCRIPT_DATA_HASH;
        case COLLATERAL_INPUTS_PARSING_ERROR:   // key 13
            return SWO_TX_PARSING_FAIL_COLLATERAL_INPUTS;
        case REQUIRED_SIGNERS_PARSING_ERROR:    // key 14
            return SWO_TX_PARSING_FAIL_REQUIRED_SIGNERS;
        // key 15: network id - nothing to parse in body
        case COLLATERAL_OUTPUT_PARSING_ERROR:   // key 16
            return SWO_TX_PARSING_FAIL_COLLATERAL_OUTPUT;
        case TOTAL_COLLATERAL_PARSING_ERROR:    // key 17
            return SWO_TX_PARSING_FAIL_TOTAL_COLLATERAL;
        case REFERENCE_INPUTS_PARSING_ERROR:    // key 18
            return SWO_TX_PARSING_FAIL_REFERENCE_INPUTS;
        case VOTING_PROCEDURES_PARSING_ERROR:   // key 19
            return SWO_TX_PARSING_FAIL_VOTING_PROCEDURES;
        // key 20 is proposal procedures (NOT SUPPORTED - intentionally excluded from Ledger Cardano app)
        case TREASURY_PARSING_ERROR:        // key 21
            return SWO_TX_PARSING_FAIL_TREASURY;
        case DONATION_PARSING_ERROR:        // key 22
            return SWO_TX_PARSING_FAIL_DONATION;
        case CANONICAL_ORDERING_ERROR:
            return SWO_TX_PARSING_FAIL_CANONICAL_ORDER;
        case TX_SIZE_TOO_LARGE_ERROR:
            return SWO_INVALID_TX_LENGTH;
        case TX_BUFFER_NOT_FULLY_CONSUMED_ERROR:
            return SWO_TX_PARSING_FAIL_BUFFER_NOT_FULLY_CONSUMED;
        case OUT_OF_MEMORY_ERROR:
            return SWO_INSUFFICIENT_MEMORY;
    default:
        LEDGER_ASSERT(false, "Unmapped parser error - all cases should be explicit");
        return SWO_TX_PARSING_FAIL;  // fallback if assert is disabled
    }
}

static inline bool canonical_key_ok(bool has_previous,
                                    const uint8_t* previous,
                                    size_t previous_size,
                                    const uint8_t* next,
                                    size_t next_size) {
    if (!has_previous) {
        return true;
    }
    return cbor_mapKeyFulfillsCanonicalOrdering(previous, previous_size, next, next_size);
}

static void free_asset_group_node(output_asset_group_node_t *group_node) {
    if (group_node == NULL) {
        return;
    }
    flist_node_t *token_node = group_node->asset_group.tokens;
    while (token_node != NULL) {
        flist_node_t *token_next = token_node->next;
        APP_MEM_FREE(token_node);
        token_node = token_next;
    }
    group_node->asset_group.tokens = NULL;
    APP_MEM_FREE(group_node);
}

static void free_asset_groups(flist_node_t *group_node) {
    while (group_node != NULL) {
        flist_node_t *group_next = group_node->next;
        free_asset_group_node((output_asset_group_node_t *) group_node);
        group_node = group_next;
    }
}

static void free_output_item(tx_output_node_t *item) {
    if (item == NULL) {
        return;
    }

    // Free dynamically allocated address_params_t for device-owned outputs
    if (item->output_data.destination.type == DESTINATION_DEVICE_OWNED &&
        item->output_data.destination.params != NULL) {
        APP_MEM_FREE(item->output_data.destination.params);
        item->output_data.destination.params = NULL;
    }

    free_asset_groups(item->output_data.assetGroups);
    item->output_data.assetGroups = NULL;
    APP_MEM_FREE(item);
}

static void free_certificate_item(tx_certificate_node_t *item) {
    if (item == NULL) {
        return;
    }

    if (item->certificate.type == CERTIFICATE_STAKE_POOL_REGISTRATION) {
        flist_node_t *owner_node = item->certificate.poolRegistration.poolOwners;
        while (owner_node != NULL) {
            flist_node_t *next = owner_node->next;
            APP_MEM_FREE(owner_node);
            owner_node = next;
        }
        item->certificate.poolRegistration.poolOwners = NULL;

        flist_node_t *relay_node = item->certificate.poolRegistration.relays;
        while (relay_node != NULL) {
            flist_node_t *next = relay_node->next;
            APP_MEM_FREE(relay_node);
            relay_node = next;
        }
        item->certificate.poolRegistration.relays = NULL;
    }

    APP_MEM_FREE(item);
}

static void free_mint_item(mint_asset_group_node_t *item) {
    if (item == NULL) {
        return;
    }
    flist_node_t *token_node = item->asset_group.tokens;
    while (token_node != NULL) {
        flist_node_t *token_next = token_node->next;
        APP_MEM_FREE(token_node);
        token_node = token_next;
    }
    item->asset_group.tokens = NULL;
    APP_MEM_FREE(item);
}

static void free_vote_list(flist_node_t *vote_node) {
    while (vote_node != NULL) {
        flist_node_t *vote_next = vote_node->next;
        APP_MEM_FREE(vote_node);
        vote_node = vote_next;
    }
}

static void free_voter_votes_item(voter_votes_node_t *voter_item) {
    if (voter_item == NULL) {
        return;
    }

    free_vote_list(voter_item->voter_votes_data.votes);
    voter_item->voter_votes_data.votes = NULL;
    APP_MEM_FREE(voter_item);
}

parser_status_e parse_tx(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(tx_params != NULL, "NULL tx_params");
    LEDGER_ASSERT(tx_body != NULL, "NULL tx_body");

    if (buf->size > MAX_TX_BUFFER_SIZE) {
        return TX_SIZE_TOO_LARGE_ERROR;
    }

    // Initialize all transaction body fields
    explicit_bzero(tx_body, sizeof(*tx_body));

    parser_status_e status;

    // key 0: inputs
    status = parse_tx_inputs(buf, tx_params, tx_body);
    if (status != PARSING_OK) {
        return status;
    }

    // key 1: outputs
    status = parse_tx_outputs(buf, tx_params, tx_body);
    if (status != PARSING_OK) {
        return status;
    }

    // key 2: fee
    ASSERT_TYPE(tx_body->fee, uint64_t);
    if (!buffer_read_u64(buf, &tx_body->fee, BE)) {
        return FEE_PARSING_ERROR;
    }

    // key 3: ttl (optional)
    if (tx_params->includeTtl) {
        ASSERT_TYPE(tx_body->ttl, uint64_t);
        if (!buffer_read_u64(buf, &tx_body->ttl, BE)) {
            return TTL_PARSING_ERROR;
        }
    }

    // key 4: certificates
    TRACE("About to parse %u certificates", tx_params->num_certificates);
    status = parse_tx_certificates(buf, tx_params, tx_body);
    if (status != PARSING_OK) {
        TRACE("Certificate parsing failed with status=%d", status);
        return status;
    }
    TRACE("Successfully parsed all certificates");

    // key 5: withdrawals
    status = parse_tx_withdrawals(buf, tx_params, tx_body);
    if (status != PARSING_OK) {
        return status;
    }

    // key 8: validity_interval_start
    if (tx_params->includeValidityIntervalStart) {
        ASSERT_TYPE(tx_body->validityIntervalStart, uint64_t);
        if (!buffer_read_u64(buf, &tx_body->validityIntervalStart, BE)) {
            return VALIDITY_INTERVAL_START_PARSING_ERROR;
        }
    }

    // key 9: mint
    status = parse_tx_mint_groups(buf, tx_params, tx_body);
    if (status != PARSING_OK) {
        return status;
    }

    // key 11: script data hash
    if (tx_params->includeScriptDataHash) {
        if (!buffer_read_bytes_ptr(buf, &tx_body->scriptDataHash, SCRIPT_DATA_HASH_LENGTH)) {
            return SCRIPT_DATA_HASH_PARSING_ERROR;
        }
    }

    // key 13: collateral inputs
    if (tx_params->num_collateral_inputs > 0) {
        status = parse_tx_collateral_inputs(buf, tx_params, tx_body);
        if (status != PARSING_OK) {
            return status;
        }
    }

    // key 14: required signers
    if (tx_params->num_required_signers > 0) {
        status = parse_tx_required_signers(buf, tx_params, tx_body);
        if (status != PARSING_OK) {
            return status;
        }
    }

    // key 15: network ID - nothing to parse, just a flag (already in init APDU)

    // key 16: collateral output
    if (tx_params->includeCollateralOutput) {
        status = parse_tx_collateral_output(buf, tx_params, tx_body);
        if (status != PARSING_OK) {
            return status;
        }
    }

    // key 17: total collateral
    if (tx_params->includeTotalCollateral) {
        ASSERT_TYPE(tx_body->totalCollateral, uint64_t);
        if (!buffer_read_u64(buf, &tx_body->totalCollateral, BE)) {
            return TOTAL_COLLATERAL_PARSING_ERROR;
        }
    }

    // key 18: reference inputs (parsed same as regular inputs)
    if (tx_params->num_reference_inputs > 0) {
        for (uint16_t i = 0; i < tx_params->num_reference_inputs; i++) {
            status = parse_input_item(buf, &tx_body->reference_inputs, REFERENCE_INPUTS_PARSING_ERROR);
            if (status != PARSING_OK) {
                return status;
            }
        }
    }

    // key 19: voting procedures
    if (tx_params->num_voters > 0) {
        status = parse_tx_voting_procedures(buf, tx_params, tx_body);
        if (status != PARSING_OK) {
            return status;
        }
    }

    // key 21: treasury (optional)
    if (tx_params->includeTreasury) {
        ASSERT_TYPE(tx_body->treasury, uint64_t);
        if (!buffer_read_u64(buf, &tx_body->treasury, BE)) {
            return TREASURY_PARSING_ERROR;
        }
    }

    // key 22: donation (optional)
    if (tx_params->includeDonation) {
        ASSERT_TYPE(tx_body->donation, uint64_t);
        if (!buffer_read_u64(buf, &tx_body->donation, BE)) {
            return DONATION_PARSING_ERROR;
        }
    }

    if (buffer_can_read(buf, 1)) {
        TRACE("TX parsing: buffer not fully consumed");
        return TX_BUFFER_NOT_FULLY_CONSUMED_ERROR;
    }
    return PARSING_OK;
}


void tx_handle_parse_error(parser_status_e status) {
    LEDGER_ASSERT(status != PARSING_OK, "tx_handle_parse_error received PARSING_OK");
    uint16_t swo = _map_parser_status_to_swo(status);
    TRACE("tx_handle_parse_error status=%d swo=0x%04x", status, swo);
    send_swo_and_reset(swo);
}

// Helper function to parse a single input (reused for inputs, collateral inputs, reference inputs)
// error_on_failure: error code to return if parsing fails (e.g., INPUTS_PARSING_ERROR, COLLATERAL_INPUTS_PARSING_ERROR)
static parser_status_e parse_input_item(buffer_t *buf, flist_node_t **list_head, parser_status_e error_on_failure) {
    tx_input_node_t *item = NULL;
    if (!APP_MEM_CALLOC((void **) &item, (uint16_t) sizeof(*item))) {
        TRACE("parse_input_item: out of memory allocating tx_input_node");
        return OUT_OF_MEMORY_ERROR;
    }

    // Store pointer to tx hash in raw buffer instead of copying
    if (!buffer_read_bytes_ptr(buf, &item->input.txHash, TX_HASH_LENGTH)) {
        APP_MEM_FREE(item);
        return error_on_failure;
    }
    ASSERT(item->input.txHash != NULL);

    ASSERT_TYPE(item->input.index, uint32_t);
    if (!buffer_read_u32(buf, &item->input.index, BE)) {
        APP_MEM_FREE(item);
        return error_on_failure;
    }

    item->flist_node.next = NULL;
    flist_push_back(list_head, (flist_node_t *) item);
    return PARSING_OK;
}

static parser_status_e parse_tx_inputs(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    for (uint16_t i = 0; i < tx_params->num_inputs; i++) {
        parser_status_e status = parse_input_item(buf, &tx_body->inputs, INPUTS_PARSING_ERROR);
        if (status != PARSING_OK) {
            return status;
        }
    }
    return PARSING_OK;
}

static void cleanup_parsed_output(parsed_tx_output_t *output) {
    LEDGER_ASSERT(output != NULL, "NULL output");

    cleanup_output_destination(&output->destination);
    free_asset_groups(output->assetGroups);
    output->assetGroups = NULL;
}

static parser_status_e cleanup_token_parse_error(parsed_tx_output_t *output,
                                                 output_asset_group_node_t *group_node,
                                                 output_token_node_t *token_item,
                                                 parser_status_e status) {
    LEDGER_ASSERT(output != NULL, "NULL output");

    if (token_item != NULL) {
        APP_MEM_FREE(token_item);
    }
    if (group_node != NULL) {
        free_asset_group_node(group_node);
    }
    cleanup_parsed_output(output);
    return status;
}

static parser_status_e parse_output_asset_groups(buffer_t *output_buf,
                                                 parsed_tx_output_t *output,
                                                 parser_status_e parse_failure_status) {
    LEDGER_ASSERT(output_buf != NULL, "NULL output_buf");
    LEDGER_ASSERT(output != NULL, "NULL output");

    output->assetGroups = NULL;
    if (output->numAssetGroups == 0) {
        return PARSING_OK;
    }

    const uint8_t *previous_policy_id = NULL;
    bool has_previous_policy = false;

    for (uint16_t asset_group_index = 0; asset_group_index < output->numAssetGroups; asset_group_index++) {
        output_asset_group_node_t *group_node = NULL;
        if (!APP_MEM_CALLOC((void **) &group_node, (uint16_t) sizeof(*group_node))) {
            TRACE("Out of memory allocating asset group");
            cleanup_parsed_output(output);
            return OUT_OF_MEMORY_ERROR;
        }

        output_asset_group_t *group = &group_node->asset_group;
        if (!buffer_read_bytes_ptr(output_buf, &group->policyId, MINTING_POLICY_ID_LENGTH)) {
            free_asset_group_node(group_node);
            cleanup_parsed_output(output);
            return parse_failure_status;
        }
        ASSERT(group->policyId != NULL);

        if (!canonical_key_ok(has_previous_policy,
                              previous_policy_id,
                              MINTING_POLICY_ID_LENGTH,
                              group->policyId,
                              MINTING_POLICY_ID_LENGTH)) {
            TRACE("Output asset groups not canonical");
            free_asset_group_node(group_node);
            cleanup_parsed_output(output);
            return CANONICAL_ORDERING_ERROR;
        }
        previous_policy_id = group->policyId;
        has_previous_policy = true;

        ASSERT_TYPE(group->numTokens, uint16_t);
        if (!buffer_read_u16(output_buf, &group->numTokens, BE)) {
            free_asset_group_node(group_node);
            cleanup_parsed_output(output);
            return parse_failure_status;
        }
        TRACE("Deserialize: asset group %u: %u tokens",
              asset_group_index,
              group->numTokens);

        group->tokens = NULL;

        const uint8_t *previous_token_name = NULL;
        size_t previous_token_len = 0;
        bool has_previous_token = false;

        for (uint16_t token_index = 0; token_index < group->numTokens; token_index++) {
            output_token_node_t *token_item = NULL;
            if (!APP_MEM_CALLOC((void **) &token_item, (uint16_t) sizeof(*token_item))) {
                TRACE("Out of memory allocating token");
                free_asset_group_node(group_node);
                cleanup_parsed_output(output);
                return OUT_OF_MEMORY_ERROR;
            }

            output_token_t *token = &token_item->token_data;
            ASSERT_TYPE(token->assetNameLen, uint8_t);
            if (!buffer_read_u8(output_buf, &token->assetNameLen)) {
                return cleanup_token_parse_error(output,
                                                 group_node,
                                                 token_item,
                                                 parse_failure_status);
            }
            if (token->assetNameLen > MAX_ASSET_NAME_LENGTH) {
                return cleanup_token_parse_error(output,
                                                 group_node,
                                                 token_item,
                                                 parse_failure_status);
            }

            if (!buffer_read_bytes_ptr(output_buf, &token->assetName, token->assetNameLen)) {
                return cleanup_token_parse_error(output,
                                                 group_node,
                                                 token_item,
                                                 parse_failure_status);
            }
            ASSERT(token->assetName != NULL);

            if (!canonical_key_ok(has_previous_token,
                                  previous_token_name,
                                  previous_token_len,
                                  token->assetName,
                                  token->assetNameLen)) {
                TRACE("Output asset group %u tokens not canonical", asset_group_index);
                return cleanup_token_parse_error(output,
                                                 group_node,
                                                 token_item,
                                                 CANONICAL_ORDERING_ERROR);
            }
            previous_token_name = token->assetName;
            previous_token_len = token->assetNameLen;
            has_previous_token = true;

            ASSERT_TYPE(token->amount, uint64_t);
            if (!buffer_read_u64(output_buf, &token->amount, BE)) {
                return cleanup_token_parse_error(output,
                                                 group_node,
                                                 token_item,
                                                 parse_failure_status);
            }

            token_item->flist_node.next = NULL;
            flist_push_back(&group->tokens, (flist_node_t *) token_item);
        }

        group_node->flist_node.next = NULL;
        flist_push_back(&output->assetGroups, (flist_node_t *) group_node);
    }

    return PARSING_OK;
}

static parser_status_e parse_output_payload(buffer_t *output_buf,
                                            parsed_tx_output_t *output,
                                            parser_status_e parse_failure_status) {
    LEDGER_ASSERT(output_buf != NULL, "NULL output_buf");
    LEDGER_ASSERT(output != NULL, "NULL output");

    parser_status_e status = parse_output_destination(output_buf,
                                                      &output->destination);
    if (status != PARSING_OK) {
        if (status == OUT_OF_MEMORY_ERROR) {
            return OUT_OF_MEMORY_ERROR;
        }
        return parse_failure_status;
    }

    ASSERT_TYPE(output->adaAmount, uint64_t);
    if (!buffer_read_u64(output_buf, &output->adaAmount, BE)) {
        status = parse_failure_status;
        goto cleanup;
    }
    if (output->adaAmount >= LOVELACE_MAX_SUPPLY) {
        TRACE("Output ADA amount out of bounds: %llu",
              (unsigned long long) output->adaAmount);
        status = parse_failure_status;
        goto cleanup;
    }

    status = parse_output_format(output_buf, &output->format, parse_failure_status);
    if (status != PARSING_OK) {
        goto cleanup;
    }

    ASSERT_TYPE(output->numAssetGroups, uint16_t);
    if (!buffer_read_u16(output_buf, &output->numAssetGroups, BE)) {
        status = parse_failure_status;
        goto cleanup;
    }

    status = parse_output_asset_groups(output_buf,
                                       output,
                                       parse_failure_status);
    if (status != PARSING_OK) {
        goto cleanup;
    }

    status = parse_output_datum(output_buf, &output->datum, parse_failure_status);
    if (status != PARSING_OK) {
        goto cleanup;
    }

    status = parse_output_ref_script(output_buf, &output->refScript, parse_failure_status);
    if (status != PARSING_OK) {
        goto cleanup;
    }

    if (buffer_can_read(output_buf, 1)) {
        TRACE("Deserialize: output buffer not fully consumed: offset=%u, size=%u",
              (unsigned int) output_buf->offset,
              (unsigned int) output_buf->size);
        status = parse_failure_status;
        goto cleanup;
    }

    return PARSING_OK;

cleanup:
    cleanup_parsed_output(output);
    return status;
}

static parser_status_e parse_tx_outputs(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    for (uint16_t i = 0; i < tx_params->num_outputs; i++) {
        uint16_t output_len;
        if (!buffer_read_u16(buf, &output_len, BE)) {
            return OUTPUTS_PARSING_ERROR;
        }
        TRACE("Deserialize: Output %u: length=%u, buffer offset before parse=%u",
              i, output_len, (unsigned int) buf->offset);

        // Create sub-buffer for this output with exact length
        if (!buffer_can_read(buf, output_len)) {
            return OUTPUTS_PARSING_ERROR;
        }
        buffer_t output_buf = {
            .ptr = buffer_get_cur(buf),
            .size = output_len,
            .offset = 0
        };

        tx_output_node_t *item = NULL;
        if (!APP_MEM_CALLOC((void **) &item, (uint16_t) sizeof(*item))) {
            TRACE("parse_tx_outputs: out of memory allocating tx_output_node");
            return OUT_OF_MEMORY_ERROR;
        }

        parser_status_e status = parse_output_payload(&output_buf,
                                                      &item->output_data,
                                                      OUTPUTS_PARSING_ERROR);
        if (status != PARSING_OK) {
            free_output_item(item);
            return status;
        }
        TRACE("Deserialize: Output %u payload parsed", i);
        TRACE("Deserialize: Output %u fully consumed, advancing main buffer by %u bytes",
              i, output_len);

        // Advance main buffer past this output
        if (!buffer_seek_cur(buf, output_len)) {
            free_output_item(item);
            return OUTPUTS_PARSING_ERROR;
        }
        TRACE("Deserialize: Output %u complete, buffer offset now=%u",
              i,
              (unsigned int) buf->offset);

        item->flist_node.next = NULL;
        flist_push_back(&tx_body->outputs, (flist_node_t *) item);
    }
    return PARSING_OK;
}

static parser_status_e parse_tx_mint_groups(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    const uint8_t* previous_policy_id = NULL;
    bool has_previous_policy = false;

    for (uint16_t ag = 0; ag < tx_params->num_mint_asset_groups; ag++) {
        mint_asset_group_node_t *item = NULL;
        if (!APP_MEM_CALLOC((void **) &item, (uint16_t) sizeof(*item))) {
            TRACE("parse_tx_mint_groups: out of memory allocating mint asset group");
            return OUT_OF_MEMORY_ERROR;
        }

        // Store pointer to policy ID in raw buffer instead of copying
        if (!buffer_read_bytes_ptr(buf, &item->asset_group.policyId, MINTING_POLICY_ID_LENGTH)) {
            free_mint_item(item);
            return MINT_PARSING_ERROR;
        }
        ASSERT(item->asset_group.policyId != NULL);
        if (!canonical_key_ok(has_previous_policy,
                              previous_policy_id,
                              MINTING_POLICY_ID_LENGTH,
                              item->asset_group.policyId,
                              MINTING_POLICY_ID_LENGTH)) {
            TRACE("Mint asset groups not canonical");
            free_mint_item(item);
            return CANONICAL_ORDERING_ERROR;
        }
        previous_policy_id = item->asset_group.policyId;
        has_previous_policy = true;

        ASSERT_TYPE(item->asset_group.numTokens, uint16_t);
        if (!buffer_read_u16(buf, &item->asset_group.numTokens, BE)) {
            free_mint_item(item);
            return MINT_PARSING_ERROR;
        }

        // Initialize tokens linked list
        item->asset_group.tokens = NULL;

        const uint8_t* previous_token_name = NULL;
        size_t previous_token_len = 0;
        bool has_previous_token = false;

        for (uint16_t tk = 0; tk < item->asset_group.numTokens; tk++) {
            // Allocate list node for this token
            mint_token_node_t *token_item = NULL;
            if (!APP_MEM_CALLOC((void **) &token_item, (uint16_t) sizeof(*token_item))) {
                TRACE("parse_tx_mint_groups: out of memory allocating mint token node");
                free_mint_item(item);
                return OUT_OF_MEMORY_ERROR;
            }

            mint_token_t *token = &token_item->token;
            if (!buffer_read_u8(buf, &token->assetNameLen)) {
                APP_MEM_FREE(token_item);
                free_mint_item(item);
                return MINT_PARSING_ERROR;
            }
            if (token->assetNameLen > MAX_MINT_ASSET_NAME_LENGTH) {
                APP_MEM_FREE(token_item);
                free_mint_item(item);
                return MINT_PARSING_ERROR;
            }

            // Store pointer to asset name in raw buffer instead of copying.
            // Empty asset names are valid (`asset_name` is CBOR bytes in Cardano CDDL).
            if (!buffer_read_bytes_ptr(buf, &token->assetName, token->assetNameLen)) {
                APP_MEM_FREE(token_item);
                free_mint_item(item);
                return MINT_PARSING_ERROR;
            }
            ASSERT(token->assetName != NULL);

            if (!canonical_key_ok(has_previous_token,
                                  previous_token_name,
                                  previous_token_len,
                                  token->assetName,
                                  token->assetNameLen)) {
                TRACE("Mint asset group %u tokens not canonical", ag);
                APP_MEM_FREE(token_item);
                free_mint_item(item);
                return CANONICAL_ORDERING_ERROR;
            }
            previous_token_name = token->assetName;
            previous_token_len = token->assetNameLen;
            has_previous_token = true;

            if (!buffer_read_int64(buf, &token->amount, BE)) {
                APP_MEM_FREE(token_item);
                free_mint_item(item);
                return MINT_PARSING_ERROR;
            }

            TRACE("Deserialize: Mint token %u: name_len=%u, amount=", tk, token->assetNameLen);
            TRACE("%lld", (long long) token->amount);

            // Add token to asset group's token list
            token_item->flist_node.next = NULL;
            flist_push_back(&item->asset_group.tokens, (flist_node_t *) token_item);
        }

        item->flist_node.next = NULL;
        flist_push_back(&tx_body->mint_asset_groups, (flist_node_t *) item);
    }
    return PARSING_OK;
}

/// Parse certificate data structure supporting multiple certificate types
static parser_status_e parse_tx_certificates(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    TRACE("parse_tx_certificates: num_certificates=%u buf->offset=%u buf->size=%u",
          tx_params->num_certificates,
          (unsigned int) buf->offset,
          (unsigned int) buf->size);
    for (uint16_t i = 0; i < tx_params->num_certificates; i++) {
        tx_certificate_node_t *item = NULL;
        if (!APP_MEM_CALLOC((void **) &item, (uint16_t) sizeof(*item))) {
            TRACE("OUT OF MEMORY");
            return OUT_OF_MEMORY_ERROR;
        }

        // Read certificate type
        uint8_t cert_type_wire;
        if (!buffer_read_u8(buf, &cert_type_wire)) {
            TRACE("FAILED TO READ CERTIFICATE TYPE BYTE");
            APP_MEM_FREE(item);
            return CERTIFICATES_PARSING_ERROR;
        }
        certificate_type_t cert_type = (certificate_type_t) cert_type_wire;
        TRACE("Deserialize: Certificate %u type=%u", i, cert_type_wire);

        // Parse certificate data based on type
        parser_status_e status = PARSING_OK;
        switch (cert_type) {
            case CERTIFICATE_STAKE_REGISTRATION:
            case CERTIFICATE_STAKE_DEREGISTRATION:
                status = parse_certificate_stake_registration_deregistration(buf, cert_type, &item->certificate);
                break;

            case CERTIFICATE_STAKE_DELEGATION:
                status = parse_certificate_stake_delegation(buf, &item->certificate);
                break;

            case CERTIFICATE_STAKE_REGISTRATION_CONWAY:
            case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY:
                status = parse_certificate_stake_registration_deregistration_conway(buf, cert_type, &item->certificate);
                break;

            case CERTIFICATE_STAKE_POOL_RETIREMENT:
                status = parse_certificate_stake_pool_retirement(buf, &item->certificate);
                break;

            case CERTIFICATE_VOTE_DELEGATION:
                status = parse_certificate_vote_delegation(buf, &item->certificate);
                break;

            case CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION:
                status = parse_certificate_stake_pool_and_drep_delegation(buf, &item->certificate);
                break;
            case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL:
                status = parse_certificate_account_registration_delegation_to_stake_pool(buf, &item->certificate);
                break;
            case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP:
                status = parse_certificate_account_registration_delegation_to_drep(buf, &item->certificate);
                break;
            case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP:
                status = parse_certificate_account_registration_delegation_to_stake_pool_and_drep(buf, &item->certificate);
                break;

            case CERTIFICATE_AUTHORIZE_COMMITTEE_HOT:
                status = parse_certificate_authorize_committee_hot(buf, &item->certificate);
                break;

            case CERTIFICATE_RESIGN_COMMITTEE_COLD:
                status = parse_certificate_resign_committee_cold(buf, &item->certificate);
                break;

            case CERTIFICATE_DREP_REGISTRATION:
                status = parse_certificate_drep_registration(buf, &item->certificate);
                break;

            case CERTIFICATE_DREP_DEREGISTRATION:
                status = parse_certificate_drep_deregistration(buf, &item->certificate);
                break;

            case CERTIFICATE_DREP_UPDATE:
                status = parse_certificate_drep_update(buf, &item->certificate);
                break;

            case CERTIFICATE_STAKE_POOL_REGISTRATION:
                status = parse_certificate_stake_pool_registration(buf, &item->certificate);
                break;

        default:
            // Unknown certificate type
            status = CERTIFICATES_PARSING_ERROR;
            break;
        }

        if (status != PARSING_OK) {
            TRACE("Certificate parse failure: type=%u status=%d", cert_type_wire, status);
            free_certificate_item(item);
            return status;
        }

        item->flist_node.next = NULL;
        flist_push_back(&tx_body->certificates, (flist_node_t *) item);
    }
    return PARSING_OK;
}

static parser_status_e parse_tx_withdrawals(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    // Withdrawals are serialized as a canonical CBOR map keyed by reward accounts.
    // Building those addresses here would require deriving them before the security
    // policies run, so the canonical-order enforcement for withdrawals is postponed
    // to the later planning stage where the derived reward addresses are already
    // exposed to policy checks.
    for (uint16_t i = 0; i < tx_params->num_withdrawals; i++) {
        tx_withdrawal_node_t *item = NULL;
        if (!APP_MEM_CALLOC((void **) &item, (uint16_t) sizeof(*item))) {
            TRACE("parse_tx_withdrawals: out of memory allocating withdrawal node");
            return OUT_OF_MEMORY_ERROR;
        }

        ASSERT_TYPE(item->withdrawal.amount, uint64_t);
        if (!buffer_read_u64(buf, &item->withdrawal.amount, BE)) {
            APP_MEM_FREE(item);
            return WITHDRAWALS_PARSING_ERROR;
        }

        parser_status_e status = parse_stake_credential(buf, &item->withdrawal.stakeCredential);
        if (status != PARSING_OK) {
            TRACE("Withdrawal %u credential parsing failed: status=%d", i, status);
            APP_MEM_FREE(item);
            return status;
        }

        TRACE("Deserialize: Withdrawal %u, type=%u", i, item->withdrawal.stakeCredential.type);

        item->flist_node.next = NULL;
        flist_push_back(&tx_body->withdrawals, (flist_node_t *) item);
    }
    return PARSING_OK;
}

/// Clean up dynamically allocated memory in transaction outputs (including list items)
void transaction_free_outputs(tx_parsed_body_t *tx_body) {
    LEDGER_ASSERT(tx_body != NULL, "NULL tx_body");

    flist_node_t *output_node = tx_body->outputs;
    while (output_node != NULL) {
        flist_node_t *next = output_node->next;

        free_output_item((tx_output_node_t *) output_node);
        output_node = next;
    }
    tx_body->outputs = NULL;
}

/// Clean up dynamically allocated memory in transaction certificates (including list items)
void transaction_free_certificates(tx_parsed_body_t *tx_body) {
    LEDGER_ASSERT(tx_body != NULL, "NULL tx_body");

    flist_node_t *certificate_node = tx_body->certificates;
    while (certificate_node != NULL) {
        flist_node_t *next = certificate_node->next;
        free_certificate_item((tx_certificate_node_t *) certificate_node);
        certificate_node = next;
    }
    tx_body->certificates = NULL;
}

void transaction_free_withdrawals(tx_parsed_body_t *tx_body) {
    LEDGER_ASSERT(tx_body != NULL, "NULL tx_body");

    flist_node_t *withdrawal_node = tx_body->withdrawals;
    while (withdrawal_node != NULL) {
        // Withdrawal items don't have additional allocated memory
        // (credential data is stored inline in the union)
        flist_node_t *next = withdrawal_node->next;
        APP_MEM_FREE(withdrawal_node);
        withdrawal_node = next;
    }
    tx_body->withdrawals = NULL;
}

/// Clean up dynamically allocated memory in transaction mint (including list items)
void transaction_free_mint(tx_parsed_body_t *tx_body) {
    LEDGER_ASSERT(tx_body != NULL, "NULL tx_body");

    flist_node_t *mint_node = tx_body->mint_asset_groups;
    while (mint_node != NULL) {
        mint_asset_group_node_t *item = (mint_asset_group_node_t *) mint_node;
        flist_node_t *next = mint_node->next;

        // Free all token nodes in the linked list
        flist_node_t *token_node = item->asset_group.tokens;
        while (token_node != NULL) {
            flist_node_t *token_next = token_node->next;
            APP_MEM_FREE(token_node);
            token_node = token_next;
        }

        // Free the list item itself
        APP_MEM_FREE(mint_node);
        mint_node = next;
    }
    tx_body->mint_asset_groups = NULL;
}

/// Clean up collateral inputs (same structure as regular inputs)
void transaction_free_collateral_inputs(tx_parsed_body_t *tx_body) {
    LEDGER_ASSERT(tx_body != NULL, "NULL tx_body");

    flist_node_t *input_node = tx_body->collateral_inputs;
    while (input_node != NULL) {
        flist_node_t *next = input_node->next;
        APP_MEM_FREE(input_node);
        input_node = next;
    }
    tx_body->collateral_inputs = NULL;
}

/// Clean up required signers
void transaction_free_required_signers(tx_parsed_body_t *tx_body) {
    LEDGER_ASSERT(tx_body != NULL, "NULL tx_body");

    flist_node_t *signer_node = tx_body->required_signers;
    while (signer_node != NULL) {
        flist_node_t *next = signer_node->next;
        APP_MEM_FREE(signer_node);
        signer_node = next;
    }
    tx_body->required_signers = NULL;
}

/// Clean up reference inputs (same structure as regular inputs)
void transaction_free_reference_inputs(tx_parsed_body_t *tx_body) {
    LEDGER_ASSERT(tx_body != NULL, "NULL tx_body");

    flist_node_t *input_node = tx_body->reference_inputs;
    while (input_node != NULL) {
        flist_node_t *next = input_node->next;
        APP_MEM_FREE(input_node);
        input_node = next;
    }
    tx_body->reference_inputs = NULL;
}

void transaction_free_voting_procedures(tx_parsed_body_t *tx_body) {
    LEDGER_ASSERT(tx_body != NULL, "NULL tx_body");

    flist_node_t *voter_node = tx_body->voting_procedures;
    while (voter_node != NULL) {
        voter_votes_node_t *voter_item = (voter_votes_node_t *) voter_node;
        flist_node_t *next = voter_node->next;
        free_vote_list(voter_item->voter_votes_data.votes);
        APP_MEM_FREE(voter_node);
        voter_node = next;
    }
    tx_body->voting_procedures = NULL;
}

void transaction_free_collateral_output(tx_parsed_body_t *tx_body) {
    LEDGER_ASSERT(tx_body != NULL, "NULL tx_body");

    cleanup_parsed_output(&tx_body->collateral_output);
    tx_body->collateral_output.numAssetGroups = 0;
}

/**
 * Cleanup transaction lists by freeing all allocated memory
 */
void tx_context_cleanup(void) {
    tx_parsed_body_t *tx_body = &G_context.tx_info.tx_body;

    // Free in CBOR key order (matches transaction_body CDDL)
    // key 0: inputs
    flist_node_t *input_node = tx_body->inputs;
    while (input_node != NULL) {
        flist_node_t *next = input_node->next;
        APP_MEM_FREE(input_node);
        input_node = next;
    }
    tx_body->inputs = NULL;

    // key 1: outputs
    transaction_free_outputs(tx_body);

    // key 4: certificates
    transaction_free_certificates(tx_body);

    // key 5: withdrawals
    transaction_free_withdrawals(tx_body);

    // key 9: mint
    transaction_free_mint(tx_body);

    // key 13: collateral inputs
    transaction_free_collateral_inputs(tx_body);

    // key 14: required signers
    transaction_free_required_signers(tx_body);

    // key 18: reference inputs
    transaction_free_reference_inputs(tx_body);

    // key 19: voting procedures
    transaction_free_voting_procedures(tx_body);

    // key 16: collateral output
    transaction_free_collateral_output(tx_body);

    // Free raw tx buffer
    APP_MEM_FREE_AND_NULL((void **) &G_context.tx_info.raw_tx);
    G_context.tx_info.planned_ui_pairs = 0;
}

// ================== Parsing functions for elements 13-18 ==================

static parser_status_e parse_tx_collateral_inputs(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    for (uint16_t i = 0; i < tx_params->num_collateral_inputs; i++) {
        parser_status_e status = parse_input_item(buf, &tx_body->collateral_inputs, COLLATERAL_INPUTS_PARSING_ERROR);
        if (status != PARSING_OK) {
            return status;
        }
    }
    return PARSING_OK;
}

static parser_status_e parse_tx_required_signers(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    for (uint16_t i = 0; i < tx_params->num_required_signers; i++) {
        tx_required_signer_node_t *item = NULL;
        if (!APP_MEM_CALLOC((void **) &item, (uint16_t) sizeof(*item))) {
            TRACE("parse_tx_required_signers: out of memory allocating signer node");
            return OUT_OF_MEMORY_ERROR;
        }

        // Read signer type (1 byte)
        uint8_t type;
        if (!buffer_read_u8(buf, &type)) {
            APP_MEM_FREE(item);
            return REQUIRED_SIGNERS_PARSING_ERROR;
        }
        item->required_signer.type = (required_signer_type_t) type;

        // Read path or hash based on type
        switch (item->required_signer.type) {
            case REQUIRED_SIGNER_WITH_PATH:
                // Parse BIP44 path
                if (!buffer_read_bip44_path(buf, &item->required_signer.keyPath)) {
                    APP_MEM_FREE(item);
                    return REQUIRED_SIGNERS_PARSING_ERROR;
                }
                break;
            case REQUIRED_SIGNER_WITH_HASH:
                // Read 28-byte key hash
                if (!buffer_read_bytes_ptr(buf, &item->required_signer.keyHash, ADDRESS_KEY_HASH_LENGTH)) {
                    APP_MEM_FREE(item);
                    return REQUIRED_SIGNERS_PARSING_ERROR;
                }
                ASSERT(item->required_signer.keyHash != NULL);
                break;
            default:
                APP_MEM_FREE(item);
                return REQUIRED_SIGNERS_PARSING_ERROR;
        }

        item->flist_node.next = NULL;
        flist_push_back(&tx_body->required_signers, (flist_node_t *) item);
    }
    return PARSING_OK;
}

static parser_status_e parse_tx_collateral_output(buffer_t *buf, const tx_params_t *tx_params MARK_UNUSED, tx_parsed_body_t *tx_body) {
    uint16_t output_len;
    if (!buffer_read_u16(buf, &output_len, BE)) {
        return COLLATERAL_OUTPUT_PARSING_ERROR;
    }

    if (!buffer_can_read(buf, output_len)) {
        return COLLATERAL_OUTPUT_PARSING_ERROR;
    }

    buffer_t output_buf = {
        .ptr = buffer_get_cur(buf),
        .size = output_len,
        .offset = 0
    };

    parser_status_e status = parse_output_payload(&output_buf,
                                                  &tx_body->collateral_output,
                                                  COLLATERAL_OUTPUT_PARSING_ERROR);
    if (status != PARSING_OK) {
        return status;
    }

    TRACE("Deserialize: Collateral output payload parsed");

    if (!buffer_seek_cur(buf, output_len)) {
        return COLLATERAL_OUTPUT_PARSING_ERROR;
    }

    return PARSING_OK;
}

static parser_status_e parse_tx_voting_procedures(buffer_t *buf, const tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    parser_status_e status = PARSING_OK;
    voter_votes_node_t *voter_item = NULL;
    vote_node_t *vote_item = NULL;

    // The voter list is defined as a canonical CBOR map keyed by voters. The
    // canonical ordering cannot be enforced here because the voter key encoding
    // depends on the credential type (paths would need to be hashed/derived),
    // and those derived bytes are not exposed before security policies execute.
    // Validating the canonical order therefore happens later (see
    // tx_validate_and_compute_hash) after policy checks have already derived
    // the voter keys.
    // For each voter in the outer map
    for (uint16_t voter_idx = 0; voter_idx < tx_params->num_voters; voter_idx++) {
        // Allocate list node for this voter
        voter_item = NULL;
        if (!APP_MEM_CALLOC((void **) &voter_item, (uint16_t) sizeof(*voter_item))) {
            TRACE("parse_tx_voting_procedures: out of memory allocating voter node");
            status = OUT_OF_MEMORY_ERROR;
            goto cleanup;
        }

        // Initialize votes list
        voter_item->voter_votes_data.votes = NULL;

        // Parse voter (ext_voter_t)
        uint8_t voter_type_byte;
        if (!buffer_read_u8(buf, &voter_type_byte)) {
            status = VOTING_PROCEDURES_PARSING_ERROR;
            goto cleanup;
        }
        voter_item->voter_votes_data.voter.type = (ext_voter_type_t) voter_type_byte;

        // Parse voter key/hash based on type
        switch (voter_item->voter_votes_data.voter.type) {
            case EXT_VOTER_COMMITTEE_HOT_KEY_PATH:
            case EXT_VOTER_DREP_KEY_PATH:
            case EXT_VOTER_STAKE_POOL_KEY_PATH:
                if (!buffer_read_bip44_path(buf, &voter_item->voter_votes_data.voter.keyPath)) {
                    status = VOTING_PROCEDURES_PARSING_ERROR;
                    goto cleanup;
                }
                break;

            case EXT_VOTER_COMMITTEE_HOT_KEY_HASH:
            case EXT_VOTER_DREP_KEY_HASH:
            case EXT_VOTER_STAKE_POOL_KEY_HASH:
                if (!buffer_read_bytes_ptr(buf, &voter_item->voter_votes_data.voter.keyHash,
                                           ADDRESS_KEY_HASH_LENGTH)) {
                    status = VOTING_PROCEDURES_PARSING_ERROR;
                    goto cleanup;
                }
                break;

            case EXT_VOTER_COMMITTEE_HOT_SCRIPT_HASH:
            case EXT_VOTER_DREP_SCRIPT_HASH:
                if (!buffer_read_bytes_ptr(buf, &voter_item->voter_votes_data.voter.scriptHash,
                                           SCRIPT_HASH_LENGTH)) {
                    status = VOTING_PROCEDURES_PARSING_ERROR;
                    goto cleanup;
                }
                break;

            default:
                status = VOTING_PROCEDURES_PARSING_ERROR;
                goto cleanup;
        }

        ASSERT_TYPE(voter_item->voter_votes_data.numVotes, uint16_t);
        if (!buffer_read_u16(buf, &voter_item->voter_votes_data.numVotes, BE)) {
            status = VOTING_PROCEDURES_PARSING_ERROR;
            goto cleanup;
        }

        // Parse each vote for this voter
        for (uint16_t vote_idx = 0; vote_idx < voter_item->voter_votes_data.numVotes; vote_idx++) {
            // Allocate list node for this vote
            vote_item = NULL;
            if (!APP_MEM_CALLOC((void **) &vote_item, (uint16_t) sizeof(*vote_item))) {
                TRACE("parse_tx_voting_procedures: out of memory allocating vote node");
                status = OUT_OF_MEMORY_ERROR;
                goto cleanup;
            }

            // Parse gov_action_id (tx_hash + index)
            if (!buffer_read_bytes_ptr(buf, &vote_item->vote_data.govActionId.txHash, TX_HASH_LENGTH)) {
                status = VOTING_PROCEDURES_PARSING_ERROR;
                goto cleanup;
            }
            ASSERT(vote_item->vote_data.govActionId.txHash != NULL);

            ASSERT_TYPE(vote_item->vote_data.govActionId.govActionIndex, uint32_t);
            if (!buffer_read_u32(buf, &vote_item->vote_data.govActionId.govActionIndex, BE)) {
                status = VOTING_PROCEDURES_PARSING_ERROR;
                goto cleanup;
            }
            // Parse voting_procedure (vote + optional anchor)
            uint8_t vote_byte;
            if (!buffer_read_u8(buf, &vote_byte)) {
                status = VOTING_PROCEDURES_PARSING_ERROR;
                goto cleanup;
            }
            switch (vote_byte) {
                case VOTE_NO:
                case VOTE_YES:
                case VOTE_ABSTAIN:
                    vote_item->vote_data.voteOption = (vote_t) vote_byte;
                    break;
                default:
                    status = VOTING_PROCEDURES_PARSING_ERROR;
                    goto cleanup;
            }

            if (!buffer_read_anchor(buf, &vote_item->vote_data.anchor)) {
                status = VOTING_PROCEDURES_PARSING_ERROR;
                goto cleanup;
            }

            // Add vote to voter's vote list
            vote_item->flist_node.next = NULL;
            flist_push_back(&voter_item->voter_votes_data.votes, (flist_node_t *) vote_item);
            vote_item = NULL;
        }

        // Add voter to transaction's voter list
        voter_item->flist_node.next = NULL;
        flist_push_back(&tx_body->voting_procedures, (flist_node_t *) voter_item);
        voter_item = NULL;
    }

    return PARSING_OK;

cleanup:
    if (vote_item != NULL) {
        APP_MEM_FREE(vote_item);
    }
    free_voter_votes_item(voter_item);
    transaction_free_voting_procedures(tx_body);
    return status;
}

// Reference inputs parsing is inline in parse_tx() since they use the same format as regular inputs
