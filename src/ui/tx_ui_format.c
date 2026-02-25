/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file tx_ui_format.c
 * @brief Transaction UI formatting (Phase 2 of 2-phase architecture)
 *
 * This file implements Phase 2 of transaction processing: formatting the validated
 * transaction into human-readable strings for display on the device.
 *
 * ## Architecture Overview
 *
 * **Phase 1** (tx_validate.c) has already:
 * - Validated the transaction structure
 * - Run security policies (rejecting unsafe transactions)
 * - Computed the transaction hash
 * - Counted how many UI pairs will be needed
 *
 * **Phase 2** (this file) now:
 * - Formats each transaction element into display strings
 * - Builds NBGL key-value pairs for the UI
 * - Constructs warning structures
 * - Frees parsed transaction data after formatting
 *
 * ## CRITICAL SYNCHRONIZATION REQUIREMENT
 *
 * The number of UI pairs added in this file MUST EXACTLY MATCH the count from Phase 1.
 * This is verified by a runtime ASSERT (line ~2040).
 *
 * **When adding new displayable fields:**
 * 1. Update tx_validate.c to count the additional pairs
 * 2. Update this file to format and display those pairs
 * 3. Ensure both files iterate elements in IDENTICAL order
 *
 * **Example:** Device-owned addresses show 2 extra pairs:
 * - tx_validate.c: `plan->pair_count += 2`  (line 257, 1269)
 * - tx_ui_format.c: calls `addPaymentInfoUIPairs()` + `addStakingInfoUIPairs()` (line 263, 1655)
 *
 * See tx_validate.h for complete architecture documentation.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "cardano_swo.h"
#include "globals.h"
#include "format.h"
#include "ui_constants.h"
#include "tx_output_types.h"
#include "tx.h"
#include "tx_parse_outputs.h"
#include "tx_ui_plan.h"
#include "keyDerivation.h"
#include "mem.h"
#include "securityPolicy.h"
#include "securityWarnings.h"
#include "tx_utils.h"
#include "assert.h"
#include "ipUtils.h"
#include "ui_utils.h"
#include "ui_formatters.h"
#include "ui_warnings.h"
#include "ui_display_tx.h"
#include "tx_ui_helpers.h"
#include "io.h"
#include "app_context.h"
#include "cardano_tokens.h"
#include "tx_voting_procedure_types.h"
#include "bech32.h"

// Max display lengths
#define MAX_DATUM_HASH_STRING_LENGTH (2 * OUTPUT_DATUM_HASH_LENGTH + 1)
#define MAX_INPUT_DISPLAY_STRING_LENGTH (MAX_TX_HASH_DISPLAY_LENGTH + 3 + MAX_UINT64_STRING_LENGTH)

static bool format_input_with_index(const tx_input_t *input, char *out, size_t out_size) {
    LEDGER_ASSERT(out != NULL, "NULL output buffer");
    LEDGER_ASSERT(input != NULL, "NULL input");
    int hex_status = bytes_to_lowercase_hex(out, out_size, input->txHash, TX_HASH_LENGTH);
    if (hex_status != 0) {
        return false;
    }
    size_t hash_len = strlen(out);
    if (hash_len + 1 >= out_size) {
        return false;
    }
    STATIC_ASSERT(!IS_SIGNED_TYPE(typeof(input->index)), "signed type for %u");
    int written = snprintf(out + hash_len, out_size - hash_len, " / %u", input->index);
    LEDGER_ASSERT(written > 0, "snprintf input index formatting failed");
    LEDGER_ASSERT((size_t)written + hash_len + 1 <= out_size, "Input display buffer overflow");
    return true;
}

static void add_ui_network_details(const tx_params_t* tx_params) {
    LEDGER_ASSERT(tx_params != NULL, "NULL tx_params");

    if (!shouldShowNetworkDetails(tx_params)) {
        return;
    }

    START_COUNT();
    UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Network ID", "Net ID"),
                   MAX_UINT64_STRING_LENGTH,
                   format_uint64,
                   (uint64_t) tx_params->networkId);
    UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Protocol magic", "Prot magic"),
                   MAX_UINT64_STRING_LENGTH,
                   format_uint64,
                   (uint64_t) tx_params->protocolMagic);
    CHECK_COUNT(UI_PAIRS_NETWORK_DETAILS);
}

static void add_ui_and_free_inputs(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    flist_node_t *node = tx_body->inputs;
    while (node != NULL) {
        tx_input_node_t *input_node = (tx_input_node_t *) node;
        security_policy_t input_policy = policyForSignTxInput(tx_params->txSigningMode, &input_node->input, &G_context.tx_info.warning_bits);
        LEDGER_ASSERT(input_policy != POLICY_DENY, "Input denied during UI");

        if (input_policy == POLICY_SHOW) {
            START_COUNT();
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Input"), MAX_INPUT_DISPLAY_STRING_LENGTH, format_input_with_index, &input_node->input);
            CHECK_COUNT(UI_PAIRS_INPUT);
        }

        node = node->next;
        APP_MEM_FREE(input_node); // only after next is assigned
    }
    tx_body->inputs = NULL;
}


static uint16_t count_output_tokens(flist_node_t* asset_group_nodes) {
    uint16_t total_tokens = 0;
    flist_node_t *node = asset_group_nodes;
    while (node != NULL) {
        output_asset_group_node_t *group_node = (output_asset_group_node_t *) node;
        total_tokens += group_node->asset_group.numTokens;
        node = node->next;
    }
    return total_tokens;
}

static void add_ui_and_free_output_tokens(const output_asset_group_t *group,
                                               flist_node_t *token_nodes,
                                               bool show_tokens) {
    flist_node_t *node = token_nodes;
    while (node != NULL) {
        output_token_node_t *token_node = (output_token_node_t *) node;
        output_token_t *token = &token_node->token_data;

        if (show_tokens) {
            UI_ADD_FORMAT3(UI_STATIC_LABEL("Fingerprint"), MAX_TOKEN_FINGERPRINT_STRING_LENGTH, format_asset_fingerprint_bech32, group->policyId, token->assetName, token->assetNameLen);
            UI_ADD_FORMAT4(UI_STATIC_LABEL("Token amount"), MAX_TOKEN_AMOUNT_STRING_LENGTH, format_token_amount_output, group->policyId, token->assetName, token->assetNameLen, token->amount);
        }

        node = node->next;
        APP_MEM_FREE(token_node);
    }
}

static void add_ui_and_free_output_asset_groups(flist_node_t* asset_group_nodes,
                                            uint16_t numGroups,
                                            bool show_tokens) {
    uint16_t group_count = 0;
    flist_node_t *node = asset_group_nodes;
    while (node != NULL) {
        group_count++;
        output_asset_group_node_t *group_node = (output_asset_group_node_t *) node;
        output_asset_group_t *group = &group_node->asset_group;
        add_ui_and_free_output_tokens(group, group->tokens, show_tokens);
        group->tokens = NULL;

        node = node->next;
        APP_MEM_FREE(group_node);
    }
    LEDGER_ASSERT(group_count == numGroups, "Output asset group count mismatch");
}

// Helper function to format output address (handles both third-party and device-owned destinations)
static bool format_output_address(const tx_output_description_t *output_desc, char *out, size_t out_size) {
    LEDGER_ASSERT(output_desc != NULL, "NULL output_desc");

    return format_tx_output_destination_human_readable(&output_desc->destination, out, out_size);
}

// Keep this in lockstep with tx_validate.c output pair-counting rules.
static void add_ui_and_free_outputs(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    uint16_t output_num = 1;
    flist_node_t *node = tx_body->outputs;
    TRACE("Formatting %u outputs", tx_params->num_outputs);
    while (node != NULL) {
        tx_output_node_t *output_node = (tx_output_node_t *) node;

        tx_output_description_t output_desc = {
            .format = output_node->output_data.format,
            .amount = output_node->output_data.adaAmount,
            .numAssetGroups = output_node->output_data.numAssetGroups,
            .includeDatum = (output_node->output_data.datum != NULL),
            .includeRefScript = (output_node->output_data.refScript != NULL),
        };

        output_desc.destination = output_node->output_data.destination;

        warning_bits_t output_warnings = 0;
        security_policy_t policy = policyForSignTxOutput(
            &output_desc,
            tx_params->txSigningMode,
            tx_params->networkId,
            tx_params->protocolMagic,
            &output_warnings
        );
                LEDGER_ASSERT(warning_bits_except_mask(output_warnings, G_context.tx_info.warning_bits) == 0, "Output warnings mismatch");
        LEDGER_ASSERT(policy != POLICY_DENY, "Output denied during UI");
        if (policy == POLICY_SHOW) {
            TRACE("Formatting output #%u", output_num);
            {
                START_COUNT();
                UI_ADD_FORMAT1(UI_STATIC_LABEL("Output"), MAX_UINT64_STRING_LENGTH, format_index_with_prefix, output_num);
                UI_ADD_FORMAT1(UI_STATIC_LABEL("Address"), MAX_HUMAN_ADDRESS_LENGTH, format_output_address, &output_desc);

                // For device-owned addresses, show payment and staking details
                if (output_node->output_data.destination.type == DESTINATION_DEVICE_OWNED) {
                    addPaymentInfoUIPairs(output_node->output_data.destination.params);
                    addStakingInfoUIPairs(output_node->output_data.destination.params);
                }

                UI_ADD_FORMAT1(UI_STATIC_LABEL("Amount"), MAX_ADA_AMOUNT_STRING_LENGTH, format_ada_amount, output_node->output_data.adaAmount);
                CHECK_COUNT(UI_PAIRS_OUTPUT_BASE +
                            (output_node->output_data.destination.type == DESTINATION_DEVICE_OWNED ? UI_PAIRS_OUTPUT_DEVICE_OWNED : 0));
            }

            const output_datum_t* datum = output_node->output_data.datum;
            if (datum != NULL) {
                security_policy_t datum_policy = policyForSignTxOutputDatumHash(policy, &G_context.tx_info.warning_bits);
                LEDGER_ASSERT(datum_policy != POLICY_DENY, "Output datum policy denied during UI");
                if (datum_policy == POLICY_SHOW) {
                    START_COUNT();
                    switch (datum->type) {
                        case DATUM_HASH:
                            UI_ADD_FORMAT3(UI_STATIC_LABEL("Datum hash"), MAX_BECH32_STRING_LENGTH, format_bech32, "datum", datum->hash, OUTPUT_DATUM_HASH_LENGTH);
                            break;
                        case DATUM_INLINE:
                            UI_ADD_FORMAT2(UI_STATIC_LABEL("Datum"), MAX_INLINE_DATUM_STRING_LENGTH, format_incomplete_hex_with_length, datum->inline_datum.buffer, datum->inline_datum.length);
                            break;
                        default:
                            LEDGER_ASSERT(false, "Unknown datum type");
                            break;
                    }
                    CHECK_COUNT(UI_PAIRS_OUTPUT_DATUM);
                }
            }

            const ref_script_t* ref_script = output_node->output_data.refScript;
            if (ref_script != NULL) {
                security_policy_t ref_script_policy = policyForSignTxOutputRefScript(policy, &G_context.tx_info.warning_bits);
                LEDGER_ASSERT(ref_script_policy != POLICY_DENY, "Output ref script policy denied during UI");
                if (ref_script_policy == POLICY_SHOW) {
                    START_COUNT();
                    UI_ADD_FORMAT2(UI_STATIC_LABEL("Script"), MAX_REFERENCE_SCRIPT_STRING_LENGTH, format_incomplete_hex_with_length, ref_script->data, ref_script->size);
                    CHECK_COUNT(UI_PAIRS_OUTPUT_REF_SCRIPT);
                }
            }

            if (output_node->output_data.assetGroups != NULL) {
                uint16_t token_count = count_output_tokens(
                    output_node->output_data.assetGroups);
                START_COUNT();
                add_ui_and_free_output_asset_groups(
                    output_node->output_data.assetGroups,
                    output_node->output_data.numAssetGroups,
                    true
                );
                CHECK_COUNT(UI_PAIRS_TOKEN * token_count);
                output_node->output_data.assetGroups = NULL;
            }

            output_num++;
        }

        if (output_node->output_data.assetGroups != NULL) {
            add_ui_and_free_output_asset_groups(
                output_node->output_data.assetGroups,
                output_node->output_data.numAssetGroups,
                false
            );
            output_node->output_data.assetGroups = NULL;
        }
        // Note: inline datum and reference script data are pointers into the raw_tx buffer,
        // not separately allocated, so they do not need to be freed
        node = node->next;
        cleanup_output_destination(&output_node->output_data.destination);
        APP_MEM_FREE(output_node);
    }
    tx_body->outputs = NULL;
}

static void add_ui_and_free_fee(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    warning_bits_t fee_warnings = 0;
    security_policy_t fee_policy =
        policyForSignTxFee(tx_params->txSigningMode, tx_body->fee, &fee_warnings);
    LEDGER_ASSERT(fee_policy != POLICY_DENY, "Fee security policy denied during UI");
        LEDGER_ASSERT(warning_bits_except_mask(fee_warnings, G_context.tx_info.warning_bits) == 0, "Fee warnings mismatch between validation and UI");
    if (fee_policy == POLICY_SHOW) {
        START_COUNT();
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Fee"), MAX_ADA_AMOUNT_STRING_LENGTH, format_ada_amount, tx_body->fee);
        CHECK_COUNT(UI_PAIRS_FEE);
    }
}

static void add_ui_and_free_ttl(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    if (!tx_params->includeTtl) {
        return;
    }
    security_policy_t ttl_policy = policyForSignTxTtl(tx_body->ttl, &G_context.tx_info.warning_bits);
    LEDGER_ASSERT(ttl_policy != POLICY_DENY, "TTL denied during UI");
    if (ttl_policy == POLICY_SHOW) {
        START_COUNT();
        UI_ADD_FORMAT3(UI_STATIC_LABEL("TTL"), MAX_VALIDITY_BOUNDARY_STRING_LENGTH, format_validity_boundary, tx_body->ttl, tx_params->networkId, tx_params->protocolMagic);
        CHECK_COUNT(UI_PAIRS_TTL);
    }
}

static bool should_show_pool_registration(
    const certificate_data_t *certificate,
    sign_tx_signingmode_t txSigningMode,
    pool_owner_counts_t *pool_owner_counts) {
    LEDGER_ASSERT(pool_owner_counts != NULL, "NULL pool owner counts");
    LEDGER_ASSERT(
        (certificate != NULL) &&
        (certificate->type == CERTIFICATE_STAKE_POOL_REGISTRATION) &&
        (certificate->poolRegistration != NULL),
        "Invalid pool registration certificate"
    );

    const pool_registration_data_t *poolReg = certificate->poolRegistration;
    if (poolReg == NULL) {
        LEDGER_ASSERT(false, "NULL poolRegistration");
        __builtin_unreachable();
    }
    *pool_owner_counts = count_pool_owner_nodes(
        poolReg->poolOwners
    );
    security_policy_t policy = policyForSignTxStakePoolRegistrationInit(
        txSigningMode,
        poolReg->numPoolOwners,
        pool_owner_counts->path_owners,
        &G_context.tx_info.warning_bits);
    LEDGER_ASSERT(policy != POLICY_DENY, "Certificate denied during UI");
    return policy == POLICY_SHOW;
}

static void add_ui_and_free_certificate_pool_registration(const certificate_data_t* certificate,
                                                     sign_tx_signingmode_t txSigningMode) {
    pool_owner_counts_t pool_owner_counts;
    if (!should_show_pool_registration(certificate, txSigningMode, &pool_owner_counts)) {
        return;
    }

    TRACE("Formatting certificate type=%u", certificate->type);
    {
        START_COUNT();
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Certificate"),
                       MAX_CERTIFICATE_TYPE_LENGTH,
                       format_certificate_type,
                       certificate->type);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_POOL_REGISTRATION_BASE);
    }

    security_policy_t pool_id_policy = policyForSignTxStakePoolRegistrationPoolId(
        txSigningMode,
        &certificate->poolId,
        &G_context.tx_info.warning_bits);
    LEDGER_ASSERT(pool_id_policy != POLICY_DENY, "Pool ID security policy denied");

    if (pool_id_policy == POLICY_SHOW) {
        START_COUNT();
        const pool_id_t *pool_id = &certificate->poolId;
        uint8_t pool_key_hash[POOL_KEY_HASH_LENGTH] = {0};

        switch (pool_id->keyReferenceType) {
            case KEY_REFERENCE_PATH:
                keyPathToKeyHash(&pool_id->path, pool_key_hash, sizeof(pool_key_hash));
                break;
            case KEY_REFERENCE_HASH:
                LEDGER_ASSERT(pool_id->hash != NULL, "NULL pool ID hash");
                memcpy(pool_key_hash, pool_id->hash, POOL_KEY_HASH_LENGTH);
                break;
            default:
                LEDGER_ASSERT(false, "Unsupported pool ID type");
        }

        UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool ID"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       "pool",
                       pool_key_hash,
                       POOL_KEY_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_POOL_ID);
    }

    security_policy_t vrf_policy = policyForSignTxStakePoolRegistrationVrfKey(txSigningMode, &G_context.tx_info.warning_bits);
    LEDGER_ASSERT(vrf_policy != POLICY_DENY, "VRF key security policy denied");

    if (vrf_policy == POLICY_SHOW) {
        START_COUNT();
        UI_ADD_FORMAT3(UI_STATIC_LABEL("VRF key hash"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       "vrf_vk",
                       certificate->poolRegistration->vrfKeyHash,
                       VRF_KEY_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_POOL_VRF_KEY);
    }

    {
        START_COUNT();
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Pledge"),
                       MAX_ADA_AMOUNT_STRING_LENGTH,
                       format_ada_amount,
                       certificate->poolRegistration->pledge);

        UI_ADD_FORMAT1(UI_STATIC_LABEL("Cost"),
                       MAX_ADA_AMOUNT_STRING_LENGTH,
                       format_ada_amount,
                       certificate->poolRegistration->cost);

        UI_ADD_FORMAT2(UI_STATIC_LABEL("Profit margin"),
                       MAX_PROFIT_MARGIN_STRING_LENGTH,
                       format_pool_margin,
                       certificate->poolRegistration->marginNumerator,
                       certificate->poolRegistration->marginDenominator);
        CHECK_COUNT(UI_PAIRS_POOL_FIXED);
    }

    security_policy_t reward_policy = policyForSignTxStakePoolRegistrationRewardAccount(
        txSigningMode,
        G_context.tx_info.tx_params.networkId,
        &certificate->poolRegistration->rewardAccount,
        &G_context.tx_info.warning_bits);
    LEDGER_ASSERT(reward_policy != POLICY_DENY, "Reward account security policy denied");

    if (reward_policy == POLICY_SHOW) {
        START_COUNT();
        UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Pool reward address", "Reward addr"),
                       MAX_HUMAN_ADDRESS_LENGTH,
                       format_pool_reward_account,
                       G_context.tx_info.tx_params.networkId,
                       &certificate->poolRegistration->rewardAccount);
        CHECK_COUNT(UI_PAIRS_POOL_REWARD_ACCOUNT);
    }

    uint32_t owner_index = 0;
    flist_node_t* owner_node = certificate->poolRegistration->poolOwners;
    while (owner_node != NULL) {
        tx_certificate_node_t* owner_item = (tx_certificate_node_t*) owner_node;
        ext_credential_t* owner_credential = &owner_item->certificate.stakeCredential;

        security_policy_t owner_policy = policyForSignTxStakePoolRegistrationOwner(
            G_context.tx_info.tx_params.txSigningMode,
            owner_credential,
            &G_context.tx_info.warning_bits);
        LEDGER_ASSERT(owner_policy != POLICY_DENY, "Pool owner security policy denied");

        if (owner_policy == POLICY_SHOW) {
            START_COUNT();
            UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Owner reward address", "Owner addr"),
                           MAX_HUMAN_ADDRESS_LENGTH,
                           format_reward_account_from_credential,
                           G_context.tx_info.tx_params.networkId,
                           owner_credential);
            CHECK_COUNT(UI_PAIRS_POOL_OWNER);
        }

        owner_node = owner_node->next;
        APP_MEM_FREE(owner_item);
        owner_index++;
    }
    ((certificate_data_t*) certificate)->poolRegistration->poolOwners = NULL;

    LEDGER_ASSERT(owner_index == pool_owner_counts.total_owners, "Pool owner index mismatch");
    if (pool_owner_counts.total_owners == 0) {
        warning_bits_set(&G_context.tx_info.warning_bits,
                         WARNING_BIT_POOL_REGISTRATION_NO_OWNERS);
        {
            START_COUNT();
            UI_ADD_STATIC(UI_STATIC_LABEL("Pool owners"), UI_STATIC_LABEL("(none)"));
            CHECK_COUNT(UI_PAIRS_POOL_NO_OWNERS);
        }
    }

    uint32_t relay_index = 0;
    flist_node_t* relay_node = certificate->poolRegistration->relays;
    while (relay_node != NULL) {
        tx_certificate_node_t* relay_item = (tx_certificate_node_t*) relay_node;
        pool_relay_t* relay = (pool_relay_t*) &relay_item->certificate;

        security_policy_t relay_policy = policyForSignTxStakePoolRegistrationRelay(
            G_context.tx_info.tx_params.txSigningMode,
            relay,
            &G_context.tx_info.warning_bits);
        LEDGER_ASSERT(relay_policy != POLICY_DENY, "Relay security policy denied");
        if (relay_policy == POLICY_SHOW) {
            {
                START_COUNT();
                UI_ADD_FORMAT1(UI_STATIC_LABEL("Relay"),
                               MAX_RELAY_INDEX_STRING_LENGTH,
                               format_index_with_prefix,
                               relay_index + 1);
                CHECK_COUNT(UI_PAIRS_POOL_RELAY_HEADER);
            }

            switch (relay->format) {
                case RELAY_SINGLE_HOST_IP: {
                    START_COUNT();
                    if (!relay->ipv4.isNull) {
                        UI_ADD_FORMAT1(UI_STATIC_LABEL("IPv4"), MAX_IPV4_STR_LENGTH, format_ipv4, &relay->ipv4);
                    }
                    if (!relay->ipv6.isNull) {
                        UI_ADD_FORMAT1(UI_STATIC_LABEL("IPv6"), MAX_IPV6_STR_LENGTH, format_ipv6, &relay->ipv6);
                    }
                    if (!relay->port.isNull) {
                        UI_ADD_FORMAT1(UI_STATIC_LABEL("Port"), MAX_UINT64_STRING_LENGTH, format_uint16, relay->port.number);
                    }
                    CHECK_COUNT((!relay->ipv4.isNull ? UI_PAIRS_POOL_RELAY_IPV4 : 0) +
                                (!relay->ipv6.isNull ? UI_PAIRS_POOL_RELAY_IPV6 : 0) +
                                (!relay->port.isNull ? UI_PAIRS_POOL_RELAY_PORT : 0));
                    break;
                }

                case RELAY_SINGLE_HOST_NAME: {
                    START_COUNT();
                    if (relay->dnsNameSize > 0) {
                        UI_ADD_FORMAT2(UI_STATIC_LABEL("DNS name"),
                                       MAX_DNS_NAME_LENGTH,
                                       format_dns_name,
                                       relay->dnsName,
                                       relay->dnsNameSize);
                    }
                    if (!relay->port.isNull) {
                        UI_ADD_FORMAT1(UI_STATIC_LABEL("Port"), MAX_UINT64_STRING_LENGTH, format_uint16, relay->port.number);
                    }
                    CHECK_COUNT((relay->dnsNameSize > 0 ? UI_PAIRS_POOL_RELAY_DNS : 0) +
                                (!relay->port.isNull ? UI_PAIRS_POOL_RELAY_PORT : 0));
                    break;
                }

                case RELAY_MULTIPLE_HOST_NAME: {
                    START_COUNT();
                    if (relay->dnsNameSize > 0) {
                        UI_ADD_FORMAT2(UI_STATIC_LABEL("SRV DNS"),
                                       MAX_DNS_NAME_LENGTH,
                                       format_dns_name,
                                       relay->dnsName,
                                       relay->dnsNameSize);
                    }
                    CHECK_COUNT(relay->dnsNameSize > 0 ? UI_PAIRS_POOL_RELAY_DNS : 0);
                    break;
                }

                default:
                    LEDGER_ASSERT(false, "Unknown relay type");
            }
        }

        relay_node = relay_node->next;
        APP_MEM_FREE(relay_item);
        relay_index++;
    }
    ((certificate_data_t*) certificate)->poolRegistration->relays = NULL;

    LEDGER_ASSERT(relay_index == certificate->poolRegistration->numRelays, "Relay index mismatch");
    if (relay_index == 0) {
        warning_bits_set(&G_context.tx_info.warning_bits,
                         WARNING_BIT_POOL_REGISTRATION_NO_RELAYS);
        {
            START_COUNT();
            UI_ADD_STATIC(UI_STATIC_LABEL("Pool relays"), UI_STATIC_LABEL("(none)"));
            CHECK_COUNT(UI_PAIRS_POOL_NO_RELAYS);
        }
    }

    if (certificate->poolRegistration->poolMetadataIsNull) {
        security_policy_t no_metadata_policy = policyForSignTxStakePoolRegistrationNoMetadata(&G_context.tx_info.warning_bits);
        LEDGER_ASSERT(no_metadata_policy != POLICY_DENY, "No metadata security policy denied");

        if (no_metadata_policy == POLICY_SHOW) {
            START_COUNT();
            UI_ADD_STATIC(UI_STATIC_LABEL("Metadata"), UI_STATIC_LABEL("(none)"));
            CHECK_COUNT(UI_PAIRS_POOL_NO_METADATA);
        }
    } else {
        warning_bits_t metadata_warnings = 0;
        security_policy_t metadata_policy =
            policyForSignTxStakePoolRegistrationMetadata(
                &certificate->poolRegistration->poolMetadata,
                &metadata_warnings
            );
        LEDGER_ASSERT(warning_bits_except_mask(metadata_warnings, G_context.tx_info.warning_bits) == 0, "Pool metadata warnings mismatch between validation and UI");
        LEDGER_ASSERT(metadata_policy != POLICY_DENY, "Metadata security policy denied");

        if (metadata_policy == POLICY_SHOW) {
            {
                START_COUNT();
                if (certificate->poolRegistration->poolMetadata.urlSize == 0) {
                    LEDGER_ASSERT(warning_bits_has(G_context.tx_info.warning_bits, WARNING_BIT_POOL_REGISTRATION_EMPTY_METADATA_URL), "Empty pool metadata URL warning missing");
                    UI_ADD_STATIC(UI_LABEL_BY_SCREEN("Pool metadata url", "Metadata url"),
                                  UI_STATIC_LABEL("(empty)"));
                } else {
                    UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Pool metadata url", "Metadata url"),
                                   MAX_POOL_METADATA_URL_LENGTH,
                                   format_url,
                                   certificate->poolRegistration->poolMetadata.url,
                                   certificate->poolRegistration->poolMetadata.urlSize);
                }
                UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Pool metadata hash", "Metadata hash"),
                               MAX_POOL_METADATA_HASH_STRING_LENGTH,
                               format_hex_bytes,
                               certificate->poolRegistration->poolMetadata.hash,
                               POOL_METADATA_HASH_LENGTH);
                CHECK_COUNT(UI_PAIRS_POOL_METADATA);
            }
        }
    }
}

static bool should_show_certificate(
    certificate_type_t certificate_type,
    const certificate_data_t *certificate,
    sign_tx_signingmode_t txSigningMode) {
    LEDGER_ASSERT(certificate != NULL, "NULL certificate data");

    security_policy_t policy = POLICY_DENY;
    switch (certificate_type) {
        case CERTIFICATE_STAKE_REGISTRATION:
        case CERTIFICATE_STAKE_DEREGISTRATION:
        case CERTIFICATE_STAKE_REGISTRATION_CONWAY:
        case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY:
        case CERTIFICATE_STAKE_DELEGATION:
            policy = policyForSignTxCertificateStaking(
                txSigningMode,
                certificate_type,
                &certificate->stakeCredential,
                &G_context.tx_info.warning_bits);
            break;

        case CERTIFICATE_VOTE_DELEGATION:
            policy = policyForSignTxCertificateVoteDelegation(
                txSigningMode,
                &certificate->stakeCredential,
                &certificate->drep,
                &G_context.tx_info.warning_bits);
            break;

        case CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION:
            policy = policyForSignTxCertificateStakePoolAndDRepDelegation(
                txSigningMode,
                &certificate->stakeCredential,
                &certificate->drep,
                &G_context.tx_info.warning_bits);
            break;

        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL:
            policy = policyForSignTxCertificateAccountRegistrationDelegationToStakePool(
                txSigningMode,
                &certificate->stakeCredential,
                &G_context.tx_info.warning_bits);
            break;

        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP:
            policy = policyForSignTxCertificateAccountRegistrationDelegationToDRep(
                txSigningMode,
                &certificate->stakeCredential,
                &certificate->drep,
                &G_context.tx_info.warning_bits);
            break;

        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP:
            policy = policyForSignTxCertificateStakePoolAndDRepDelegation(
                txSigningMode,
                &certificate->stakeCredential,
                &certificate->drep,
                &G_context.tx_info.warning_bits);
            break;

        case CERTIFICATE_AUTHORIZE_COMMITTEE_HOT:
            policy = policyForSignTxCertificateCommitteeAuth(
                txSigningMode,
                &certificate->coldCredential,
                &certificate->hotCredential,
                &G_context.tx_info.warning_bits);
            break;

        case CERTIFICATE_RESIGN_COMMITTEE_COLD:
            policy = policyForSignTxCertificateCommitteeResign(
                txSigningMode,
                &certificate->coldCredential,
                &G_context.tx_info.warning_bits);
            break;

        case CERTIFICATE_DREP_REGISTRATION:
        case CERTIFICATE_DREP_DEREGISTRATION:
        case CERTIFICATE_DREP_UPDATE:
            policy = policyForSignTxCertificateDRep(
                txSigningMode,
                &certificate->dRepCredential,
                &G_context.tx_info.warning_bits);
            break;

        case CERTIFICATE_STAKE_POOL_RETIREMENT:
            policy = policyForSignTxCertificateStakePoolRetirement(
                txSigningMode,
                &certificate->poolCredential,
                certificate->retirementEpoch,
                &G_context.tx_info.warning_bits);
            break;

        case CERTIFICATE_STAKE_POOL_REGISTRATION:
            LEDGER_ASSERT(false, "CERTIFICATE_STAKE_POOL_REGISTRATION should be treated separately");
            return false;

        default:
            TRACE("Unknown certificate type: %u", certificate_type);
            LEDGER_ASSERT(false, "Unknown certificate type");
            return false;
    }

    LEDGER_ASSERT(policy != POLICY_DENY, "Certificate denied during UI");
    return policy == POLICY_SHOW;
}

static void add_ui_and_free_certificates(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    flist_node_t *node = tx_body->certificates;
    TRACE("Formatting %u certificates", tx_params->num_certificates);
    while (node != NULL) {
        tx_certificate_node_t *certificate_node = (tx_certificate_node_t *) node;
        const certificate_data_t *certificate = &certificate_node->certificate;
        if (certificate->type == CERTIFICATE_STAKE_POOL_REGISTRATION) {
            // treated separately
            add_ui_and_free_certificate_pool_registration(certificate, tx_params->txSigningMode);
        } else if (should_show_certificate(
                       certificate->type,
                       certificate,
                       tx_params->txSigningMode)) {
            addCertificateUIPairs(certificate);
        }

        node = node->next;
        APP_MEM_FREE(certificate_node);
    }
    tx_body->certificates = NULL;
}

static void add_ui_and_free_withdrawals(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    flist_node_t *node = tx_body->withdrawals;
    TRACE("Formatting %u withdrawals", tx_params->num_withdrawals);
    while (node != NULL) {
        tx_withdrawal_node_t *withdrawal_node = (tx_withdrawal_node_t *) node;

        warning_bits_t withdrawal_warnings = 0;
        security_policy_t policy = policyForSignTxWithdrawal(
            tx_params->txSigningMode,
            &withdrawal_node->withdrawal.stakeCredential,
            &withdrawal_warnings
        );
                LEDGER_ASSERT(warning_bits_except_mask(withdrawal_warnings, G_context.tx_info.warning_bits) == 0, "Withdrawal warnings mismatch");

        LEDGER_ASSERT(policy != POLICY_DENY, "Withdrawal denied during UI");
        if (policy == POLICY_SHOW) {
            addWithdrawalUIPairs(
                G_context.tx_info.tx_params.networkId,
                &withdrawal_node->withdrawal
            );
        }

        node = node->next;
        APP_MEM_FREE(withdrawal_node);
    }
    tx_body->withdrawals = NULL;
}

static void add_ui_and_free_aux_data_hash(tx_params_t *tx_params, tx_parsed_body_t *tx_body MARK_UNUSED) {
    if (!tx_params->includeAuxDataHash) {
        return;
    }
    security_policy_t policy = policyForSignTxAuxData(tx_params->auxDataType, &G_context.tx_info.warning_bits);
    LEDGER_ASSERT(policy != POLICY_DENY, "Aux data denied during UI");
    if (policy == POLICY_SHOW) {
        START_COUNT();
        UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Auxiliary data hash", "Aux data hash"), MAX_TX_HASH_DISPLAY_LENGTH, format_hex_bytes, tx_params->auxDataHash, AUX_DATA_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_AUXILIARY_DATA_HASH);
    }
}

static void add_ui_and_free_validity_interval_start(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    if (!tx_params->includeValidityIntervalStart) {
        return;
    }
    security_policy_t validity_interval_start_policy = policyForSignTxValidityIntervalStart(&G_context.tx_info.warning_bits);
    LEDGER_ASSERT(validity_interval_start_policy != POLICY_DENY, "Validity interval start denied during UI");
    if (validity_interval_start_policy == POLICY_SHOW) {
        START_COUNT();
        UI_ADD_FORMAT3(UI_STATIC_LABEL("Valid from"), MAX_VALIDITY_BOUNDARY_STRING_LENGTH, format_validity_boundary, tx_body->validityIntervalStart, tx_params->networkId, tx_params->protocolMagic);
        CHECK_COUNT(UI_PAIRS_VALIDITY_INTERVAL_START);
    }
}

// Local formatter for mint summary display (e.g., "2 asset groups", "1 asset group")
static bool format_mint_summary(uint16_t num_groups, char *out, size_t outSize) {
    STATIC_ASSERT(!IS_SIGNED_TYPE(typeof(num_groups)), "signed type for %u");
    int written = snprintf(out, outSize, "%u asset group%s", num_groups, (num_groups == 1) ? "" : "s");
    LEDGER_ASSERT(written > 0, "snprintf mint summary formatting failed");
    return (size_t)written + 1 < outSize;
}

static void add_ui_and_free_mint(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    if (tx_body->mint_asset_groups == NULL) {
        return;
    }

    security_policy_t mint_policy = policyForSignTxMintInit(tx_params->txSigningMode, &G_context.tx_info.warning_bits);
    LEDGER_ASSERT(mint_policy != POLICY_DENY, "Mint denied during UI");
    const bool show_mint = (mint_policy == POLICY_SHOW);

    START_COUNT();
    if (show_mint) {
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Mint"), MAX_MINT_SUMMARY_STRING_LENGTH, format_mint_summary, tx_params->num_mint_asset_groups);
    }

    uint16_t token_count = 0;
    flist_node_t *node = tx_body->mint_asset_groups;
    while (node != NULL) {
        mint_asset_group_node_t *asset_group_node = (mint_asset_group_node_t *) node;
        mint_asset_group_t *asset_group = &asset_group_node->asset_group;

        LEDGER_ASSERT(asset_group->policyId != NULL, "Missing policy id");
        flist_node_t *node2 = asset_group->tokens;
        while (node2 != NULL) {
            mint_token_node_t *token_node_entry = (mint_token_node_t *) node2;
            mint_token_t *token = &token_node_entry->token;

            if (show_mint) {
                UI_ADD_FORMAT3(UI_STATIC_LABEL("Fingerprint"), MAX_TOKEN_FINGERPRINT_STRING_LENGTH, format_asset_fingerprint_bech32, asset_group->policyId, token->assetName, token->assetNameLen);
                UI_ADD_FORMAT4(UI_STATIC_LABEL("Mint amount"), MAX_TOKEN_AMOUNT_STRING_LENGTH, format_token_amount_mint, asset_group->policyId, token->assetName, token->assetNameLen, token->amount);
                token_count++;
            }

            node2 = node2->next;
            APP_MEM_FREE(token_node_entry);
        }
        asset_group_node->asset_group.tokens = NULL;

        node = node->next;
        APP_MEM_FREE(asset_group_node);
    }

    tx_body->mint_asset_groups = NULL;

    if (show_mint) {
        // Count: 1 summary + (2 * num_tokens)
        uint16_t expected = UI_PAIRS_MINT_SUMMARY + (UI_PAIRS_TOKEN * token_count);
        CHECK_COUNT(expected);
    }
}

static void add_ui_and_free_script_data_hash(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    if (!tx_params->includeScriptDataHash) {
        return;
    }
    security_policy_t policy = policyForSignTxScriptDataHash(tx_params->txSigningMode, &G_context.tx_info.warning_bits);
    LEDGER_ASSERT(policy != POLICY_DENY, "Script data hash denied during UI");
    if (policy == POLICY_SHOW) {
        START_COUNT();
        UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("Script data hash", "Script hash"), MAX_BECH32_STRING_LENGTH, format_bech32, "script_data", tx_body->scriptDataHash, SCRIPT_DATA_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_SCRIPT_DATA_HASH);
    }
}

static void add_ui_and_free_collateral_inputs(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    flist_node_t *node = tx_body->collateral_inputs;
    while (node != NULL) {
        tx_collateral_input_node_t *collateral_input_node = (tx_collateral_input_node_t *) node;

        security_policy_t collateral_input_policy = policyForSignTxCollateralInput(
            tx_params->txSigningMode,
            tx_params->includeTotalCollateral,
            &collateral_input_node->input, &G_context.tx_info.warning_bits);
        LEDGER_ASSERT(collateral_input_policy != POLICY_DENY, "Collateral input policy denied during UI");

        if (collateral_input_policy == POLICY_SHOW) {
            START_COUNT();
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Coll input"), MAX_INPUT_DISPLAY_STRING_LENGTH, format_input_with_index, &collateral_input_node->input);
            CHECK_COUNT(UI_PAIRS_COLLATERAL_INPUT);
        }

        node = node->next;
        APP_MEM_FREE(collateral_input_node);
    }
    tx_body->collateral_inputs = NULL;
}

static void add_ui_and_free_required_signers(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    flist_node_t *node = tx_body->required_signers;
    while (node != NULL) {
        tx_required_signer_node_t *required_signer_node = (tx_required_signer_node_t *) node;
        required_signer_t *required_signer = &required_signer_node->required_signer;

        security_policy_t policy = policyForSignTxRequiredSigner(tx_params->txSigningMode, required_signer, &G_context.tx_info.warning_bits);
        LEDGER_ASSERT(policy != POLICY_DENY, "Required signer denied during UI");

        if (policy == POLICY_SHOW) {
            START_COUNT();
            switch (required_signer->type) {
                case REQUIRED_SIGNER_WITH_HASH: {
                    UI_ADD_FORMAT3(UI_STATIC_LABEL("Required signer"), MAX_BECH32_STRING_LENGTH, format_bech32, "req_signer_vkh", required_signer->keyHash, ADDRESS_KEY_HASH_LENGTH);
                    break;
                }
                case REQUIRED_SIGNER_WITH_PATH: {
                    UI_ADD_FORMAT1(UI_STATIC_LABEL("Required signer"), MAX_BIP44_PATH_STRING_LENGTH, format_bip44_path, &required_signer->keyPath);
                    break;
                }
                default:
                    LEDGER_ASSERT(false, "Unknown required signer type");
            }
            CHECK_COUNT(UI_PAIRS_REQUIRED_SIGNER);
        }

        node = node->next;
        APP_MEM_FREE(required_signer_node); // only after next is assigned
    }
    tx_body->required_signers = NULL;
}

// Keep this in lockstep with tx_validate.c collateral-output pair-counting rules.
static void add_ui_and_free_collateral_output(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    if (!tx_params->includeCollateralOutput) {
        return;
    }
    tx_output_description_t collateral_desc = {
        .format = tx_body->collateral_output.format,
        .amount = tx_body->collateral_output.adaAmount,
        .numAssetGroups = tx_body->collateral_output.numAssetGroups,
        .includeDatum = (tx_body->collateral_output.datum != NULL),
        .includeRefScript = (tx_body->collateral_output.refScript != NULL),
    };

    collateral_desc.destination = tx_body->collateral_output.destination;

    security_policy_t collateral_policy = policyForSignTxCollateralOutputAddress(
        &collateral_desc,
        tx_params->txSigningMode,
        tx_params->networkId,
        tx_params->protocolMagic,
        tx_params->includeTotalCollateral,
        &G_context.tx_info.warning_bits);
    LEDGER_ASSERT(collateral_policy != POLICY_DENY, "Collateral output denied during UI");

    security_policy_t collateral_ada_policy =
        policyForSignTxCollateralOutputAdaAmount(collateral_policy, tx_params->includeTotalCollateral, &G_context.tx_info.warning_bits);
    LEDGER_ASSERT(collateral_ada_policy != POLICY_DENY, "Collateral ADA policy denied during UI");
    security_policy_t collateral_tokens_policy =
        policyForSignTxCollateralOutputTokens(collateral_policy, &collateral_desc, &G_context.tx_info.warning_bits);
    LEDGER_ASSERT(collateral_tokens_policy != POLICY_DENY, "Collateral tokens policy denied during UI");
    bool show_collateral_tokens =
        (collateral_policy == POLICY_SHOW) && (collateral_tokens_policy == POLICY_SHOW);
    TRACE("Collateral output: policy=%d ada_policy=%d tokens_policy=%d numAssets=%u",
          collateral_policy, collateral_ada_policy, collateral_tokens_policy,
          (unsigned)tx_body->collateral_output.numAssetGroups);

    if (collateral_policy == POLICY_SHOW) {
        START_COUNT();
        UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Collateral address", "Coll address"), MAX_HUMAN_ADDRESS_LENGTH, format_output_address, &collateral_desc);

        // For device-owned collateral addresses, show payment and staking details
        if (collateral_desc.destination.type == DESTINATION_DEVICE_OWNED) {
            addPaymentInfoUIPairs(collateral_desc.destination.params);
            addStakingInfoUIPairs(collateral_desc.destination.params);
        }

        if (collateral_ada_policy == POLICY_SHOW) {
            UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Collateral amount", "Coll amount"), MAX_ADA_AMOUNT_STRING_LENGTH, format_ada_amount, collateral_desc.amount);
        }

        uint16_t expected = UI_PAIRS_COLLATERAL_OUTPUT_ADDRESS;
        if (collateral_desc.destination.type == DESTINATION_DEVICE_OWNED) {
            expected += UI_PAIRS_COLLATERAL_OUTPUT_DEVICE_OWNED;
        }
        if (collateral_ada_policy == POLICY_SHOW) {
            expected += UI_PAIRS_COLLATERAL_OUTPUT_AMOUNT;
        }
        CHECK_COUNT(expected);
    }

    uint16_t token_count = (show_collateral_tokens && tx_body->collateral_output.assetGroups != NULL)
        ? count_output_tokens(tx_body->collateral_output.assetGroups)
        : 0;

    START_COUNT();
    add_ui_and_free_output_asset_groups(
        tx_body->collateral_output.assetGroups,
        tx_body->collateral_output.numAssetGroups,
        show_collateral_tokens);

    if (token_count > 0) {
        CHECK_COUNT(UI_PAIRS_TOKEN * token_count);
    }

    cleanup_output_destination(&tx_body->collateral_output.destination);
    tx_body->collateral_output.assetGroups = NULL;
}

static void add_ui_and_free_total_collateral(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    if (!tx_params->includeTotalCollateral) {
        return;
    }
    security_policy_t policy = policyForSignTxTotalCollateral(&G_context.tx_info.warning_bits);
    LEDGER_ASSERT(policy != POLICY_DENY, "Total collateral denied during UI");
    if (policy == POLICY_SHOW) {
        START_COUNT();
        UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Total collateral", "Total coll"), MAX_ADA_AMOUNT_STRING_LENGTH, format_ada_amount, tx_body->totalCollateral);
        CHECK_COUNT(UI_PAIRS_TOTAL_COLLATERAL);
    }
}

static void add_ui_and_free_reference_inputs(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    flist_node_t *node = tx_body->reference_inputs;
    while (node != NULL) {
        tx_input_node_t *ref_input_node = (tx_input_node_t *) node;

        security_policy_t reference_input_policy = policyForSignTxReferenceInput(
            tx_params->txSigningMode,
            &ref_input_node->input, &G_context.tx_info.warning_bits);
        LEDGER_ASSERT(reference_input_policy != POLICY_DENY, "Reference input denied during UI");

        if (reference_input_policy == POLICY_SHOW) {
            START_COUNT();
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Ref input"), MAX_INPUT_DISPLAY_STRING_LENGTH, format_input_with_index, &ref_input_node->input);
            CHECK_COUNT(UI_PAIRS_REFERENCE_INPUT);
        }

        node = node->next;
        APP_MEM_FREE(ref_input_node);
    }
    tx_body->reference_inputs = NULL;
}

static void add_ui_and_free_voting_procedures(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    flist_node_t *node = tx_body->voting_procedures;
    while (node != NULL) {
        voter_votes_node_t *voter_node = (voter_votes_node_t *) node;

        security_policy_t policy = policyForSignTxVotingProcedure(tx_params->txSigningMode, &voter_node->voter_votes_data.voter, &G_context.tx_info.warning_bits);
        LEDGER_ASSERT(policy != POLICY_DENY, "Voting procedure denied during UI");

        if (policy == POLICY_SHOW) {
            addVoterUIPairs(&voter_node->voter_votes_data.voter);
        }

        flist_node_t *vote_node = voter_node->voter_votes_data.votes;
        while (vote_node != NULL) {
            vote_node_t *vote_node_data = (vote_node_t *) vote_node;
            vote_item_t *vote_data = &vote_node_data->vote_data;

            if (policy == POLICY_SHOW) {
                START_COUNT();
                UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Gov action tx hash", "Action tx hash"), MAX_TX_HASH_DISPLAY_LENGTH, format_hex_bytes, vote_data->govActionId.txHash, TX_HASH_LENGTH);
                UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Gov action index", "Action index"), MAX_UINT64_STRING_LENGTH, format_uint64, vote_data->govActionId.govActionIndex);
                UI_ADD_FORMAT1(UI_STATIC_LABEL("Vote"), MAX_VOTE_OPTION_LENGTH, format_vote_option, vote_data->voteOption);
                CHECK_COUNT(UI_PAIRS_VOTE);

                addAnchorUIPairs(&vote_data->anchor);
            }

            vote_node = vote_node->next;
            APP_MEM_FREE(vote_node_data);
        }
        voter_node->voter_votes_data.votes = NULL;

        node = node->next;
        APP_MEM_FREE(voter_node);
    }
    tx_body->voting_procedures = NULL;
}

static void add_ui_and_free_treasury(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    if (!tx_params->includeTreasury) {
        return;
    }
    security_policy_t policy = policyForSignTxTreasury(tx_params->txSigningMode, tx_body->treasury, &G_context.tx_info.warning_bits);
    LEDGER_ASSERT(policy != POLICY_DENY, "Treasury denied during UI");

    if (policy == POLICY_SHOW) {
        START_COUNT();
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Treasury"), MAX_ADA_AMOUNT_STRING_LENGTH, format_ada_amount, tx_body->treasury);
        CHECK_COUNT(UI_PAIRS_TREASURY);
    }
}

static void add_ui_and_free_donation(tx_params_t *tx_params, tx_parsed_body_t *tx_body) {
    if (!tx_params->includeDonation) {
        return;
    }
    security_policy_t policy = policyForSignTxDonation(tx_params->txSigningMode, tx_body->donation, &G_context.tx_info.warning_bits);
    LEDGER_ASSERT(policy != POLICY_DENY, "Donation denied during UI");

    if (policy == POLICY_SHOW) {
        START_COUNT();
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Donation"), MAX_ADA_AMOUNT_STRING_LENGTH, format_ada_amount, tx_body->donation);
        CHECK_COUNT(UI_PAIRS_DONATION);
    }
}

static void add_ui_and_free_tx_hash(void) {
    security_policy_t policy = policyForSignTxDisplayTxHash(G_context.tx_info.tx_params.txSigningMode, &G_context.tx_info.warning_bits);
    LEDGER_ASSERT(policy != POLICY_DENY, "Transaction hash display denied during UI");
    if (policy == POLICY_SHOW) {
        START_COUNT();
        UI_ADD_FORMAT2(UI_STATIC_LABEL("Tx hash"),
                       MAX_TX_HASH_DISPLAY_LENGTH,
                       format_hex_bytes,
                       G_context.tx_info.tx_hash,
                       sizeof(G_context.tx_info.tx_hash));
        CHECK_COUNT(UI_PAIRS_TX_HASH);
    }
}

static int add_ui_strings_and_free_parsed_data(void) {
    LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_HASHED, "String formatting invoked too early");
    tx_params_t *tx_params = &G_context.tx_info.tx_params;
    tx_parsed_body_t *tx_body = &G_context.tx_info.tx_body;

    // Initialize error status before formatting
    ui_reset_error_status();

    TRACE("UI formatting starting");

    add_ui_network_details(tx_params);
    add_ui_and_free_inputs(tx_params, tx_body);
    add_ui_and_free_outputs(tx_params, tx_body);
    add_ui_and_free_fee(tx_params, tx_body);
    add_ui_and_free_ttl(tx_params, tx_body);
    add_ui_and_free_certificates(tx_params, tx_body);
    add_ui_and_free_withdrawals(tx_params, tx_body);
    add_ui_and_free_aux_data_hash(tx_params, tx_body);
    add_ui_and_free_validity_interval_start(tx_params, tx_body);
    add_ui_and_free_mint(tx_params, tx_body);
    add_ui_and_free_script_data_hash(tx_params, tx_body);
    add_ui_and_free_collateral_inputs(tx_params, tx_body);
    add_ui_and_free_required_signers(tx_params, tx_body);
    add_ui_and_free_collateral_output(tx_params, tx_body);
    add_ui_and_free_total_collateral(tx_params, tx_body);
    add_ui_and_free_reference_inputs(tx_params, tx_body);
    add_ui_and_free_voting_procedures(tx_params, tx_body);
    add_ui_and_free_treasury(tx_params, tx_body);
    add_ui_and_free_donation(tx_params, tx_body);
    add_ui_and_free_tx_hash();

    TRACE("UI formatting complete: actual_pairs=%u planned_pairs=%u",
          ui_pairs_get_count(), G_context.tx_info.planned_ui_pairs);
    ui_status_t status = ui_get_error_status();
    switch (status) {
        case UI_STATUS_SUCCESS:
            return SWO_SUCCESS;
        case UI_STATUS_OUT_OF_MEMORY:
            return SWO_INSUFFICIENT_MEMORY;
        case UI_STATUS_UNINITIALIZED:
        default:
            LEDGER_ASSERT(false, "Unexpected UI warning status");
            return SWO_COMMAND_NOT_ALLOWED;
    }
}

static inline bool status_requires_streaming(int status) {
    return status == SWO_INSUFFICIENT_MEMORY;
}

static int ui_build_pairs(void) {
    return add_ui_strings_and_free_parsed_data();
}

int ui_prepare_transaction_review(void) {
    if (G_context.req_type != REQUEST_SIGN_TRANSACTION) {
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return SWO_COMMAND_NOT_ALLOWED;
    }
    LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_HASHED, "UI prep called too early");
    uint32_t pair_count = G_context.tx_info.planned_ui_pairs;

    TRACE("Preparing TX review: planned_ui_pairs=%u max_ui_pairs=%u", pair_count, MAX_UI_PAIRS);
    // pair_count should never be 0 - at minimum we display fee
    LEDGER_ASSERT(pair_count > 0, "UI pair count is zero - at minimum fee must be displayed");

    // If pair count exceeds UI capability, reject the transaction
    if (pair_count > MAX_UI_PAIRS) {
        TRACE("UI pair count exceeds limit: %u > %u", pair_count, MAX_UI_PAIRS);
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return SWO_INSUFFICIENT_MEMORY;
    }

    if (!ui_pairs_init((uint8_t) pair_count)) {
        TRACE("ui_pairs_init failed for %u pairs", pair_count);
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return SWO_INSUFFICIENT_MEMORY;
    }

    int status = ui_build_pairs();
    TRACE("UI build status=0x%04x actual_pairs=%u planned_pairs=%u",
          status, ui_pairs_get_count(), pair_count);
    if (status != SWO_SUCCESS) {
        ui_all_cleanup();
        if (status_requires_streaming(status)) {
            // TODO we can add range to ui_build_pairs, but then maybe deallocation should be done more carefully
            // TODO so that the range can be applied on subsequent runs of ui_build_pairs
            LEDGER_ASSERT(false, "Need streaming UI but not implemented (status=0x%04x)", status);
        }
        return status;
    }

    // Assert that CVote-specific warnings haven't leaked into transaction warnings.
    LEDGER_ASSERT(!warning_bits_has_any_cvote_tx_forbidden(G_context.tx_info.warning_bits), "CVote warning leaked into transaction warnings");

    ui_status_t warning_status = ui_build_warnings(G_context.tx_info.warning_bits);
    switch (warning_status) {
        case UI_STATUS_SUCCESS:
            break;
        case UI_STATUS_OUT_OF_MEMORY:
            ui_all_cleanup();
            return SWO_INSUFFICIENT_MEMORY;
        case UI_STATUS_UNINITIALIZED:
        default:
            LEDGER_ASSERT(false, "Unexpected UI warning status");
            ui_all_cleanup();
            return SWO_COMMAND_NOT_ALLOWED;
    }

    // Validate that the actual number of pairs formatted matches the planned count
    TRACE("UI pair count mismatch check: planned=%u formatted=%u",
          (unsigned int) pair_count, ui_pairs_get_count());
        LEDGER_ASSERT(ui_pairs_get_count() == (uint16_t) pair_count, "UI pair count mismatch");

    return SWO_SUCCESS;
}
