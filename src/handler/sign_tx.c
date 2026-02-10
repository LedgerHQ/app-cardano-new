/*****************************************************************************
 *   Ledger App Cardano.
 *   (c) 2025 Vacuumlabs
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <string.h>   // memset, explicit_bzero

#include "app_context.h"
#include "bip44.h"
#include "buffer.h"
#include "cardano_constants.h"
#include "cardano_parsers.h"
#include "cardano_swo.h"
#include "globals.h"
#include "messageSigning.h"
#include "io.h"
#include "mem.h"
#include "menu.h"
#include "nbgl_use_case.h"
#include "securityPolicy.h"
#include "ui_display_tx.h"
#include "sign_tx.h"
#include "tx.h"
#include "tx_credential_types.h"
#include "tx_output_types.h"
#include "tx_parse.h"
#include "tx_utils.h"
#include "tx_validate.h"
#include "utils.h"

#ifdef HAVE_SWAP
#include "swap.h"
#include "swap_error_code_helpers.h"
#include "swap_lib.h"
#endif

static bool is_valid_tx_signing_mode(uint8_t tx_signing_mode) {
    switch (tx_signing_mode) {
        case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
        case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
        case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
            return true;
        default:
            return false;
    }
}

/**
 * Helper: Initialize transaction from P1_TX_INIT APDU
 * Validates all transaction metadata and checks security policy
 */
static void handle_tx_init_apdu(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata passed to handle_tx_init_apdu");
    G_context.tx_info.raw_tx = NULL;
    G_context.tx_info.raw_tx_len = 0;
    G_context.tx_info.warning_bits = 0;
    G_context.tx_info.cvote_warning_bits = 0;
    G_context.tx_info.planned_ui_pairs = 0;
    explicit_bzero(&G_context.tx_info.single_account_data, sizeof(single_account_data_t));
    explicit_bzero(&G_context.tx_info.pool_owner_path, sizeof(bip44_path_t));
    G_context.tx_info.pool_owner_path_present = false;

    // Read and validate options (fixed header)
    uint64_t options;
    if (!buffer_read_u64(cdata, &options, BE)) {
        TRACE("TX init: missing options");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }
    bool tagCborSets = options & TX_OPTIONS_TAG_CBOR_SETS;
    options &= ~TX_OPTIONS_TAG_CBOR_SETS;
    if (options != 0) {
        TRACE("TX init: unsupported options");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }
    G_context.tx_info.transaction.tagCborSets = tagCborSets;

    // Read network parameters and signing mode
    if (!buffer_read_u8(cdata, &G_context.tx_info.transaction.networkId) ||
        !buffer_read_u32(cdata, &G_context.tx_info.transaction.protocolMagic, BE)) {
        TRACE("TX init: missing network parameters");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Validate network ID immediately - return specific error code
    if (!isValidNetworkId(G_context.tx_info.transaction.networkId)) {
        TRACE("TX init: invalid network id %u", G_context.tx_info.transaction.networkId);
        send_swo_and_reset(SWO_INVALID_NETWORK_ID);
        return;
    }

    // Validate mainnet protocol magic - return specific error code
    if (G_context.tx_info.transaction.networkId == MAINNET_NETWORK_ID &&
        G_context.tx_info.transaction.protocolMagic != MAINNET_PROTOCOL_MAGIC) {
        TRACE("TX init: invalid mainnet protocol magic %u", G_context.tx_info.transaction.protocolMagic);
        send_swo_and_reset(SWO_INVALID_PROTOCOL_MAGIC);
        return;
    }

    uint8_t txSigningMode;
    if (!buffer_read_u8(cdata, &txSigningMode)) {
        TRACE("TX init: missing signing mode");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }
    if (!is_valid_tx_signing_mode(txSigningMode)) {
        TRACE("TX init: invalid signing mode %u", txSigningMode);
        send_swo_and_reset(SWO_WRONG_TX_INIT_APDU_DATA);
        return;
    }
    G_context.tx_info.transaction.txSigningMode = (sign_tx_signingmode_t) txSigningMode;

    // Read transaction structure counts (fields 0-1: inputs and outputs, always present)
    if (!buffer_read_u16(cdata, &G_context.tx_info.transaction.num_inputs, BE) ||
        !buffer_read_u16(cdata, &G_context.tx_info.transaction.num_outputs, BE)) {
        TRACE("TX init: missing inputs/outputs counts");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Field 3 (TTL) - optional
    if (!buffer_read_flag_included(cdata, &G_context.tx_info.transaction.includeTtl)) {
        TRACE("TX init: invalid TTL inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }

    // Field 4 (certificates) - optional
    if (!buffer_read_u16(cdata, &G_context.tx_info.transaction.num_certificates, BE)) {
        TRACE("TX init: missing certificates count");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }
    TRACE(">>>INIT: num_certificates=%u", G_context.tx_info.transaction.num_certificates);

    // Field 5 (withdrawals) - optional
    if (!buffer_read_u16(cdata, &G_context.tx_info.transaction.num_withdrawals, BE)) {
        TRACE("TX init: missing withdrawals count");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Field 7 (auxiliary data hash) - optional
    bool includeAuxDataHash = false;
    if (!buffer_read_flag_included(cdata, &includeAuxDataHash)) {
        TRACE("TX init: invalid aux data hash inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }
    G_context.tx_info.transaction.includeAuxDataHash = includeAuxDataHash;
    if (includeAuxDataHash) {
        uint8_t auxDataTypeByte = 0;
        if (!buffer_read_u8(cdata, &auxDataTypeByte)) {
            TRACE("TX init: missing aux data type");
            send_swo_and_reset(SWO_WRONG_TX_INIT_APDU_DATA);
        return;
        }

        if (auxDataTypeByte == AUX_DATA_TYPE_ARBITRARY_HASH) {
            G_context.tx_info.transaction.auxDataType = AUX_DATA_TYPE_ARBITRARY_HASH;
            if (!buffer_read_bytes(cdata,
                                   G_context.tx_info.transaction.auxDataHash,
                                   AUX_DATA_HASH_LENGTH)) {
                TRACE("TX init: missing aux data hash bytes");
                send_swo_and_reset(SWO_WRONG_TX_INIT_APDU_DATA);
        return;
            }
        } else if (auxDataTypeByte == AUX_DATA_TYPE_CVOTE_REGISTRATION) {
            G_context.tx_info.transaction.auxDataType = AUX_DATA_TYPE_CVOTE_REGISTRATION;
            explicit_bzero(G_context.tx_info.transaction.auxDataHash,
                           AUX_DATA_HASH_LENGTH);
        } else {
            TRACE("TX init: unsupported aux data type %u", auxDataTypeByte);
            send_swo_and_reset(SWO_WRONG_TX_INIT_APDU_DATA);
        return;
        }
    } else {
        G_context.tx_info.transaction.auxDataType = AUX_DATA_TYPE_ARBITRARY_HASH;
        explicit_bzero(G_context.tx_info.transaction.auxDataHash,
                       AUX_DATA_HASH_LENGTH);
    }

    // Field 8 (validity interval start) - optional
    if (!buffer_read_flag_included(cdata, &G_context.tx_info.transaction.includeValidityIntervalStart)) {
        TRACE("TX init: invalid validity interval start inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }

    // Field 9 (mint) - optional
    if (!buffer_read_u16(cdata, &G_context.tx_info.transaction.num_mint_asset_groups, BE)) {
        TRACE("TX init: missing mint asset group count");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Field 11 (script data hash) - optional
    bool includeScriptDataHash = false;
    if (!buffer_read_flag_included(cdata, &includeScriptDataHash)) {
        TRACE("TX init: invalid script data hash inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }
    G_context.tx_info.transaction.includeScriptDataHash = includeScriptDataHash;

    // Field 13 (collateral inputs)
    if (!buffer_read_u16(cdata, &G_context.tx_info.transaction.num_collateral_inputs, BE)) {
        TRACE("TX init: missing collateral inputs count");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Field 14 (required signers)
    if (!buffer_read_u16(cdata, &G_context.tx_info.transaction.num_required_signers, BE)) {
        TRACE("TX init: missing required signers count");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Field 15 (network ID)
    if (!buffer_read_flag_included(cdata, &G_context.tx_info.transaction.includeNetworkId)) {
        TRACE("TX init: invalid network id inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }

    // Field 16 (collateral output)
    if (!buffer_read_flag_included(cdata, &G_context.tx_info.transaction.includeCollateralOutput)) {
        TRACE("TX init: invalid collateral output inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }

    // Field 17 (total collateral)
    if (!buffer_read_flag_included(cdata, &G_context.tx_info.transaction.includeTotalCollateral)) {
        TRACE("TX init: invalid total collateral inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }

    // Field 18 (reference inputs)
    if (!buffer_read_u16(cdata, &G_context.tx_info.transaction.num_reference_inputs, BE)) {
        TRACE("TX init: missing reference inputs count");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Field 19 (voting procedures)
    if (!buffer_read_u16(cdata, &G_context.tx_info.transaction.num_voters, BE)) {
        TRACE("TX init: missing voters count");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Field 21 (treasury) - optional
    if (!buffer_read_flag_included(cdata, &G_context.tx_info.transaction.includeTreasury)) {
        TRACE("TX init: invalid treasury inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }

    // Field 22 (donation) - optional
    if (!buffer_read_flag_included(cdata, &G_context.tx_info.transaction.includeDonation)) {
        TRACE("TX init: invalid donation inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }

    // Read number of witnesses
    if (!buffer_read_u16(cdata, &G_context.tx_info.num_witnesses, BE)) {
        TRACE("TX init: missing witnesses count");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }
    if (buffer_can_read(cdata, 1)) {
        TRACE("TX init APDU not fully consumed");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }
    LEDGER_ASSERT(!buffer_can_read(cdata, 1), "APDU not fully consumed");

    TRACE("TX Mode=%d, Network: ID=%d, Magic=%u, Inputs=%u, Outputs=%u, Withdrawals=%u, Mint=%u, includeTTL=%d, includeVIS=%d, Witnesses=%u",
        G_context.tx_info.transaction.txSigningMode,
        G_context.tx_info.transaction.networkId,
        G_context.tx_info.transaction.protocolMagic,
        G_context.tx_info.transaction.num_inputs,
        G_context.tx_info.transaction.num_outputs,
        G_context.tx_info.transaction.num_withdrawals,
        G_context.tx_info.transaction.num_mint_asset_groups,
        G_context.tx_info.transaction.includeTtl,
        G_context.tx_info.transaction.includeValidityIntervalStart,
        G_context.tx_info.num_witnesses
    );

    // Check security policy
    bool includeMint = (G_context.tx_info.transaction.num_mint_asset_groups > 0);

    security_policy_t init_policy = policyForSignTxInit(
        G_context.tx_info.transaction.txSigningMode,
        G_context.tx_info.transaction.networkId,
        G_context.tx_info.transaction.protocolMagic,
        G_context.tx_info.transaction.num_outputs,
        G_context.tx_info.transaction.num_certificates,
        G_context.tx_info.transaction.num_withdrawals,
        includeMint,
        G_context.tx_info.transaction.includeScriptDataHash,
        G_context.tx_info.transaction.num_collateral_inputs,
        G_context.tx_info.transaction.num_required_signers,
        G_context.tx_info.transaction.includeNetworkId,
        G_context.tx_info.transaction.includeCollateralOutput,
        G_context.tx_info.transaction.includeTotalCollateral,
        G_context.tx_info.transaction.num_reference_inputs,
        G_context.tx_info.transaction.num_voters,
        G_context.tx_info.transaction.includeTreasury,
        G_context.tx_info.transaction.includeDonation,
        &G_context.tx_info.warning_bits);

    TRACE("Transaction init security policy: %d", (int) init_policy);

    if (init_policy == POLICY_DENY) {
        TRACE("Security policy DENY - rejecting transaction init");
        send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        return;
    }

    // Determine if CVote auxiliary data is expected
    bool cvote_aux_data_expected = (includeAuxDataHash &&
                                    (G_context.tx_info.transaction.auxDataType == AUX_DATA_TYPE_CVOTE_REGISTRATION));

    // Show spinner only in standalone mode; in swap mode UI must stay in Exchange app.
#ifdef HAVE_SWAP
    if (!G_called_from_swap)
#endif
    {
        TRACE("Calling nbgl_useCaseSpinner(\"Processing\")");
        nbgl_useCaseSpinner("Processing");
    }

    if (cvote_aux_data_expected) {
        G_context.tx_info.cvote_aux_data.state = CVOTE_AUX_DATA_STATE_EXPECTING_INIT;
        G_context.state.tx_state = TX_STATE_AUX_DATA;
        TRACE("Transaction initialized, waiting for CVote AUX_DATA");
    } else {
        G_context.tx_info.cvote_aux_data.state = CVOTE_AUX_DATA_STATE_NONE;
        // Transition to CHUNKS state - now ready to receive transaction data chunks
        G_context.state.tx_state = TX_STATE_CHUNKS;
        TRACE("Transaction initialized, waiting for data chunks");
    }

    io_send_sw(SWO_SUCCESS);
}

/**
 * Helper: Accumulate transaction data chunks into buffer.
 * Returns true on success. On failure, sends SW and resets context.
 */
static bool handle_tx_data_chunk(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata passed to handle_tx_data_chunk");
    TRACE("SWO_SUCCESS constant = 0x%04x", SWO_SUCCESS);
    const size_t chunk_size = buffer_remaining(cdata);

    // Validate we're in the correct state for receiving chunks
    if (G_context.state.tx_state != TX_STATE_CHUNKS) {
        TRACE("Invalid state for chunk reception: expected TX_STATE_CHUNKS, got %d", G_context.state.tx_state);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return false;
    }

    // Allocate buffer on first data chunk
    if (G_context.tx_info.raw_tx == NULL) {
        TRACE("Allocating transaction buffer: %d bytes", TX_BUFFER_SIZE);
        if (!APP_MEM_CALLOC((void **) &G_context.tx_info.raw_tx, (uint16_t) TX_BUFFER_SIZE)) {
            TRACE("Failed to allocate %d byte transaction buffer!", TX_BUFFER_SIZE);
            send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
            return false;
        }
        TRACE("Transaction buffer allocated: %d bytes at %p", TX_BUFFER_SIZE, G_context.tx_info.raw_tx);
    }

    // Check if adding this chunk would exceed buffer
    if (G_context.tx_info.raw_tx_len + chunk_size > TX_BUFFER_SIZE) {
        TRACE("Transaction too large: current=%u, chunk=%u, max=%u",
              (unsigned) G_context.tx_info.raw_tx_len,
              (unsigned) chunk_size,
              (unsigned) TX_BUFFER_SIZE);
        send_swo_and_reset(SWO_INVALID_TX_LENGTH);
        return false;
    }

    // Copy chunk data
    if (!buffer_move(cdata,
                     G_context.tx_info.raw_tx + G_context.tx_info.raw_tx_len,
                     chunk_size)) {
        TRACE("Failed to copy transaction chunk");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return false;
    }
    G_context.tx_info.raw_tx_len += chunk_size;
    TRACE("Copied %u bytes, total: %u", (unsigned) chunk_size, (unsigned) G_context.tx_info.raw_tx_len);

    return true;
}

void handler_sign_tx(buffer_t *cdata, uint8_t p1) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata passed to sign_tx handler");
    TRACE_BUFFER_T(cdata);

    switch (p1) {
        case P1_TX_INIT:
            if (G_context.req_type != REQUEST_NONE ||
                G_context.state.tx_state != TX_STATE_NONE) {
                TRACE("TX init rejected: request already active");
                send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
                return;
            }
#ifdef HAVE_SWAP
            if (G_called_from_swap && G_swap_response_ready) {
                // Safety against trying to make the app sign multiple TXs in swap mode
                TRACE("Safety against double signing triggered");
                swap_reject_and_exit(SWAP_EC_ERROR_GENERIC, SWAP_APP_CODE_MULTI_SIGN);
            }
            if (G_called_from_swap) {
                TRACE("Swap mode transaction started");
            }
#endif
            G_context.req_type = REQUEST_SIGN_TRANSACTION;
            G_context.state.tx_state = TX_STATE_NONE;
            handle_tx_init_apdu(cdata);
            return;

        case P1_TX_CHUNK:
            if (G_context.req_type != REQUEST_SIGN_TRANSACTION) {
                TRACE("TX data chunk rejected: wrong request type %d", G_context.req_type);
                send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
                return;
            }

            // More data chunks to follow
            if (!handle_tx_data_chunk(cdata)) {
                return;
            }
            io_send_sw(SWO_SUCCESS);
            return;

        case P1_TX_CONFIRM:
            if (G_context.req_type != REQUEST_SIGN_TRANSACTION) {
                TRACE("TX final chunk rejected: wrong request type %d", G_context.req_type);
                send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
                return;
            }

            // Final chunk
            if (!handle_tx_data_chunk(cdata)) {
                return;
            }

            // Parse and build hash
            LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_CHUNKS, "Bad state before parse");
            G_context.state.tx_state = TX_STATE_RECEIVED;

            LEDGER_ASSERT(G_context.tx_info.raw_tx != NULL, "Raw transaction buffer missing");

            buffer_t buf = {
                .ptr = G_context.tx_info.raw_tx,
                .size = G_context.tx_info.raw_tx_len,
                .offset = 0
            };

            parser_status_e parse_status = parse_tx(&buf, &G_context.tx_info.transaction);
            if (parse_status != PARSING_OK) {
                tx_handle_parse_error(parse_status);
                return;
            }
            G_context.state.tx_state = TX_STATE_PARSED;
            tx_ui_plan_t ui_plan = {0};
            // Validate transaction and compute hash. On failure, stop immediately before UI prep.
            int validation_status = tx_validate_and_compute_hash(&ui_plan);
            if (validation_status != SWO_SUCCESS) {
                TRACE("TX validation/hash failed: 0x%04x", validation_status);
                send_swo_and_reset(validation_status);
                return;
            }

            G_context.state.tx_state = TX_STATE_HASHED;

#ifdef HAVE_SWAP
            if (G_called_from_swap) {
                // Validate swap parameters against parsed transaction
                // Check fee
                if (!swap_check_fee_validity(G_context.tx_info.transaction.fee)) {
                    swap_reject_and_exit(SWAP_EC_ERROR_WRONG_FEES, SWAP_APP_CODE_DEFAULT);
                }

                // Check outputs: exactly one THIRD_PARTY output must be present and it must
                // match the destination + amount validated by Exchange.
                size_t third_party_output_count = 0;
                flist_node_t *node = G_context.tx_info.transaction.outputs;
                while (node != NULL) {
                    tx_output_node_t *outputNode = (tx_output_node_t *) node;
                    parsed_tx_output_t *output = &outputNode->output_data;

                    if (output->destination.type == DESTINATION_THIRD_PARTY) {
                        third_party_output_count++;
                        if (!swap_check_destination_validity(&output->destination)) {
                            swap_reject_and_exit(SWAP_EC_ERROR_WRONG_DESTINATION,
                                                 SWAP_APP_CODE_DEFAULT);
                        }
                        if (!swap_check_amount_validity(output->adaAmount)) {
                            swap_reject_and_exit(SWAP_EC_ERROR_WRONG_AMOUNT,
                                                 SWAP_APP_CODE_DEFAULT);
                        }
                    }
                    node = node->next;
                }

                if (third_party_output_count != 1) {
                    TRACE("Swap: expected exactly one THIRD_PARTY output, found %u",
                          (unsigned int) third_party_output_count);
                    swap_reject_and_exit(SWAP_EC_ERROR_WRONG_DESTINATION, SWAP_APP_CODE_DEFAULT);
                }

                // In swap mode, skip UI and auto-approve the transaction
                G_context.state.tx_state = TX_STATE_APPROVED;
                io_send_response_pointer(
                    G_context.tx_info.tx_hash,
                    sizeof(G_context.tx_info.tx_hash),
                    SWO_SUCCESS);
                return;
            }
#endif

            LEDGER_ASSERT(ui_plan.pair_count > 0, "Invalid UI plan");
            G_context.tx_info.planned_ui_pairs = ui_plan.pair_count;

            int ui_prep_result = ui_prepare_transaction_review();
            if (ui_prep_result != SWO_SUCCESS) {
                tx_review_cleanup();
                TRACE("TX UI preparation failed: 0x%04x", ui_prep_result);
                send_swo_and_reset(ui_prep_result);
                return;
            }

            G_context.state.tx_state = TX_STATE_UI_PREPARED;
            ui_display_transaction();
            // waiting for NBGL callback tx_review_choice, so no APDU sent
            return;

        default:
            TRACE("Unexpected P1 for SIGN_TX");
            send_swo_and_reset(SWO_INCORRECT_P1_P2);
            return;
    }
}

void finalize_sign_tx(bool confirm) {
    LEDGER_ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION,
                  "finalize_sign_tx called without REQUEST_SIGN_TRANSACTION");
    LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_UI_PREPARED,
                  "finalize_sign_tx called in wrong state: %d", G_context.state.tx_state);

    if (!confirm) {
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        return;
    }

    G_context.state.tx_state = TX_STATE_APPROVED;
    G_context.tx_info.current_witness = 0;
    io_send_response_pointer(G_context.tx_info.tx_hash, SIZEOF(G_context.tx_info.tx_hash), SWO_SUCCESS);

    if (G_context.tx_info.num_witnesses == 0) {
        // there are no witnesses, we are done with this tx
        reset_app_context();
    }
}


// All witnesses processed
void finalize_witness(bool confirm)
{
    if (!confirm) {
        // Reject entire signing operation - no more witnesses will be processed
        TRACE("Witness rejected by user");
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        return;
    }

    // Witness confirmed - sign transaction hash with the selected witness path
    getWitness(&G_context.tx_info.witness_path,
               G_context.tx_info.tx_hash,
               SIZEOF(G_context.tx_info.tx_hash),
               G_context.tx_info.witness_signature,
               SIZEOF(G_context.tx_info.witness_signature));

    TRACE_BUFFER(G_context.tx_info.witness_signature, ED25519_SIGNATURE_LENGTH);

    // Witness confirmed - send signature back
#ifdef HAVE_SWAP
    if (G_called_from_swap &&
        (G_context.tx_info.current_witness + 1 == G_context.tx_info.num_witnesses)) {
        // The final witness response must return to Exchange app.
        TRACE("Swap mode: final witness response will return to Exchange");
        G_swap_response_ready = true;
    }
#endif
    io_send_response_pointer(
        G_context.tx_info.witness_signature,
        ED25519_SIGNATURE_LENGTH,
        SWO_SUCCESS
    );
    G_context.tx_info.current_witness++;
    if (G_context.tx_info.current_witness == G_context.tx_info.num_witnesses) {
        // All witnesses processed - reset context to prevent further APDUs for this tx
        reset_app_context();
    }
}

void handler_sign_tx_witness(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata passed to sign_tx_witness handler");
    TRACE_BUFFER_T(cdata);

    // Verify we're in correct state for witness signing
    if (G_context.req_type != REQUEST_SIGN_TRANSACTION) {
        TRACE("Bad request type for witness signing: %d", G_context.req_type);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return;
    }

    if (G_context.state.tx_state != TX_STATE_APPROVED) {
        TRACE("Bad state for witness signing: expected TX_STATE_APPROVED, got %d", G_context.state.tx_state);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return;
    }

    // Check that we haven't exceeded the expected number of witnesses
    if (G_context.tx_info.current_witness >= G_context.tx_info.num_witnesses) {
        TRACE("Witness count exceeded: current=%d, expected=%d",
              G_context.tx_info.current_witness,
              G_context.tx_info.num_witnesses
        );
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return;
    }

    // Parse witness path from APDU data
    // buffer_read_bip44_path reads the length byte and all path components
    if (!buffer_read_bip44_path(cdata, &G_context.tx_info.witness_path)) {
        TRACE("Witness APDU: failed to parse BIP44 path");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }
    if (buffer_can_read(cdata, 1)) {
        TRACE("Witness APDU not fully consumed");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }
    LEDGER_ASSERT(!buffer_can_read(cdata, 1), "APDU not fully consumed");

    TRACE("Witness %d: path length=%d",
           G_context.tx_info.current_witness,
           G_context.tx_info.witness_path.length);

    // Check security policy for witness signing
    // Determine if mint is present in the transaction
    bool mintPresent = (G_context.tx_info.transaction.num_mint_asset_groups > 0);

    // Get pool owner path if this is a pool registration
    const bip44_path_t* poolOwnerPath = NULL;
    switch (G_context.tx_info.transaction.txSigningMode) {
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
            if (G_context.tx_info.pool_owner_path_present) {
                poolOwnerPath = &G_context.tx_info.pool_owner_path;
            }
            break;
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
            break;
        default:
            break;
    }

    warning_bits_t witness_warnings = 0;
#ifdef HAVE_SWAP
    const bool isSwap = G_called_from_swap;
#else
    const bool isSwap = false;
#endif
    security_policy_t policy = policyForSignTxWitness(
        G_context.tx_info.transaction.txSigningMode,
        isSwap,
        &G_context.tx_info.witness_path,
        mintPresent,
        poolOwnerPath,
        &witness_warnings
    );

    TRACE("Witness security policy: %d", (int) policy);

#ifdef HAVE_SWAP
    // Invariant: swap-validated params must only exist in swap invocation context.
    if (swap_transaction_params_initialized() && !G_called_from_swap) {
        LEDGER_ASSERT(false, "Swap params initialized outside swap context");
    }
#endif

    // Handle DENY policy
    if (policy == POLICY_DENY) {
        TRACE("Security policy DENY - rejecting witness");
#ifdef HAVE_SWAP
        if (G_called_from_swap) {
            swap_reject_and_exit(SWAP_EC_ERROR_GENERIC, SWAP_APP_CODE_DENIED_WITNESS_POLICY);
        }
#endif
        send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        return;
    }

    switch (policy) {
        case POLICY_HIDE:
            // POLICY_HIDE: witness does not require user confirmation
            // Finalize directly without displaying UI (similar to silent pubkey export)
            finalize_witness(true);

            // Handle UI state: if this was the last witness, return to main menu
            // Otherwise, the spinner from tx_review_choice will continue showing
            // Note: In swap mode, finalize_witness calls os_lib_end() so this code
            // is not reached, but we guard it anyway for safety.
            if (G_context.tx_info.current_witness == G_context.tx_info.num_witnesses) {
#ifdef HAVE_SWAP
                if (!G_called_from_swap)
#endif
                {
                    // All witnesses processed - return to main menu
                    TRACE("All POLICY_HIDE witnesses complete, returning to main menu");
                    ui_menu_main();
                }
            }
            return;

        case POLICY_SHOW:
            ui_display_witness(&G_context.tx_info.witness_path, policy, witness_warnings);
            // waiting for NBGL callback witness_review_choice, so no APDU sent
            return;

        case POLICY_DENY:
            // Already handled earlier in function - should never reach here
            LEDGER_ASSERT(false, "POLICY_DENY should be handled before signing");
            return;

        default:
            LEDGER_ASSERT(false, "Invalid security policy");
            return;
    }
}
