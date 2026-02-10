/*****************************************************************************
 *   Ledger App Cardano.
 *   (c) 2025 Ledger SAS and Vacuumlabs
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

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"
#include "io.h"
#include "ledger_assert.h"

#include "parser.h"
#include "dispatcher.h"
#include "globals.h"
#include "cardano_swo.h"
#include "assert.h"
#include "utils.h"
#include "app_context.h"
#include "get_serial.h"
#include "get_version.h"
#include "get_app_name.h"
#include "get_public_key.h"
#include "sign_tx.h"
#include "sign_tx_aux_data.h"
#include "sign_opcert.h"
#include "derive_address.h"
#include "derive_native_script_hash.h"
#include "sign_cvote.h"
#include "sign_msg.h"

#ifdef DEBUG
#include "debug_settings.h"
#endif

#ifdef HAVE_SWAP
#include "swap.h"
#include "swap_error_code_helpers.h"
#include "swap_lib.h"
#endif

/**
 * Map request type to its expected instruction
 * Used to detect instruction interleaving attacks
 *
 * Precondition: req_type != REQUEST_NONE
 */
static command_e req_type_to_instruction(request_type_e req_type) {
    LEDGER_ASSERT(req_type != REQUEST_NONE, "REQUEST_NONE does not map to an instruction");

    switch (req_type) {
        case REQUEST_EXPORT_PUBKEY:
            return INS_GET_PUBLIC_KEY;
        case REQUEST_SIGN_TRANSACTION:
            return INS_SIGN_TX;
        case REQUEST_SIGN_OPCERT:
            return INS_SIGN_OPCERT;
        case REQUEST_DERIVE_ADDRESS:
            return INS_DERIVE_ADDRESS;
        case REQUEST_DERIVE_NATIVE_SCRIPT_HASH:
            return INS_DERIVE_NATIVE_SCRIPT_HASH;
        case REQUEST_CVOTE:
            return INS_SIGN_CVOTE;
        case REQUEST_SIGN_MSG:
            return INS_SIGN_MSG;
        default:
            LEDGER_ASSERT(false, "Unknown request type");
            return INS_GET_VERSION;  // Unreachable
    }
}


void apdu_dispatcher(const command_t *cmd) {
    LEDGER_ASSERT(cmd != NULL, "NULL cmd");
    apdu_response_begin(cmd->ins);
    TRACE("G_context.req_type: %d", G_context.req_type);

    // Log the appropriate state based on request type
    switch (G_context.req_type) {
        case REQUEST_SIGN_TRANSACTION:
            TRACE("G_context.state.tx_state: %d", G_context.state.tx_state);
            break;
        case REQUEST_SIGN_OPCERT:
            TRACE("G_context.state.opcert_state: %d", G_context.state.opcert_state);
            break;
        case REQUEST_DERIVE_ADDRESS:
            TRACE("G_context.state.derive_address_state: %d", G_context.state.derive_address_state);
            break;
        default:
            // Stateless operations (GET_PUBLIC_KEY, GET_VERSION, etc.)
            break;
    }

    // Guard against instruction interleaving attacks
    // If an operation is in progress, only allow the same instruction to continue
    if (G_context.req_type != REQUEST_NONE) {
        command_e expected_ins = req_type_to_instruction(G_context.req_type);
        if (cmd->ins != expected_ins) {
            TRACE("Instruction interleaving detected: current=%d (req_type=%d), attempted=%d",
                  expected_ins,
                  G_context.req_type,
                  cmd->ins);
            send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
            apdu_response_assert_sent_or_deferred();
            return;
        }
        TRACE("Same instruction continuing: ins=%d", cmd->ins);
    } else {
        // This is a new request, ensure we start with a clean context
        reset_app_context();
    }

#ifdef HAVE_SWAP
    // In swap mode, only allow a restricted set of instructions
    if (G_called_from_swap) {
        if (cmd->ins != INS_GET_VERSION &&
            cmd->ins != INS_GET_PUBLIC_KEY &&
            cmd->ins != INS_DERIVE_ADDRESS &&
            cmd->ins != INS_SIGN_TX) {
            TRACE("Instruction %d not allowed in swap mode", cmd->ins);
            swap_reject_and_exit(SWAP_EC_ERROR_WRONG_METHOD, SWAP_APP_CODE_BAD_INS);
        }
    }
#endif

    if (cmd->cla != CLA) {
        send_swo_and_reset(SWO_INVALID_CLA);
        apdu_response_assert_sent_or_deferred();
        return;
    }

    // Create data buffer upfront from APDU data
    buffer_t data_buffer = {.ptr = cmd->data, .size = cmd->lc, .offset = 0};

    switch (cmd->ins) {
        case INS_GET_SERIAL:
            if (cmd->p1 != P1_UNUSED || cmd->p2 != P2_UNUSED) {
                send_swo_and_reset(SWO_INCORRECT_P1_P2);
                apdu_response_assert_sent_or_deferred();
                return;
            }

            handler_get_serial(&data_buffer);
            apdu_response_assert_sent_or_deferred();
            return;

        case INS_GET_VERSION:
            if (cmd->p1 != P1_UNUSED || cmd->p2 != P2_UNUSED) {
                send_swo_and_reset(SWO_INCORRECT_P1_P2);
                apdu_response_assert_sent_or_deferred();
                return;
            }

            handler_get_version(&data_buffer);
            apdu_response_assert_sent_or_deferred();
            return;

        case INS_GET_APP_NAME:
            if (cmd->p1 != P1_UNUSED || cmd->p2 != P2_UNUSED) {
                send_swo_and_reset(SWO_INCORRECT_P1_P2);
                apdu_response_assert_sent_or_deferred();
                return;
            }

            handler_get_app_name(&data_buffer);
            apdu_response_assert_sent_or_deferred();
            return;

        case INS_GET_PUBLIC_KEY: {
            if (cmd->p1 != P1_UNUSED || cmd->p2 != P2_UNUSED) {
                send_swo_and_reset(SWO_INCORRECT_P1_P2);
                apdu_response_assert_sent_or_deferred();
                return;
            }

            handler_get_public_key(&data_buffer);
            apdu_response_assert_sent_or_deferred();
            return;
        }

        case INS_DERIVE_ADDRESS:
            if (cmd->p2 != P2_UNUSED) {
                send_swo_and_reset(SWO_INCORRECT_P1_P2);
                apdu_response_assert_sent_or_deferred();
                return;
            }

            // Validate and dispatch based on P1 value
            switch (cmd->p1) {
                case P1_ADDRESS_RETURN:
                case P1_ADDRESS_DISPLAY:
                    handler_derive_address(&data_buffer, cmd->p1);
                    apdu_response_assert_sent_or_deferred();
                    return;
                default:
                    send_swo_and_reset(SWO_INCORRECT_P1_P2);
                    apdu_response_assert_sent_or_deferred();
                    return;
            }

        case INS_DERIVE_NATIVE_SCRIPT_HASH:
            // P2 must be unused for native script hash APDUs
            if (cmd->p2 != P2_UNUSED) {
                send_swo_and_reset(SWO_INCORRECT_P1_P2);
                apdu_response_assert_sent_or_deferred();
                return;
            }
            // Validate and dispatch based on P1 value
            switch (cmd->p1) {
                case P1_NATIVE_SCRIPT_START_COMPLEX:
                case P1_NATIVE_SCRIPT_ADD_SIMPLE:
                case P1_NATIVE_SCRIPT_FINISH:
                    handler_derive_native_script_hash(&data_buffer, cmd->p1);
                    apdu_response_assert_sent_or_deferred();
                    return;
                default:
                    send_swo_and_reset(SWO_INCORRECT_P1_P2);
                    apdu_response_assert_sent_or_deferred();
                    return;
            }

        case INS_SIGN_TX:
            // Check if this is a witness APDU
            if (cmd->p1 == P1_TX_SIGN_WITNESS) {
                if (cmd->p2 != P2_UNUSED) {
                    send_swo_and_reset(SWO_INCORRECT_P1_P2);
                    apdu_response_assert_sent_or_deferred();
                    return;
                }

                handler_sign_tx_witness(&data_buffer);
                apdu_response_assert_sent_or_deferred();
                return;
            }

            // Check if this is auxiliary data APDU (CVote)
            if (cmd->p1 == P1_TX_AUX_DATA) {
                if (cmd->p2 != P2_AUX_DATA_INIT && cmd->p2 != P2_AUX_DATA_DELEGATION) {
                    send_swo_and_reset(SWO_INCORRECT_P1_P2);
                    apdu_response_assert_sent_or_deferred();
                    return;
                }

                handler_sign_tx_aux_data(&data_buffer, cmd->p2);
                apdu_response_assert_sent_or_deferred();
                return;
            }

            // Transaction processing
            // P1 controls flow: P1_TX_INIT (0x00), P1_TX_CHUNK (0x01), P1_TX_CONFIRM (0x02)
            // P2 must be unused for transaction body APDUs
            if (cmd->p2 != P2_UNUSED) {
                send_swo_and_reset(SWO_INCORRECT_P1_P2);
                apdu_response_assert_sent_or_deferred();
                return;
            }

            handler_sign_tx(&data_buffer, cmd->p1);
            apdu_response_assert_sent_or_deferred();
            return;

        case INS_SIGN_OPCERT: {
            if (cmd->p1 != P1_UNUSED || cmd->p2 != P2_UNUSED) {
                send_swo_and_reset(SWO_INCORRECT_P1_P2);
                apdu_response_assert_sent_or_deferred();
                return;
            }

            handler_sign_opcert(&data_buffer);
            apdu_response_assert_sent_or_deferred();
            return;
        }

        case INS_SIGN_CVOTE: {
            // P2 must be unused for cvote
            if (cmd->p2 != P2_UNUSED) {
                send_swo_and_reset(SWO_INCORRECT_P1_P2);
                apdu_response_assert_sent_or_deferred();
                return;
            }
            // Validate and dispatch based on P1 value
            switch (cmd->p1) {
                case P1_CVOTE_INIT:
                case P1_CVOTE_CHUNK:
                case P1_CVOTE_CONFIRM:
                    handler_sign_cvote(&data_buffer, cmd->p1);
                    apdu_response_assert_sent_or_deferred();
                    return;
                default:
                    send_swo_and_reset(SWO_INCORRECT_P1_P2);
                    apdu_response_assert_sent_or_deferred();
                    return;
            }
        }

        case INS_SIGN_MSG: {
            // P2 must be unused for message signing
            if (cmd->p2 != P2_UNUSED) {
                send_swo_and_reset(SWO_INCORRECT_P1_P2);
                apdu_response_assert_sent_or_deferred();
                return;
            }
            // Validate and dispatch based on P1 value
            switch (cmd->p1) {
                case P1_SIGN_MSG_INIT:
                case P1_SIGN_MSG_CHUNK:
                case P1_SIGN_MSG_CONFIRM:
                    handler_sign_msg(&data_buffer, cmd->p1);
                    apdu_response_assert_sent_or_deferred();
                    return;
                default:
                    send_swo_and_reset(SWO_INCORRECT_P1_P2);
                    apdu_response_assert_sent_or_deferred();
                    return;
            }
        }

#ifdef DEBUG
        case INS_DEBUG_SET_SETTINGS: {
            // Debug-only command to set app settings for testing
            if (cmd->p1 != P1_UNUSED || cmd->p2 != P2_UNUSED) {
                send_swo_and_reset(SWO_INCORRECT_P1_P2);
                apdu_response_assert_sent_or_deferred();
                return;
            }

            handler_debug_set_settings(&data_buffer);
            apdu_response_assert_sent_or_deferred();
            return;
        }
#endif

        default:
            send_swo_and_reset(SWO_INVALID_INS);
            apdu_response_assert_sent_or_deferred();
            return;
    }
}
