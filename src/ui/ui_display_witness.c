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
#include <string.h>   // memset

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "bip44.h"
#include "format.h"

#include "ui_icons.h"
#include "ui_constants.h"
#include "globals.h"
#include "utils.h"
#include "app_context.h"
#include "cardano_swo.h"
#include "securityPolicy.h"
#include "menu.h"
#include "mem.h"
#include "tx_parse.h"
#include "ui_utils.h"
#include "sign_tx.h"

static void witness_review_choice(bool confirm) {
    // CLEANUP
    if (G_context.tx_info.witness_path_str != NULL) {
        APP_MEM_FREE(G_context.tx_info.witness_path_str);
        G_context.tx_info.witness_path_str = NULL;
    }

    // FINALIZE
    finalize_witness(confirm);

    // SHOW STATUS
    if (confirm) {
        if (G_context.tx_info.current_witness == G_context.tx_info.num_witnesses) {
            // All witnesses processed - show final success status
            TRACE("Calling nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main)");
            nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
        } else {
            // More witnesses to process - show spinner
            TRACE("Calling nbgl_useCaseSpinner(\"Processing\")");
            nbgl_useCaseSpinner("Processing");
        }
    } else {
        TRACE("Calling nbgl_useCaseStatus(\"Witness denied\", true, ui_menu_main)");
        nbgl_useCaseStatus("Witness denied", true, ui_menu_main);
    }
}

void ui_display_witness(const bip44_path_t* witnessPath,
                       security_policy_t securityPolicy,
                       warning_bits_t warnings) {
    TRACE("=== ui_display_witness START ===");
    TRACE("securityPolicy: %d", securityPolicy);

    if (G_context.state.tx_state != TX_STATE_APPROVED || G_context.req_type != REQUEST_SIGN_TRANSACTION) {
        TRACE("Bad state detected - returning error");
        send_swo_and_reset(SWO_BAD_STATE);
        return;
    }

    // Allocate display buffer for witness path
    G_context.tx_info.witness_path_str =
        (char *) APP_MEM_ALLOC_ZEROED(MAX_BIP44_PATH_STRING_LENGTH + UI_BUFFER_SAFETY_MARGIN);
    if (G_context.tx_info.witness_path_str == NULL) {
        TRACE("Failed to allocate witness path string");
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }

    bool isUnusual = warning_bits_has(warnings, WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH);

    if (securityPolicy != POLICY_SHOW) {
        LEDGER_ASSERT(false, "Unexpected security policy");
        return;
    }

    TRACE("isUnusual: %d", isUnusual);

    // Format the witness path as a string
    bool formatted = format_bip44_path(witnessPath,
                                       G_context.tx_info.witness_path_str,
                                       MAX_BIP44_PATH_STRING_LENGTH + UI_BUFFER_SAFETY_MARGIN);
    LEDGER_ASSERT(formatted, "Unable to format witness path");
    LEDGER_ASSERT(strlen(G_context.tx_info.witness_path_str) <= MAX_BIP44_PATH_STRING_LENGTH,
                  "Witness path ui string buffer too short");

    if (isUnusual) {
        // A mild warning about unusual path
        // No immediate threat, just to be aware that the witness key is unusual
        TRACE("Calling nbgl_useCaseChoice(title=Sign with UNUSUAL key)");
        nbgl_useCaseChoice(
            &WARNING_ICON,
            "Sign with UNUSUAL key",
            G_context.tx_info.witness_path_str,
            "Confirm",
            "Reject",
            witness_review_choice
        );
    } else {
        // Normal path display
        TRACE("Calling nbgl_useCaseChoice(title=Witness)");
        nbgl_useCaseChoice(
            &ICON_APP_CARDANO,
            "Witness",
            G_context.tx_info.witness_path_str,
            "Confirm",
            "Reject",
            witness_review_choice
        );
    }

    return;
}
