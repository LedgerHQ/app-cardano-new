/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

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
#include "sign_tx_ctx.h"
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
    // No dynamically allocated UI buffers to release in this flow.

    // FINALIZE
    if (!confirm) {
        TRACE("User rejected");
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
        return;
    }

    TRACE("User confirmed");
    nbgl_useCaseSpinner("Processing");
    const bool is_last_witness = is_last_witness_to_process();
    finalize_witness();

    // SHOW STATUS
    if (is_last_witness) {
        // All witnesses processed - show final success status
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    }
}

void ui_display_witness(const bip44_path_t* witnessPath,
                       security_policy_t securityPolicy,
                       warning_bits_t warnings) {
    TRACE("=== ui_display_witness START ===");
    TRACE("securityPolicy: %d", securityPolicy);

    if (G_context.state.tx_state != TX_STATE_APPROVED || G_context.req_type != REQUEST_SIGN_TRANSACTION) {
        TRACE("Bad state detected - returning error");
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return;
    }

    bool isUnusual = warning_bits_has(warnings, WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH);

    if (securityPolicy != POLICY_SHOW) {
        LEDGER_ASSERT(false, "Unexpected security policy");
        return;
    }

    TRACE("isUnusual: %d", isUnusual);

    // Format the witness path into static buffer
    bool formatted = format_bip44_path(witnessPath,
                                       tx_witness_ctx()->witness_path_str,
                                       sizeof(tx_witness_ctx()->witness_path_str));
    LEDGER_ASSERT(formatted, "Unable to format witness path");
    LEDGER_ASSERT(strlen(tx_witness_ctx()->witness_path_str) <= MAX_BIP44_PATH_STRING_LENGTH, "Witness path ui string buffer too short");

    if (isUnusual) {
        // A mild warning about unusual path
        // No immediate threat, just to be aware that the witness key is unusual
        nbgl_useCaseChoice(
            &WARNING_ICON,
            "Sign with UNUSUAL key",
            tx_witness_ctx()->witness_path_str,
            "Confirm",
            "Reject",
            witness_review_choice
        );
    } else {
        // Normal path display
        nbgl_useCaseChoice(
            &ICON_APP_CARDANO,
            "Witness",
            tx_witness_ctx()->witness_path_str,
            "Confirm",
            "Reject",
            witness_review_choice
        );
    }

    return;
}
