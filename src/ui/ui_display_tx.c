/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>  // bool

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "utils.h"

#include "ui_icons.h"
#include "globals.h"
#include "cardano_swo.h"
#include "menu.h"
#include "app_context.h"
#include "tx_parse.h"
#include "ui_utils.h"
#include "ui_warnings.h"
#include "ui_display_tx.h"
#include "sign_tx.h"

void tx_review_cleanup(void) {
    ui_all_cleanup();
}

static void tx_review_choice(bool confirm) {
    const bool has_witnesses = (G_context.tx_info.num_witnesses > 0);

    // CLEANUP
    tx_review_cleanup();

    // FINALIZE
    finalize_sign_tx(confirm);

    // SHOW STATUS
    if (confirm) {
        if (has_witnesses) {
            nbgl_useCaseSpinner("Processing");
        } else {
            nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
        }
        return;
    }
    nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
}

void ui_display_transaction(void) {
    if (G_context.req_type != REQUEST_SIGN_TRANSACTION || G_context.state.tx_state != TX_STATE_UI_PREPARED) {
        G_context.state.tx_state = TX_STATE_NONE;
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return;
    }

    const char *review_subtitle = NULL;
    switch (G_context.tx_info.tx_params.txSigningMode) {
        case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
            review_subtitle = "Plutus execution";
            break;
        case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
            review_subtitle = "Multisig transaction";
            break;
        default:
            break;
    }

    const nbgl_warning_t *warningPtr = ui_get_warnings();
    nbgl_useCaseAdvancedReview(TYPE_TRANSACTION,
                               g_pairsList,
                               &ICON_APP_CARDANO,
                               "Review transaction",
                               review_subtitle,
                               "Sign transaction",
                               NULL,
                               warningPtr,
                               tx_review_choice);

    return;
}
