#include <stdbool.h>  // bool

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "utils.h"

#include "ui_icons.h"
#include "globals.h"
#include "cardano_swo.h"
#include "menu.h"
#include "tx_parse.h"
#include "ui_utils.h"
#include "ui_warnings.h"
#include "ui_display_tx.h"
#include "app_context.h"

void tx_review_cleanup(void) {
    ui_pairs_cleanup();
    ui_free_warnings();
}

static void tx_review_choice(bool confirm) {
    // CLEANUP
    tx_review_cleanup();

    if (confirm) {
        // FINALIZE
        G_context.state.tx_state = TX_STATE_APPROVED;
        G_context.tx_info.current_witness = 0;
        io_send_response_pointer(G_context.tx_info.tx_hash, sizeof(G_context.tx_info.tx_hash), SWO_SUCCESS);

        // SHOW STATUS
        if (G_context.tx_info.num_witnesses > 0) {
            TRACE("Calling nbgl_useCaseSpinner(\"Processing\")");
            nbgl_useCaseSpinner("Processing");
        } else {
            reset_app_context();
            TRACE("Calling nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main)");
            nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
        }
    } else {
        // FINALIZE
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);

        // SHOW STATUS
        TRACE("Calling nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main)");
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
        return;
    }
}

void ui_display_transaction(void) {
    if (G_context.req_type != REQUEST_SIGN_TRANSACTION || G_context.state.tx_state != TX_STATE_UI_PREPARED) {
        G_context.state.tx_state = TX_STATE_NONE;
        send_swo_and_reset(SWO_BAD_STATE);
        return;
    }

    const char *review_subtitle = NULL;
    switch (G_context.tx_info.transaction.txSigningMode) {
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
    TRACE("Calling nbgl_useCaseAdvancedReview(TYPE_TRANSACTION)");
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
