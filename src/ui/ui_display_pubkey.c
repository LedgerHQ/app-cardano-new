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
#include "utils.h"
#include "app_context.h"
#include "cardano_swo.h"
#include "opcert_types.h"
#include "menu.h"
#include "securityPolicy.h"
#include "get_public_key.h"
#include "ui_utils.h"
#include "cardano_settings.h"
#include "mem.h"

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_UI_DISPLAY to trace UI flow details.
 */
#ifdef TRACE_UI_DISPLAY
#define TRACE_MODULE(...) TRACE("[ui_pubkey] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void)0  // Compiled out
#endif

#define PUBKEY_EXPORT_TITLE_BUFFER_SIZE 64
#define PUBKEY_EXPORT_TITLE_ALLOCATION_SIZE (PUBKEY_EXPORT_TITLE_BUFFER_SIZE + UI_BUFFER_SAFETY_MARGIN)

static char *g_pubkey_export_choice_title = NULL;

static void pubkey_review_cleanup(void) {
    APP_MEM_FREE_AND_NULL((void **) &g_pubkey_export_choice_title);
}

static void pubkey_review_choice(bool confirm) {
    // CLEANUP
    pubkey_review_cleanup();

    // FINALIZE
    if (!confirm) {
        TRACE_MODULE("User rejected");
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main);
        return;
    }

    TRACE_MODULE("User confirmed");
    // does not need a spinner
    finalize_pubkey_export();

    // SHOW STATUS
    // Keep a custom status here: exporting a public key is not a signing operation,
    // and nbgl_reviewStatusType_t has no "public key exported" equivalent.
    nbgl_useCaseStatus("Public key exported", true, ui_menu_main);
}

void ui_display_pubkey(security_policy_t securityPolicy, warning_bits_t warnings) {
    TRACE_MODULE("=== ui_display_pubkey START ===");
    TRACE_MODULE("securityPolicy: %d", securityPolicy);

    LEDGER_ASSERT(G_context.req_type == REQUEST_EXPORT_PUBKEY,
                  "ui_display_pubkey called with wrong request type: %d",
                  G_context.req_type);

    pubkey_ctx_t* pk = &G_context.pk_info;
    LEDGER_ASSERT(
        warning_bits_except_mask(warnings,
                                 warning_bits_mask_for(WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) == 0,
        "Unexpected warning bits: 0x%08x",
        (unsigned int) warnings);

    // Format path into static buffer
    bool pathFormatted = format_bip44_path(&pk->path,
                                           G_context.pk_info.path_str,
                                           sizeof(G_context.pk_info.path_str));
    LEDGER_ASSERT(pathFormatted, "Unable to format public key path");
    LEDGER_ASSERT(strlen(G_context.pk_info.path_str) <= MAX_BIP44_PATH_STRING_LENGTH, "Public key path ui string buffer too short");

    switch (securityPolicy) {
        case POLICY_SHOW:
            pk->silentExport = false;
            break;

        case POLICY_HIDE:
            LEDGER_ASSERT(is_silent_pubkey_export_allowed(), "Silent pubkey export not allowed");
            pk->silentExport = true;
            finalize_pubkey_export();
            return;

        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unexpected security policy");
            return;
        // LCOV_EXCL_STOP
    }

    bool isColdKey = (bip44_classifyPath(&pk->path) == PATH_POOL_COLD_KEY);
    const char* keyTypeLabel = isColdKey ? "Cold public key" : "Public key";

    // Prepare icon and title based on whether path is unusual
    bool isUnusual = warning_bits_has(warnings, WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH);
    const nbgl_icon_details_t* icon = isUnusual ? &WARNING_ICON : &ICON_APP_CARDANO;
    const char* exportPrefix = isUnusual ? "Export UNUSUAL" : "Export";

    pubkey_review_cleanup();
    LEDGER_ASSERT(allocate_zeroed((void **) &g_pubkey_export_choice_title, PUBKEY_EXPORT_TITLE_ALLOCATION_SIZE), "Failed to allocate public key export title");

    int written = snprintf(g_pubkey_export_choice_title,
                           PUBKEY_EXPORT_TITLE_ALLOCATION_SIZE,
                           "%s %s",
                           exportPrefix,
                           keyTypeLabel);

    LEDGER_ASSERT(written > 0, "snprintf UI title formatting failed");
    LEDGER_ASSERT((size_t) written + 1 < PUBKEY_EXPORT_TITLE_ALLOCATION_SIZE, "UI title truncated");
    ASSERT(icon != NULL);
    nbgl_useCaseChoice(
                        icon,
                        g_pubkey_export_choice_title,
                        G_context.pk_info.path_str,
                        "Export",
                        "Reject",
                        pubkey_review_choice
    );

    return;
}
