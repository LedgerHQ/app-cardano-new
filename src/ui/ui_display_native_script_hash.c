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

#include "app_context.h"
#include "bech32.h"
#include "cardano_constants.h"
#include "cardano_swo.h"
#include "derive_native_script_hash.h"
#include "globals.h"
#include "io.h"
#include "menu.h"
#include "nbgl_use_case.h"
#include "memory/mem.h"
#include "securityPolicy.h"
#include "ui/ui_formatters.h"
#include "ui/ui_icons.h"
#include "ui/ui_utils.h"
#include "ui_display_native_script_hash.h"
#include "utils/utils.h"

void build_position_description(const derive_native_script_hash_ctx_t *ctx,
                                uint8_t level,
                                char *out,
                                size_t out_len) {
    explicit_bzero(out, out_len);
    char *ptr = out;
    char *end = out + out_len;

    // Position prefix
    snprintf(ptr, end - ptr, "");
    ptr += strlen(ptr);

    LEDGER_ASSERT(level >= 1, "Invalid level %d", level);
    LEDGER_ASSERT(level < MAX_SCRIPT_DEPTH, "Excedeed max script depth");

    // Levels
    for (size_t i = 1; i <= level; i++) {
        uint32_t position =
            ctx->complexScripts[i].totalScripts - ctx->complexScripts[i].remainingScripts + 1;
        STATIC_ASSERT(!IS_SIGNED(position), "signed type for %u");
        snprintf(ptr, end - ptr, "%u.", position);
        LEDGER_ASSERT(strlen(out) + 1 < out_len, "Excedeed output size");
        ptr += strlen(ptr);
    }

    // Remove trailing '.'
    LEDGER_ASSERT(ptr > out, "Excedeed output size");
    *(ptr - 1) = '\0';
    LEDGER_ASSERT(strlen(out) + 1 < out_len, "Excedeed output size");
    return;
}

bool is_required_position(const derive_native_script_hash_ctx_t *ctx) {
    if (ctx->level == 0) {
        return false;  // No position at root level for simple scripts
    }
    if (ctx->level == 1 &&
        (ctx->ui_scriptType == UI_SCRIPT_ALL || ctx->ui_scriptType == UI_SCRIPT_N_OF_K ||
         ctx->ui_scriptType == UI_SCRIPT_ANY)) {
        return false;  // No position at root level for complex scripts
    }
    return true;
}

bool format_position(derive_native_script_hash_ctx_t *ctx,
                     char *position_description,
                     size_t position_descriptionLen) {
    uint8_t level = ctx->level;

    // Complex scripts show position of parent level
    if (ctx->ui_scriptType == UI_SCRIPT_ALL || ctx->ui_scriptType == UI_SCRIPT_N_OF_K ||
        ctx->ui_scriptType == UI_SCRIPT_ANY) {
        if (ctx->level <= 1) {
            return false;  // No position to show at root level
        }
        level = ctx->level - 1;
    }

    build_position_description(ctx, level, position_description, position_descriptionLen);
    TRACE("Position: %s", position_description);
    return true;
}

bool format_remaining(uint8_t remaining_scripts, char *out, size_t out_size) {
    LEDGER_ASSERT(out != NULL, "NULL output buffer");
    STATIC_ASSERT(!IS_SIGNED(remaining_scripts), "signed type for %u");
    int chars_written = snprintf(out, out_size, "%u nested scripts", remaining_scripts);
    return (chars_written > 0 && chars_written < (int)out_size);
}

bool format_required_signatures(uint8_t requiredScripts,
                                uint8_t remainingScripts,
                                char *out,
                                size_t out_size) {
    LEDGER_ASSERT(out != NULL, "NULL output buffer");
    STATIC_ASSERT(!IS_SIGNED(requiredScripts), "signed type for %u");
    STATIC_ASSERT(!IS_SIGNED(remainingScripts), "signed type for %u");
    int chars_written =
        snprintf(out, out_size, "%u out of %u signatures", requiredScripts, remainingScripts);
    return (chars_written > 0 && chars_written < (int)out_size);
}

static void derive_native_script_hash_buffer_cleanup(void) {
    // Cleanup all tracked allocations (all string buffers and warning structure)
    ui_cleanup_tracked_allocations();
    // Cleanup the pairs array
    ui_pairs_cleanup();
}

static void derive_native_script_hash_review_continue(bool confirm) {
    // CLEANUP
    derive_native_script_hash_buffer_cleanup();

    // FINALIZE
    if (confirm) {
        io_send_response_pointer(NULL, 0, SWO_SUCCESS);
    } else {
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
    }

    // SHOW STATUS
    if (confirm) {
        TRACE("User confirmed");
    } else {
        TRACE("User rejected");
        nbgl_useCaseStatus("Native script hash\nrejected", false, ui_menu_main);
    }
}

static void derive_native_script_hash_review_confirmation_output(bool confirm) {
    // CLEANUP
    derive_native_script_hash_buffer_cleanup();

    // FINALIZE
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    if (confirm) {
        TRACE("User confirmed");
        io_send_response_pointer(ctx->scriptHashBuffer, SCRIPT_HASH_LENGTH, SWO_SUCCESS);
    } else {
        TRACE("User rejected");
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
    }

    // SHOW STATUS
    if (confirm) {
        TRACE("User confirmed");
        nbgl_useCaseStatus("Confirm\n native script hash", true, ui_menu_main);
        reset_app_context();
    } else {
        TRACE("User rejected");
        nbgl_useCaseStatus("Native script hash\nrejected", false, ui_menu_main);
        // send_swo_and_reset already called reset_app_context
        // TODO we should call reset_app_context anyway? compare with other such functions
    }
}

static void derive_native_script_hash_review_ask_confirmation(bool confirm) {
    // CLEANUP
    derive_native_script_hash_buffer_cleanup();

    // FINALIZE
    if (confirm) {
        TRACE("User confirmed");

    } else {
        TRACE("User rejected");
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
    }

    // SHOW STATUS
    if (confirm) {
        TRACE("User confirmed");
        nbgl_useCaseReviewStreamingFinish("Confirm hash",
                                          derive_native_script_hash_review_confirmation_output);
    } else {
        TRACE("User rejected");
        nbgl_useCaseStatus("Native script hash\nrejected", false, ui_menu_main);
    }
}

#define MAX_POSITION_DESCRIPTION_LENGTH       100
#define MAX_NESTED_SCRIPTS_DESCRIPTION_LENGTH 87
#define MAX_SIGNATURES_DESCRIPTION_LENGTH     87
#define MAX_TIMELOCK_DESCRIPTION_LENGTH       40
#define MAX_POLICY_ID_STRING_LENGTH           (2 * SCRIPT_HASH_LENGTH)

void display_complex_script_content(ui_native_script_type scriptType) {
    TRACE("display_complex_script_content");

    LEDGER_ASSERT(scriptType == UI_SCRIPT_ALL || scriptType == UI_SCRIPT_ANY ||
                      scriptType == UI_SCRIPT_N_OF_K,
                  "Invalid script type for complex script display");

    const char *script_label = NULL;
    int ui_pairs_count = 0;
    switch (scriptType) {
        case UI_SCRIPT_ALL:
            script_label = "ALL";
            ui_pairs_count = 2;
            break;
        case UI_SCRIPT_ANY:
            script_label = "ANY";
            ui_pairs_count = 2;
            break;
        case UI_SCRIPT_N_OF_K:
            script_label = "N out K";
            ui_pairs_count = 3;
            break;
        default:
            break;
    }

    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    bool required_position = is_required_position(ctx);
    if (required_position) {
        ui_pairs_count++;
    }
    if (!ui_pairs_init(ui_pairs_count)) {
        TRACE("Failed to initialize pairs");
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }
    if (required_position) {
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Position"),
                       MAX_POSITION_DESCRIPTION_LENGTH,
                       format_position,
                       ctx);
    }
    UI_ADD_STATIC(UI_STATIC_LABEL("Script type"), script_label);
    if (scriptType == UI_SCRIPT_N_OF_K) {
        UI_ADD_FORMAT2(UI_STATIC_LABEL("Requirement"),
                       MAX_NESTED_SCRIPTS_DESCRIPTION_LENGTH,
                       format_required_signatures,
                       ctx->scriptContent.requiredScripts,
                       ctx->complexScripts[ctx->level].remainingScripts);
    }
    UI_ADD_FORMAT1(UI_STATIC_LABEL("Content"),
                   MAX_NESTED_SCRIPTS_DESCRIPTION_LENGTH,
                   format_remaining,
                   ctx->complexScripts[ctx->level].remainingScripts);

    nbgl_useCaseReviewStreamingContinue(g_pairsList, derive_native_script_hash_review_continue);
}

void ui_display_native_script_hash(security_policy_t securityPolicy) {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;

    TRACE("securityPolicy: %d", securityPolicy);
    if (securityPolicy == POLICY_DENY) {
        TRACE("Security condition not satisfied");
        send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        return;
    }

    switch (ctx->ui_scriptType) {
        case UI_SCRIPT_INIT: {
            // TODO: mismatch with previous app: first screen is passed automatically without user
            // intervention just after a call to function nbgl_useCaseReviewStreamingContinue
            nbgl_useCaseReviewStreamingStart(TYPE_OPERATION,
                                             &ICON_APP_CARDANO,
                                             "Review Script",
                                             NULL,
                                             derive_native_script_hash_review_continue);
            break;
        }
        case UI_SCRIPT_ALL: {
            TRACE("UI_SCRIPT_ALL");
            display_complex_script_content(UI_SCRIPT_ALL);
            break;
        }
        case UI_SCRIPT_N_OF_K: {
            TRACE("UI_SCRIPT_N_OF_K");
            display_complex_script_content(UI_SCRIPT_N_OF_K);
            break;
        }
        case UI_SCRIPT_ANY: {
            TRACE("UI_SCRIPT_ANY");
            display_complex_script_content(UI_SCRIPT_ANY);
            break;
        }
        case UI_SCRIPT_PUBKEY_PATH: {
            TRACE("UI_SCRIPT_PUBKEY_PATH");
            int ui_pairs_count = 2;
            bool required_position = is_required_position(ctx);
            if (required_position) {
                ui_pairs_count++;
            }
            if (!ui_pairs_init(ui_pairs_count)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            if (required_position) {
                UI_ADD_FORMAT1(UI_STATIC_LABEL("Position"),
                               MAX_POSITION_DESCRIPTION_LENGTH,
                               format_position,
                               ctx);
            }
            UI_ADD_STATIC(UI_STATIC_LABEL("Script type"), UI_STATIC_LABEL("Pubkey path"));
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Pubkey path"),
                           MAX_BIP44_PATH_STRING_LENGTH,
                           format_bip44_path,
                           &ctx->scriptContent.pubkeyPath);

            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_review_continue);
            break;
        }
        case UI_SCRIPT_PUBKEY_HASH: {
            TRACE("UI_SCRIPT_PUBKEY_HASH");
            int ui_pairs_count = 2;
            bool required_position = is_required_position(ctx);
            if (required_position) {
                ui_pairs_count++;
            }
            if (!ui_pairs_init(ui_pairs_count)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            if (required_position) {
                UI_ADD_FORMAT1(UI_STATIC_LABEL("Position"),
                               MAX_POSITION_DESCRIPTION_LENGTH,
                               format_position,
                               ctx);
            }
            UI_ADD_STATIC(UI_STATIC_LABEL("Script type"), UI_STATIC_LABEL("Pubkey hash"));
            UI_ADD_FORMAT3(UI_STATIC_LABEL("Pubkey hash"),
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           "addr_shared_vkh",
                           ctx->scriptContent.pubkeyHash,
                           ADDRESS_KEY_HASH_LENGTH);

            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_review_continue);
            break;
        }
        case UI_SCRIPT_INVALID_BEFORE: {
            TRACE("UI_SCRIPT_INVALID_BEFORE");
            int ui_pairs_count = 2;
            bool required_position = is_required_position(ctx);
            if (required_position) {
                ui_pairs_count++;
            }
            if (!ui_pairs_init(ui_pairs_count)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            if (required_position) {
                UI_ADD_FORMAT1(UI_STATIC_LABEL("Position"),
                               MAX_POSITION_DESCRIPTION_LENGTH,
                               format_position,
                               ctx);
            }
            UI_ADD_STATIC(UI_STATIC_LABEL("Script type"), UI_STATIC_LABEL("Invalid before"));
            UI_ADD_FORMAT2(UI_STATIC_LABEL("Invalid before"),
                           MAX_TIMELOCK_DESCRIPTION_LENGTH,
                           format_decimal_amount,
                           ctx->scriptContent.timelock,
                           0);

            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_review_continue);
            break;
        }
        case UI_SCRIPT_INVALID_HEREAFTER: {
            TRACE("UI_SCRIPT_INVALID_HEREAFTER");
            int ui_pairs_count = 2;
            bool required_position = is_required_position(ctx);
            if (required_position) {
                ui_pairs_count++;
            }
            if (!ui_pairs_init(ui_pairs_count)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            if (required_position) {
                UI_ADD_FORMAT1(UI_STATIC_LABEL("Position"),
                               MAX_POSITION_DESCRIPTION_LENGTH,
                               format_position,
                               ctx);
            }
            UI_ADD_STATIC(UI_STATIC_LABEL("Script type"), UI_STATIC_LABEL("Invalid hereafter"));
            UI_ADD_FORMAT2(UI_STATIC_LABEL("Invalid hereafter"),
                           MAX_TIMELOCK_DESCRIPTION_LENGTH,
                           format_decimal_amount,
                           ctx->scriptContent.timelock,
                           0);

            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_review_continue);
            break;
        }
        case UI_SCRIPT_DISPLAY_BECH32: {
            static char encodedStr[MAX_BECH32_STRING_LENGTH] = {0};
            explicit_bzero(encodedStr, SIZEOF(encodedStr));
            format_bech32("script",
                          ctx->scriptHashBuffer,
                          SCRIPT_HASH_LENGTH,
                          encodedStr,
                          SIZEOF(encodedStr));

            if (!ui_pairs_init(1)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            g_pairs[0].item = "Script hash";
            g_pairs[0].value = encodedStr;

            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_review_ask_confirmation);
            break;
        }
        case UI_SCRIPT_DISPLAY_POLICY_ID: {
            if (!ui_pairs_init(1)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            UI_ADD_FORMAT2(UI_STATIC_LABEL("Policy ID"),
                           MAX_POLICY_ID_STRING_LENGTH,
                           format_hex_bytes,
                           ctx->scriptHashBuffer,
                           SCRIPT_HASH_LENGTH);

            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_review_ask_confirmation);
            break;
        }
        default: {
            TRACE("Invalid UI step");
            send_swo_and_reset(SWO_BAD_STATE);
            return;
        }
    }
    return;
}
