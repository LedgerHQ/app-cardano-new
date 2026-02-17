/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

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
#include "mem.h"
#include "ui_formatters.h"
#include "ui_icons.h"
#include "ui_utils.h"
#include "ui_display_native_script_hash.h"
#include "utils.h"

void build_position_description(const derive_native_script_hash_ctx_t *ctx,
                                uint8_t level,
                                char *out,
                                size_t out_len) {
    explicit_bzero(out, out_len);
    char *ptr = out;
    char *end = out + out_len;

    LEDGER_ASSERT(level >= 1, "Invalid level %d", level);
    LEDGER_ASSERT(level < MAX_SCRIPT_DEPTH, "Exceeded max script depth");

    // Levels
    for (size_t i = 1; i <= level; i++) {
        uint32_t position =
            ctx->complexScripts[i].totalScripts - ctx->complexScripts[i].remainingScripts + 1;
        STATIC_ASSERT(!IS_SIGNED_TYPE(typeof(position)), "signed type for %u");
        snprintf(ptr, end - ptr, "%u.", position);
        LEDGER_ASSERT(strlen(out) + 1 < out_len, "Exceeded output size");
        ptr += strlen(ptr);
    }

    // Remove trailing '.'
    LEDGER_ASSERT(ptr > out, "Exceeded output size");
    *(ptr - 1) = '\0';
    LEDGER_ASSERT(strlen(out) + 1 < out_len, "Exceeded output size");
    return;
}

bool is_required_position(const derive_native_script_hash_ctx_t *ctx) {
    if (ctx->level == 0) {
        return false;  // No position at root level for simple scripts
    }
    if (ctx->level == 1) {
        switch (ctx->ui_scriptType) {
            case UI_SCRIPT_ALL:
            case UI_SCRIPT_N_OF_K:
            case UI_SCRIPT_ANY:
                return false;  // No position at root level for complex scripts
            default:
                break;
        }
    }
    return true;
}

bool format_position(derive_native_script_hash_ctx_t *ctx,
                     char *position_description,
                     size_t position_descriptionLen) {
    uint8_t level = ctx->level;

    // Complex scripts show position of parent level
    switch (ctx->ui_scriptType) {
        case UI_SCRIPT_ALL:
        case UI_SCRIPT_N_OF_K:
        case UI_SCRIPT_ANY:
            if (ctx->level <= 1) {
                return false;  // No position to show at root level
            }
            level = ctx->level - 1;
            break;
        default:
            break;
    }

    build_position_description(ctx, level, position_description, position_descriptionLen);
    TRACE("Position: %s", position_description);
    return true;
}

bool format_remaining(uint32_t remaining_scripts, char *out, size_t out_size) {
    LEDGER_ASSERT(out != NULL, "NULL output buffer");
    STATIC_ASSERT(!IS_SIGNED_TYPE(typeof(remaining_scripts)), "signed type for %u");
    int chars_written = snprintf(out, out_size, "%u nested scripts", remaining_scripts);
    return (chars_written > 0 && chars_written < (int)out_size);
}

bool format_required_signatures(uint32_t requiredScripts,
                                uint32_t remainingScripts,
                                char *out,
                                size_t out_size) {
    LEDGER_ASSERT(out != NULL, "NULL output buffer");
    STATIC_ASSERT(!IS_SIGNED_TYPE(typeof(requiredScripts)), "signed type for %u");
    STATIC_ASSERT(!IS_SIGNED_TYPE(typeof(remainingScripts)), "signed type for %u");
    int chars_written =
        snprintf(out, out_size, "%u out of %u signatures", requiredScripts, remainingScripts);
    return (chars_written > 0 && chars_written < (int)out_size);
}

static void derive_native_script_hash_buffer_cleanup(void) {
    ui_all_cleanup();
}

static void derive_native_script_hash_streaming_continue_choice(bool confirm) {
    // CLEANUP
    derive_native_script_hash_buffer_cleanup();

    // FINALIZE
    if (confirm) {
        apdu_response_send_data(NULL, 0, SWO_SUCCESS);
    } else {
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
    }

    // SHOW STATUS
    if (confirm) {
        TRACE("User confirmed");
    } else {
        TRACE("User rejected");
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main);
    }
}

void ui_start_native_script_streaming(void) {
    // Start NBGL streaming with title screen
    nbgl_useCaseReviewStreamingStart(TYPE_OPERATION,
                                     &ICON_APP_CARDANO,
                                     "Review Script",
                                     NULL,
                                     derive_native_script_hash_streaming_continue_choice);
}

static void derive_native_script_hash_review_choice(bool confirm) {
    // CLEANUP
    derive_native_script_hash_buffer_cleanup();

    // FINALIZE
    if (!confirm) {
        TRACE("User rejected");
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main);
        return;
    }

    TRACE("User confirmed");
    // does not need a spinner
    finalize_derive_native_script_hash();

    // SHOW STATUS
    nbgl_useCaseStatus("Confirm native script hash", true, ui_menu_main);
}

static void derive_native_script_hash_streaming_finish_continue(bool confirm) {
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
                                          derive_native_script_hash_review_choice);
    } else {
        TRACE("User rejected");
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main);
    }
}

#define MAX_POSITION_DESCRIPTION_LENGTH       100
#define MAX_NESTED_SCRIPTS_DESCRIPTION_LENGTH 87
#define MAX_SIGNATURES_DESCRIPTION_LENGTH     87
#define MAX_TIMELOCK_DESCRIPTION_LENGTH       40
#define MAX_POLICY_ID_STRING_LENGTH           (2 * SCRIPT_HASH_LENGTH)

// Native script UI pair counts
#define UI_PAIRS_POSITION     1
#define UI_PAIRS_SCRIPT_TYPE  1
#define UI_PAIRS_REQUIREMENT  1
#define UI_PAIRS_CONTENT      1
#define UI_PAIRS_PUBKEY_PATH  1
#define UI_PAIRS_PUBKEY_HASH  1
#define UI_PAIRS_TIMELOCK     1
#define UI_PAIRS_SCRIPT_HASH  1
#define UI_PAIRS_POLICY_ID    1

void display_complex_script_content(ui_native_script_type scriptType) {
    TRACE("display_complex_script_content");

    const char *script_label = NULL;
    int expectedPairs = 0;
    switch (scriptType) {
        case UI_SCRIPT_ALL:
            script_label = "ALL";
            expectedPairs = UI_PAIRS_SCRIPT_TYPE + UI_PAIRS_CONTENT;
            break;
        case UI_SCRIPT_ANY:
            script_label = "ANY";
            expectedPairs = UI_PAIRS_SCRIPT_TYPE + UI_PAIRS_CONTENT;
            break;
        case UI_SCRIPT_N_OF_K:
            script_label = "N of K";
            expectedPairs = UI_PAIRS_SCRIPT_TYPE + UI_PAIRS_REQUIREMENT + UI_PAIRS_CONTENT;
            break;
        default:
            LEDGER_ASSERT(false, "Invalid script type for complex script display");
            return;
    }

    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    bool required_position = is_required_position(ctx);
    if (required_position) {
        expectedPairs += UI_PAIRS_POSITION;
    }
    if (!ui_pairs_init(expectedPairs)) {
        TRACE("Failed to initialize pairs");
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }
    START_COUNT();
    if (required_position) {
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Position"),
                       MAX_POSITION_DESCRIPTION_LENGTH,
                       format_position,
                       ctx);
    }
    UI_ADD_STATIC(UI_STATIC_LABEL("Script type"), script_label);
    switch (scriptType) {
        case UI_SCRIPT_N_OF_K:
            UI_ADD_FORMAT2(UI_STATIC_LABEL("Requirement"),
                           MAX_NESTED_SCRIPTS_DESCRIPTION_LENGTH,
                           format_required_signatures,
                           ctx->scriptContent.requiredScripts,
                           ctx->complexScripts[ctx->level].remainingScripts);
            break;
        default:
            break;
    }
    UI_ADD_FORMAT1(UI_STATIC_LABEL("Content"),
                   MAX_NESTED_SCRIPTS_DESCRIPTION_LENGTH,
                   format_remaining,
                   ctx->complexScripts[ctx->level].remainingScripts);
    CHECK_COUNT(expectedPairs);

    nbgl_useCaseReviewStreamingContinue(g_pairsList, derive_native_script_hash_streaming_continue_choice);
}

void ui_display_native_script_hash(void) {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;

    switch (ctx->ui_scriptType) {
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
            int expectedPairs = UI_PAIRS_SCRIPT_TYPE + UI_PAIRS_PUBKEY_PATH;
            bool required_position = is_required_position(ctx);
            if (required_position) {
                expectedPairs += UI_PAIRS_POSITION;
            }
            if (!ui_pairs_init(expectedPairs)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            START_COUNT();
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
            CHECK_COUNT(expectedPairs);

            nbgl_useCaseReviewStreamingContinue(g_pairsList, derive_native_script_hash_streaming_continue_choice);
            break;
        }
        case UI_SCRIPT_PUBKEY_HASH: {
            TRACE("UI_SCRIPT_PUBKEY_HASH");
            int expectedPairs = UI_PAIRS_SCRIPT_TYPE + UI_PAIRS_PUBKEY_HASH;
            bool required_position = is_required_position(ctx);
            if (required_position) {
                expectedPairs += UI_PAIRS_POSITION;
            }
            if (!ui_pairs_init(expectedPairs)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            START_COUNT();
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
            CHECK_COUNT(expectedPairs);

            nbgl_useCaseReviewStreamingContinue(g_pairsList, derive_native_script_hash_streaming_continue_choice);
            break;
        }
        case UI_SCRIPT_INVALID_BEFORE: {
            TRACE("UI_SCRIPT_INVALID_BEFORE");
            int expectedPairs = UI_PAIRS_SCRIPT_TYPE + UI_PAIRS_TIMELOCK;
            bool required_position = is_required_position(ctx);
            if (required_position) {
                expectedPairs += UI_PAIRS_POSITION;
            }
            if (!ui_pairs_init(expectedPairs)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            START_COUNT();
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
            CHECK_COUNT(expectedPairs);

            nbgl_useCaseReviewStreamingContinue(g_pairsList, derive_native_script_hash_streaming_continue_choice);
            break;
        }
        case UI_SCRIPT_INVALID_HEREAFTER: {
            TRACE("UI_SCRIPT_INVALID_HEREAFTER");
            int expectedPairs = UI_PAIRS_SCRIPT_TYPE + UI_PAIRS_TIMELOCK;
            bool required_position = is_required_position(ctx);
            if (required_position) {
                expectedPairs += UI_PAIRS_POSITION;
            }
            if (!ui_pairs_init(expectedPairs)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            START_COUNT();
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
            CHECK_COUNT(expectedPairs);

            nbgl_useCaseReviewStreamingContinue(g_pairsList, derive_native_script_hash_streaming_continue_choice);
            break;
        }
        case UI_SCRIPT_DISPLAY_BECH32: {
            const int expectedPairs = UI_PAIRS_SCRIPT_HASH;
            if (!ui_pairs_init(expectedPairs)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            START_COUNT();
            UI_ADD_FORMAT3(UI_STATIC_LABEL("Script hash"),
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           "script",
                           ctx->scriptHashBuffer,
                           SCRIPT_HASH_LENGTH);
            CHECK_COUNT(expectedPairs);

            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_streaming_finish_continue);
            break;
        }
        case UI_SCRIPT_DISPLAY_POLICY_ID: {
            const int expectedPairs = UI_PAIRS_POLICY_ID;
            if (!ui_pairs_init(expectedPairs)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            START_COUNT();
            UI_ADD_FORMAT2(UI_STATIC_LABEL("Policy ID"),
                           MAX_POLICY_ID_STRING_LENGTH,
                           format_hex_bytes,
                           ctx->scriptHashBuffer,
                           SCRIPT_HASH_LENGTH);
            CHECK_COUNT(expectedPairs);

            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_streaming_finish_continue);
            break;
        }
        default: {
            LEDGER_ASSERT(false, "Invalid UI step");
            return;
        }
    }
    return;
}
