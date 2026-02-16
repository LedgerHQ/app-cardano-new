/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <string.h>

#include "addressUtilsShelley.h"
#include "app_context.h"
#include "assert.h"
#include "buffer.h"
#include "cardano_parsers.h"
#include "cardano_swo.h"
#include "derive_native_script_hash_builder.h"
#include "derive_native_script_hash.h"
#include "deriveNativeScriptHash_types.h"
#include "globals.h"
#include "io.h"
#include "keyDerivation.h"
#include "securityPolicy.h"
#include "ui_display_native_script_hash.h"
#include "utils.h"

// Complex native script handlers
static void deriveNativeScriptHash_handleAll() {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    nativeScriptHashBuilder_startComplexScript_all(
        &ctx->hashBuilder,
        ctx->complexScripts[ctx->level].remainingScripts);
    ctx->ui_scriptType = UI_SCRIPT_ALL;
    apdu_response_deferred();
    ui_display_native_script_hash();
    return;
}

static void deriveNativeScriptHash_handleAny() {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    nativeScriptHashBuilder_startComplexScript_any(
        &ctx->hashBuilder,
        ctx->complexScripts[ctx->level].remainingScripts);
    ctx->ui_scriptType = UI_SCRIPT_ANY;
    apdu_response_deferred();
    ui_display_native_script_hash();
    return;
}

static void deriveNativeScriptHash_handleNofK(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata passed to deriveNativeScriptHash_handleNofK");
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    bool read32 = buffer_read_u32(cdata, &ctx->scriptContent.requiredScripts, BE);
    if (read32 == false) {
        TRACE("Failed to read requiredScripts");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }
    if (buffer_can_read(cdata, 1)) {
        TRACE("NofK APDU not fully consumed");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }
    if (ctx->complexScripts[ctx->level].remainingScripts < ctx->scriptContent.requiredScripts) {
        TRACE("remainingScripts less than requiredScripts");
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_COUNT);
        return;
    }
    nativeScriptHashBuilder_startComplexScript_n_of_k(
        &ctx->hashBuilder,
        ctx->scriptContent.requiredScripts,
        ctx->complexScripts[ctx->level].remainingScripts);

    ctx->ui_scriptType = UI_SCRIPT_N_OF_K;
    apdu_response_deferred();
    ui_display_native_script_hash();
    return;
}

static inline bool isCurrentComplexScriptComplete() {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    return ctx->level > 0 && ctx->complexScripts[ctx->level].remainingScripts == 0;
}

static inline void finishComplexScriptsAndPropagate() {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    while (isCurrentComplexScriptComplete()) {
        LEDGER_ASSERT(ctx->level > 0, "Bad script level");
        ctx->level--;
        LEDGER_ASSERT(ctx->complexScripts[ctx->level].remainingScripts > 0, "Bad script count");
        ctx->complexScripts[ctx->level].remainingScripts--;
    }
}

static inline void finishSimpleScriptAndPropagate() {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    LEDGER_ASSERT(ctx->level < MAX_SCRIPT_DEPTH, "Depth overflow");
    LEDGER_ASSERT(ctx->complexScripts[ctx->level].remainingScripts > 0, "Bad script count");
    ctx->complexScripts[ctx->level].remainingScripts--;
    if (isCurrentComplexScriptComplete()) {
        finishComplexScriptsAndPropagate();
    }
}

static inline bool isScriptExpectedAtCurrentLevel() {
    // if the number of remaining scripts is not bigger than 0, then this request
    // is invalid in the current context, as Ledger was not expecting another
    // script to be parsed
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    if (ctx->level >= MAX_SCRIPT_DEPTH) {
        return false;
    }
    return ctx->complexScripts[ctx->level].remainingScripts > 0;
}

static bool parse_native_script_pubkey_credential(buffer_t *buf, ext_credential_t *credential) {
    TRACE("Parsing native script pubkey credential");

    if (!buffer_read_credential(buf, credential)) {
        TRACE("Failed to parse credential");
        return false;
    }

    // Native script pubkey constraints only allow KEY_HASH and KEY_PATH
    if (credential->type == EXT_CREDENTIAL_SCRIPT_HASH) {
        TRACE("Script hash not allowed for native script pubkey");
        return false;
    }

    TRACE("Successfully parsed native script pubkey credential, type=%u", credential->type);
    return true;
}

// Simple native script handlers
static bool deriveNativeScriptHash_handlePubkey(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata passed to deriveNativeScriptHash_handlePubkey");
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;

    // Parse pubkey credential (only KEY_PATH and KEY_HASH allowed, not SCRIPT_HASH)
    ext_credential_t credential;
    if (!parse_native_script_pubkey_credential(cdata, &credential)) {
        TRACE("Failed to parse native script pubkey credential");
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_PUBKEY_CREDENTIAL);
        return false;
    }
    if (buffer_can_read(cdata, 1)) {
        TRACE("Pubkey APDU not fully consumed");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return false;
    }

    // Derive or extract the pubkey hash
    uint8_t pubkeyHash[ADDRESS_KEY_HASH_LENGTH] = {0};
    switch (credential.type) {
        case EXT_CREDENTIAL_KEY_PATH: {
            TRACE("Credential type - device-owned key: derive hash from path");
            // Device-owned key: derive hash from path
            ctx->scriptContent.pubkeyPath = credential.keyPath;
            ctx->ui_scriptType = UI_SCRIPT_PUBKEY_PATH;  // Tag the union immediately

            // Check security policy for device-owned keys
            warning_bits_t warnings = 0;
            const security_policy_t policy =
                policyForDeriveNativeScriptHashDevicePubkey(&ctx->scriptContent.pubkeyPath,
                                                            &warnings);
            LEDGER_ASSERT(warnings == 0, "Warnings not implemented in native script hash UI");
            switch (policy) {
                case POLICY_DENY:
                    TRACE("Security condition not satisfied");
                    send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
                    return false;
                case POLICY_SHOW:
                    // Derive hash only after policy check to avoid asserts on denied paths.
                    keyPathToKeyHash(
                        &ctx->scriptContent.pubkeyPath, pubkeyHash, ADDRESS_KEY_HASH_LENGTH);
                    break;
                case POLICY_HIDE:
                    LEDGER_ASSERT(false, "POLICY_HIDE not supported for native script device pubkey");
                    break;
                default:
                    LEDGER_ASSERT(false, "Invalid policy value: %d", policy);
            }
            break;
        }
        case EXT_CREDENTIAL_KEY_HASH:
            TRACE("Credential type - third-party key: use provided hash");
            // Third-party key: use provided hash
            LEDGER_ASSERT(SIZEOF(ctx->scriptContent.pubkeyHash) == ADDRESS_KEY_HASH_LENGTH,
                          "Bad key hash size");

            // Copy hash to context for UI display and to local buffer
            memmove(ctx->scriptContent.pubkeyHash, credential.keyHash, ADDRESS_KEY_HASH_LENGTH);
            ctx->ui_scriptType = UI_SCRIPT_PUBKEY_HASH;  // Tag the union immediately
            memmove(pubkeyHash, credential.keyHash, ADDRESS_KEY_HASH_LENGTH);
            break;
        default:
            LEDGER_ASSERT(false, "Unexpected credential type: %d", credential.type);
            return false;
    }
    
    // Add pubkey hash to script hash builder (single call for both paths)
    nativeScriptHashBuilder_addScript_pubkey(&ctx->hashBuilder, pubkeyHash, SIZEOF(pubkeyHash));
    

    // Display to user
    apdu_response_deferred();
    ui_display_native_script_hash();
    return true;
}

static bool deriveNativeScriptHash_handleInvalidBefore(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata passed to deriveNativeScriptHash_handleInvalidBefore");
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    bool read_timelock = buffer_read_u64(cdata, &ctx->scriptContent.timelock, BE);
    if (!read_timelock) {
        TRACE("Failed to read timelock");
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_TIMELOCK);
        return false;
    }
    if (buffer_can_read(cdata, 1)) {
        TRACE("Invalid before APDU not fully consumed");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return false;
    }
    nativeScriptHashBuilder_addScript_invalidBefore(&ctx->hashBuilder, ctx->scriptContent.timelock);
    ctx->ui_scriptType = UI_SCRIPT_INVALID_BEFORE;
    apdu_response_deferred();
    ui_display_native_script_hash();
    return true;
}

static bool deriveNativeScriptHash_handleInvalidHereafter(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata passed to deriveNativeScriptHash_handleInvalidHereafter");
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    bool read_timelock = buffer_read_u64(cdata, &ctx->scriptContent.timelock, BE);
    if (!read_timelock) {
        TRACE("Failed to read timelock");
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_TIMELOCK);
        return false;
    }
    if (buffer_can_read(cdata, 1)) {
        TRACE("Invalid hereafter APDU not fully consumed");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return false;
    }
    nativeScriptHashBuilder_addScript_invalidHereafter(&ctx->hashBuilder,
                                                       ctx->scriptContent.timelock);
    ctx->ui_scriptType = UI_SCRIPT_INVALID_HEREAFTER;
    apdu_response_deferred();
    ui_display_native_script_hash();
    return true;
}

// Finish native script handlers
static void deriveNativeScriptHash_displayNativeScriptHash_bech32() {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    ctx->ui_scriptType = UI_SCRIPT_DISPLAY_BECH32;
    apdu_response_deferred();
    ui_display_native_script_hash();
}

static void deriveNativeScriptHash_displayNativeScriptHash_policyId() {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    ctx->ui_scriptType = UI_SCRIPT_DISPLAY_POLICY_ID;
    apdu_response_deferred();
    ui_display_native_script_hash();
}

// Complex script start handler
static void deriveNativeScriptHash_handleComplexScriptStart(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata passed to deriveNativeScriptHash_handleComplexScriptStart");
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;

    if (!isScriptExpectedAtCurrentLevel()) {
        TRACE("More scripts expected");
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_NESTING);
        return;
    }

    if (ctx->level + 1 >= MAX_SCRIPT_DEPTH) {
        TRACE("Native script depth unsupported");
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_DEPTH_UNSUPPORTED);
        return;
    }

    ctx->level++;
    LEDGER_ASSERT(ctx->level < MAX_SCRIPT_DEPTH, "Native script depth overflow");

    uint8_t nativeScriptType = 0;
    bool read_nativeScriptType = buffer_read_u8(cdata, &nativeScriptType);
    if (!read_nativeScriptType) {
        TRACE("Failed to read nativeScriptType");
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_TYPE);
        return;
    }

    bool read_remainingScripts =
        buffer_read_u32(cdata, &ctx->complexScripts[ctx->level].remainingScripts, BE);
    if (!read_remainingScripts) {
        TRACE("Failed to read remainingScripts");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }
    ctx->complexScripts[ctx->level].totalScripts = ctx->complexScripts[ctx->level].remainingScripts;
    if (nativeScriptType != NATIVE_SCRIPT_N_OF_K && buffer_can_read(cdata, 1)) {
        TRACE("Complex script start APDU not fully consumed");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    switch (nativeScriptType) {
        case NATIVE_SCRIPT_ALL:
            deriveNativeScriptHash_handleAll();
            break;

        case NATIVE_SCRIPT_ANY:
            deriveNativeScriptHash_handleAny();
            break;

        case NATIVE_SCRIPT_N_OF_K:
            deriveNativeScriptHash_handleNofK(cdata);
            break;

        default:
            TRACE("Bad nativeScriptType");
            send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_TYPE);
            return;
    }

    if (isCurrentComplexScriptComplete()) {
        finishComplexScriptsAndPropagate();
    }

    return;
}

// Simple script handler
static void deriveNativeScriptHash_handleSimpleScript(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata passed to deriveNativeScriptHash_handleSimpleScript");
    if (!isScriptExpectedAtCurrentLevel()) {
        TRACE("More scripts expected");
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_NESTING);
        return;
    }

    uint8_t nativeScriptType = 0;
    bool read_nativeScriptType = buffer_read_u8(cdata, &nativeScriptType);
    if (!read_nativeScriptType) {
        TRACE("Failed to read nativeScriptType");
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_TYPE);
        return;
    }

    bool parse_succeeded = false;

    // parse data
    switch (nativeScriptType) {
        case NATIVE_SCRIPT_PUBKEY:
            parse_succeeded = deriveNativeScriptHash_handlePubkey(cdata);
            break;
        case NATIVE_SCRIPT_INVALID_BEFORE:
            parse_succeeded = deriveNativeScriptHash_handleInvalidBefore(cdata);
            break;
        case NATIVE_SCRIPT_INVALID_HEREAFTER:
            parse_succeeded = deriveNativeScriptHash_handleInvalidHereafter(cdata);
            break;
        default:
            TRACE("Bad nativeScriptType");
            send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_TYPE);
            return;
    }

    if (!parse_succeeded) {
        return;
    }

    finishSimpleScriptAndPropagate();
    return;
}

static void deriveNativeScriptHash_handleWholeNativeScriptFinish(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata passed to deriveNativeScriptHash_handleWholeNativeScriptFinish");
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;

    // we finish only if there are no more scripts to be processed
    if (ctx->level != 0 || ctx->complexScripts[0].remainingScripts != 0) {
        TRACE("Finish received before all scripts were processed");
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_NESTING);
        return;
    }

    uint8_t displayFormat = 0;
    bool read_displayFormat = buffer_read_u8(cdata, &displayFormat);
    if (!read_displayFormat) {
        TRACE("Failed to read read_displayFormat");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }
    if (buffer_can_read(cdata, 1)) {
        TRACE("Finish APDU not fully consumed");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    switch (displayFormat) {
        case DISPLAY_NATIVE_SCRIPT_HASH_BECH32: {
            nativeScriptHashBuilder_finalize(&ctx->hashBuilder,
                                             ctx->scriptHashBuffer,
                                             SCRIPT_HASH_LENGTH);

            deriveNativeScriptHash_displayNativeScriptHash_bech32();
            break;
        }
        case DISPLAY_NATIVE_SCRIPT_HASH_POLICY_ID: {
            nativeScriptHashBuilder_finalize(&ctx->hashBuilder,
                                             ctx->scriptHashBuffer,
                                             SCRIPT_HASH_LENGTH);
            deriveNativeScriptHash_displayNativeScriptHash_policyId();
            break;
        }
        default:
            TRACE("Bad displayFormat");
            send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_DISPLAY_FORMAT);
            return;
    }
    return;
}

static void deriveNativeScriptHash_handleInit(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata");

    // Init APDU should have no payload
    if (buffer_can_read(cdata, 1)) {
        TRACE("Init APDU should be empty");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Init entry invariant: no active request
    if (G_context.req_type != REQUEST_NONE) {
        TRACE("Request already active");
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return;
    }

    // Set up request state
    G_context.req_type = REQUEST_DERIVE_NATIVE_SCRIPT_HASH;
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    ctx->level = 0;
    ctx->complexScripts[0].remainingScripts = 1;
    ctx->complexScripts[0].totalScripts = 1;
    nativeScriptHashBuilder_init(&ctx->hashBuilder);

    apdu_response_deferred();
    ui_start_native_script_streaming();
}

void handler_derive_native_script_hash(buffer_t *cdata, uint8_t script_type) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata passed to handler_derive_native_script_hash");

    TRACE_BUFFER_T(cdata);

    switch (script_type) {
        case P1_NATIVE_SCRIPT_INIT:
            deriveNativeScriptHash_handleInit(cdata);
            break;
        case P1_NATIVE_SCRIPT_START_COMPLEX:
        case P1_NATIVE_SCRIPT_ADD_SIMPLE:
        case P1_NATIVE_SCRIPT_FINISH:
            // All script/finish APDUs require active request
            if (G_context.req_type != REQUEST_DERIVE_NATIVE_SCRIPT_HASH) {
                TRACE("No active derive native script hash request");
                send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
                return;
            }
            switch (script_type) {
                case P1_NATIVE_SCRIPT_START_COMPLEX:
                    deriveNativeScriptHash_handleComplexScriptStart(cdata);
                    break;
                case P1_NATIVE_SCRIPT_ADD_SIMPLE:
                    deriveNativeScriptHash_handleSimpleScript(cdata);
                    break;
                case P1_NATIVE_SCRIPT_FINISH:
                    deriveNativeScriptHash_handleWholeNativeScriptFinish(cdata);
                    break;
                default:
                    LEDGER_ASSERT(false, "Invalid native script type: %d", script_type);
                    break;
            }
            break;
        default:
            TRACE("Bad script type: %d", script_type);
            send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
            break;
    }
    return;
}

void finalize_derive_native_script_hash(bool confirmed) {
    LEDGER_ASSERT(G_context.req_type == REQUEST_DERIVE_NATIVE_SCRIPT_HASH, "Bad req_type");

    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    LEDGER_ASSERT(ctx->hashBuilder.state == NATIVE_SCRIPT_HASH_BUILDER_FINISHED,
                  "Hash builder not in finished state");

    if (!confirmed) {
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        return;
    }

    LEDGER_ASSERT(ctx->scriptHashBuffer != NULL || SCRIPT_HASH_LENGTH == 0,
                  "NULL response data with non-zero size");
    apdu_response_send_data(ctx->scriptHashBuffer, SCRIPT_HASH_LENGTH, SWO_SUCCESS);
    reset_app_context();
}
