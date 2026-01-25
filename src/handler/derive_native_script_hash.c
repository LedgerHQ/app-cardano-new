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
    security_policy_t policy = POLICY_SHOW;
    ui_display_native_script_hash(policy);
    return;
}

static void deriveNativeScriptHash_handleAny() {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    nativeScriptHashBuilder_startComplexScript_any(
        &ctx->hashBuilder,
        ctx->complexScripts[ctx->level].remainingScripts);
    ctx->ui_scriptType = UI_SCRIPT_ANY;
    security_policy_t policy = POLICY_SHOW;
    ui_display_native_script_hash(policy);
    return;
}

static void deriveNativeScriptHash_handleNofK(buffer_t *cdata) {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    bool read32 = buffer_read_u32(cdata, &ctx->scriptContent.requiredScripts, BE);
    if (read32 == false) {
        TRACE("Failed to read requiredScripts");
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_TYPE);
        return;
    }
    if (ctx->complexScripts[ctx->level].remainingScripts < ctx->scriptContent.requiredScripts) {
        LEDGER_ASSERT(false, "remainingScripts less than requiredScripts");
        return;
    }
    nativeScriptHashBuilder_startComplexScript_n_of_k(
        &ctx->hashBuilder,
        ctx->scriptContent.requiredScripts,
        ctx->complexScripts[ctx->level].remainingScripts);

    ctx->ui_scriptType = UI_SCRIPT_N_OF_K;
    security_policy_t policy = POLICY_SHOW;
    ui_display_native_script_hash(policy);
    return;
}

static inline bool isComplexScriptFinished() {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    return ctx->level > 0 && ctx->complexScripts[ctx->level].remainingScripts == 0;
}

static inline int complexScriptFinished() {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    while (isComplexScriptFinished()) {
        ASSERT(ctx->level > 0);
        ctx->level--;
        ASSERT(ctx->level < MAX_SCRIPT_DEPTH);
        ASSERT(ctx->complexScripts[ctx->level].remainingScripts > 0);
        ctx->complexScripts[ctx->level].remainingScripts--;
    }
    return 0;
}

static inline int simpleScriptFinished() {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    ASSERT(ctx->level < MAX_SCRIPT_DEPTH);
    ASSERT(ctx->complexScripts[ctx->level].remainingScripts > 0);
    ctx->complexScripts[ctx->level].remainingScripts--;
    if (isComplexScriptFinished()) {
        complexScriptFinished();
    }
    return 0;
}

static inline bool areMoreScriptsExpected() {
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
static void deriveNativeScriptHash_handlePubkey(buffer_t *cdata) {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;

    // Parse pubkey credential (only KEY_PATH and KEY_HASH allowed, not SCRIPT_HASH)
    ext_credential_t credential;
    if (!parse_native_script_pubkey_credential(cdata, &credential)) {
        TRACE("Failed to parse native script pubkey credential");
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_PUBKEY_CREDENTIAL);
        return;
    }

    // Derive or extract the pubkey hash
    uint8_t pubkeyHash[ADDRESS_KEY_HASH_LENGTH] = {0};
    security_policy_t policy;

    if (credential.type == EXT_CREDENTIAL_KEY_PATH) {
        // Device-owned key: derive hash from path
        ctx->scriptContent.pubkeyPath = credential.keyPath;
        ctx->ui_scriptType = UI_SCRIPT_PUBKEY_PATH;  // Tag the union immediately

        // Derive hash from the path stored in union
        keyPathToKeyHash(&ctx->scriptContent.pubkeyPath, pubkeyHash, ADDRESS_KEY_HASH_LENGTH);

        // Check security policy for device-owned keys
        warning_bits_t warnings = 0;
        warning_bits_init(&warnings);
        policy = policyForDeriveNativeScriptHashDevicePubkey(&ctx->scriptContent.pubkeyPath, &warnings);
    } else {
        // Third-party key: use provided hash
        LEDGER_ASSERT(credential.type == EXT_CREDENTIAL_KEY_HASH,
                      "Expected KEY_HASH credential type");
        LEDGER_ASSERT(SIZEOF(ctx->scriptContent.pubkeyHash) == ADDRESS_KEY_HASH_LENGTH,
                      "incorrect key hash size in script");

        // Copy hash to context for UI display and to local buffer
        memmove(ctx->scriptContent.pubkeyHash, credential.keyHash, ADDRESS_KEY_HASH_LENGTH);
        ctx->ui_scriptType = UI_SCRIPT_PUBKEY_HASH;  // Tag the union immediately
        memmove(pubkeyHash, credential.keyHash, ADDRESS_KEY_HASH_LENGTH);
        policy = POLICY_SHOW;
    }

    // Add pubkey hash to script hash builder (single call for both paths)
    nativeScriptHashBuilder_addScript_pubkey(&ctx->hashBuilder, pubkeyHash, SIZEOF(pubkeyHash));

    // Display to user
    ui_display_native_script_hash(policy);
    return;
}

static void deriveNativeScriptHash_handleInvalidBefore(buffer_t *cdata) {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    bool read_timelock = buffer_read_u64(cdata, &ctx->scriptContent.timelock, BE);
    if (!read_timelock) {
        TRACE("Failed to read timelock");
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_TIMELOCK);
        return;
    }
    nativeScriptHashBuilder_addScript_invalidBefore(&ctx->hashBuilder, ctx->scriptContent.timelock);
    ctx->ui_scriptType = UI_SCRIPT_INVALID_BEFORE;
    security_policy_t policy = POLICY_SHOW;
    ui_display_native_script_hash(policy);
    return;
}

static void deriveNativeScriptHash_handleInvalidHereafter(buffer_t *cdata) {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    bool read_timelock = buffer_read_u64(cdata, &ctx->scriptContent.timelock, BE);
    if (!read_timelock) {
        TRACE("Failed to read timelock");
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_TIMELOCK);
        return;
    }
    nativeScriptHashBuilder_addScript_invalidHereafter(&ctx->hashBuilder,
                                                       ctx->scriptContent.timelock);
    ctx->ui_scriptType = UI_SCRIPT_INVALID_HEREAFTER;
    security_policy_t policy = POLICY_SHOW;
    ui_display_native_script_hash(policy);
    return;
}

// Finish native script handlers
int deriveNativeScriptHash_displayNativeScriptHash_bech32() {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    ctx->ui_scriptType = UI_SCRIPT_DISPLAY_BECH32;
    security_policy_t policy = POLICY_SHOW;
    ui_display_native_script_hash(policy);
    return 0;
}

int deriveNativeScriptHash_displayNativeScriptHash_policyId() {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    ctx->ui_scriptType = UI_SCRIPT_DISPLAY_POLICY_ID;
    security_policy_t policy = POLICY_SHOW;
    ui_display_native_script_hash(policy);
    return 0;
}

// Complex script start handler
static void deriveNativeScriptHash_handleComplexScriptStart(buffer_t *cdata) {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;

    if (!areMoreScriptsExpected()) {
        TRACE("More scripts expected");
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_NESTING);
        return;
    }

    ctx->level++;

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
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_TYPE);
        return;
    }
    ctx->complexScripts[ctx->level].totalScripts = ctx->complexScripts[ctx->level].remainingScripts;

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

    if (isComplexScriptFinished()) {
        complexScriptFinished();
    }

    return;
}

// Simple script handler
static void deriveNativeScriptHash_handleSimpleScript(buffer_t *cdata) {
    if (!areMoreScriptsExpected()) {
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

    // parse data
    switch (nativeScriptType) {
        case NATIVE_SCRIPT_PUBKEY:
            deriveNativeScriptHash_handlePubkey(cdata);
            break;
        case NATIVE_SCRIPT_INVALID_BEFORE:
            deriveNativeScriptHash_handleInvalidBefore(cdata);
            break;
        case NATIVE_SCRIPT_INVALID_HEREAFTER:
            deriveNativeScriptHash_handleInvalidHereafter(cdata);
            break;
        default:
            TRACE("Bad nativeScriptType");
            send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_TYPE);
            return;
    }

    simpleScriptFinished();
    return;
}

static void deriveNativeScriptHash_handleWholeNativeScriptFinish(buffer_t *cdata) {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;

    // we finish only if there are no more scripts to be processed
    if (ctx->level != 0 || ctx->complexScripts[0].remainingScripts != 0) {
        LEDGER_ASSERT(false, "We finish only if there are no more scripts to be processed");
        return;
    }

    uint8_t displayFormat = 0;
    bool read_displayFormat = buffer_read_u8(cdata, &displayFormat);
    if (!read_displayFormat) {
        TRACE("Failed to read read_displayFormat");
        send_swo_and_reset(SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_TYPE);
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
            send_swo_and_reset(SWO_BAD_STATE);
            return;
    }
    G_context.req_type = REQUEST_NONE;
    return;
}

void handler_derive_native_script_hash(buffer_t *cdata, uint8_t script_type) {

    if (!cdata->ptr) {
        TRACE("cdata->ptr is NULL");
        io_send_sw(SWO_WRONG_DATA_LENGTH);
        return;
    }

    TRACE_BUFFER(cdata->ptr, cdata->size);

    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    if (G_context.req_type != REQUEST_DERIVE_NATIVE_SCRIPT_HASH) {
        explicit_bzero(&G_context, sizeof(G_context));
        ctx->level = 0;
        ctx->complexScripts[ctx->level].remainingScripts = 1;
        nativeScriptHashBuilder_init(&ctx->hashBuilder);
        ctx->ui_scriptType = UI_SCRIPT_INIT;
        security_policy_t policy = POLICY_SHOW;
        ui_display_native_script_hash(policy);
    }

    G_context.req_type = REQUEST_DERIVE_NATIVE_SCRIPT_HASH;

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
            TRACE("Bad script type");
            LEDGER_ASSERT(false, "script type should be handled before");
            break;
    }
    return;
}
