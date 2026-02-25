/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "utils.h"
#include "buffer.h"
#include "sign_msg.h"
#include "cardano_swo.h"
#include "globals.h"
#include "addressUtilsShelley.h"
#include "securityPolicy.h"
#include "assert.h"
#include "app_context.h"
#include "io.h"
#include "cardano_parsers.h"
#include "cardano_buffer.h"
#include "messageSigning.h"
#include "ui_sign_msg.h"
#include "keyDerivation.h"
#include "textUtils.h"
#include "cbor.h"
#include "nbgl_use_case.h"
#include "app_mem_utils.h"

// Overhead for Sig_structure CBOR encoding:
// - 1 byte array(4) header
// - 1 + 10 bytes "Signature1" text
// - up to 3 + (MAX_ADDRESS_LENGTH + 32) bytes protectedHeader as bstr
// - 1 byte empty external_aad
// - up to 5 bytes payload bstr length header
// Conservative fixed overhead (covers all CBOR tokens + protectedHeader).
#define SIG_STRUCTURE_OVERHEAD 256

static bool ensure_sign_msg_request_type(request_type_e required_request_type) {
    if (G_context.req_type != required_request_type) {
        TRACE("Rejecting sign_msg command for req_type %d (expected %d)",
              G_context.req_type,
              required_request_type);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return false;
    }
    return true;
}

static bool ensure_sign_msg_state(sign_msg_state_e required_state) {
    if (G_context.state.sign_msg_state != required_state) {
        TRACE("Rejecting sign_msg command in state %d (expected %d)",
              G_context.state.sign_msg_state,
              required_state);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return false;
    }
    return true;
}

static bool is_msg_length_valid_for_sign_msg_init(uint32_t message_length,
                                                  bool hash_payload,
                                                  bool is_ascii) {
    // msgBuffer allocation in INIT uses uint16_t-sized APP_MEM_CALLOC.
    if (message_length > UINT16_MAX) {
        return false;
    }

    // Non-ASCII messages are displayed as hex in UI:
    // max_len = 2 * message_length + 1.
    // UI formatting allocates max_len + UI_BUFFER_SAFETY_MARGIN where safety margin is 2 bytes.
    // Keep this guard in sync with UI_ADD_FORMAT2 allocation constraints.
    if (!is_ascii) {
        const size_t max_hex_display_length = 2 * (size_t) message_length + 1;
        const size_t ui_hex_display_allocation_size = max_hex_display_length + 2;
        if (ui_hex_display_allocation_size > UINT16_MAX) {
            return false;
        }
    }

    // Non-hashed payload uses raw message bytes as Sig_structure payload.
    if (!hash_payload) {
        const size_t sig_structure_max_size = SIG_STRUCTURE_OVERHEAD + (size_t) message_length;
        if (sig_structure_max_size > UINT16_MAX) {
            return false;
        }
    }

    return true;
}

// ============================== INIT ==============================

void signMsg_handle_init(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata");
    LEDGER_ASSERT(G_context.state.sign_msg_state == SIGN_MSG_STATE_INIT, "Invalid sign_msg state");

    sign_msg_ctx_t *ctx = &G_context.sign_msg_info;

    // Parse INIT APDU payload:
    // [4 bytes: msgLength] [BIP44 path] [1 byte: hashPayload] [1 byte: isAscii]
    // [1 byte: addressFieldType] [address_params if addressFieldType == ADDRESS]

    uint32_t msg_length_from_wire = 0;
    if (!buffer_read_u32(cdata, &msg_length_from_wire, BE)) {
        TRACE("Failed to read msgLength");
        send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_MSG_LENGTH);
        return;
    }
    TRACE("Message length = %u", msg_length_from_wire);
    if (msg_length_from_wire > UINT16_MAX) {
        TRACE("Message length out of uint16 range: %u", msg_length_from_wire);
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }
    ctx->msgLength = (uint16_t) msg_length_from_wire;

    if (!buffer_read_bip44_path(cdata, &ctx->signingPath)) {
        TRACE("Failed to read signing path");
        send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_SIGNING_PATH);
        return;
    }
    TRACE("Signing path:");
    BIP44_PRINTF(&ctx->signingPath);

    uint8_t hashPayload_byte;
    if (!buffer_read_u8(cdata, &hashPayload_byte)) {
        TRACE("Failed to read hashPayload");
        send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_HASH_PAYLOAD);
        return;
    }
    ctx->hashPayload = (hashPayload_byte != 0);
    TRACE("Hash payload = %d", ctx->hashPayload);

    uint8_t isAscii_byte;
    if (!buffer_read_u8(cdata, &isAscii_byte)) {
        TRACE("Failed to read isAscii");
        send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_IS_ASCII);
        return;
    }
    ctx->isAscii = (isAscii_byte != 0);
    TRACE("Is ASCII = %d", ctx->isAscii);

    uint8_t addressFieldType_byte;
    if (!buffer_read_u8(cdata, &addressFieldType_byte)) {
        TRACE("Failed to read addressFieldType");
        send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_ADDRESS_FIELD_TYPE);
        return;
    }
    ctx->addressFieldType = (cip8_address_field_type_t) addressFieldType_byte;
    TRACE("Address field type = %d", ctx->addressFieldType);

    switch (ctx->addressFieldType) {
        case CIP8_ADDRESS_FIELD_ADDRESS:
            if (!buffer_read_address_params(cdata, &ctx->address_params)) {
                TRACE("Failed to parse address params");
                send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_ADDRESS_PARAMS);
                return;
            }
            // Copy any hash pointers into context-owned storage: the INIT APDU buffer
            // will be overwritten before CONFIRM stage when deriveAddress is called.
            address_params_copyHashesToStorage(&ctx->address_params,
                                             &ctx->hashStorage);
            break;
        case CIP8_ADDRESS_FIELD_KEYHASH:
            // No additional data to parse
            break;
        default:
            TRACE("Invalid address field type");
            send_swo_and_reset(SWO_SIGN_MSG_INVALID_ADDRESS_FIELD_TYPE);
            return;
    }

    if (!is_msg_length_valid_for_sign_msg_init(ctx->msgLength, ctx->hashPayload, ctx->isAscii)) {
        TRACE("Message length rejected at INIT: len=%u hashPayload=%d isAscii=%d",
              ctx->msgLength,
              ctx->hashPayload,
              ctx->isAscii);
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }

    // Verify APDU fully consumed
    if (deny_unconsumed_bytes(cdata, SWO_WRONG_DATA_LENGTH)) {
        TRACE("INIT APDU not fully consumed");
        return;
    }
    // Check security policy and collect warnings
    ctx->warnings = 0;
    security_policy_t policy = policyForSignMsg(&ctx->signingPath,
                                                 ctx->addressFieldType,
                                                 &ctx->address_params,
                                                 &ctx->warnings);
    TRACE("Policy: %d", (int) policy);
    if (policy == POLICY_DENY) {
        TRACE("Policy denied");
        send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        return;
    }

    // Initialize hash context (always compute hash even for non-hashed payload)
    blake2b_224_init(&ctx->msgHashCtx);

    // Derive and store witness public key (needed for response and possibly address field)
    extendedPublicKey_t extPubKey = {0};
    deriveExtendedPublicKey(&ctx->signingPath, &extPubKey);
    STATIC_ASSERT(SIZEOF(extPubKey.pubKey) == SIZEOF(ctx->witnessKey),
                  "wrong witness key size");
    memmove(ctx->witnessKey, extPubKey.pubKey, SIZEOF(extPubKey.pubKey));
    explicit_bzero(&extPubKey, SIZEOF(extPubKey));

    // Initialize chunk tracking
    ctx->remainingBytes = ctx->msgLength;

    // Dynamically allocate message buffer to accumulate all chunks
    if (ctx->msgLength > 0) {
        if (!APP_MEM_CALLOC((void **) &ctx->msgBuffer, (uint16_t) ctx->msgLength)) {
            TRACE("Failed to allocate %u byte message buffer", ctx->msgLength);
            send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
            return;
        }
        ctx->msgBufferSize = ctx->msgLength;
    }

    // Show spinner to indicate message processing
    TRACE("Calling nbgl_useCaseSpinner(\"Processing\")");
    nbgl_useCaseSpinner("Processing");

    // Transition: skip CHUNK stage for empty messages
    if (ctx->msgLength == 0) {
        G_context.state.sign_msg_state = SIGN_MSG_STATE_CONFIRM;
    } else {
        G_context.state.sign_msg_state = SIGN_MSG_STATE_CHUNK;
    }

    apdu_response_send_sw(SWO_SUCCESS);
}

// ============================== CHUNK ==============================

void signMsg_handle_chunk(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata");
    LEDGER_ASSERT(G_context.state.sign_msg_state == SIGN_MSG_STATE_CHUNK, "Invalid sign_msg state");

    sign_msg_ctx_t *ctx = &G_context.sign_msg_info;

    // Parse chunk: [4 bytes: chunkSize] [chunkSize bytes: data]
    uint32_t chunkSize_u32;
    if (!buffer_read_u32(cdata, &chunkSize_u32, BE)) {
        TRACE("Failed to read chunk size");
        send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_CHUNK_SIZE);
        return;
    }
    TRACE("Chunk size = %u", chunkSize_u32);

    // Validate chunk size doesn't exceed remaining bytes
    if (chunkSize_u32 > ctx->remainingBytes) {
        TRACE("Chunk size exceeds remaining bytes");
        send_swo_and_reset(SWO_SIGN_MSG_INVALID_CHUNK_SIZE);
        return;
    }

    // Each chunk must be exactly min(remaining, MAX_CIP8_MSG_CHUNK_SIZE)
    uint32_t expectedChunkSize = MIN(ctx->remainingBytes, MAX_CIP8_MSG_CHUNK_SIZE);
    if (chunkSize_u32 != expectedChunkSize) {
        TRACE("Chunk size mismatch: expected %u, got %u",
              expectedChunkSize,
              chunkSize_u32);
        send_swo_and_reset(SWO_SIGN_MSG_INVALID_CHUNK_SIZE);
        return;
    }

    // Validate buffer has enough data
    if (!buffer_can_read(cdata, chunkSize_u32)) {
        TRACE("Insufficient data in buffer");
        send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_CHUNK_DATA);
        return;
    }

    if (chunkSize_u32 > 0) {
        // Compute write offset into the accumulated message buffer
        const uint32_t writeOffset = ctx->msgLength - ctx->remainingBytes;
        LEDGER_ASSERT(ctx->msgBuffer != NULL, "Message buffer not allocated");
        LEDGER_ASSERT(writeOffset + chunkSize_u32 <= ctx->msgBufferSize, "Chunk would overflow message buffer");

        // Read chunk data directly into accumulated message buffer
        if (!buffer_read_bytes(cdata, ctx->msgBuffer + writeOffset, chunkSize_u32)) {
            TRACE("Failed to read chunk data");
            send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_CHUNK_DATA);
            return;
        }

        // ASCII validation on this chunk
        if (ctx->isAscii) {
            if (!str_isUnambiguousAscii(ctx->msgBuffer + writeOffset, chunkSize_u32)) {
                TRACE("ASCII validation failed");
                send_swo_and_reset(SWO_SIGN_MSG_INVALID_ASCII);
                return;
            }
        }

        // Add chunk to hash
        blake2b_224_append(&ctx->msgHashCtx, ctx->msgBuffer + writeOffset, chunkSize_u32);
    }

    // Update remaining bytes
    ctx->remainingBytes -= chunkSize_u32;

    // Transition to CONFIRM if all bytes received
    if (ctx->remainingBytes == 0) {
        G_context.state.sign_msg_state = SIGN_MSG_STATE_CONFIRM;
    }

    apdu_response_send_sw(SWO_SUCCESS);
}

// ============================== CONFIRM ==============================

// Helper: prepare address field (derive address or compute key hash)
static void prepare_address_field(sign_msg_ctx_t *ctx) {
    switch (ctx->addressFieldType) {
        case CIP8_ADDRESS_FIELD_ADDRESS: {
            ctx->addressFieldSize =
                deriveAddress(&ctx->address_params, ctx->addressField, SIZEOF(ctx->addressField));
            LEDGER_ASSERT(ctx->addressFieldSize > 0 && ctx->addressFieldSize <= SIZEOF(ctx->addressField), "Invalid address length");
            break;
        }

        case CIP8_ADDRESS_FIELD_KEYHASH: {
            STATIC_ASSERT(SIZEOF(ctx->addressField) >= ADDRESS_KEY_HASH_LENGTH,
                          "wrong address field size");
            keyPathToKeyHash(&ctx->signingPath, ctx->addressField, ADDRESS_KEY_HASH_LENGTH);
            ctx->addressFieldSize = ADDRESS_KEY_HASH_LENGTH;
            break;
        }

        default:
            LEDGER_ASSERT(false, "Invalid address field type");
    }
}

// Helper: create CBOR-encoded protected header
static size_t create_protected_header(sign_msg_ctx_t *ctx,
                                      uint8_t *protectedHeaderBuffer,
                                      size_t maxSize) {
    // protectedHeader = {
    //     1 : -8,                         // set algorithm to EdDSA
    //     "address" : address_bytes       // raw address or key hash
    // }
    buffer_t buffer = buffer_create(protectedHeaderBuffer, maxSize);

    // Map with 2 entries
    LEDGER_ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_MAP, 2), "CBOR write failed");

    // Key: 1 (unsigned)
    LEDGER_ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_UNSIGNED, 1), "CBOR write failed");

    // Value: -8 (algorithm EdDSA)
    // cbor_writeToken expects the actual negative value, not the CBOR-encoded form
    int64_t negValue = -8;
    uint64_t negValueAsU64;
    STATIC_ASSERT(SIZEOF(negValue) == SIZEOF(negValueAsU64), "size mismatch");
    memmove(&negValueAsU64, &negValue, SIZEOF(negValue));
    LEDGER_ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_NEGATIVE, negValueAsU64), "CBOR write failed");

    // Key: "address" (text string)
    const char *address_key = "address";
    const size_t address_key_len = strlen(address_key);
    LEDGER_ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_TEXT, address_key_len), "CBOR write failed");
    LEDGER_ASSERT(buffer_write_bytes(&buffer, (const uint8_t *) address_key, address_key_len), "Buffer overflow");

    // Value: address bytes
    prepare_address_field(ctx);
    LEDGER_ASSERT(ctx->addressFieldSize > 0, "Address field not prepared");

    LEDGER_ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_BYTES, ctx->addressFieldSize), "CBOR write failed");
    LEDGER_ASSERT(buffer_write_bytes(&buffer, ctx->addressField, ctx->addressFieldSize), "Buffer overflow");

    const size_t protectedHeaderSize = buffer.offset;
    LEDGER_ASSERT(protectedHeaderSize > 0 && protectedHeaderSize <= maxSize, "Invalid header size");

    return protectedHeaderSize;
}

// Helper: build Sig_structure and sign it
// Returns false on allocation failures, true on success.
static bool build_and_sign_sig_structure(sign_msg_ctx_t *ctx) {
    // Sig_structure = [
    //     context : "Signature1",
    //     body_protected : CBOR_encode(protectedHeader),
    //     external_aad : bstr,            // empty buffer
    //     payload : bstr                  // message hash or raw message
    // ]

    // Compute payload size for allocation
    const size_t payloadSize = ctx->hashPayload
        ? SIZEOF(ctx->msgHash)
        : ctx->msgLength;

    const size_t sigStructureMaxSize = SIG_STRUCTURE_OVERHEAD + payloadSize;

    // Dynamically allocate Sig_structure buffer
    uint8_t *sigStructure = NULL;
    if (sigStructureMaxSize > UINT16_MAX) {
        TRACE("Sig_structure too large for allocation: %u", (unsigned) sigStructureMaxSize);
        return false;
    }
    if (!APP_MEM_CALLOC((void **) &sigStructure, (uint16_t) sigStructureMaxSize)) {
        TRACE("Failed to allocate %u byte Sig_structure buffer", (unsigned) sigStructureMaxSize);
        return false;
    }

    buffer_t buffer = buffer_create(sigStructure, sigStructureMaxSize);

    // Array with 4 elements
    LEDGER_ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_ARRAY, 4), "CBOR write failed");

    // Element 1: "Signature1" (text string)
    const char *context = "Signature1";
    const size_t context_len = strlen(context);
    LEDGER_ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_TEXT, context_len), "CBOR write failed");
    LEDGER_ASSERT(buffer_write_bytes(&buffer, (const uint8_t *) context, context_len), "Buffer overflow");

    // Element 2: CBOR-encoded protectedHeader (as bytes)
    uint8_t protectedHeaderBuffer[MAX_ADDRESS_LENGTH + 32];
    const size_t protectedHeaderSize =
        create_protected_header(ctx, protectedHeaderBuffer, SIZEOF(protectedHeaderBuffer));

    LEDGER_ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_BYTES, protectedHeaderSize), "CBOR write failed");
    LEDGER_ASSERT(buffer_write_bytes(&buffer, protectedHeaderBuffer, protectedHeaderSize), "Buffer overflow");

    // Element 3: empty external_aad (empty byte string)
    LEDGER_ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_BYTES, 0), "CBOR write failed");

    // Element 4: payload (message hash or raw message)
    // Finalize hash first
    STATIC_ASSERT(SIZEOF(ctx->msgHash) * 8 == 224, "inconsistent message hash size");
    blake2b_224_finalize(&ctx->msgHashCtx, ctx->msgHash, SIZEOF(ctx->msgHash));

    if (ctx->hashPayload) {
        // Payload is the hash
        LEDGER_ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_BYTES, SIZEOF(ctx->msgHash)), "CBOR write failed");
        LEDGER_ASSERT(buffer_write_bytes(&buffer, ctx->msgHash, SIZEOF(ctx->msgHash)), "Buffer overflow");
    } else {
        // Payload is the raw message from accumulated buffer
        LEDGER_ASSERT(ctx->remainingBytes == 0, "Message not fully received");
        LEDGER_ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_BYTES, ctx->msgLength), "CBOR write failed");
        LEDGER_ASSERT(buffer_write_bytes(&buffer, ctx->msgBuffer, ctx->msgLength), "Buffer overflow");
    }

    const size_t sigStructureSize = buffer.offset;
    TRACE("Sig_structure size = %u", sigStructureSize);
    TRACE_BUFFER(sigStructure, sigStructureSize);

    // CIP-8/COSE Sig_structure has fixed semantics and no extra app-defined domain-separation
    // field for Cardano witness-vs-message separation. Adding a custom prefix/tag here would
    // break interoperability, so we sign the standard CBOR Sig_structure bytes as defined.
    // This check only guards against the degenerate 32-byte ambiguity with raw tx hashes.
    LEDGER_ASSERT(sigStructureSize != TX_HASH_LENGTH, "Sig_structure size equals TX_HASH_LENGTH");

    // Sign the Sig_structure
    signRawMessageWithPath(&ctx->signingPath,
                           sigStructure,
                           sigStructureSize,
                           ctx->signature,
                           SIZEOF(ctx->signature));

    APP_MEM_FREE(sigStructure);

    return true;
}

void signMsg_handle_confirm(buffer_t *cdata) {
    LEDGER_ASSERT(G_context.state.sign_msg_state == SIGN_MSG_STATE_CONFIRM, "Invalid sign_msg state");
    LEDGER_ASSERT(cdata != NULL, "NULL cdata");

    sign_msg_ctx_t *ctx = &G_context.sign_msg_info;

    // CONFIRM APDU must be empty
    if (deny_unconsumed_bytes(cdata, SWO_SIGN_MSG_CONFIRM_MUST_BE_EMPTY)) {
        TRACE("CONFIRM APDU must be empty");
        return;
    }

    // Build Sig_structure and sign it
    if (!build_and_sign_sig_structure(ctx)) {
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }

    // Display UI for user confirmation
    apdu_response_deferred();
    ui_display_sign_msg(POLICY_SHOW, ctx->warnings);
}

void finalize_sign_msg(void) {
    LEDGER_ASSERT(G_context.req_type == REQUEST_SIGN_MSG, "Bad req_type");
    LEDGER_ASSERT(G_context.state.sign_msg_state == SIGN_MSG_STATE_CONFIRM, "Bad sign_msg state");

    // User confirmed - send response
    sign_msg_ctx_t *ctx = &G_context.sign_msg_info;

    // Response format (matching old app):
    // [64 bytes: signature] [32 bytes: witnessKey] [4 bytes: addressFieldSize BE]
    // [addressFieldSize bytes: addressField]
    uint8_t response_buffer[ED25519_SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH + 4 + MAX_ADDRESS_LENGTH];
    buffer_t response = buffer_create(response_buffer, SIZEOF(response_buffer));

    LEDGER_ASSERT(buffer_write_bytes(&response, ctx->signature, SIZEOF(ctx->signature)), "Write signature failed");
    LEDGER_ASSERT(buffer_write_bytes(&response, ctx->witnessKey, SIZEOF(ctx->witnessKey)), "Write witness key failed");
    LEDGER_ASSERT(buffer_write_u32(&response, ctx->addressFieldSize, BE), "Write address size failed");
    LEDGER_ASSERT(buffer_write_bytes(&response, ctx->addressField, ctx->addressFieldSize), "Write address failed");

    const size_t response_size = response.offset;
    TRACE("Response size = %u", response_size);

    apdu_response_send_data(response_buffer, response_size, SWO_SUCCESS);
    reset_app_context();
}

// ============================== MAIN HANDLER ==============================

void handler_sign_msg(buffer_t *cdata, uint8_t p1) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata");
    TRACE_BUFFER_T(cdata);

    switch (p1) {
        case P1_SIGN_MSG_INIT: {
            TRACE("P1_SIGN_MSG_INIT");
            if (!ensure_sign_msg_request_type(REQUEST_NONE)) {
                return;
            }
            if (!ensure_sign_msg_state(SIGN_MSG_STATE_NONE)) {
                return;
            }
            G_context.req_type = REQUEST_SIGN_MSG;
            G_context.state.sign_msg_state = SIGN_MSG_STATE_INIT;
            signMsg_handle_init(cdata);
            break;
        }
        case P1_SIGN_MSG_CHUNK: {
            TRACE("P1_SIGN_MSG_CHUNK");
            if (!ensure_sign_msg_request_type(REQUEST_SIGN_MSG)) {
                return;
            }
            if (!ensure_sign_msg_state(SIGN_MSG_STATE_CHUNK)) {
                return;
            }
            signMsg_handle_chunk(cdata);
            break;
        }
        case P1_SIGN_MSG_CONFIRM: {
            TRACE("P1_SIGN_MSG_CONFIRM");
            if (!ensure_sign_msg_request_type(REQUEST_SIGN_MSG)) {
                return;
            }
            if (!ensure_sign_msg_state(SIGN_MSG_STATE_CONFIRM)) {
                return;
            }
            signMsg_handle_confirm(cdata);
            break;
        }
        default:
            TRACE("Bad P1 value");
            LEDGER_ASSERT(false, "P1 should be handled before");
            break;
    }
}
