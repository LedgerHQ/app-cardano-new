
#include <stdint.h>

#include "utils.h"
#include "buffer.h"
#include "sign_cvote.h"
#include "cardano_swo.h"
#include "globals.h"
#include "addressUtilsShelley.h"
#include "securityPolicy.h"
#include "assert.h"
#include "app_context.h"
#include "io.h"
#include "cardano_parsers.h"
#include "buffer_write.h"
#include "cvote/vote_cast_hash_builder.h"
#include "messageSigning.h"
#include "ui_cvote.h"
#include "buffer_helpers.h"

static bool ensure_sign_cvote_stage(cvote_stage_e required_stage) {
    if (G_context.state.cvote_state != required_stage) {
        TRACE("Rejecting CVote command in stage %d (expected %d)",
              G_context.state.cvote_state,
              required_stage);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return false;
    }
    return true;
}

// ============================== INIT ==============================
__noinline_due_to_stack__ static void handle_sign_cvote_init_apdu(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "cdata is NULL");
    LEDGER_ASSERT(G_context.state.cvote_state == VOTECAST_STAGE_INIT, "Invalid cvote state");

    cvote_cxt_t *ctx = &G_context.cvote_info;

    // Parse the total remaining votecast bytes from the 4-byte length field
    if (!buffer_read_u32(cdata, &ctx->remaining_votecast_bytes, BE)) {
        TRACE("Failed to read remaining_votecast_bytes");
        send_swo_and_reset(SWO_CVOTE_PARSING_FAIL_REMAINING_VOTECAST_BYTES);
        return;
    }
    if (ctx->remaining_votecast_bytes == 0) {
        TRACE("Remaining votecast bytes is zero");
        send_swo_and_reset(SWO_WRONG_LENGTH);
        return;
    }
    TRACE("Remaining votecast bytes = %u", ctx->remaining_votecast_bytes);

    // Verify that the rest of the APDU contains exactly the amount of data specified
    const size_t votecast_chunk_size = buffer_remaining(cdata);
    const uint8_t *votecast_chunk_ptr = buffer_current_ptr(cdata);
    if (votecast_chunk_size > ctx->remaining_votecast_bytes) {
        TRACE("APDU contains more data than specified in length field");
        send_swo_and_reset(SWO_WRONG_LENGTH);
        return;
    }
    if (votecast_chunk_size > MAX_VOTECAST_CHUNK_SIZE) {
        TRACE("Votecast chunk too large");
        send_swo_and_reset(SWO_WRONG_LENGTH);
        return;
    }

    // Parse UI display fields from the votecast data
    // Note: This parsing is incomplete - we only extract fields needed for UI display.
    // The entire votecast fragment (including these fields) will be hashed below.

    if (!buffer_read_bytes(cdata, ctx->vote_plan_id, VOTE_PLAN_ID_SIZE)) {
        TRACE("Failed to read votePlanId");
        send_swo_and_reset(SWO_CVOTE_PARSING_FAIL_VOTE_PLAN_ID);
        return;
    }
    TRACE("Vote plan id:");
    TRACE_BUFFER(ctx->vote_plan_id, VOTE_PLAN_ID_SIZE);

    if (!buffer_read_u8(cdata, &ctx->proposal_index)) {
        TRACE("Failed to read proposalIndex");
        send_swo_and_reset(SWO_CVOTE_PARSING_FAIL_PROPOSAL_INDEX);
        return;
    }
    TRACE("Proposal index = %u", ctx->proposal_index);

    if (!buffer_read_u8(cdata, &ctx->payload_type_tag)) {
        TRACE("Failed to read payloadTypeTag");
        send_swo_and_reset(SWO_CVOTE_PARSING_FAIL_PAYLOAD_TYPE_TAG);
        return;
    }
    TRACE("Payload type tag = %u", ctx->payload_type_tag);

    vote_cast_hash_builder_init(&ctx->votecast_hash_builder, ctx->remaining_votecast_bytes);
    vote_cast_hash_builder_chunk(&ctx->votecast_hash_builder,
                                 votecast_chunk_ptr,
                                 votecast_chunk_size);

    ctx->remaining_votecast_bytes -= votecast_chunk_size;

    if (ctx->remaining_votecast_bytes == 0) {
        G_context.state.cvote_state = VOTECAST_STAGE_CONFIRM;
    } else {
        G_context.state.cvote_state = VOTECAST_STAGE_CHUNK;
    }

    io_send_sw(SWO_SUCCESS);
}

// ============================== VOTECAST CHUNK ==============================

__noinline_due_to_stack__ static void handle_sign_cvote_chunk_apdu(buffer_t *cdata) {
    LEDGER_ASSERT(G_context.state.cvote_state == VOTECAST_STAGE_CHUNK, "Invalid cvote state");
    LEDGER_ASSERT(cdata != NULL, "cdata is NULL");
    cvote_cxt_t *ctx = &G_context.cvote_info;

    const size_t chunkSize = cdata->size;
    TRACE("chunkSize = %u", chunkSize);

    if (chunkSize == 0) {
        TRACE("Empty chunk");
        send_swo_and_reset(SWO_WRONG_LENGTH);
        return;
    }
    if (chunkSize > MAX_VOTECAST_CHUNK_SIZE) {
        TRACE("Chunk size too large");
        send_swo_and_reset(SWO_WRONG_LENGTH);
        return;
    }
    if (chunkSize > ctx->remaining_votecast_bytes) {
        TRACE("Chunk size exceeds remaining bytes");
        send_swo_and_reset(SWO_WRONG_LENGTH);
        return;
    }

    vote_cast_hash_builder_chunk(&ctx->votecast_hash_builder,
                                 buffer_current_ptr(cdata),
                                 chunkSize);

    ctx->remaining_votecast_bytes -= chunkSize;

    if (ctx->remaining_votecast_bytes == 0) {
        G_context.state.cvote_state = VOTECAST_STAGE_CONFIRM;
    }

    TRACE("Remaining votecast bytes = %u", ctx->remaining_votecast_bytes);
    io_send_sw(SWO_SUCCESS);
}

// ============================== CONFIRM ==============================
__noinline_due_to_stack__ static void handle_sign_cvote_confirm_apdu(buffer_t *cdata) {
    LEDGER_ASSERT(G_context.state.cvote_state == VOTECAST_STAGE_CONFIRM, "Invalid cvote state");
    LEDGER_ASSERT(cdata != NULL, "cdata is NULL");

    cvote_cxt_t *ctx = &G_context.cvote_info;

    // Parse witness path from CONFIRM APDU
    bool read_path = buffer_read_bip44_path(cdata, &ctx->witness_path);
    if (!read_path) {
        TRACE("Failed to read bip44 path");
        send_swo_and_reset(SWO_BIP44_PATH_PARSING_FAIL);
        return;
    }
    TRACE("Witness path:");
    BIP44_PRINTF(&ctx->witness_path);

    // Ensure the entire APDU has been consumed
    LEDGER_ASSERT(!buffer_can_read(cdata, 1), "APDU not fully consumed");

    // Check security policy for witness path
    warning_bits_t warnings = 0;
    warning_bits_init(&warnings);
    security_policy_t policy = policyForSignCVoteWitness(&ctx->witness_path, &warnings);
    TRACE("Policy: %d", (int) policy);
    if (policy == POLICY_DENY) {
        TRACE("Policy denied");
        send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        return;
    }

    // Display UI (signature will be computed after user confirms)
    ui_display_cvote_confirm(policy);
    // waiting for NBGL callback cvote_review_choice, so no APDU sent
}

void finalize_sign_cvote(bool confirmed) {
    LEDGER_ASSERT(G_context.req_type == REQUEST_CVOTE,
                  "finalize_sign_cvote called without REQUEST_CVOTE");
    LEDGER_ASSERT(G_context.state.cvote_state == VOTECAST_STAGE_CONFIRM,
                  "finalize_sign_cvote called in wrong state: %d", G_context.state.cvote_state);

    if (!confirmed) {
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        return;
    }

    // User confirmed
    cvote_cxt_t *ctx = &G_context.cvote_info;

    // Finalize the hash into a local buffer
    uint8_t votecast_hash[VOTECAST_HASH_LENGTH];
    vote_cast_hash_builder_finalize(&ctx->votecast_hash_builder,
                                 votecast_hash,
                                 SIZEOF(votecast_hash));

    TRACE("votecast hash:");
    TRACE_BUFFER(votecast_hash, SIZEOF(votecast_hash));

    // Compute witness signature
    getWitness(&ctx->witness_path,
               votecast_hash,
               SIZEOF(votecast_hash),
               ctx->witness_signature,
               SIZEOF(ctx->witness_signature));

    // Prepare response: hash (32 bytes) + signature (64 bytes)
    uint8_t response_buffer[VOTECAST_HASH_LENGTH + ED25519_SIGNATURE_LENGTH];
    write_buffer_t response = buffer_init_write(response_buffer, SIZEOF(response_buffer));

    buffer_write_bytes(&response, votecast_hash, SIZEOF(votecast_hash));
    buffer_write_bytes(&response, ctx->witness_signature, SIZEOF(ctx->witness_signature));

    LEDGER_ASSERT(buffer_written_size(&response) == SIZEOF(response_buffer),
                  "Response buffer size mismatch");

    io_send_response_pointer(response_buffer, SIZEOF(response_buffer), SWO_SUCCESS);
    reset_app_context();
}

void handler_sign_cvote(buffer_t *cdata, uint8_t p1) {
    if (G_context.req_type != REQUEST_CVOTE) {
        explicit_bzero(&G_context, sizeof(G_context));
        G_context.state.cvote_state = VOTECAST_STAGE_NONE;
    }
    G_context.req_type = REQUEST_CVOTE;

    switch (p1) {
        case P1_CVOTE_INIT: {
            TRACE("P1_CVOTE_INIT");
            G_context.state.cvote_state = VOTECAST_STAGE_INIT;
            handle_sign_cvote_init_apdu(cdata);
            break;
        }
        case P1_CVOTE_CHUNK: {
            TRACE("P1_CVOTE_CHUNK");
            if (!ensure_sign_cvote_stage(VOTECAST_STAGE_CHUNK)) {
                return;
            }
            handle_sign_cvote_chunk_apdu(cdata);
            break;
        }
        case P1_CVOTE_CONFIRM: {
            TRACE("P1_CVOTE_CONFIRM");
            if (!ensure_sign_cvote_stage(VOTECAST_STAGE_CONFIRM)) {
                return;
            }
            handle_sign_cvote_confirm_apdu(cdata);
            break;
        }
        default:
            TRACE("Bad display type");
            LEDGER_ASSERT(false, "display type should be handled before");
            break;
    }
    return;
}
