/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Public interface for transaction processing (policy enforcement, UI, hashing).
 * Implementation is in tx_processing.c and tx_processing_pool_registration.c.
 */

#pragma once

#include "buffer.h"

#include "cardano_swo.h"
#include "securityPolicyType.h"
#include "tx.h"
#include "tx_parse.h"

// Standard policy dispatch: deny → reject tx, show → call render_fn, hide → skip.
// Requires render_fn to accept (mode, ...) where mode is const tx_processing_mode_t *.
// Only suitable when SHOW and HIDE branches have no extra logic beyond the UI call.
//
// WARNING: POLICY_DENY causes an immediate `return false` in the *calling function*.
// This is intentional — denial must abort transaction processing unconditionally.
// Callers do not need to check a return value; the function terminates on DENY.
#define APPLY_POLICY(policy, render_fn, mode, ...) \
    do { \
        switch (policy) { \
            case POLICY_DENY: \
                send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED); \
                return false; \
            case POLICY_SHOW: \
                render_fn(mode, ##__VA_ARGS__); \
                break; \
            case POLICY_HIDE: \
                break; \
            default: \
                LEDGER_ASSERT(false, "Unknown policy"); \
                break; \
        } \
    } while (0)

/**
 * Mutable processing state for one pass over the transaction body.
 * Stored in global tx context (not on the stack) due to hash_builder size.
 * Initialized by tx_processing_state_init() at the start of each pass.
 */
typedef struct {
    const tx_processing_mode_t *mode;  // points into transaction_ctx_t.parse_mode
    warning_bits_t *warning_bits; // points to global warnings or local dummy

    tx_hash_builder_t hash_builder;
    bool hash_builder_initialized;

    uint16_t swap_third_party_output_count;
} tx_processing_state_t;

void tx_processing_state_init(const tx_processing_mode_t *mode, warning_bits_t *warning_bits);

bool tx_process_inputs(buffer_t *buf, tx_processing_state_t *state);
bool tx_process_collateral_inputs(buffer_t *buf, tx_processing_state_t *state);
bool tx_process_required_signers(buffer_t *buf, tx_processing_state_t *state);
bool tx_process_reference_inputs(buffer_t *buf, tx_processing_state_t *state);
bool tx_validate(buffer_t *buf);
bool tx_render_ui_chunk(uint16_t from);
bool tx_prepare_ui_review(void);

