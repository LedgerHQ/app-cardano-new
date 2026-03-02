/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Public interface for transaction processing (policy enforcement, UI, hashing).
 * Implementation is in tx_processing.c, tx_processing_outputs.c, and
 * tx_processing_certificates.c.
 */

#pragma once

#include "buffer.h"

#include "cardano_swo.h"
#include "securityPolicyType.h"
#include "tx.h"
#include "tx_hash_builder.h"
#include "tx_ui_pair_counts.h"
#include "securityWarnings.h"
#include "cbor_canonical.h"

typedef struct {
    bool run_validation;              // pass 1: true, pass 2: true
    bool run_hash_builder;            // pass 1: true, pass 2: false
    bool ui_count_pairs;              // pass 1: true, pass 2: false
    bool ui_render;                   // pass 1: false, pass 2: true
} tx_processing_mode_t;

/**
 * Unpacked view of global tx context for use at the top of processing functions.
 * Created as a local variable via tx_get_ctx(); never stored globally.
 * mode is embedded by value (not a pointer) so static analysis can confirm it is
 * always initialized and non-null.
 */
typedef struct {
    const tx_params_t      *tx_params;
    tx_processing_mode_t    mode;
    warning_bits_t         *warning_bits;
    tx_hash_builder_t      *hash_builder;
} tx_processing_ctx_t;

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
    const tx_processing_mode_t *mode;  // points into transaction_ctx_t.processing_mode
    warning_bits_t *warning_bits; // points to global warnings or local dummy

    tx_hash_builder_t hash_builder;
    bool hash_builder_initialized;

    uint16_t swap_third_party_output_count;
} tx_processing_state_t;

// ---------------------------------------------------------------------------
// Canonical ordering macros (tx_processing layer — error-reporting wrappers)
// ---------------------------------------------------------------------------

/**
 * Declare a canonical ordering tracker in the current scope.
 * Must appear before any ENFORCE_CANONICAL_ORDERING_CHECK using the same name.
 */
#define ENFORCE_CANONICAL_ORDERING_START(tracker_name) \
    CBOR_CANONICAL_START(tracker_name)

/**
 * Check that next_key maintains canonical ordering relative to the previous key
 * seen by tracker_name. On failure, calls tx_handle_parse_error(error_swo) and
 * returns false from the enclosing function.
 */
#define ENFORCE_CANONICAL_ORDERING_CHECK(tracker_name, next_key, next_key_length, error_swo) \
    do { \
        if (!CBOR_CANONICAL_CHECK(tracker_name, next_key, next_key_length)) { \
            tx_handle_parse_error(error_swo); \
            return false; \
        } \
    } while (0)

// ---------------------------------------------------------------------------
// Context helpers
// ---------------------------------------------------------------------------

void validate_parse_tx_mode(const tx_processing_mode_t *mode);

void tx_processing_state_init(const tx_processing_mode_t *mode, warning_bits_t *warning_bits);

/**
 * Assert that the global tx processing context is valid and return an unpacked view.
 * Call at the top of every tx_process_* function after asserting buf != NULL.
 */
tx_processing_ctx_t tx_get_ctx(void);

void tx_handle_parse_error(uint16_t swo);

// ---------------------------------------------------------------------------
// Credential/DRep/voter conversion helpers (ext → hash-builder format)
// ---------------------------------------------------------------------------

credential_t credential_for_tx_hash_from_ext_credential(const ext_credential_t *credential);

drep_t drep_for_tx_hash_from_ext_drep(const ext_drep_t *ext_drep);

voter_t voter_for_tx_hash_from_ext_voter(const ext_voter_t *ext_voter);

// ---------------------------------------------------------------------------
// Processing entry points
// ---------------------------------------------------------------------------

bool tx_process_inputs(buffer_t *buf, tx_processing_state_t *state);
bool tx_process_collateral_inputs(buffer_t *buf, tx_processing_state_t *state);
bool tx_process_required_signers(buffer_t *buf, tx_processing_state_t *state);
bool tx_process_reference_inputs(buffer_t *buf, tx_processing_state_t *state);
bool tx_validate(buffer_t *buf);
bool tx_render_ui_chunk(uint16_t from);
bool tx_render_ui_all(void);
