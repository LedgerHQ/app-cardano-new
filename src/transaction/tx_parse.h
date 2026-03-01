/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "buffer.h"

#include "tx.h"
#include "tx_hash_builder.h"
#include "tx_ui_plan.h"
#include "securityWarnings.h"

typedef struct {
    bool run_validation;              // pass 1: true, pass 2: true
    bool run_hash_builder;            // pass 1: true, pass 2: false
    bool run_ui_planning;             // pass 1: true, pass 2: false
    bool run_ui_rendering;            // pass 1: false, pass 2: true
} tx_processing_mode_t;

/**
 * Unpacked view of global tx context for use at the top of processing functions.
 * Created as a local variable via tx_get_ctx(); never stored globally.
 */
typedef struct {
    const tx_params_t        *tx_params;
    const tx_processing_mode_t *mode;
    warning_bits_t           *warning_bits;
    tx_hash_builder_t        *hash_builder;
} tx_processing_ctx_t;

/**
 * Assert that the global tx processing context is valid and return an unpacked view.
 * Call at the top of every tx_process_* function after asserting buf != NULL.
 */
tx_processing_ctx_t tx_get_ctx(void);

void tx_handle_parse_error(uint16_t swo);

// ---------------------------------------------------------------------------
// Context helpers
// ---------------------------------------------------------------------------

void validate_parse_tx_mode(const tx_processing_mode_t *mode);

#include "cbor_canonical.h"

// ---------------------------------------------------------------------------
// Parse-item helpers
// ---------------------------------------------------------------------------

bool parse_input(buffer_t *buf, tx_input_t *out_input);

bool parse_required_signer(buffer_t *buf, required_signer_t *out_required_signer);

bool parse_voter_votes_header(buffer_t *buf,
                              ext_voter_t *out_voter,
                              uint16_t *out_num_votes);

bool parse_vote(buffer_t *buf, vote_item_t *out_vote_item);

bool parse_withdrawal(buffer_t *buf, withdrawal_t *out_withdrawal);

bool parse_mint_token(buffer_t *buf, mint_token_t *out_mint_token);

// ---------------------------------------------------------------------------
// Credential/DRep/voter conversion helpers (ext → hash-builder format)
// ---------------------------------------------------------------------------

credential_t credential_for_tx_hash_from_ext_credential(const ext_credential_t *credential);

drep_t drep_for_tx_hash_from_ext_drep(const ext_drep_t *ext_drep);

voter_t voter_for_tx_hash_from_ext_voter(const ext_voter_t *ext_voter);
