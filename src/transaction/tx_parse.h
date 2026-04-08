/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "buffer.h"

#include "tx.h"

// ---------------------------------------------------------------------------
// Parse-item helpers
// ---------------------------------------------------------------------------

bool parse_input(buffer_t *buf, tx_input_t *out_input);

bool parse_required_signer(buffer_t *buf, required_signer_t *out_required_signer);

bool parse_voter_votes_header(buffer_t *buf, ext_voter_t *out_voter, uint16_t *out_num_votes);

bool parse_vote(buffer_t *buf, vote_item_t *out_vote_item);

bool parse_withdrawal(buffer_t *buf, withdrawal_t *out_withdrawal);

bool parse_mint_token(buffer_t *buf, mint_token_t *out_mint_token);
