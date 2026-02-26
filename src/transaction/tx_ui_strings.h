/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>

#include "tx.h"
#include "tx_certificate_types.h"
#include "tx_credential_types.h"
#include "tx_parse.h"

/**
 * UI planning/rendering functions for individual transaction elements.
 *
 * Each function handles both passes (run_ui_planning and run_ui_rendering)
 * for one parsed tx element. They take only the mode and the parsed element
 * (plus any extra scalars needed for formatting).
 *
 * Naming: tx_ui_plan_or_render_<element>(mode, parsed_<element>, ...)
 */

void tx_ui_plan_or_render_input(const parse_tx_mode_t *mode, const tx_input_t *parsed_input);

void tx_ui_plan_or_render_collateral_input(const parse_tx_mode_t *mode,
                                           const tx_input_t *parsed_input);

void tx_ui_plan_or_render_reference_input(const parse_tx_mode_t *mode,
                                          const tx_input_t *parsed_input);

void tx_ui_plan_or_render_required_signer(const parse_tx_mode_t *mode,
                                          const required_signer_t *parsed_required_signer);

void tx_ui_plan_or_render_mint_summary(const parse_tx_mode_t *mode,
                                       uint16_t num_mint_asset_groups);

void tx_ui_plan_or_render_mint_token(const parse_tx_mode_t *mode,
                                     const mint_token_t *mint_token);

void tx_ui_plan_or_render_fee(const parse_tx_mode_t *mode, uint64_t parsed_fee);

void tx_ui_plan_or_render_ttl(const parse_tx_mode_t *mode, uint64_t parsed_ttl);

void tx_ui_plan_or_render_validity_interval_start(const parse_tx_mode_t *mode,
                                                  uint64_t validity_interval_start);

void tx_ui_plan_or_render_withdrawal(const parse_tx_mode_t *mode,
                                     const withdrawal_t *parsed_withdrawal,
                                     uint8_t network_id);

void tx_ui_plan_or_render_aux_data_hash(const parse_tx_mode_t *mode,
                                        const uint8_t *aux_data_hash);

void tx_ui_plan_or_render_script_data_hash(const parse_tx_mode_t *mode,
                                           const uint8_t *script_data_hash);

void tx_ui_plan_or_render_total_collateral(const parse_tx_mode_t *mode,
                                           uint64_t total_collateral);

void tx_ui_plan_or_render_voter(const parse_tx_mode_t *mode, const ext_voter_t *parsed_voter);

void tx_ui_plan_or_render_vote(const parse_tx_mode_t *mode, const vote_item_t *parsed_vote);

void tx_ui_plan_or_render_vote_anchor(const parse_tx_mode_t *mode, const anchor_t *anchor);

void tx_ui_plan_or_render_treasury(const parse_tx_mode_t *mode, uint64_t treasury);

void tx_ui_plan_or_render_donation(const parse_tx_mode_t *mode, uint64_t donation);

void tx_ui_plan_or_render_tx_hash(const parse_tx_mode_t *mode, const uint8_t *tx_hash);
