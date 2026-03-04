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
 * Each function handles both passes (ui_count_pairs and ui_render)
 * for one parsed tx element. They take only the mode and the parsed element
 * (plus any extra scalars needed for formatting).
 *
 * Naming: tx_ui_plan_or_render_<element>(mode, parsed_<element>, ...)
 */

void tx_ui_plan_or_render_network_details(const tx_processing_mode_t *mode,
                                          const tx_params_t *tx_params);

void tx_ui_plan_or_render_input(const tx_processing_mode_t *mode,
                                const tx_input_t *parsed_input,
                                uint16_t input_index);

void tx_ui_plan_or_render_collateral_input(const tx_processing_mode_t *mode,
                                           const tx_input_t *parsed_input,
                                           uint16_t input_index);

void tx_ui_plan_or_render_reference_input(const tx_processing_mode_t *mode,
                                          const tx_input_t *parsed_input,
                                          uint16_t input_index);

void tx_ui_plan_or_render_required_signer(const tx_processing_mode_t *mode,
                                          const required_signer_t *parsed_required_signer,
                                          uint16_t signer_index);

void tx_ui_plan_or_render_mint_summary(const tx_processing_mode_t *mode,
                                       uint16_t num_mint_asset_groups);

void tx_ui_plan_or_render_mint_token(const tx_processing_mode_t *mode,
                                     const mint_token_t *mint_token);

void tx_ui_plan_or_render_fee(const tx_processing_mode_t *mode, uint64_t parsed_fee);

void tx_ui_plan_or_render_ttl(const tx_processing_mode_t *mode, uint64_t parsed_ttl);

void tx_ui_plan_or_render_validity_interval_start(const tx_processing_mode_t *mode,
                                                  uint64_t validity_interval_start);

void tx_ui_plan_or_render_withdrawal(const tx_processing_mode_t *mode,
                                     const withdrawal_t *parsed_withdrawal,
                                     uint8_t network_id);

void tx_ui_plan_or_render_aux_data_hash(const tx_processing_mode_t *mode,
                                        const uint8_t *aux_data_hash);

void tx_ui_plan_or_render_script_data_hash(const tx_processing_mode_t *mode,
                                           const uint8_t *script_data_hash);

void tx_ui_plan_or_render_total_collateral(const tx_processing_mode_t *mode,
                                           uint64_t total_collateral);

void tx_ui_plan_or_render_voter(const tx_processing_mode_t *mode,
                                const ext_voter_t *parsed_voter,
                                uint16_t voter_index);

void tx_ui_plan_or_render_vote(const tx_processing_mode_t *mode, const vote_item_t *parsed_vote);

void tx_ui_plan_or_render_vote_anchor(const tx_processing_mode_t *mode, const anchor_t *anchor);

void tx_ui_plan_or_render_treasury(const tx_processing_mode_t *mode, uint64_t treasury);

void tx_ui_plan_or_render_donation(const tx_processing_mode_t *mode, uint64_t donation);

void tx_ui_plan_or_render_tx_hash(const tx_processing_mode_t *mode, const uint8_t *tx_hash);
