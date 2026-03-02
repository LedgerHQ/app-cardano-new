/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>

#include "tx_output_types.h"
#include "tx_hash_builder.h"
#include "tx_parse.h"

/**
 * UI planning/rendering functions for transaction outputs and collateral outputs.
 */

void tx_ui_plan_or_render_output(const tx_processing_mode_t *mode,
                                 uint16_t output_index,
                                 const tx_output_description_t *output_desc);

void tx_ui_plan_or_render_collateral_output_address(const tx_processing_mode_t *mode,
                                                    const tx_output_description_t *output_desc);

void tx_ui_plan_or_render_collateral_output_amount(const tx_processing_mode_t *mode,
                                                   const tx_output_description_t *output_desc);

void tx_ui_plan_or_render_output_token(const tx_processing_mode_t *mode,
                                       const uint8_t *policy_id,
                                       const output_token_t *token);

void tx_ui_plan_or_render_output_datum(const tx_processing_mode_t *mode,
                                       const output_datum_t *datum);

void tx_ui_plan_or_render_output_ref_script(const tx_processing_mode_t *mode,
                                            const ref_script_t *ref_script);
