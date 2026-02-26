/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "buffer.h"
#include "tx_processing.h"

/**
 * Process all transaction outputs (tx map key 1).
 *
 * Iterates over tx_params->num_outputs outputs. For each output:
 *   - Parses top-level fields (destination, amount, format, presence flags, asset groups)
 *   - Applies security policy
 *   - Feeds hash builder (pass 1)
 *   - Plans / renders UI (pass 1 / pass 2)
 *
 * @return true on success, false on error (send_swo_and_reset already called)
 */
bool tx_process_outputs(buffer_t *buf, tx_processing_state_t *state);

/**
 * Process the collateral output (tx map key 16) if present.
 *
 * @return true on success or if no collateral output, false on error
 */
bool tx_process_collateral_output(buffer_t *buf);
