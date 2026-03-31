/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include "securityPolicy.h"
#include "bip44.h"
#include "tx_processing.h"

/**
 * Transaction display and signing UI functions
 * Handles NBGL transaction review flows
 */

/**
 * Display transaction information on the device and ask confirmation to sign.
 */
void ui_display_transaction(void);

/**
 * Display the blind-signing choice for long transactions before review.
 */
void ui_display_blind_signing_choice(void);

/**
 * Render the selected transaction review and convert recoverable render failures
 * into SWO_INSUFFICIENT_MEMORY.
 */
bool tx_render_ui_or_fail(tx_ui_review_mode_e review_mode);

/**
 * Clean up all NBGL review state (display buffers + warnings).
 * Call this once the review use case finishes but you still need the parsed
 * transaction context for the witness flow.
 */
void tx_review_cleanup(void);

/**
 * Display transaction witness for signing approval
 *
 * @param witnessPath BIP44 path for the witness
 * @param securityPolicy Security policy result
 * @param warnings Warning bits
 */
void ui_display_witness(const bip44_path_t* witnessPath,
                        security_policy_t securityPolicy,
                        warning_bits_t warnings);
