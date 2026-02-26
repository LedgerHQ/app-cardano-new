/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "buffer.h"
#include "tx.h"
#include "tx_processing.h"

/**
 * Process all certificates in a transaction.
 *
 * Parses each certificate from the buffer and dispatches to type-specific handlers.
 * Pool registration certificates are handled specially with per-item validation and hashing.
 * Other certificate types use the unified policy/UI/hash flow.
 *
 * @param[in]  buf      Buffer with transaction data
 * @param[in]  state    Transaction processing state
 *
 * @return true on success, false on error (send_swo_and_reset already called)
 */
bool tx_process_certificates(buffer_t *buf, tx_processing_state_t *state);

/**
 * Process a CERTIFICATE_STAKE_POOL_REGISTRATION certificate.
 *
 * Handles security policy enforcement, UI planning/rendering, and hash building
 * for a pool registration certificate. The `buf` parameter is needed to compute
 * the transaction end pointer used when re-scanning owners and relays stored as
 * raw pointers into the original buffer.
 *
 * The caller is responsible for calling cleanup_certificate_data() on
 * parsed_cert regardless of the return value; this function only calls it
 * on its own internal early-exit error paths.
 *
 * @param[in]  buf                Buffer containing the full transaction
 * @param[in]  state              Transaction processing state
 * @param[in]  parsed_cert        Certificate data (must be CERTIFICATE_STAKE_POOL_REGISTRATION)
 *
 * @return true on success, false on error (send_swo_and_reset already called)
 */
bool process_pool_registration_certificate(buffer_t *buf,
                                           tx_processing_state_t *state,
                                           const certificate_data_t *parsed_cert);
