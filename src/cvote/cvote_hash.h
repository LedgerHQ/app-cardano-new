/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "cvote_parser.h"

/**
 * Initialize hash builder for CVote registration.
 * Sets up the CBOR serialization context for building auxiliary data hash.
 */
void cvote_hash_builder_setup(cvote_aux_data_t *aux_data);

/**
 * Add a delegation to the CVote registration hash.
 * Asserts on invalid credential type (must be KEY or KEY_PATH).
 */
void cvote_hash_builder_add_delegation(cvote_aux_data_t *aux_data,
                                       const cvote_credential_t *credential,
                                       uint32_t weight);

/**
 * Finalize the CVote auxiliary data hash.
 * Adds common fields (vote key, staking key, payment address, nonce, voting purpose if CIP36),
 * appends the registration signature, and computes the final CBOR hash.
 * All input data must be validated during parsing - any error here indicates a bug.
 * Asserts on validation failures.
 */
void cvote_hash_finalize(void);
