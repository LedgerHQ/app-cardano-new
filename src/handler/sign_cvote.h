/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include "buffer.h"

/**
 * Handler for INS_SIGN_CVOTE command.
 *
 * Handles CIP-36 votecast fragment signing in three stages:
 * - P1_CVOTE_INIT: Initialize with votecast data length and first chunk
 * - P1_CVOTE_CHUNK: Receive additional votecast data chunks
 * - P1_CVOTE_CONFIRM: Provide witness path and trigger signing
 *
 * @param[in] cdata
 *   Buffer containing APDU data
 * @param[in] p1
 *   P1 parameter value indicating stage (INIT, CHUNK, or CONFIRM)
 */
void handler_sign_cvote(buffer_t *cdata, uint8_t p1);

/**
 * Finalize cvote signing after user confirmation.
 *
 * Computes the votecast hash, signs it with the witness key,
 * and sends the response containing both hash and signature.
 *
 * @param[in] confirmed
 *   true if user confirmed, false if rejected
 */
void finalize_sign_cvote(bool confirmed);
