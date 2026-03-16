/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tx.h"
#include "bip44.h"

/**
 * Checks if a witness path violates the single-account security model.
 *
 * The single-account security model ensures that all witnesses in a transaction
 * use the same BIP44 account number. This prevents cross-account signing which
 * could indicate a confused deputy attack.
 *
 * On the first call, stores the account information from the path.
 * On subsequent calls, checks if the path uses the same account and Byron/Shelley prefix.
 * Byron and Shelley prefixes can be mixed only at account 0 (hardened(0)).
 *
 * @param[in] path
 *   BIP44 path to check and potentially store
 *
 * @return
 *   true if the path violates the single-account security model
 *   false if the path is acceptable or was stored successfully
 */
bool violatesSingleAccountOrStoreIt(const bip44_path_t* path);

/**
 * Allocate a zeroed temporary buffer from app memory or fail hard.
 *
 * Intended for short-lived transaction/UI helpers that move work off the stack on Ledger
 * devices with tighter stack budgets.
 */
uint8_t *tx_alloc_temp_buffer_or_fail(size_t size);

/**
 * Resolve a transaction output destination into raw address bytes.
 *
 * For third-party destinations, copies the provided raw bytes.
 * For device-owned destinations, derives address bytes from params.
 *
 * @return true on success, false on invalid destination or conversion failure.
 */
bool tx_output_destination_to_address_bytes(const tx_output_destination_t* destination,
                                            uint8_t* addressBuffer,
                                            size_t addressBufferSize,
                                            size_t* outAddressLength);

/**
 * Format a transaction output destination as a human-readable address string.
 *
 * @return true on success, false on conversion/format failure.
 */
bool format_tx_output_destination_human_readable(const tx_output_destination_t* destination,
                                                 char* out,
                                                 size_t outSize);
