/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Returns true if next_key maintains canonical CBOR map key ordering relative
 * to previous_key (shorter keys first; equal-length keys in lexicographic order).
 * Duplicate keys return false.
 */
bool cbor_mapKeyFulfillsCanonicalOrdering(const uint8_t *previous_key,
                                          size_t previous_key_length,
                                          const uint8_t *next_key,
                                          size_t next_key_length);

/**
 * Maximum key size the tracker can hold. Sized to accommodate the largest
 * serialized CBOR map key used in transaction processing (gov action key: 72 bytes).
 */
#define CBOR_CANONICAL_MAX_KEY_SIZE 72

/**
 * Tracker for canonical CBOR map key ordering across loop iterations.
 * Copies each key internally so callers may use stack-local key buffers.
 * Declare with ENFORCE_CANONICAL_ORDERING_START(), then check each key with
 * ENFORCE_CANONICAL_ORDERING_CHECK().
 */
typedef struct {
    uint8_t previous_key[CBOR_CANONICAL_MAX_KEY_SIZE];
    size_t previous_key_length;
    bool has_previous;
} cbor_canonical_tracker_t;

bool cbor_canonical_tracker_check_and_advance(cbor_canonical_tracker_t *tracker,
                                               const uint8_t *next_key,
                                               size_t next_key_length);

/**
 * Declare a canonical ordering tracker in the current scope.
 * Must appear before any ENFORCE_CANONICAL_ORDERING_CHECK using the same name.
 */
#define ENFORCE_CANONICAL_ORDERING_START(tracker_name) \
    cbor_canonical_tracker_t tracker_name = {.previous_key = {0}, .previous_key_length = 0, .has_previous = false}

/**
 * Check that next_key maintains canonical ordering relative to the previous key
 * seen by tracker_name. On failure, calls tx_handle_parse_error(error_swo) and
 * returns false from the enclosing function.
 */
#define ENFORCE_CANONICAL_ORDERING_CHECK(tracker_name, next_key, next_key_length, error_swo) \
    do { \
        if (!cbor_canonical_tracker_check_and_advance(&(tracker_name), \
                                                      (next_key), \
                                                      (next_key_length))) { \
            tx_handle_parse_error(error_swo); \
            return false; \
        } \
    } while (0)
