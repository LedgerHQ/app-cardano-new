/* SPDX-FileCopyrightText: 2016-2025 Ledger */
/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include "app_mem_utils.h"
#include "assert.h"

bool mem_utils_reset_app_heap(void);

/**
 * Allocate zeroed memory from the app heap.
 *
 * Asserts that allocation_size fits in uint16_t (as required by APP_MEM_CALLOC).
 * Returns true on success, false on failure (out of memory).
 */
static inline bool allocate_zeroed(void **result, size_t allocation_size) {
    LEDGER_ASSERT(allocation_size <= UINT16_MAX, "Allocation size too large");
    *result = NULL;
    if (allocation_size == 0) {
        return true;
    }
    return APP_MEM_CALLOC(result, (uint16_t) allocation_size);
}
