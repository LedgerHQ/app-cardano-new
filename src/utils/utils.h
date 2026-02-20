/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h> // Required for size_t
#include "assert.h"
#include "cardano_buffer.h"

// -----------------------------------------------------------------------------
// Type Safety Macros
// -----------------------------------------------------------------------------

/*
 * Internal helper to detect if a variable is a pointer.
 *
 * Logic:
 * 1. __builtin_classify_type(x) == 5 detects Pointers AND Arrays.
 * If x is a Struct, Int, or Float, we must NOT attempt to index it (x[0]),
 * as that causes a syntax error in the parser even if the branch is not taken.
 *
 * 2. We use __builtin_choose_expr to swap 'x' with a dummy safe array
 * ((int[1]){0}) whenever 'x' is NOT a pointer/array.
 * - If x is Struct: Check runs on dummy array -> Returns 0 (Safe).
 * - If x is Pointer: Check runs on x -> Returns 1 (Unsafe).
 * - If x is Array: Check runs on x -> Returns 0 (Safe).
 *
 * 3. __builtin_types_compatible_p distinguishes Arrays from Pointers.
 * - Array:  typeof(arr) vs typeof(&arr[0]) (int*)... NOT Compatible.
 * - Pointer: typeof(ptr) vs typeof(&ptr[0]) (int*)... ARE Compatible.
 */
#define _SAFE_DUMMY_ARR ((int[1]){0})

#define _IS_UNSAFE_PTR(x)                                                                          \
    __builtin_types_compatible_p(                                                                  \
        __typeof__(__builtin_choose_expr(__builtin_classify_type(x) == 5, x, _SAFE_DUMMY_ARR)),    \
        __typeof__(&(__builtin_choose_expr(__builtin_classify_type(x) == 5, x, _SAFE_DUMMY_ARR))[0]) \
    )

/*
 * Helper that generates a compile-time error (negative array size) if
 * the condition is true (1). Returns 0 if safe.
 */
#define _COMPILE_TIME_ASSERT_NOT_PTR(condition) \
    (sizeof(char[1 - 2 * !!(condition)]) * 0)

/*
 * SIZEOF(var)
 * Safe wrapper for sizeof.
 * Returns sizeof(var), but fails to compile if 'var' is a pointer.
 * Works for Scalars, Arrays, and Structs.
 */
#define SIZEOF(var) \
    (sizeof(var) + _COMPILE_TIME_ASSERT_NOT_PTR(_IS_UNSAFE_PTR(var)))

/*
 * ARRAY_LEN(arr)
 * Safe wrapper for array length calculation.
 * Fails to compile if 'arr' is a pointer or a non-array type (e.g. struct).
 *
 * Note: We rely on the fact that &x[0] is invalid syntax for structs/scalars,
 * and the compatibility check fails for pointers.
 */
#define ARRAY_LEN(arr)                                                          \
    (sizeof(arr) / sizeof((arr)[0]) +                                           \
     _COMPILE_TIME_ASSERT_NOT_PTR(__builtin_types_compatible_p(__typeof__(arr), __typeof__(&(arr)[0]))))


// -----------------------------------------------------------------------------
// Iteration & Logic
// -----------------------------------------------------------------------------

/* Any buffer claiming to be longer than this is a bug.
 * Enforced against MAX_TX_BUFFER_SIZE by STATIC_ASSERT in tx_constants.h. */
#define BUFFER_SIZE_PARANOIA (21 * 1024 + 1)

/*
 * MARK_UNUSED
 * The 'deprecated' attribute ensures that if you accidentally start using
 * a variable marked unused, the compiler will warn you.
 */
#define MARK_UNUSED __attribute__((unused, deprecated))

#define IS_SIGNED_TYPE(type) (((type)(-1)) < 0)


// -----------------------------------------------------------------------------
// Tracing / Logging
// -----------------------------------------------------------------------------

#ifdef HAVE_PRINTF

#define TRACE(...)                              \
    do {                                        \
        PRINTF("[%s:%d] ", __func__, __LINE__); \
        PRINTF("" __VA_ARGS__);                 \
        PRINTF("\n");                           \
    } while (0)

static inline void trace_buffer_t_impl(const buffer_t *buffer) {
    LEDGER_ASSERT(buffer != NULL, "TRACE_BUFFER_T NULL buffer");

    size_t remaining = buffer_data_size(buffer);
    if (remaining == 0) {
        TRACE("empty buffer (total_size=%u)", (unsigned)buffer->size);
        return;
    }

    TRACE("%.*h", (int)remaining, buffer_get_cur(buffer));
}

#define TRACE_BUFFER(BUF, SIZE) TRACE("%.*h", (int)(SIZE), BUF)
#define TRACE_BUFFER_T(BUF)     trace_buffer_t_impl(BUF)

#else // !HAVE_PRINTF

#define TRACE(...)              do {} while(0)
#define TRACE_BUFFER(BUF, SIZE) do {} while(0)
#define TRACE_BUFFER_T(BUF)     do {} while(0)

#endif
