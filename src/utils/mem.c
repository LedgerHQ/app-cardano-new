/* SPDX-FileCopyrightText: 2016-2025 Ledger */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Dynamic allocator that uses a fixed-length buffer that is hopefully big enough
 *
 * The two functions alloc & dealloc use the buffer as a simple stack.
 * Especially useful when an unpredictable amount of data will be received and have to be stored
 * during the transaction but discarded right after.
 */

#include <stdint.h>
#include <string.h>
#include "mem.h"
#include "app_mem_utils.h"
#include "os_print.h"
#include "os.h"

#if defined(TARGET_NANOX)
#define SIZE_MEM_BUFFER (23 * 1024)
#else
#define SIZE_MEM_BUFFER (25 * 1024)
#endif

static uint8_t mem_buffer[SIZE_MEM_BUFFER] __attribute__((aligned(sizeof(intmax_t))));

bool mem_utils_reset_app_heap(void) {
    explicit_bzero(mem_buffer, sizeof(mem_buffer));
    return mem_utils_init(mem_buffer, sizeof(mem_buffer));
}
