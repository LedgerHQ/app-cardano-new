/*******************************************************************************
 *   Ledger Cardano App
 *   (c) 2016-2025 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

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

// TODO 24 * 1024 does not compile for Nano X
#define SIZE_MEM_BUFFER (23 * 1024)

static uint8_t mem_buffer[SIZE_MEM_BUFFER] __attribute__((aligned(sizeof(intmax_t))));
void *app_mem_get_buffer(void) {
    return mem_buffer;
}

size_t app_mem_get_buffer_size(void) {
    return sizeof(mem_buffer);
}

bool mem_utils_reset_app_heap(void) {
    explicit_bzero(mem_buffer, sizeof(mem_buffer));
    return mem_utils_init(mem_buffer, sizeof(mem_buffer));
}
