/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef H_TEST_NATIVE_SCRIPT_UTILS
#define H_TEST_NATIVE_SCRIPT_UTILS

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "buffer.h"
#include "cardano_constants.h"
#include "deriveNativeScriptHash/deriveNativeScriptHash_types.h"

// ----------------------------------------------------------------------
// IO Mock Functions (must be provided by test utilities)
// ----------------------------------------------------------------------

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo);
int io_send_sw(uint16_t swo);

// ----------------------------------------------------------------------
// Test Utilities
// ----------------------------------------------------------------------

/**
 * Initialize test memory heap
 */
bool test_mem_init(void);

/**
 * Reset global context to zero
 */
void reset_context(void);

/**
 * Reset response buffer and status word
 */
void reset_response_buffer(void);

/**
 * Get last status word from mock IO
 */
uint16_t get_last_sw(void);

/**
 * Get response buffer from mock IO
 */
const uint8_t *get_response_buffer(void);

/**
 * Get response buffer length from mock IO
 */
size_t get_response_buffer_length(void);

/**
 * Run derive native script init APDU handler (P1=INIT, empty payload)
 */
void run_derive_native_script_init_apdu(void);

/**
 * Run derive native script APDU handler
 */
void run_derive_native_script_apdu(buffer_t *buffer, uint8_t p1);

// ----------------------------------------------------------------------
// APDU Buffer Construction Helpers
// ----------------------------------------------------------------------

/**
 * Write uint32 in big-endian format
 */
void write_u32_be(uint8_t *buffer, uint32_t value);

/**
 * Construct APDU buffer for complex script start
 * Format: [script_type: 1 byte][children_count: 4 bytes BE]
 * For N_OF_K, add: [required_count: 4 bytes BE]
 */
void build_complex_script_start_buffer(
    uint8_t *buffer,
    size_t *buffer_length,
    uint8_t script_type,
    uint32_t children_count,
    uint32_t required_count  // Only used for N_OF_K
);

#endif  // H_TEST_NATIVE_SCRIPT_UTILS
