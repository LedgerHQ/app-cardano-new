/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>

typedef enum swap_error_common_code_e {
    SWAP_EC_ERROR_INTERNAL = 0x00,
    SWAP_EC_ERROR_WRONG_AMOUNT = 0x01,
    SWAP_EC_ERROR_WRONG_DESTINATION = 0x02,
    SWAP_EC_ERROR_WRONG_FEES = 0x03,
    SWAP_EC_ERROR_WRONG_METHOD = 0x04,
    SWAP_EC_ERROR_CROSSCHAIN_WRONG_MODE = 0x05,
    SWAP_EC_ERROR_CROSSCHAIN_WRONG_METHOD = 0x06,
    SWAP_EC_ERROR_CROSSCHAIN_WRONG_HASH = 0x07,
    SWAP_EC_ERROR_GENERIC = 0xFF,
} swap_error_common_code_t;

__attribute__((noreturn)) void send_swap_error_simple(uint16_t status_word,
                                                      uint8_t common_error_code,
                                                      uint8_t application_specific_error_code);
