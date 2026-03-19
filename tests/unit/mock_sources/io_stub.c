/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>

__attribute__((weak)) int io_send_sw(uint16_t swo) {
    fprintf(stderr, "[mock io_send_sw] sw=0x%04x\n", swo);
    return 0;
}

__attribute__((weak)) int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    (void) buffer;
    (void) bufferLength;
    fprintf(stderr, "[mock io_send_response_pointer] sw=0x%04x\n", swo);
    return 0;
}

// Weak symbol - will be overridden by real implementation if app_context.c is linked
__attribute__((weak)) void send_swo_and_reset(uint16_t swo) {
    fprintf(stderr, "[mock send_swo_and_reset] sw=0x%04x\n", swo);
    io_send_sw(swo);
}

uintptr_t pic(uintptr_t linked_address) {
    return linked_address;
}
