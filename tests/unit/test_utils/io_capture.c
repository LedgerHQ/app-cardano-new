/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "io_capture.h"

#include <string.h>

#include "app_assert.h"
#ifdef HAVE_SWAP
#include "os.h"
#include "swap.h"
#endif

uint8_t g_last_response[IO_CAPTURE_MAX_RESPONSE_SIZE];
size_t g_last_response_len = 0;
uint16_t g_last_response_swo = 0;

void io_capture_reset(void) {
    g_last_response_len = 0;
    g_last_response_swo = 0;
}

__attribute__((weak)) int io_send_response_pointer(const uint8_t *buffer,
                                                   size_t bufferLength,
                                                   uint16_t swo) {
    LEDGER_ASSERT(bufferLength <= sizeof(g_last_response), "Response buffer overflow");

    if (buffer != NULL && bufferLength > 0) {
        memcpy(g_last_response, buffer, bufferLength);
    }

    g_last_response_len = bufferLength;
    g_last_response_swo = swo;

#ifdef HAVE_SWAP
    // Match SDK behavior in swap mode: once Exchange response is marked ready,
    // terminate app control flow from within the response send path.
    if (G_called_from_swap && G_swap_response_ready) {
        os_lib_end();
    }
#endif

    return 0;
}

__attribute__((weak)) int io_send_sw(uint16_t swo) {
    g_last_response_len = 0;
    g_last_response_swo = swo;
    return 0;
}
