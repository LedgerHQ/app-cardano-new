/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define IO_CAPTURE_MAX_RESPONSE_SIZE 4096

extern uint8_t g_last_response[IO_CAPTURE_MAX_RESPONSE_SIZE];
extern size_t g_last_response_len;
extern uint16_t g_last_response_swo;

void io_capture_reset(void);
