/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "buffer.h"

void handler_sign_opcert(buffer_t *cdata);

/**
 * Finalize operational certificate signing after user confirmation.
 *
 * Assembles the opcert bytestring and signs it with the pool cold key.
 * Sets appropriate state and sends response back to client.
 */
void finalize_sign_opcert(void);
