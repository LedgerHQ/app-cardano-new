/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "buffer.h"

/**
 * Handler for CIP-8 message signing (INS_SIGN_MSG).
 *
 * @param[in] cdata  APDU command data buffer
 * @param[in] p1     P1 parameter (INIT/CHUNK/CONFIRM)
 */
void handler_sign_msg(buffer_t *cdata, uint8_t p1);

/**
 * Finalize message signing after user confirmation.
 */
void finalize_sign_msg(void);
