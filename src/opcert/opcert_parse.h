/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "buffer.h"

#include "opcert_types.h"

/**
 * Deserialize opcert from buf into opcert.
 * On failure, sends the appropriate SW and resets app context.
 *
 * @return true on success, false on failure (SW already sent).
 */
bool parse_opcert(buffer_t *buf, parsed_opcert_t *opcert);
