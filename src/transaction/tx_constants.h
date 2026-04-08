/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "utils.h"

// Maximum raw transaction buffer length accepted from the host.
// This is a validation limit, not an allocation size - actual allocation
// is determined by the client-provided raw_tx_total_length in INIT APDU.
//
// Theoretical maximum: 19,456 bytes (16KB CBOR + 2816B overhead + 256B margin)
// Set to 21 KB to provide additional room for UI structures on top of tx buffer.
// See doc/tx_raw_buffer.md for details.
#define MAX_TX_BUFFER_SIZE (21 * 1024)  // 21 KB

STATIC_ASSERT(BUFFER_SIZE_PARANOIA > MAX_TX_BUFFER_SIZE,
              "BUFFER_SIZE_PARANOIA must be > MAX_TX_BUFFER_SIZE");
