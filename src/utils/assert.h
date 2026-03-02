/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#define STATIC_ASSERT _Static_assert

#define ASSERT_TYPE(expr, expected_type) \
    STATIC_ASSERT(__builtin_types_compatible_p(__typeof__((expr)), expected_type), "Wrong type")

#include "ledger_assert.h"

#define ASSERT(x) LEDGER_ASSERT((x), "probably a bug")
