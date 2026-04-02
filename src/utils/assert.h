/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#define STATIC_ASSERT _Static_assert

#define ASSERT_TYPE(expr, expected_type) \
    STATIC_ASSERT(__builtin_types_compatible_p(__typeof__((expr)), expected_type), "Wrong type")

#include "ledger_assert.h"

// Redeclare assert_exit as noreturn so the static analyzer understands that
// ASSERT() never returns when the condition is false.
// The SDK omits noreturn on assert_exit() in the non-display path; we strengthen
// it here. Not needed when HAVE_LEDGER_ASSERT_DISPLAY is set (that path uses
// assert_display_exit which is already declared noreturn).
#ifndef HAVE_LEDGER_ASSERT_DISPLAY
void assert_exit(bool confirm) __attribute__((noreturn));
#endif

// this short version is useful to decrease the .text footprint
// which is a problem for debug builds
#define ASSERT(x) LEDGER_ASSERT((x), "bug")
