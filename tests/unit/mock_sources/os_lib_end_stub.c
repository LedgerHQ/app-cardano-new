/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>

#include "ledger_assert.h"

__attribute__((noreturn)) void os_lib_end(void) {
    LEDGER_ASSERT(false, "Unexpected os_lib_end in unit test");
    for (;;) {}
}
