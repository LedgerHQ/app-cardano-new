/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "ui_display_tx.h"
#include "ui_utils.h"
#include "ui_warnings.h"

void tx_review_cleanup(void) {
    ui_free_pairs();
    ui_free_warnings();
}
