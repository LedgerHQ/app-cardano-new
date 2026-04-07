/* SPDX-FileCopyrightText: 2016-2025 Ledger */
/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "swap.h"
#include "ui_formatters.h"
#include "utils.h"

#ifdef HAVE_SWAP

// On error, leave printable_amount as empty string. This is the SDK-mandated error
// convention for this callback — the framework has no return value to check.
void swap_handle_get_printable_amount(get_printable_amount_parameters_t *params) {
    uint64_t amount;

    TRACE("Inside swap_handle_get_printable_amount");
    explicit_bzero(params->printable_amount, sizeof(params->printable_amount));

    // swap_str_to_u64 may legitimately fail on malformed input from the swap partner app.
    if (!swap_str_to_u64(params->amount, params->amount_length, &amount)) {
        TRACE("Amount copy error");
        return;
    }

    // Format as ADA with 6 decimal places and " ADA" suffix
    bool formatted = format_ada_amount(amount,
                                       params->printable_amount,
                                       sizeof(params->printable_amount));
    LEDGER_ASSERT(formatted, "Failed to format ADA amount");

    TRACE("Amount=%s", params->printable_amount);
}

#endif  // HAVE_SWAP
