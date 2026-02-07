/*****************************************************************************
 *   Ledger App Cardano.
 *   (c) 2025 Ledger SAS and Vacuumlabs
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include "swap.h"
#include "ui_formatters.h"
#include "utils.h"

#ifdef HAVE_SWAP

// Set empty printable_amount on error, printable amount otherwise
void swap_handle_get_printable_amount(get_printable_amount_parameters_t *params) {
    uint64_t amount;

    TRACE("Inside swap_handle_get_printable_amount");
    explicit_bzero(params->printable_amount, sizeof(params->printable_amount));

    if (!swap_str_to_u64(params->amount, params->amount_length, &amount)) {
        TRACE("Amount copy error");
        return;
    }

    // Format as ADA with 6 decimal places and " ADA" suffix
    if (!format_ada_amount(amount,
                           params->printable_amount,
                           sizeof(params->printable_amount))) {
        TRACE("Failed to format ADA amount");
        explicit_bzero(params->printable_amount, sizeof(params->printable_amount));
        return;
    }

    TRACE("Amount=%s", params->printable_amount);
}

#endif  // HAVE_SWAP
