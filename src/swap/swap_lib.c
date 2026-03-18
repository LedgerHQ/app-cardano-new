/* SPDX-FileCopyrightText: 2016-2025 Ledger */
/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "swap_lib.h"

#ifdef HAVE_SWAP

#include <string.h>

#include "os.h"
#include "ledger_assert.h"
#include "swap_error_code_helpers.h"

#include "addressUtilsShelley.h"
#include "utils.h"

typedef struct swap_validated_s {
    bool initialized;
    uint64_t amount;
    uint64_t fee;
    char destination[MAX_HUMAN_ADDRESS_LENGTH];
} swap_validated_t;

static swap_validated_t G_swap_validated;

bool swap_transaction_params_initialized(void) {
    return G_swap_validated.initialized;
}

__attribute__((noreturn)) void swap_reject_and_exit(uint8_t common_error_code,
                                                    uint8_t application_specific_error_code) {
    send_swap_error_simple(SWO_SWAP_CHECKING_FAIL,
                           common_error_code,
                           application_specific_error_code);
    LEDGER_ASSERT(false, "send_swap_error_simple unexpectedly returned");
}

bool swap_copy_transaction_parameters(create_transaction_parameters_t *params) {
    TRACE("Inside swap_copy_transaction_parameters");
    LEDGER_ASSERT(params != NULL, "NULL params");

    // Ensure no extra id (Cardano does not use extra IDs)
    if (params->destination_address_extra_id == NULL) {
        TRACE("destination_address_extra_id expected");
        return false;
    }
    if (params->destination_address_extra_id[0] != '\0') {
        TRACE("destination_address_extra_id expected empty, not '%s'",
              params->destination_address_extra_id);
        return false;
    }

    // First copy parameters to stack, then clear BSS, then copy to global.
    // We need this "trick" as the input data position can overlap with app globals
    // and also because we want to memset the whole BSS segment as it is not done
    // when an app is called as a lib.
    // This is necessary as many parts of the code expect BSS variables to
    // be initialized at 0.
    swap_validated_t swap_validated;
    memset(&swap_validated, 0, sizeof(swap_validated));

    // Save destination address
    LEDGER_ASSERT(params->destination_address != NULL, "NULL destination_address");
    LEDGER_ASSERT(strlen(params->destination_address) < sizeof(swap_validated.destination),
                  "Swap destination address too long");
    strlcpy(swap_validated.destination,
            params->destination_address,
            sizeof(swap_validated.destination));
    if (swap_validated.destination[sizeof(swap_validated.destination) - 1] != '\0') {
        TRACE("Address copy error");
        return false;
    }

    TRACE("Destination received %s", params->destination_address);

    // Save amount and fees
    LEDGER_ASSERT(params->amount != NULL, "NULL amount");
    LEDGER_ASSERT(params->fee_amount != NULL, "NULL fee_amount");
    if (!swap_str_to_u64(params->amount, params->amount_length, &swap_validated.amount)) {
        TRACE("Amount copy error");
        return false;
    }
    if (!swap_str_to_u64(params->fee_amount, params->fee_amount_length, &swap_validated.fee)) {
        TRACE("Fee copy error");
        return false;
    }

    swap_validated.initialized = true;

    // Full reset the global variables
    os_explicit_zero_BSS_segment();

    // Commit from stack to global data, params becomes tainted but we won't access it anymore
    memcpy(&G_swap_validated, &swap_validated, sizeof(swap_validated));
    TRACE("Swap params committed: initialized=%d", G_swap_validated.initialized);
    return true;
}

bool swap_check_destination_validity(const tx_output_destination_t *destination) {
    char rawAddressHuman[MAX_HUMAN_ADDRESS_LENGTH] = {0};

    TRACE("Inside swap_check_destination_validity");
    LEDGER_ASSERT(destination != NULL, "NULL destination");
    LEDGER_ASSERT(G_swap_validated.initialized, "Swap validation called before initialization");

    switch (destination->type) {
        case DESTINATION_THIRD_PARTY:
            if (!format_address_human_readable(destination->address.buffer,
                                               destination->address.length,
                                               rawAddressHuman,
                                               sizeof(rawAddressHuman))) {
                TRACE("Failed to format address");
                return false;
            }
            if (strcmp(G_swap_validated.destination, rawAddressHuman) != 0) {
                TRACE("Destination mismatch: tx=%s, swap=%s",
                      rawAddressHuman,
                      G_swap_validated.destination);
                return false;
            }
            break;
        default:
            LEDGER_ASSERT(false, "Invalid destination type for swap: %d", destination->type);
            return false;  // Unreachable
    }
    TRACE("Destination VALID");
    return true;
}

bool swap_check_amount_validity(uint64_t amount) {
    TRACE("Inside swap_check_amount_validity");
    LEDGER_ASSERT(G_swap_validated.initialized, "Swap validation called before initialization");
    if (amount != G_swap_validated.amount) {
        TRACE("Invalid swap amount!");
        return false;
    }
    TRACE("Amount VALID");
    return true;
}

bool swap_check_fee_validity(uint64_t fee) {
    TRACE("Inside swap_check_fee_validity");
    LEDGER_ASSERT(G_swap_validated.initialized, "Swap validation called before initialization");
    if (fee != G_swap_validated.fee) {
        TRACE("Invalid swap fee!");
        return false;
    }
    TRACE("Fee VALID");
    return true;
}

#endif  // HAVE_SWAP
