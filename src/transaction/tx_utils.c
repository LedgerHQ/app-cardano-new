/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "tx_utils.h"

#include <stddef.h>
#include <string.h>

#include "mem.h"
#include "globals.h"
#include "bip44.h"
#include "assert.h"
#include "utils.h"

uint8_t *tx_alloc_temp_buffer_or_fail(size_t size) {
    uint8_t *buffer = NULL;
    bool allocated = APP_MEM_CALLOC((void **) &buffer, (uint16_t) size);
    ASSERT(allocated && buffer != NULL);
    return buffer;
}

bool violatesSingleAccountOrStoreIt(const bip44_path_t* path) {
    ASSERT(path != NULL);
    TRACE("Considering path");
    BIP44_PRINTF(path);
    TRACE("");

    single_account_data_t* singleAccountData = &(G_context.tx_info.single_account_data);

    if (!bip44_hasOrdinaryWalletKeyPrefix(path) || !bip44_containsAccount(path)) {
        TRACE("Invalid path in single account check");
        ASSERT(false);
    }

    const bool isByron = bip44_hasByronPrefix(path);
    const uint32_t account = bip44_getAccount(path);

    if (singleAccountData->isStored) {
        const uint32_t storedAccount = singleAccountData->accountNumber;
        if (account != storedAccount) {
            TRACE("Account mismatch: current=%u, stored=%u", account, storedAccount);
            return true;
        }
        const bool combinesByronAndShelley = singleAccountData->isByron != isByron;
        const bool combinationAllowed = (storedAccount == bip44_harden(0));
        if (combinesByronAndShelley && !combinationAllowed) {
            TRACE("Byron/Shelley mixing not allowed for account %u", storedAccount);
            return true;
        }
    } else {
        singleAccountData->isStored = true;
        singleAccountData->isByron = isByron;
        singleAccountData->accountNumber = account;
        TRACE("Stored single account data: account=%u, isByron=%d", account, isByron);
    }

    return false;
}

bool tx_output_destination_to_address_bytes(const tx_output_destination_t* destination,
                                            uint8_t* addressBuffer,
                                            size_t addressBufferSize,
                                            size_t* outAddressLength) {
    ASSERT(destination != NULL);
    ASSERT(addressBuffer != NULL);
    ASSERT(outAddressLength != NULL);

    LEDGER_ASSERT(addressBufferSize < BUFFER_SIZE_PARANOIA,
                  "address buffer size too large: %u",
                  (unsigned) addressBufferSize);

    switch (destination->type) {
        case DESTINATION_THIRD_PARTY:
            if (destination->address.buffer == NULL ||
                destination->address.length == 0 ||
                destination->address.length > MAX_ADDRESS_LENGTH ||
                destination->address.length > addressBufferSize) {
                return false;
            }
            memmove(addressBuffer, destination->address.buffer, destination->address.length);
            *outAddressLength = destination->address.length;
            return true;

        case DESTINATION_DEVICE_OWNED: {
            size_t derivedAddressLength =
                deriveAddress(&destination->params, addressBuffer, addressBufferSize);
            LEDGER_ASSERT(derivedAddressLength > 0 &&
                          derivedAddressLength <= MAX_ADDRESS_LENGTH &&
                          derivedAddressLength <= addressBufferSize,
                          "Invalid derived destination address length: %u",
                          (unsigned) derivedAddressLength);
            *outAddressLength = derivedAddressLength;
            return true;
        }

        default:
            return false;
    }
}

__noinline_due_to_stack__
bool format_tx_output_destination_human_readable(const tx_output_destination_t* destination,
                                                 char* out,
                                                 size_t outSize) {
    uint8_t *addressBytes = tx_alloc_temp_buffer_or_fail(MAX_ADDRESS_LENGTH);
    size_t addressLength = 0;
    if (!tx_output_destination_to_address_bytes(destination,
                                                addressBytes,
                                                MAX_ADDRESS_LENGTH,
                                                &addressLength)) {
        APP_MEM_FREE_AND_NULL((void **) &addressBytes);
        return false;
    }

    bool formatted = format_address_human_readable(addressBytes, addressLength, out, outSize);
    APP_MEM_FREE_AND_NULL((void **) &addressBytes);
    return formatted;
}
