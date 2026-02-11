/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "tx_utils.h"
#include <string.h>
#include "globals.h"
#include "bip44.h"
#include "assert.h"
#include "utils.h"

bool violatesSingleAccountOrStoreIt(const bip44_path_t* path) {
    LEDGER_ASSERT(path != NULL, "NULL path in single-account check");
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
    LEDGER_ASSERT(destination != NULL, "NULL destination");
    LEDGER_ASSERT(addressBuffer != NULL, "NULL address buffer");
    LEDGER_ASSERT(outAddressLength != NULL, "NULL outAddressLength");

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
            if (destination->params == NULL) {
                return false;
            }
            size_t derivedAddressLength =
                deriveAddress(destination->params, addressBuffer, addressBufferSize);
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

bool format_tx_output_destination_human_readable(const tx_output_destination_t* destination,
                                                 char* out,
                                                 size_t outSize) {
    uint8_t addressBytes[MAX_ADDRESS_LENGTH] = {0};
    size_t addressLength = 0;
    if (!tx_output_destination_to_address_bytes(destination,
                                                addressBytes,
                                                SIZEOF(addressBytes),
                                                &addressLength)) {
        return false;
    }

    return format_address_human_readable(addressBytes, addressLength, out, outSize);
}

pool_owner_counts_t count_pool_owner_nodes(const flist_node_t* owners) {
    pool_owner_counts_t counts = {0};
    const flist_node_t* node = owners;
    while (node != NULL) {
        const tx_certificate_node_t* owner_item = (const tx_certificate_node_t*) node;
        const ext_credential_t* owner_cred = &owner_item->certificate.stakeCredential;
        if (owner_cred->type == EXT_CREDENTIAL_KEY_PATH) {
            counts.path_owners++;
            if (counts.first_path_owner == NULL) {
                counts.first_path_owner = owner_cred;
            }
        }
        counts.total_owners++;
        node = node->next;
    }
    LEDGER_ASSERT(counts.path_owners <= counts.total_owners, "Pool owner count mismatch");
    LEDGER_ASSERT((counts.path_owners == 0) == (counts.first_path_owner == NULL),
                  "Pool owner path state mismatch");
    return counts;
}
